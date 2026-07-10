package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VardrSec/vardrgate/internal/api"
	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/coverage"
	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/job"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/openapi"
	"github.com/VardrSec/vardrgate/internal/store"
)

func main() {
	// Subcommands: "serve" (default) runs the HTTP API; "run" executes a single
	// job file offline — the contract VardrRunner and CI use.
	if len(os.Args) > 1 && os.Args[1] == "run" {
		if err := runJob(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "gen" {
		if err := genTestCases(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "coverage" {
		if err := reportCoverage(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	serve()
}

// runJob executes one job envelope and writes the sanitized result as JSON.
// It never blocks on the network longer than the job's execution budget and
// exits non-zero on any error so callers (VardrRunner, CI) can gate on it.
func runJob(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	jobPath := fs.String("job", "", "path to the job JSON file (required)")
	outPath := fs.String("out", "", "path to write the result JSON (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *jobPath == "" {
		return errors.New("--job is required")
	}

	env, err := job.Load(*jobPath)
	if err != nil {
		return err
	}

	c := client.NewWithConfig(nil, env.ClientConfig())
	eng := engine.New(c)

	result, err := eng.Run(context.Background(), env.TestCase())
	if err != nil {
		return fmt.Errorf("run job: %w", err)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	out = append(out, '\n')

	if *outPath == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// genTestCases reads an OpenAPI spec and writes starter authorization test cases
// as a JSON array (to --out or stdout). The output is a scaffold: fill in
// credential values before running.
func genTestCases(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	specPath := fs.String("spec", "", "path to an OpenAPI 3 JSON spec (required)")
	baseURL := fs.String("base", "", "base URL to use instead of the spec's first server")
	outPath := fs.String("out", "", "path to write the generated cases (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" {
		return errors.New("--spec is required")
	}

	data, err := os.ReadFile(*specPath)
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}
	spec, err := openapi.Parse(data)
	if err != nil {
		return err
	}

	cases := spec.GenerateTestCases(*baseURL)
	out, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cases: %w", err)
	}
	out = append(out, '\n')

	if *outPath == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		return fmt.Errorf("write cases: %w", err)
	}
	return nil
}

// reportCoverage matches a set of test cases against an OpenAPI spec and writes
// a tested/untested coverage report as JSON (to --out or stdout).
func reportCoverage(args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	specPath := fs.String("spec", "", "path to an OpenAPI 3 JSON spec (required)")
	casesPath := fs.String("cases", "", "path to a JSON array of test cases (required)")
	outPath := fs.String("out", "", "path to write the report (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" || *casesPath == "" {
		return errors.New("--spec and --cases are required")
	}

	specData, err := os.ReadFile(*specPath)
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}
	spec, err := openapi.Parse(specData)
	if err != nil {
		return err
	}

	casesData, err := os.ReadFile(*casesPath)
	if err != nil {
		return fmt.Errorf("read cases: %w", err)
	}
	var cases []model.AuthorizationTestCase
	if err := json.Unmarshal(casesData, &cases); err != nil {
		return fmt.Errorf("parse cases: %w", err)
	}

	report := coverage.Analyze(spec, cases)
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	out = append(out, '\n')

	if *outPath == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func serve() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port, err := resolvePort()
	if err != nil {
		log.Error("invalid PORT", "error", err)
		os.Exit(1)
	}

	allowPrivate, err := resolveAllowPrivateTargets()
	if err != nil {
		log.Error("invalid ALLOW_PRIVATE_TARGETS", "error", err)
		os.Exit(1)
	}
	if allowPrivate {
		log.Warn("ALLOW_PRIVATE_TARGETS is enabled; loopback and private-network targets are permitted")
	}

	c := client.NewWithConfig(nil, client.Config{AllowPrivateTargets: allowPrivate})
	eng := engine.New(c)

	keys := resolveAPIKeys()
	if len(keys) == 0 {
		log.Warn("no API keys configured; the /jobs, /runner, and /audit endpoints are unauthenticated (development only)")
	} else {
		log.Info("API key authentication enabled", "tenants", len(distinctTenants(keys)))
	}

	st, closeStore, err := resolveStore(log)
	if err != nil {
		log.Error("failed to open job store", "error", err)
		os.Exit(1)
	}
	defer closeStore()

	handler := api.New(log, eng, st, keys)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("server starting", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	stop()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	log.Info("server stopped")
}

func resolvePort() (int, error) {
	raw := os.Getenv("PORT")
	if raw == "" {
		return 8080, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("PORT must be an integer between 1 and 65535, got %q", raw)
	}
	return n, nil
}

// resolveStore selects the job store from the environment. VARDRGATE_DB, when
// set, opens a durable SQLite store at that path (jobs survive restart);
// otherwise an ephemeral in-memory store is used. The returned func closes the
// store on shutdown.
func resolveStore(log *slog.Logger) (store.Store, func(), error) {
	path := os.Getenv("VARDRGATE_DB")
	if path == "" {
		log.Warn("VARDRGATE_DB is not set; using an in-memory job store (jobs do not survive restart)")
		return store.NewMemory(), func() {}, nil
	}
	sq, err := store.NewSQLite(path)
	if err != nil {
		return nil, nil, err
	}
	log.Info("using durable job store", "path", path)
	return sq, func() { sq.Close() }, nil
}

// resolveAPIKeys builds the bearer-token → tenant map from the environment.
//
//	VARDRGATE_API_KEYS="tenant-a:key1,tenant-b:key2"  → per-tenant isolation
//	VARDRGATE_API_KEY="key"                           → single "default" tenant
//
// VARDRGATE_API_KEYS takes precedence. An empty result disables auth (dev only).
func resolveAPIKeys() map[string]string {
	keys := map[string]string{}
	if multi := os.Getenv("VARDRGATE_API_KEYS"); multi != "" {
		for _, pair := range strings.Split(multi, ",") {
			pair = strings.TrimSpace(pair)
			tenant, key, ok := strings.Cut(pair, ":")
			tenant, key = strings.TrimSpace(tenant), strings.TrimSpace(key)
			if ok && tenant != "" && key != "" {
				keys[key] = tenant
			}
		}
		return keys
	}
	if single := os.Getenv("VARDRGATE_API_KEY"); single != "" {
		keys[single] = "default"
	}
	return keys
}

func distinctTenants(keys map[string]string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, t := range keys {
		out[t] = struct{}{}
	}
	return out
}

func resolveAllowPrivateTargets() (bool, error) {
	raw := os.Getenv("ALLOW_PRIVATE_TARGETS")
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("ALLOW_PRIVATE_TARGETS must be true or false, got %q", raw)
	}
	return v, nil
}
