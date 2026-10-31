package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VardrSec/vardrgate/internal/api"
	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/store"
)

func serve() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port, err := resolvePort()
	if err != nil {
		log.Error("invalid PORT", "error", err)
		os.Exit(exitUsage)
	}
	host, err := resolveHost()
	if err != nil {
		log.Error("invalid VARDRGATE_HOST", "error", err)
		os.Exit(exitUsage)
	}

	allowPrivate, err := resolveAllowPrivateTargets()
	if err != nil {
		log.Error("invalid ALLOW_PRIVATE_TARGETS", "error", err)
		os.Exit(exitUsage)
	}
	if allowPrivate {
		log.Warn("ALLOW_PRIVATE_TARGETS is enabled; loopback and private-network targets are permitted")
	}

	c := client.NewWithConfig(nil, client.Config{AllowPrivateTargets: allowPrivate})
	eng := engine.New(c)

	keys := resolveAPIKeys()
	if len(keys) == 0 {
		log.Warn("no API keys configured; /tests/execute and the /jobs, /runner, and /audit endpoints are unauthenticated (development only)")
		if !isLoopback(host) {
			log.Warn("serving without API keys on a non-loopback address; any client that can reach it can run tests", "host", host)
		}
	} else {
		log.Info("API key authentication enabled", "tenants", len(distinctTenants(keys)))
	}

	st, closeStore, err := resolveStore(log)
	if err != nil {
		log.Error("failed to open job store", "error", err)
		os.Exit(exitUsage)
	}
	defer closeStore()

	handler := api.New(log, eng, st, keys)

	srv := &http.Server{
		Addr:              net.JoinHostPort(host, strconv.Itoa(port)),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("server starting", "addr", srv.Addr, "version", versionString())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "error", err)
			os.Exit(exitUsage)
		}
	}()

	<-ctx.Done()
	stop()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown error", "error", err)
		os.Exit(exitUsage)
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

// resolveHost returns the address to listen on: VARDRGATE_HOST, or loopback
// when unset, so a bare `vardrgate` is reachable only from this machine. Set it
// to 0.0.0.0 (or ::) to listen on every interface, together with API keys.
func resolveHost() (string, error) {
	raw := os.Getenv("VARDRGATE_HOST")
	if raw == "" {
		return "127.0.0.1", nil
	}
	if raw != "localhost" && net.ParseIP(raw) == nil {
		return "", fmt.Errorf("VARDRGATE_HOST must be an IP address or localhost, got %q", raw)
	}
	return raw, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
