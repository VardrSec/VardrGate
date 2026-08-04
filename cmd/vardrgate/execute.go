package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/demo"
	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/job"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/policy"
	"github.com/VardrSec/vardrgate/internal/secretref"
)

// failOnNone disables finding-based gating. It is the default so that adding
// the flag to an existing pipeline is a deliberate act, never a surprise.
const failOnNone = "none"

// runCases executes either a job envelope (--job) or a file of test cases
// (--cases) and writes the sanitized result JSON.
//
// --cases closes the loop with `gen`, which emits a JSON array: before this the
// generated file had no command that would accept it back.
func runCases(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vardrgate run (--job <file> | --cases <file>) [flags]

Executes authorization test cases and writes the result JSON.

Flags:
`)
		fs.PrintDefaults()
	}
	jobPath := fs.String("job", "", "path to a job envelope JSON file")
	casesPath := fs.String("cases", "", "path to a JSON array of test cases (as produced by `vardrgate gen`)")
	outPath := fs.String("out", "", "path to write the result JSON (default: stdout)")
	failOn := fs.String("fail-on", failOnNone, "exit 2 when a finding at or above this severity is reported (none, info, low, medium, high, critical)")
	allowPrivate := fs.Bool("allow-private-targets", false, "permit loopback and private-network targets (--cases only; a job envelope carries its own setting)")
	timeout := fs.Duration("timeout", 0, "per-request timeout (--cases only; 0 uses the client default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*jobPath == "") == (*casesPath == "") {
		return errors.New("exactly one of --job or --cases is required")
	}

	threshold, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}

	var (
		results []engine.Result
		payload any
	)

	if *jobPath != "" {
		env, err := job.Load(*jobPath)
		if err != nil {
			return err
		}
		eng := engine.New(client.NewWithConfig(nil, env.ClientConfig()))
		res, err := eng.Run(context.Background(), env.TestCase())
		if err != nil {
			return fmt.Errorf("run job: %w", err)
		}
		results = []engine.Result{res}
		// A single job keeps emitting a single object, which is the shape
		// VardrRunner already uploads.
		payload = res
	} else {
		cases, err := loadCases(*casesPath)
		if err != nil {
			return err
		}
		if err := validateSuite(cases); err != nil {
			return err
		}
		cfg := client.Config{AllowPrivateTargets: *allowPrivate, Timeout: *timeout}
		eng := engine.New(client.NewWithConfig(nil, cfg))
		for _, tc := range cases {
			res, err := eng.Run(context.Background(), tc)
			if err != nil {
				return fmt.Errorf("case %q: %w", tc.ID, err)
			}
			results = append(results, res)
		}
		payload = results
	}

	if err := writeJSON(*outPath, payload); err != nil {
		return err
	}
	return gate(results, threshold)
}

// runPolicy dispatches the policy subcommands. Only "run" exists today; the
// subcommand form leaves room for "validate" or "compile" without another
// top-level verb.
func runPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vardrgate policy run --policy <file> --base <url> --identities <file> [flags]")
	}
	switch args[0] {
	case "run":
		return runPolicyRun(args[1:])
	case "-h", "--help", "help":
		fmt.Println("usage: vardrgate policy run --policy <file> --base <url> --identities <file> [flags]")
		return nil
	default:
		return fmt.Errorf("unknown policy subcommand %q (want: run)", args[0])
	}
}

// runPolicyRun compiles a declarative policy against a concrete environment and
// executes it. This is the path the policy format was written for: before it,
// internal/policy compiled test cases that nothing could run.
func runPolicyRun(args []string) error {
	fs := flag.NewFlagSet("policy run", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vardrgate policy run --policy <file> --base <url> --identities <file> [flags]

Compiles a declarative policy against one environment and executes it.

The identities file is a JSON array of identities whose "role" matches a key in
the policy's expect map. Credential values may reference environment variables
as ${VAR}, so the file can be committed next to the policy without secrets.

Flags:
`)
		fs.PrintDefaults()
	}
	policyPath := fs.String("policy", "", "path to the YAML policy file (required)")
	baseURL := fs.String("base", "", "base URL of the environment under test (required)")
	identitiesPath := fs.String("identities", "", "path to a JSON array of identities (required)")
	params := paramFlag{}
	fs.Var(&params, "param", "path parameter as name=value; repeat for each parameter")
	tenant := fs.String("tenant", "", "tenant the target object belongs to; enables cross_tenant_access without reading it from the response")
	caseID := fs.String("id", "", "test case id (default: derived from the endpoint)")
	outPath := fs.String("out", "", "path to write the result JSON (default: stdout)")
	failOn := fs.String("fail-on", failOnNone, "exit 2 when a finding at or above this severity is reported (none, info, low, medium, high, critical)")
	allowPrivate := fs.Bool("allow-private-targets", false, "permit loopback and private-network targets")
	timeout := fs.Duration("timeout", 0, "per-request timeout (0 uses the client default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, val := range map[string]string{"--policy": *policyPath, "--base": *baseURL, "--identities": *identitiesPath} {
		if val == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	threshold, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}

	p, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	identities, err := policy.LoadIdentities(*identitiesPath)
	if err != nil {
		return err
	}

	tc, err := p.Compile(policy.Bindings{
		TestCaseID:       *caseID,
		BaseURL:          *baseURL,
		PathParams:       params,
		Identities:       identities,
		ResourceTenantID: *tenant,
	})
	if err != nil {
		return err
	}

	cfg := client.Config{AllowPrivateTargets: *allowPrivate, Timeout: *timeout}
	eng := engine.New(client.NewWithConfig(nil, cfg))
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		return fmt.Errorf("run policy: %w", err)
	}

	if err := writeJSON(*outPath, res); err != nil {
		return err
	}
	return gate([]engine.Result{res}, threshold)
}

// runDemo executes the bundled policy against a local vulnerable fixture so a
// first run proves the tool works without any setup.
func runDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vardrgate demo [flags]

Starts a deliberately broken profile API on loopback, runs the bundled policy
against it, and reports the findings. Nothing leaves the machine.

Flags:
`)
		fs.PrintDefaults()
	}
	outPath := fs.String("out", "", "path to write the result JSON (default: summary only)")
	failOn := fs.String("fail-on", failOnNone, "exit 2 when a finding at or above this severity is reported")
	if err := fs.Parse(args); err != nil {
		return err
	}
	threshold, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := demo.Run(ctx)
	if err != nil {
		return err
	}

	if *outPath != "" {
		if err := writeJSON(*outPath, res); err != nil {
			return err
		}
	}
	fmt.Print(demoNarrative(res))
	return gate([]engine.Result{res}, threshold)
}

// demoNarrative renders the demo result for a human reading a terminal. Every
// other command emits JSON on stdout for a machine; this one exists to be read.
func demoNarrative(res engine.Result) string {
	var b strings.Builder
	b.WriteString("\nVardrGate demo — a profile API that enforces nothing.\n")
	b.WriteString("Policy: only the owner may read /users/{user_id}/profile.\n\n")

	b.WriteString("Executions:\n")
	for _, ex := range res.Executions {
		if ex.Error != "" {
			fmt.Fprintf(&b, "  %-12s error: %s\n", ex.IdentityID, ex.Error)
			continue
		}
		fmt.Fprintf(&b, "  %-12s %d %s\n", ex.IdentityID, ex.StatusCode, ex.ObservedOutcome)
	}

	if len(res.Findings) == 0 {
		b.WriteString("\nNo findings. (That is unexpected for this fixture.)\n")
		return b.String()
	}

	fmt.Fprintf(&b, "\n%s:\n", plural(len(res.Findings), "finding", "findings"))
	for _, f := range sortedBySeverity(res.Findings) {
		fmt.Fprintf(&b, "  [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.Category, f.Message)
		for _, ev := range f.Evidence {
			fmt.Fprintf(&b, "      %s\n", ev)
		}
	}
	b.WriteString("\nThe same policy runs against a real environment with:\n")
	b.WriteString("  vardrgate policy run --policy examples/profile_ownership.policy.yaml \\\n")
	b.WriteString("      --base https://api.example.com --param user_id=42 \\\n")
	b.WriteString("      --identities identities.json --fail-on high\n")
	return b.String()
}

// gate turns a run into an exit code: nothing tested outranks anything found,
// because a finding count of zero means nothing when no request succeeded.
//
// The check is per case, not across the suite. A target that dies after the
// first case leaves the rest reaching nothing while the suite-wide ratio still
// looks partial — which is exactly the green-but-tested-nothing result this
// exists to prevent.
func gate(results []engine.Result, threshold model.Severity) error {
	var unreached []string
	for _, res := range results {
		if len(res.Executions) == 0 {
			continue
		}
		failed := 0
		for _, ex := range res.Executions {
			if ex.Error != "" {
				failed++
			}
		}
		if failed == len(res.Executions) {
			unreached = append(unreached, res.TestCaseID)
		}
	}
	if len(unreached) > 0 {
		return exitError{
			code: exitNotExecuted,
			err: fmt.Errorf("%s reached nothing — every identity failed to connect, so nothing was tested: %s",
				plural(len(unreached), "case", "cases"), strings.Join(unreached, ", ")),
		}
	}

	if threshold == "" {
		return nil
	}
	var breaching []model.Finding
	for _, res := range results {
		for _, f := range res.Findings {
			if f.Severity.Rank() >= threshold.Rank() {
				breaching = append(breaching, f)
			}
		}
	}
	if len(breaching) == 0 {
		return nil
	}
	return exitError{
		code: exitFindings,
		err:  fmt.Errorf("%s at or above %s: %s", plural(len(breaching), "finding", "findings"), threshold, summarize(breaching)),
	}
}

// parseFailOn resolves the --fail-on value. An empty Severity means no gating.
func parseFailOn(s string) (model.Severity, error) {
	if strings.EqualFold(strings.TrimSpace(s), failOnNone) {
		return "", nil
	}
	sev, ok := model.ParseSeverity(s)
	if !ok {
		return "", fmt.Errorf("invalid --fail-on %q (want none, info, low, medium, high, or critical)", s)
	}
	return sev, nil
}

// summarize renders breaching findings as "category (severity)" counts, most
// severe first, for the one line a CI log will actually show.
func summarize(findings []model.Finding) string {
	counts := map[string]int{}
	worst := map[string]model.Severity{}
	for _, f := range findings {
		key := string(f.Category)
		counts[key]++
		if f.Severity.Rank() > worst[key].Rank() {
			worst[key] = f.Severity
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if ri, rj := worst[keys[i]].Rank(), worst[keys[j]].Rank(); ri != rj {
			return ri > rj
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d (%s)", k, counts[k], worst[k]))
	}
	return strings.Join(parts, ", ")
}

func sortedBySeverity(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}

func plural(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// validateSuite checks every case before any of them runs and reports all the
// problems together. A suite generated by `vardrgate gen` is a scaffold with
// empty credentials; discovering that one case at a time, after each partial
// run, is the wrong way to find out.
func validateSuite(cases []model.AuthorizationTestCase) error {
	var problems []string
	for i, tc := range cases {
		if err := engine.Validate(tc); err != nil {
			label := tc.ID
			if label == "" {
				label = fmt.Sprintf("cases[%d]", i)
			}
			problems = append(problems, fmt.Sprintf("  %s: %s", label, err))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s could not be run:\n%s\n\nCases from `vardrgate gen` are scaffolds — fill in the credential values before running them.",
		plural(len(problems), "case", "cases"), strings.Join(problems, "\n"))
}

// loadCases reads a JSON array of test cases, also accepting a single object so
// a hand-written case does not have to be wrapped in brackets.
func loadCases(path string) ([]model.AuthorizationTestCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cases: %w", err)
	}
	var cases []model.AuthorizationTestCase
	if err := json.Unmarshal(data, &cases); err != nil {
		var single model.AuthorizationTestCase
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("parse cases: %w", err)
		}
		cases = []model.AuthorizationTestCase{single}
	}
	if len(cases) == 0 {
		return nil, errors.New("cases file contains no test cases")
	}
	// `gen` writes ${VAR} placeholders into credential values; resolve them here
	// so a generated suite runs straight from the repository it lives in.
	for i := range cases {
		if err := secretref.ExpandIdentities(cases[i].Identities); err != nil {
			return nil, fmt.Errorf("case %q: %w", cases[i].ID, err)
		}
	}
	return cases, nil
}

// writeJSON writes v as indented JSON to path, or to stdout when path is empty.
func writeJSON(path string, v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	out = append(out, '\n')
	if path == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// paramFlag collects repeated --param name=value flags.
type paramFlag map[string]string

func (p paramFlag) String() string {
	if len(p) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+p[k])
	}
	return strings.Join(parts, ",")
}

func (p paramFlag) Set(v string) error {
	name, value, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("expected name=value, got %q", v)
	}
	p[strings.TrimSpace(name)] = value
	return nil
}
