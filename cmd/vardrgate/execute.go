package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/demo"
	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/job"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/policy"
	"github.com/VardrSec/vardrgate/internal/report"
	"github.com/VardrSec/vardrgate/internal/secretref"
	"github.com/VardrSec/vardrgate/internal/suite"
)

// Stdout formats. JSON is the default everywhere because VardrRunner and
// VardrMap consume it; the others are for people and CI logs (ADR 0014).
const (
	formatJSON     = "json"
	formatText     = "text"
	formatMarkdown = "markdown"
)

// outputs are the result destinations shared by every command that executes a
// test case.
type outputs struct {
	out    *string
	sarif  *string
	format *string
}

func addOutputFlags(fs *flag.FlagSet) outputs {
	return outputs{
		out:    fs.String("out", "", "path to write the result JSON (default: stdout, when --format is json)"),
		sarif:  fs.String("sarif", "", "path to write a SARIF 2.1.0 report for code scanning"),
		format: fs.String("format", formatJSON, "stdout format: json, text, or markdown (--out always writes JSON)"),
	}
}

func (o outputs) validate() error {
	switch *o.format {
	case formatJSON, formatText, formatMarkdown:
		return nil
	default:
		return fmt.Errorf("invalid --format %q (want json, text, or markdown)", *o.format)
	}
}

// emit writes every requested output. It runs before gate so that the result
// file, SARIF and summary exist even when the command exits 2 or 3, which is
// exactly when a CI job needs them.
//
// With the default JSON format and no --out, the result goes to stdout as it
// always has; with --out, stdout stays empty. Both are the contract VardrRunner
// relies on.
func (o outputs) emit(payload any, cases []report.Case) error {
	if *o.out != "" {
		if err := writeJSON(*o.out, payload); err != nil {
			return err
		}
	}
	if *o.sarif != "" {
		if err := writeSARIF(*o.sarif, cases); err != nil {
			return err
		}
	}
	switch *o.format {
	case formatText:
		return report.Text(os.Stdout, cases)
	case formatMarkdown:
		return report.Markdown(os.Stdout, cases)
	default:
		if *o.out == "" {
			return writeJSON("", payload)
		}
		return nil
	}
}

func writeSARIF(path string, cases []report.Case) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	if err := report.SARIF(f, cases, versionString()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	return nil
}

// sourcePath renders a file path the way reports name it: relative to the
// working directory with forward slashes, because code scanning rejects
// absolute paths and a CI job runs from the repository root. A path outside the
// working directory is kept as given.
func sourcePath(path string) string {
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, abs); err == nil && !strings.HasPrefix(rel, "..") {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.ToSlash(path)
}

func reportCases(source string, results []engine.Result) []report.Case {
	cases := make([]report.Case, len(results))
	for i, res := range results {
		cases[i] = report.Case{Source: sourcePath(source), Result: res}
	}
	return cases
}

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
	out := addOutputFlags(fs)
	failOn := fs.String("fail-on", failOnNone, "exit 2 when a finding at or above this severity is reported (none, info, low, medium, high, critical)")
	failOnInconclusive := fs.Bool("fail-on-inconclusive", false, "exit 4 when an identity with an allow or deny expectation could not be judged")
	allowPrivate := fs.Bool("allow-private-targets", false, "permit loopback and private-network targets (--cases only; a job envelope carries its own setting)")
	allowMutating := fs.Bool("allow-mutating", false, "confirm that replaying an unsafe method (POST/PUT/PATCH/DELETE) once per identity is intended")
	requirePreflight := fs.Bool("require-identity-preflight", false, "require at least one declared identity preflight (Runner compatibility guard)")
	strictPreflight := fs.Bool("strict-identity-preflight", false, "require principal preflight for every assessed credentialed identity")
	timeout := fs.Duration("timeout", 0, "per-request timeout (--cases only; 0 uses the client default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*jobPath == "") == (*casesPath == "") {
		return errors.New("exactly one of --job or --cases is required")
	}
	if err := out.validate(); err != nil {
		return err
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
		tc := env.TestCase()
		if flagProvided(fs, "strict-identity-preflight") {
			tc.RequireIdentityPreflight = *strictPreflight
		}
		if *requirePreflight && !hasPreflight(tc) {
			return errors.New("identity preflight required but not declared")
		}
		if *allowMutating {
			tc.Mutating = true
		}
		eng := engine.New(client.NewWithConfig(nil, env.ClientConfig()))
		res, err := eng.Run(context.Background(), tc)
		if err != nil {
			return runError(err)
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
		if *allowMutating {
			for i := range cases {
				cases[i].Mutating = true
			}
		}
		if flagProvided(fs, "strict-identity-preflight") {
			for i := range cases {
				cases[i].RequireIdentityPreflight = *strictPreflight
			}
		}
		if err := validateSuite(cases, genScaffoldHint); err != nil {
			return err
		}
		if *requirePreflight {
			for _, tc := range cases {
				if !hasPreflight(tc) {
					return errors.New("identity preflight required but not declared")
				}
			}
		}
		cfg := client.Config{AllowPrivateTargets: *allowPrivate, Timeout: *timeout}
		eng := engine.New(client.NewWithConfig(nil, cfg))
		for _, tc := range cases {
			res, err := eng.Run(context.Background(), tc)
			if err != nil {
				return runError(fmt.Errorf("case %q: %w", tc.ID, err))
			}
			results = append(results, res)
		}
		payload = results
	}

	source := *casesPath
	if *jobPath != "" {
		source = *jobPath
	}
	if err := out.emit(payload, reportCases(source, results)); err != nil {
		return err
	}
	if err := gate(results, threshold); err != nil {
		return err
	}
	return gateInconclusive(results, *failOnInconclusive)
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

// runPolicyRun compiles declarative policies against a concrete environment and
// executes them: one policy with --policy, or a suite of them with --suite.
// This is the path the policy format was written for: before it, internal/policy
// compiled test cases that nothing could run.
func runPolicyRun(args []string) error {
	fs := flag.NewFlagSet("policy run", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: vardrgate policy run --policy <file> --base <url> --identities <file> [flags]
       vardrgate policy run --suite <file> [--base <url>] [flags]

Compiles declarative policies against one environment and executes them.

The identities file is a JSON array of identities whose "role" matches a key in
the policy's expect map. Credential values may reference environment variables
as ${VAR}, so the file can be committed next to the policy without secrets.

A suite file lists many policies with their path parameters and shares one
identities file between them, so a whole API runs as one command with one exit
code. --base overrides the suite's base URL.

Flags:
`)
		fs.PrintDefaults()
	}
	policyPath := fs.String("policy", "", "path to the YAML policy file (required unless --suite)")
	suitePath := fs.String("suite", "", "path to a suite file listing many policies")
	baseURL := fs.String("base", "", "base URL of the environment under test (required with --policy; overrides the suite's base)")
	identitiesPath := fs.String("identities", "", "path to a JSON array of identities (required with --policy)")
	params := paramFlag{}
	fs.Var(&params, "param", "path parameter as name=value; repeat for each parameter")
	tenant := fs.String("tenant", "", "tenant the target object belongs to; enables cross_tenant_access without reading it from the response")
	allowMutating := fs.Bool("allow-mutating", false, "confirm that replaying an unsafe method (POST/PUT/PATCH/DELETE) once per identity is intended")
	caseID := fs.String("id", "", "test case id (default: derived from the endpoint)")
	out := addOutputFlags(fs)
	failOn := fs.String("fail-on", failOnNone, "exit 2 when a finding at or above this severity is reported (none, info, low, medium, high, critical)")
	failOnInconclusive := fs.Bool("fail-on-inconclusive", false, "exit 4 when an identity with an allow or deny expectation could not be judged")
	allowPrivate := fs.Bool("allow-private-targets", false, "permit loopback and private-network targets")
	strictPreflight := fs.Bool("strict-identity-preflight", false, "require principal preflight for every assessed credentialed identity")
	timeout := fs.Duration("timeout", 0, "per-request timeout (0 uses the client default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := out.validate(); err != nil {
		return err
	}
	threshold, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}

	var cases []suite.Case
	if *suitePath != "" {
		// Per-policy bindings live in the suite file. Accepting them on the
		// command line as well would leave it unclear which one won.
		for name, set := range map[string]bool{
			"--policy": *policyPath != "", "--identities": *identitiesPath != "",
			"--param": len(params) > 0, "--tenant": *tenant != "", "--id": *caseID != "",
		} {
			if set {
				return fmt.Errorf("%s cannot be combined with --suite; set it in the suite file", name)
			}
		}
		s, err := suite.Load(*suitePath)
		if err != nil {
			return err
		}
		if !flagProvided(fs, "fail-on-inconclusive") {
			*failOnInconclusive = s.FailOnInconclusive
		}
		var strictOverride *bool
		if flagProvided(fs, "strict-identity-preflight") {
			strictOverride = strictPreflight
		}
		cases, err = s.Compile(filepath.Dir(*suitePath), suite.Options{BaseOverride: *baseURL, AllowMutating: *allowMutating, RequireIdentityPreflight: strictOverride})
		if err != nil {
			return err
		}
	} else {
		for name, val := range map[string]string{"--policy": *policyPath, "--base": *baseURL, "--identities": *identitiesPath} {
			if val == "" {
				return fmt.Errorf("%s is required (or use --suite)", name)
			}
		}
		tc, err := compilePolicy(*policyPath, *identitiesPath, policy.Bindings{
			RequireIdentityPreflight: *strictPreflight,
			TestCaseID:               *caseID,
			BaseURL:                  *baseURL,
			PathParams:               params,
			ResourceTenantID:         *tenant,
			AllowMutating:            *allowMutating,
		})
		if err != nil {
			return err
		}
		cases = []suite.Case{{Source: *policyPath, TestCase: tc}}
	}

	// Validate every case before any request is sent. Compilation does not catch
	// everything engine validation does, such as an unconfirmed unsafe method,
	// and finding that out at entry five means entries one to four already sent
	// live traffic.
	compiled := make([]model.AuthorizationTestCase, len(cases))
	for i, c := range cases {
		compiled[i] = c.TestCase
	}
	if err := validateSuite(compiled, ""); err != nil {
		return err
	}

	cfg := client.Config{AllowPrivateTargets: *allowPrivate, Timeout: *timeout}
	eng := engine.New(client.NewWithConfig(nil, cfg))
	results := make([]engine.Result, 0, len(cases))
	reported := make([]report.Case, 0, len(cases))
	for _, c := range cases {
		res, err := eng.Run(context.Background(), c.TestCase)
		if err != nil {
			if *suitePath == "" {
				return runError(fmt.Errorf("case %q: %w", c.TestCase.ID, err))
			}
			// In a suite, one entry's failed setup must not hide every later
			// result or suppress the reports. It is recorded as not run, the
			// rest continue, and gate exits 3.
			res = engine.Result{
				TestCaseID: c.TestCase.ID,
				Executions: []model.ExecutionResult{},
				Findings:   []model.Finding{},
				Error:      err.Error(),
			}
		}
		results = append(results, res)
		reported = append(reported, report.Case{Source: sourcePath(c.Source), Result: res})
	}

	// A single policy keeps emitting a single object, as it always has; a
	// suite emits an array, matching `run --cases`.
	var payload any = results
	if *suitePath == "" {
		payload = results[0]
	}
	if err := out.emit(payload, reported); err != nil {
		return err
	}
	if err := gate(results, threshold); err != nil {
		return err
	}
	return gateInconclusive(results, *failOnInconclusive)
}

func compilePolicy(policyPath, identitiesPath string, b policy.Bindings) (model.AuthorizationTestCase, error) {
	p, err := policy.Load(policyPath)
	if err != nil {
		return model.AuthorizationTestCase{}, err
	}
	b.Identities, err = policy.LoadIdentities(identitiesPath)
	if err != nil {
		return model.AuthorizationTestCase{}, err
	}
	return p.Compile(b)
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

	report.TextCase(&b, res)
	if len(res.Findings) == 0 {
		b.WriteString("(That is unexpected for this fixture.)\n")
		return b.String()
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
	var unreached, notRun []string
	for _, res := range results {
		if res.PreflightFailed() {
			return exitError{code: exitNotExecuted, err: errors.New("identity preflight failed; authorization requests were not executed")}
		}
		if res.Error != "" {
			notRun = append(notRun, fmt.Sprintf("%s (%s)", res.TestCaseID, res.Error))
		}
		if res.Unreached() {
			unreached = append(unreached, res.TestCaseID)
		}
	}
	if len(notRun) > 0 {
		return exitError{
			code: exitNotExecuted,
			err:  fmt.Errorf("%s could not run, so nothing was tested for them: %s", plural(len(notRun), "case", "cases"), strings.Join(notRun, "; ")),
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

func hasPreflight(tc model.AuthorizationTestCase) bool {
	for _, identity := range tc.Identities {
		if identity.Preflight != nil {
			return true
		}
	}
	return false
}

func flagProvided(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// runError maps an engine failure to the right exit code. A failed setup step
// means the preconditions were never met, so nothing was tested — the same
// situation as a target that could not be reached, and the same exit code.
func runError(err error) error {
	if errors.Is(err, engine.ErrSetupFailed) {
		return exitError{code: exitNotExecuted, err: err}
	}
	return err
}

// gateInconclusive fails an opted-in run in which some expectation could not be
// judged. It runs after gate, so "not tested" and threshold findings keep their
// codes and precedence; without the flag the exit code is unchanged.
func gateInconclusive(results []engine.Result, enabled bool) error {
	if !enabled {
		return nil
	}
	var lines []string
	for _, res := range results {
		for _, a := range res.Inconclusive() {
			lines = append(lines, res.TestCaseID+": "+report.Explain(a))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return exitError{
		code: exitInconclusive,
		err:  fmt.Errorf("%s: %s", plural(len(lines), "inconclusive assessment", "inconclusive assessments"), strings.Join(lines, "; ")),
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

func plural(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// validateSuite checks every case before any of them runs and reports all the
// problems together. A suite generated by `vardrgate gen` is a scaffold with
// empty credentials; discovering that one case at a time, after each partial
// run, is the wrong way to find out. hint, when set, is appended to the error.
func validateSuite(cases []model.AuthorizationTestCase, hint string) error {
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
	msg := fmt.Sprintf("%s could not be run:\n%s", plural(len(problems), "case", "cases"), strings.Join(problems, "\n"))
	if hint != "" {
		msg += "\n\n" + hint
	}
	return errors.New(msg)
}

// genScaffoldHint explains the most common reason a --cases suite fails
// validation.
const genScaffoldHint = "Cases from `vardrgate gen` require review — confirm every TODO permission, bind resources and fill in credential references before running them."

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
		if err := secretref.ExpandVerification(cases[i].WriteVerification); err != nil {
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
