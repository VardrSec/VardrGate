package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/VardrSec/vardrgate/internal/demo"
	"github.com/VardrSec/vardrgate/internal/engine"
)

// demoIdentities mirrors demo.Identities with credential values written out,
// because model.Credential never marshals its value.
const demoIdentities = `[
  {"id": "owner", "role": "owner", "tenant_id": "tenant-a", "credential": {"type": "bearer", "value": "demo-owner-token"}},
  {"id": "other_user", "role": "other_user", "tenant_id": "tenant-b", "credential": {"type": "bearer", "value": "demo-other-token"}},
  {"id": "anonymous", "role": "anonymous", "credential": {"type": "static_header"}}
]`

// ownerOnly is a second policy against the same fixture under a different id,
// so a suite has two entries with distinct results.
const ownerOnly = `api:
  endpoint: GET /users/{user_id}/profile
expect:
  owner: allow
`

// writeSuite lays out a suite pointing at base and returns the suite path.
func writeSuite(t *testing.T, base string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"policies/profile.yaml": demo.Policy,
		"policies/owner.yaml":   ownerOnly,
		"identities.json":       demoIdentities,
		"suite.yaml": "base: " + base + `
identities: identities.json
policies:
  - policy: policies/profile.yaml
    params: {user_id: "42"}
  - policy: policies/owner.yaml
    id: owner-reads-own-profile
    params: {user_id: "42"}
`,
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "suite.yaml")
}

func startFixture(t *testing.T) string {
	t.Helper()
	base, stop, err := demo.StartFixture()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return base
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	runErr := fn()
	os.Stdout = orig
	_ = w.Close()
	return <-done, runErr
}

func readSARIF(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("SARIF not written: %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("SARIF is not JSON: %v", err)
	}
	return log
}

func TestPolicyRunSuite_RunsEveryEntryAndGatesOnce(t *testing.T) {
	suitePath := writeSuite(t, startFixture(t))
	out := filepath.Join(t.TempDir(), "result.json")
	sarif := filepath.Join(t.TempDir(), "result.sarif")

	stdout, err := captureStdout(t, func() error {
		return runPolicy([]string{"run", "--suite", suitePath, "--allow-private-targets",
			"--out", out, "--sarif", sarif, "--format", "markdown", "--fail-on", "high"})
	})
	if code := exitCode(t, err); code != exitFindings {
		t.Fatalf("exit = %d, want %d (the fixture enforces nothing): %v", code, exitFindings, err)
	}

	var results []engine.Result
	data, _ := os.ReadFile(out)
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("--out must hold a JSON array for a suite: %v", err)
	}
	if len(results) != 2 || results[1].TestCaseID != "owner-reads-own-profile" {
		t.Fatalf("results = %+v", results)
	}
	if len(results[0].Findings) == 0 || len(results[1].Findings) != 0 {
		t.Errorf("findings per case = %d, %d; want some, then none", len(results[0].Findings), len(results[1].Findings))
	}

	run := readSARIF(t, sarif)["runs"].([]any)[0].(map[string]any)
	if n := len(run["results"].([]any)); n != len(results[0].Findings) {
		t.Errorf("SARIF has %d results, want %d", n, len(results[0].Findings))
	}

	if !strings.Contains(stdout, "## VardrGate authorization results") || !strings.Contains(stdout, "owner-reads-own-profile") {
		t.Errorf("markdown summary missing from stdout:\n%s", stdout)
	}
}

// Exit 3 is when a CI job most needs its reports, so they are written before
// the gate decides the exit code.
func TestPolicyRunSuite_UnreachableTargetStillWritesReports(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String()
	_ = ln.Close()

	suitePath := writeSuite(t, closed)
	sarif := filepath.Join(t.TempDir(), "result.sarif")
	stdout, err := captureStdout(t, func() error {
		return runPolicy([]string{"run", "--suite", suitePath, "--allow-private-targets", "--sarif", sarif, "--format", "text"})
	})
	if code := exitCode(t, err); code != exitNotExecuted {
		t.Fatalf("exit = %d, want %d: %v", code, exitNotExecuted, err)
	}
	inv := readSARIF(t, sarif)["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != false {
		t.Error("SARIF must record an unsuccessful invocation when nothing was reached")
	}
	if !strings.Contains(stdout, "NOT TESTED") || !strings.Contains(stdout, "2 not tested") {
		t.Errorf("text output does not flag the unreached cases:\n%s", stdout)
	}
}

func TestPolicyRunSuite_BaseFlagOverridesTheSuite(t *testing.T) {
	suitePath := writeSuite(t, "https://not-the-real-target.invalid")
	_, err := captureStdout(t, func() error {
		return runPolicy([]string{"run", "--suite", suitePath, "--base", startFixture(t), "--allow-private-targets"})
	})
	if code := exitCode(t, err); code != exitOK {
		t.Fatalf("exit = %d; --base should have redirected the suite to the fixture: %v", code, err)
	}
}

func TestPolicyRunSuite_RejectsPerPolicyFlags(t *testing.T) {
	suitePath := writeSuite(t, "https://api.example.com")
	for _, extra := range [][]string{
		{"--policy", "p.yaml"}, {"--identities", "i.json"}, {"--param", "a=b"}, {"--tenant", "t"}, {"--id", "x"},
	} {
		args := append([]string{"run", "--suite", suitePath}, extra...)
		err := runPolicy(args)
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with --suite") {
			t.Errorf("%v: err = %v", extra, err)
		}
	}
}

func TestPolicyRun_RejectsUnknownFormat(t *testing.T) {
	err := runPolicy([]string{"run", "--policy", "p.yaml", "--base", "https://x", "--identities", "i.json", "--format", "xml"})
	if err == nil || !strings.Contains(err.Error(), "invalid --format") {
		t.Fatalf("err = %v", err)
	}
	if err := runCases([]string{"--cases", "c.json", "--format", "xml"}); err == nil || !strings.Contains(err.Error(), "invalid --format") {
		t.Fatalf("run: err = %v", err)
	}
}

// VardrRunner calls `run --job <file> --out <file>` and reads only the file.
// Adding formats must not start writing to stdout on that path.
func TestPolicyRun_DefaultJSONContractIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "p.yaml")
	identitiesPath := filepath.Join(dir, "i.json")
	_ = os.WriteFile(policyPath, []byte(demo.Policy), 0o600)
	_ = os.WriteFile(identitiesPath, []byte(demoIdentities), 0o600)
	base := startFixture(t)
	args := []string{"run", "--policy", policyPath, "--base", base, "--param", "user_id=42",
		"--identities", identitiesPath, "--allow-private-targets"}

	out := filepath.Join(dir, "result.json")
	stdout, err := captureStdout(t, func() error { return runPolicy(append(args, "--out", out)) })
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		t.Errorf("with --out and the default format, stdout must stay empty; got %q", stdout)
	}
	var single engine.Result
	data, _ := os.ReadFile(out)
	if err := json.Unmarshal(data, &single); err != nil || single.TestCaseID == "" {
		t.Errorf("a single policy must still write one JSON object: %v", err)
	}

	stdout, err = captureStdout(t, func() error { return runPolicy(args) })
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(stdout), &single); err != nil {
		t.Errorf("without --out, stdout must be the JSON result: %v", err)
	}
}

func TestSourcePath_IsRelativeWithForwardSlashes(t *testing.T) {
	if got := sourcePath(filepath.Join("policies", "a.yaml")); got != "policies/a.yaml" {
		t.Errorf("sourcePath = %q", got)
	}
	outside := filepath.Join(filepath.Dir(mustGetwd(t)), "elsewhere.yaml")
	if got := sourcePath(outside); got != filepath.ToSlash(outside) {
		t.Errorf("a path outside the working directory must be kept: got %q", got)
	}
	if sourcePath("") != "" {
		t.Error("empty stays empty")
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

// writeFiles lays out files under a fresh temp dir and returns the dir.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// An unconfirmed unsafe method compiles but fails engine validation. If that
// were only discovered when its entry ran, the entries before it would already
// have sent live requests.
func TestPolicyRunSuite_ValidatesEveryCaseBeforeAnyRequest(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := writeFiles(t, map[string]string{
		"safe.yaml":       "api:\n  endpoint: GET /things\nexpect:\n  owner: allow\n",
		"delete.yaml":     "api:\n  endpoint: DELETE /things/{id}\nexpect:\n  owner: allow\n",
		"identities.json": demoIdentities,
		"suite.yaml": "base: " + srv.URL + `
identities: identities.json
policies:
  - policy: safe.yaml
  - policy: delete.yaml
    params: {id: "1"}
`,
	})
	err := runPolicy([]string{"run", "--suite", filepath.Join(dir, "suite.yaml"), "--allow-private-targets"})
	if err == nil {
		t.Fatal("an unconfirmed DELETE must fail validation")
	}
	var ee exitError
	if errors.As(err, &ee) {
		t.Errorf("validation failure should be a usage error (exit 1), got exit %d", ee.code)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d requests were sent before validation failed; want 0", n)
	}
}

// A failed setup step in one entry must not hide the other entries' results or
// suppress the reports a CI job uploads with `if: always()`.
func TestPolicyRunSuite_FailedEntryIsReportedAndTheRestStillRun(t *testing.T) {
	base := startFixture(t)
	dir := writeFiles(t, map[string]string{
		"profile.yaml": demo.Policy,
		"needs-setup.yaml": `api:
  endpoint: GET /users/{user_id}/profile
setup:
  - name: prerequisite
    request: {method: GET, path: /does-not-exist}
expect:
  owner: allow
`,
		"identities.json": demoIdentities,
		"suite.yaml": "base: " + base + `
identities: identities.json
policies:
  - policy: needs-setup.yaml
    id: broken-setup
    params: {user_id: "42"}
  - policy: profile.yaml
    params: {user_id: "42"}
`,
	})
	out := filepath.Join(dir, "result.json")
	sarif := filepath.Join(dir, "result.sarif")
	stdout, err := captureStdout(t, func() error {
		return runPolicy([]string{"run", "--suite", filepath.Join(dir, "suite.yaml"), "--allow-private-targets",
			"--out", out, "--sarif", sarif, "--format", "text", "--fail-on", "high"})
	})
	if code := exitCode(t, err); code != exitNotExecuted {
		t.Fatalf("exit = %d, want %d: %v", code, exitNotExecuted, err)
	}
	if !strings.Contains(err.Error(), "broken-setup") {
		t.Errorf("exit message does not name the failed case: %v", err)
	}

	var results []engine.Result
	data, _ := os.ReadFile(out)
	if err := json.Unmarshal(data, &results); err != nil || len(results) != 2 {
		t.Fatalf("results = %s (%v)", data, err)
	}
	if !strings.Contains(results[0].Error, "setup step failed") {
		t.Errorf("failed entry error = %q", results[0].Error)
	}
	if len(results[1].Findings) == 0 {
		t.Error("the entry after the failed one must still run and report its findings")
	}

	inv := readSARIF(t, sarif)["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	notes, _ := inv["toolExecutionNotifications"].([]any)
	if inv["executionSuccessful"] != false || len(notes) != 1 {
		t.Errorf("SARIF invocation = %v", inv)
	}
	if !strings.Contains(stdout, "NOT TESTED: could not run") {
		t.Errorf("text output does not flag the failed entry:\n%s", stdout)
	}
}

// A single policy keeps the old behavior: its error is returned directly.
func TestPolicyRun_SingleSetupFailureStillReturnsItsError(t *testing.T) {
	base := startFixture(t)
	dir := writeFiles(t, map[string]string{
		"p.yaml":          "api:\n  endpoint: GET /users/1/profile\nsetup:\n  - name: s\n    request: {method: GET, path: /nope}\nexpect:\n  owner: allow\n",
		"identities.json": `[{"id": "owner", "role": "owner", "credential": {"type": "bearer", "value": "t"}}]`,
	})
	_, err := captureStdout(t, func() error {
		return runPolicy([]string{"run", "--policy", filepath.Join(dir, "p.yaml"), "--base", base,
			"--identities", filepath.Join(dir, "identities.json"), "--allow-private-targets"})
	})
	if code := exitCode(t, err); code != exitNotExecuted {
		t.Fatalf("exit = %d, want %d", code, exitNotExecuted)
	}
}
