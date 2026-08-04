package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

func resultWith(findings ...model.Finding) engine.Result {
	return engine.Result{
		TestCaseID: "tc",
		Executions: []model.ExecutionResult{{IdentityID: "a", StatusCode: 200}},
		Findings:   findings,
	}
}

func finding(sev model.Severity, category model.FindingCategory) model.Finding {
	return model.Finding{Severity: sev, Category: category, IdentityID: "a"}
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return exitOK
	}
	var ee exitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an exitError, got %v", err)
	}
	return ee.code
}

func TestGate_NoFindingsIsClean(t *testing.T) {
	if code := exitCode(t, gate([]engine.Result{resultWith()}, model.SeverityLow)); code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
}

func TestGate_ThresholdBoundaryIsInclusive(t *testing.T) {
	res := []engine.Result{resultWith(finding(model.SeverityHigh, model.CategoryPotentialBOLA))}
	if code := exitCode(t, gate(res, model.SeverityHigh)); code != exitFindings {
		t.Errorf("a high finding must trip --fail-on high; exit = %d", code)
	}
}

func TestGate_BelowThresholdDoesNotTrip(t *testing.T) {
	res := []engine.Result{resultWith(finding(model.SeverityLow, model.CategoryAuthorizationMismatch))}
	if code := exitCode(t, gate(res, model.SeverityHigh)); code != exitOK {
		t.Errorf("a low finding must not trip --fail-on high; exit = %d", code)
	}
}

func TestGate_NoThresholdNeverTripsOnFindings(t *testing.T) {
	res := []engine.Result{resultWith(finding(model.SeverityCritical, model.CategoryMissingAuthentication))}
	if code := exitCode(t, gate(res, "")); code != exitOK {
		t.Errorf("--fail-on none must not gate on findings; exit = %d", code)
	}
}

// The bug this exists for: every identity failing to connect used to exit 0,
// so a CI job went green having tested nothing.
func TestGate_AllExecutionsFailedIsNotExecuted(t *testing.T) {
	res := []engine.Result{{
		Executions: []model.ExecutionResult{
			{IdentityID: "a", Error: "connection refused"},
			{IdentityID: "b", Error: "connection refused"},
		},
	}}
	if code := exitCode(t, gate(res, "")); code != exitNotExecuted {
		t.Errorf("exit = %d, want %d", code, exitNotExecuted)
	}
}

func TestGate_NotExecutedOutranksFindings(t *testing.T) {
	res := []engine.Result{{
		Executions: []model.ExecutionResult{{IdentityID: "a", Error: "connection refused"}},
		Findings:   []model.Finding{finding(model.SeverityCritical, model.CategoryMissingAuthentication)},
	}}
	if code := exitCode(t, gate(res, model.SeverityLow)); code != exitNotExecuted {
		t.Errorf("exit = %d, want %d", code, exitNotExecuted)
	}
}

func TestGate_PartialFailureStillEvaluatesFindings(t *testing.T) {
	res := []engine.Result{{
		Executions: []model.ExecutionResult{
			{IdentityID: "a", StatusCode: 200},
			{IdentityID: "b", Error: "connection refused"},
		},
		Findings: []model.Finding{finding(model.SeverityCritical, model.CategoryMissingAuthentication)},
	}}
	if code := exitCode(t, gate(res, model.SeverityHigh)); code != exitFindings {
		t.Errorf("exit = %d, want %d", code, exitFindings)
	}
}

func TestGate_AggregatesAcrossASuite(t *testing.T) {
	res := []engine.Result{
		resultWith(),
		resultWith(finding(model.SeverityCritical, model.CategoryCrossTenantAccess)),
	}
	if code := exitCode(t, gate(res, model.SeverityCritical)); code != exitFindings {
		t.Errorf("exit = %d, want %d", code, exitFindings)
	}
}

func TestGate_EmptyResultsIsClean(t *testing.T) {
	if code := exitCode(t, gate(nil, model.SeverityLow)); code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
}

func TestGate_MessageNamesTheCategories(t *testing.T) {
	res := []engine.Result{resultWith(
		finding(model.SeverityHigh, model.CategoryPotentialBOLA),
		finding(model.SeverityCritical, model.CategoryCrossTenantAccess),
	)}
	err := gate(res, model.SeverityHigh)
	if err == nil {
		t.Fatal("expected a gating error")
	}
	msg := err.Error()
	// Most severe first, so the CI log line leads with the worst thing found.
	if !strings.Contains(msg, "cross_tenant_access") || !strings.Contains(msg, "potential_bola") {
		t.Errorf("message did not name both categories: %s", msg)
	}
	if strings.Index(msg, "cross_tenant_access") > strings.Index(msg, "potential_bola") {
		t.Errorf("critical must be summarised before high: %s", msg)
	}
}

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in      string
		want    model.Severity
		wantErr bool
	}{
		{"none", "", false},
		{"NONE", "", false},
		{"high", model.SeverityHigh, false},
		{" Critical ", model.SeverityCritical, false},
		{"bogus", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := parseFailOn(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseFailOn(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseFailOn(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParamFlag_Set(t *testing.T) {
	p := paramFlag{}
	if err := p.Set("user_id=42"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := p.Set("tenant=acme"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p["user_id"] != "42" || p["tenant"] != "acme" {
		t.Errorf("params = %v", map[string]string(p))
	}
	// A value may legitimately contain "=".
	if err := p.Set("filter=a=b"); err != nil || p["filter"] != "a=b" {
		t.Errorf("value containing '=' not preserved: %q (%v)", p["filter"], err)
	}
	if err := p.Set("novalue"); err == nil {
		t.Error("expected an error for a param without '='")
	}
	if err := p.Set("=v"); err == nil {
		t.Error("expected an error for a param without a name")
	}
}

func TestLoadCases_AcceptsArrayAndSingleObject(t *testing.T) {
	dir := t.TempDir()

	arrayPath := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(arrayPath, []byte(`[{"id":"a"},{"id":"b"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := loadCases(arrayPath)
	if err != nil || len(cases) != 2 {
		t.Fatalf("array: got %d cases, err %v", len(cases), err)
	}

	singlePath := filepath.Join(dir, "single.json")
	if err := os.WriteFile(singlePath, []byte(`{"id":"solo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err = loadCases(singlePath)
	if err != nil || len(cases) != 1 || cases[0].ID != "solo" {
		t.Fatalf("single: got %+v, err %v", cases, err)
	}
}

func TestLoadCases_RejectsEmptyAndMalformed(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCases(empty); err == nil {
		t.Error("expected an error for an empty array")
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCases(bad); err == nil {
		t.Error("expected a parse error")
	}

	if _, err := loadCases(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected a read error for a missing file")
	}
}

func TestRunCases_RequiresExactlyOneSource(t *testing.T) {
	if err := runCases(nil); err == nil {
		t.Error("expected an error when neither --job nor --cases is given")
	}
	if err := runCases([]string{"--job", "a.json", "--cases", "b.json"}); err == nil {
		t.Error("expected an error when both --job and --cases are given")
	}
}

func TestRunPolicy_RejectsUnknownSubcommand(t *testing.T) {
	err := runPolicy([]string{"frobnicate"})
	if err == nil || !strings.Contains(err.Error(), "unknown policy subcommand") {
		t.Fatalf("got %v", err)
	}
}

func TestRunPolicyRun_RequiresItsFlags(t *testing.T) {
	err := runPolicyRun([]string{"--base", "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected a required-flag error, got %v", err)
	}
}

// A target that dies partway through a suite leaves later cases reaching
// nothing while the suite-wide failure ratio still looks partial. That is the
// same green-but-tested-nothing result the gate exists to prevent.
func TestGate_OneUnreachedCaseInASuiteIsNotExecuted(t *testing.T) {
	res := []engine.Result{
		{
			TestCaseID: "case-1",
			Executions: []model.ExecutionResult{{IdentityID: "a", StatusCode: 200}},
		},
		{
			TestCaseID: "case-2",
			Executions: []model.ExecutionResult{
				{IdentityID: "a", Error: "connection refused"},
				{IdentityID: "b", Error: "connection refused"},
			},
		},
	}
	err := gate(res, "")
	if code := exitCode(t, err); code != exitNotExecuted {
		t.Fatalf("exit = %d, want %d", code, exitNotExecuted)
	}
	if !strings.Contains(err.Error(), "case-2") {
		t.Errorf("message did not name the unreached case: %s", err)
	}
	if strings.Contains(err.Error(), "case-1") {
		t.Errorf("message named a case that did run: %s", err)
	}
}

func TestGate_CaseWithNoExecutionsIsNotCountedAsUnreached(t *testing.T) {
	res := []engine.Result{{TestCaseID: "empty"}}
	if code := exitCode(t, gate(res, "")); code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
}
