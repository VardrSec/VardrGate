package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

func vulnerable() Case {
	return Case{
		Source: "policies/profile.yaml",
		Result: engine.Result{
			TestCaseID: "profile",
			Executions: []model.ExecutionResult{
				{IdentityID: "owner", StatusCode: 200, ObservedOutcome: model.OutcomeAllow},
				{IdentityID: "anonymous", StatusCode: 200, ObservedOutcome: model.OutcomeAllow},
			},
			Findings: []model.Finding{
				{Category: model.CategoryAuthorizationMismatch, Severity: model.SeverityLow, IdentityID: "owner", Message: "low one"},
				{Category: model.CategoryMissingAuthentication, Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh,
					IdentityID: "anonymous", Message: "anonymous got in", Evidence: []string{"status_code=200"}},
			},
		},
	}
}

func clean() Case {
	return Case{Source: "policies/admin.yaml", Result: engine.Result{
		TestCaseID: "admin",
		Executions: []model.ExecutionResult{{IdentityID: "admin", StatusCode: 200, ObservedOutcome: model.OutcomeAllow}},
		Findings:   []model.Finding{},
	}}
}

func unreached() Case {
	return Case{Source: "policies/down.yaml", Result: engine.Result{
		TestCaseID: "down",
		Executions: []model.ExecutionResult{{IdentityID: "a", Error: "connection refused"}, {IdentityID: "b", Error: "connection refused"}},
	}}
}

func render(t *testing.T, fn func(*bytes.Buffer) error) string {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestText_ShowsFindingsMostSevereFirstAndASummary(t *testing.T) {
	out := render(t, func(b *bytes.Buffer) error { return Text(b, []Case{vulnerable(), clean()}) })
	crit := strings.Index(out, "[CRITICAL] missing_authentication")
	low := strings.Index(out, "[LOW] authorization_mismatch")
	if crit == -1 || low == -1 || crit > low {
		t.Errorf("findings missing or not sorted by severity:\n%s", out)
	}
	for _, want := range []string{
		"Case profile  (policies/profile.yaml)",
		"status_code=200",
		"No findings.",
		"Summary: 2 cases, 2 findings (1 critical, 1 low), 0 not tested",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

// Zero findings for a target that was never reached must not read as clean in
// any format, not only in the exit code.
func TestEveryFormat_SaysWhenACaseWasNotTested(t *testing.T) {
	cases := []Case{unreached()}

	text := render(t, func(b *bytes.Buffer) error { return Text(b, cases) })
	if !strings.Contains(text, "NOT TESTED: every identity failed to connect") || strings.Contains(text, "No findings.") {
		t.Errorf("text does not flag the unreached case:\n%s", text)
	}
	if !strings.Contains(text, "1 not tested") {
		t.Errorf("summary does not count the unreached case:\n%s", text)
	}

	markdown := render(t, func(b *bytes.Buffer) error { return Markdown(b, cases) })
	if !strings.Contains(markdown, "Not tested") || !strings.Contains(markdown, "[!WARNING]") {
		t.Errorf("markdown does not flag the unreached case:\n%s", markdown)
	}

	log := decodeSARIF(t, cases)
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("SARIF invocation must be unsuccessful when a case tested nothing")
	}
	if len(inv.Notifications) != 1 || !strings.Contains(inv.Notifications[0].Message.Text, "down") {
		t.Errorf("SARIF notifications = %+v", inv.Notifications)
	}
}

func TestText_PreflightFailureIsNotTested(t *testing.T) {
	c := Case{Result: engine.Result{TestCaseID: "session", Preflight: []model.PreflightResult{
		{IdentityID: "owner", Status: "failed", Reason: "credential_rejected"},
	}}}
	out := render(t, func(b *bytes.Buffer) error { return Text(b, []Case{c}) })
	if !strings.Contains(out, "NOT TESTED: identity preflight failed") || !strings.Contains(out, "credential_rejected") {
		t.Errorf("preflight failure not explained:\n%s", out)
	}
}

// Evidence carries field names and paths taken from the target's responses, so
// a hostile API must not be able to break the table or inject markup.
func TestMarkdown_EscapesUntrustedValues(t *testing.T) {
	c := vulnerable()
	c.Result.Findings[1].Evidence = []string{"leaked_fields=a|b", "<img src=x onerror=alert(1)>", "`code`", "[link](https://evil.example)"}
	out := render(t, func(b *bytes.Buffer) error { return Markdown(b, []Case{c}) })
	for _, bad := range []string{"a|b", "<img", "`code`", "[link](https://evil.example)"} {
		if strings.Contains(out, bad) {
			t.Errorf("markdown contains unescaped %q:\n%s", bad, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| CRITICAL") {
			if n := strings.Count(line, "|"); n != 6 {
				t.Errorf("findings row has %d pipes, want 6 (a cell broke the table): %s", n, line)
			}
		}
	}
}

func TestMarkdown_VerdictsPerCase(t *testing.T) {
	out := render(t, func(b *bytes.Buffer) error { return Markdown(b, []Case{vulnerable(), clean()}) })
	for _, want := range []string{"❌ 2 findings (worst: critical)", "✅ No findings", "### Findings"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func decodeSARIF(t *testing.T, cases []Case) sarifLog {
	t.Helper()
	raw := render(t, func(b *bytes.Buffer) error { return SARIF(b, cases, "v0.2.0") })
	var log sarifLog
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, raw)
	}
	return log
}

func TestSARIF_ResultsReferenceRulesAndLocations(t *testing.T) {
	log := decodeSARIF(t, []Case{vulnerable(), clean()})
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("version %q, %d runs", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "VardrGate" || run.Tool.Driver.Version != "v0.2.0" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if !run.Invocations[0].ExecutionSuccessful {
		t.Error("a run where every case was reached must be successful")
	}
	if len(run.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(run.Results))
	}
	for _, r := range run.Results {
		rule := run.Tool.Driver.Rules[r.RuleIndex]
		if rule.ID != r.RuleID {
			t.Errorf("result %s points at rule %s", r.RuleID, rule.ID)
		}
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "policies/profile.yaml" {
			t.Errorf("location = %+v", r.Locations)
		}
		if r.PartialFingerprints["vardrgateFinding/v1"] == "" {
			t.Error("result has no fingerprint")
		}
	}
	crit := run.Results[1]
	if crit.Level != "error" || crit.Properties.Severity != "critical" {
		t.Errorf("critical finding level=%s severity=%s", crit.Level, crit.Properties.Severity)
	}
	if !strings.Contains(crit.Message.Text, "status_code=200") || !strings.Contains(crit.Message.Text, "case profile") {
		t.Errorf("message = %q", crit.Message.Text)
	}
	if low := run.Results[0]; low.Level != "note" {
		t.Errorf("low finding level = %s, want note", low.Level)
	}
}

// A clean scan still has to be a valid upload: an empty results array, not null.
func TestSARIF_CleanRunHasEmptyResultsArray(t *testing.T) {
	raw := render(t, func(b *bytes.Buffer) error { return SARIF(b, []Case{clean()}, "") })
	if !strings.Contains(raw, `"results": []`) {
		t.Errorf("clean run must emit an empty results array:\n%s", raw)
	}
}

// Code scanning tracks alerts across runs by fingerprint, so it must not change
// with the timestamp or with evidence such as a loopback port.
func TestSARIF_FingerprintIsStableAcrossRuns(t *testing.T) {
	a, b := vulnerable(), vulnerable()
	b.Result.Findings[1].DetectedAt = time.Now()
	b.Result.Findings[1].Evidence = []string{"url=GET http://127.0.0.1:51234/users/42"}
	fa := decodeSARIF(t, []Case{a}).Runs[0].Results[1].PartialFingerprints
	fb := decodeSARIF(t, []Case{b}).Runs[0].Results[1].PartialFingerprints
	if fa["vardrgateFinding/v1"] != fb["vardrgateFinding/v1"] {
		t.Error("fingerprint changed with timestamp or evidence")
	}

	other := vulnerable()
	other.Result.TestCaseID = "another-case"
	fo := decodeSARIF(t, []Case{other}).Runs[0].Results[1].PartialFingerprints
	if fo["vardrgateFinding/v1"] == fa["vardrgateFinding/v1"] {
		t.Error("the same finding in a different case must get a different fingerprint")
	}
}

func TestSARIF_EveryEngineCategoryHasARule(t *testing.T) {
	have := map[model.FindingCategory]bool{}
	for _, r := range knownRules {
		have[r.category] = true
	}
	for _, c := range []model.FindingCategory{
		model.CategoryPotentialBOLA, model.CategoryMissingAuthentication, model.CategoryCrossTenantAccess,
		model.CategoryPrivilegeEscalation, model.CategoryUnexpectedAccess, model.CategoryAuthorizationMismatch,
		model.CategorySensitiveDataExposure, model.CategoryCORSMisconfiguration, model.CategoryObjectPropertyExposure,
	} {
		if !have[c] {
			t.Errorf("no SARIF rule for category %s", c)
		}
	}
}

func TestSARIF_UnknownCategoryStillReported(t *testing.T) {
	c := clean()
	c.Result.Findings = []model.Finding{{Category: "future_category", Severity: model.SeverityMedium, IdentityID: "x", Message: "m"}}
	run := decodeSARIF(t, []Case{c}).Runs[0]
	if len(run.Results) != 1 || run.Tool.Driver.Rules[run.Results[0].RuleIndex].ID != "future_category" {
		t.Errorf("unknown category not reported with its own rule: %+v", run.Results)
	}
}

func TestArtifactURI(t *testing.T) {
	for in, want := range map[string]string{
		"policies/a.yaml":   "policies/a.yaml",
		`policies\a.yaml`:   "policies/a.yaml",
		"/srv/repo/a.yaml":  "file:///srv/repo/a.yaml",
		"C:/Users/x/a.yaml": "file:///C:/Users/x/a.yaml",
		`C:\Users\x\a.yaml`: "file:///C:/Users/x/a.yaml",
	} {
		if got := artifactURI(in); got != want {
			t.Errorf("artifactURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryFormat_ReportsACaseThatCouldNotRun(t *testing.T) {
	c := Case{Source: "p.yaml", Result: engine.Result{TestCaseID: "broken", Error: "setup step failed"}}
	if out := render(t, func(b *bytes.Buffer) error { return Text(b, []Case{c}) }); !strings.Contains(out, "NOT TESTED: could not run: setup step failed") {
		t.Errorf("text:\n%s", out)
	}
	if out := render(t, func(b *bytes.Buffer) error { return Markdown(b, []Case{c}) }); !strings.Contains(out, "Not tested: could not run") {
		t.Errorf("markdown:\n%s", out)
	}
	if inv := decodeSARIF(t, []Case{c}).Runs[0].Invocations[0]; inv.ExecutionSuccessful || len(inv.Notifications) != 1 {
		t.Errorf("sarif invocation = %+v", inv)
	}
}

func inconclusive() Case {
	return Case{Source: "policies/stale.yaml", Result: engine.Result{
		TestCaseID: "stale",
		Executions: []model.ExecutionResult{{IdentityID: "peer", StatusCode: 200, ObservedOutcome: model.OutcomeAllow}},
		Findings:   []model.Finding{},
		Assessments: []model.Assessment{{IdentityID: "peer", ExpectedAccess: model.AccessDecisionDeny,
			Decision: model.AssessmentInconclusive, Source: "response_assertion", Reason: "no_assertion_matched"}},
	}}
}

// An inconclusive assessment produces no finding; every format must still say
// the case is not a pass.
func TestInconclusiveIsNeverRenderedAsPass(t *testing.T) {
	var text, mdown, sarif bytes.Buffer
	if err := Text(&text, []Case{inconclusive()}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), "No findings.") || !strings.Contains(text.String(), "not a pass") ||
		!strings.Contains(text.String(), "may be stale") || !strings.Contains(text.String(), "1 inconclusive assessment") {
		t.Fatalf("text:\n%s", text.String())
	}
	if err := Markdown(&mdown, []Case{inconclusive()}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mdown.String(), "✅") || !strings.Contains(mdown.String(), "Inconclusive assessments") {
		t.Fatalf("markdown:\n%s", mdown.String())
	}
	if err := SARIF(&sarif, []Case{inconclusive()}, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sarif.String(), `"level": "warning"`) || !strings.Contains(sarif.String(), "inconclusive") {
		t.Fatalf("sarif:\n%s", sarif.String())
	}
}
