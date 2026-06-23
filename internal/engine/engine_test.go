package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// stubExecutor returns a fixed status code and classified outcome per identity ID.
type stubExecutor struct {
	responses map[string]int
	err       map[string]string
}

func (s *stubExecutor) Execute(_ context.Context, identity model.Identity, _ model.RequestTemplate) model.ExecutionResult {
	r := model.ExecutionResult{IdentityID: identity.ID}
	if msg, ok := s.err[identity.ID]; ok {
		r.Error = msg
		r.ObservedOutcome = model.OutcomeError
		return r
	}
	if code, ok := s.responses[identity.ID]; ok {
		r.StatusCode = code
		r.ObservedOutcome = model.ClassifyOutcome(code, false)
	}
	return r
}

func baseTC() model.AuthorizationTestCase {
	return model.AuthorizationTestCase{
		ID: "tc-1",
		Identities: []model.Identity{
			{ID: "admin", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-a"}},
			{ID: "user", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-u"}},
		},
		Request: model.RequestTemplate{Method: http.MethodGet, URL: "https://example.com/resource/1"},
		ExpectedAccess: []model.ExpectedAccess{
			{IdentityID: "admin", Decision: model.AccessDecisionAllow},
			{IdentityID: "user", Decision: model.AccessDecisionDeny},
		},
	}
}

func TestRun_NoFindingsWhenExpectationsMet(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusForbidden,
	}})

	result, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(result.Findings), result.Findings)
	}
}

// Issue 6: deny→allow without TenantID must be unexpected_access, not potential_bola.
func TestRun_UnexpectedAccess_WhenDeniedIdentityGetsAllow(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusOK, // should have been denied
	}})

	result, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Category != model.CategoryUnexpectedAccess {
		t.Errorf("expected category unexpected_access (no TenantID), got %q", f.Category)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("expected severity high, got %q", f.Severity)
	}
	if f.IdentityID != "user" {
		t.Errorf("expected finding for user, got %q", f.IdentityID)
	}
}

// TenantID alone is not sufficient to establish a cross-tenant object-access
// relationship. The finding must remain unexpected_access until resource-
// ownership context (owner identity, target tenant, object ID) is modelled.
func TestRun_TenantIDAloneDoesNotElevateToBOLA(t *testing.T) {
	tc := baseTC()
	tc.Identities[1].TenantID = "tenant-b"

	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusOK,
	}})

	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Category != model.CategoryUnexpectedAccess {
		t.Errorf("TenantID alone must not elevate to potential_bola; got %q",
			result.Findings[0].Category)
	}
}

func TestRun_FindingWhenAllowedIdentityIsDenied(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusForbidden, // should have been allowed
		"user":  http.StatusForbidden,
	}})

	result, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Category != model.CategoryAuthorizationMismatch {
		t.Errorf("expected authorization_mismatch, got %q", result.Findings[0].Category)
	}
}

// Issue 5: ambiguous outcomes when expected=deny must not produce findings.
func TestRun_NoFinding_WhenExpectedDenyObservedNotFound(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusNotFound, // not an allow — no finding
	}})

	result, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for 404 when expected=deny, got %d", len(result.Findings))
	}
}

func TestRun_NoFinding_WhenExpectedDenyObservedServerError(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusInternalServerError,
	}})

	result, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for 5xx when expected=deny, got %d", len(result.Findings))
	}
}

func TestRun_NoFinding_WhenExpectedDenyObservedRedirect(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusFound,
	}})

	result, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for redirect when expected=deny, got %d", len(result.Findings))
	}
}

func TestRun_SkipDecisionProducesNoFinding(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[1].Decision = model.AccessDecisionSkip

	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusOK,
	}})

	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for skipped identity, got %d", len(result.Findings))
	}
}

func TestRun_ExecutionErrorProducesNoFinding(t *testing.T) {
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK},
		err:       map[string]string{"user": "connection refused"},
	})

	result, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Executions) != 2 {
		t.Fatalf("expected 2 executions recorded, got %d", len(result.Executions))
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no finding on execution error, got %d", len(result.Findings))
	}
}

func TestRun_AllExecutionsRecorded(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusForbidden,
	}})

	result, _ := eng.Run(context.Background(), baseTC())
	if len(result.Executions) != 2 {
		t.Fatalf("expected 2 executions, got %d", len(result.Executions))
	}
}

func TestRun_TestCaseIDPropagated(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 403}})
	result, _ := eng.Run(context.Background(), baseTC())
	if result.TestCaseID != "tc-1" {
		t.Fatalf("expected TestCaseID tc-1, got %q", result.TestCaseID)
	}
}

func TestValidate_MissingID(t *testing.T) {
	tc := baseTC()
	tc.ID = ""
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestValidate_NoIdentities(t *testing.T) {
	tc := baseTC()
	tc.Identities = nil
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil {
		t.Fatal("expected error for no identities")
	}
}

func TestValidate_MissingMethod(t *testing.T) {
	tc := baseTC()
	tc.Request.Method = ""
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil {
		t.Fatal("expected error for missing method")
	}
}

func TestValidate_MissingURL(t *testing.T) {
	tc := baseTC()
	tc.Request.URL = ""
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestValidate_InvalidDecision(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[0].Decision = "maybe"
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil {
		t.Fatal("expected error for invalid decision")
	}
}

func TestSanitizeURL_RedactsSensitiveParams(t *testing.T) {
	cases := []struct {
		input           string
		sensitiveValues []string // must NOT appear in output
		safeParam       string   // must still appear in output
	}{
		{
			"https://example.com/path?api_key=secret&page=2",
			[]string{"secret"},
			"page=2",
		},
		{
			"https://example.com/?token=abc123&limit=10",
			[]string{"abc123"},
			"limit=10",
		},
		{
			"https://example.com/?resource_id=42",
			nil,
			"resource_id=42",
		},
	}
	for _, c := range cases {
		got := sanitizeURL(c.input)
		for _, bad := range c.sensitiveValues {
			if strings.Contains(got, bad) {
				t.Errorf("sanitizeURL(%q) still contains sensitive value %q: %s", c.input, bad, got)
			}
		}
		if c.safeParam != "" && !strings.Contains(got, c.safeParam) {
			t.Errorf("sanitizeURL(%q) removed non-sensitive param %q: %s", c.input, c.safeParam, got)
		}
	}
}

func TestEvidence_DoesNotContainCredentialValues(t *testing.T) {
	tc := baseTC()
	identity := tc.Identities[1] // Value = "tok-u"
	exec := model.ExecutionResult{
		IdentityID:      identity.ID,
		StatusCode:      http.StatusOK,
		ObservedOutcome: model.OutcomeAllow,
	}

	finding, ok := evaluate(tc, identity, exec, model.AccessDecisionDeny)
	if !ok {
		t.Fatal("expected a finding")
	}
	for _, e := range finding.Evidence {
		if strings.Contains(e, "tok-u") {
			t.Errorf("evidence string contains credential value: %q", e)
		}
	}
}
