package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// stubExecutor returns a fixed status code for each identity ID.
type stubExecutor struct {
	responses map[string]int // identity ID → status code
	err       map[string]string
}

func (s *stubExecutor) Execute(_ context.Context, identity model.Identity, _ model.RequestTemplate) model.ExecutionResult {
	r := model.ExecutionResult{IdentityID: identity.ID}
	if msg, ok := s.err[identity.ID]; ok {
		r.Error = msg
		return r
	}
	if code, ok := s.responses[identity.ID]; ok {
		r.StatusCode = code
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

func TestRun_FindingWhenDeniedIdentityGetsAccess(t *testing.T) {
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
	if f.Category != model.CategoryPotentialBOLA {
		t.Errorf("expected category potential_bola, got %q", f.Category)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("expected severity high, got %q", f.Severity)
	}
	if f.IdentityID != "user" {
		t.Errorf("expected finding for user, got %q", f.IdentityID)
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
	f := result.Findings[0]
	if f.Category != model.CategoryAuthorizationMismatch {
		t.Errorf("expected category authorization_mismatch, got %q", f.Category)
	}
}

func TestRun_SkipDecisionProducesNoFinding(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[1].Decision = model.AccessDecisionSkip

	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusOK, // would be a finding if not skipped
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
	// error result is still recorded
	if len(result.Executions) != 2 {
		t.Fatalf("expected 2 executions, got %d", len(result.Executions))
	}
	// no finding because we only have one weak signal
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

func TestRun_TestCaseIDPropagated(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 403}})
	result, _ := eng.Run(context.Background(), baseTC())
	if result.TestCaseID != "tc-1" {
		t.Fatalf("expected TestCaseID tc-1, got %q", result.TestCaseID)
	}
}
