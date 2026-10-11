package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// stubExecutor returns a fixed status code and classified outcome per identity ID.
type stubExecutor struct {
	responses map[string]int
	err       map[string]string
	body      map[string][]byte
	headers   map[string]map[string]string
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
	if b, ok := s.body[identity.ID]; ok {
		r.Body = b
	}
	if h, ok := s.headers[identity.ID]; ok {
		r.Headers = h
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
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if string(wire["findings"]) != "[]" {
		t.Fatalf("clean findings must serialize as [], got %s", wire["findings"])
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

	eng := New(&stubExecutor{})
	execByID := map[string]model.ExecutionResult{identity.ID: exec}
	finding, ok := eng.evaluate(tc, identity, execByID, model.AccessDecisionDeny)
	if !ok {
		t.Fatal("expected a finding")
	}
	for _, e := range finding.Evidence {
		if strings.Contains(e, "tok-u") {
			t.Errorf("evidence string contains credential value: %q", e)
		}
	}
}

func TestSanitizeURL_StripsUserinfo(t *testing.T) {
	got := sanitizeURL("https://user:hunter2@example.com/resource/1")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "user:") {
		t.Errorf("sanitizeURL did not strip userinfo: %s", got)
	}
}

func TestRun_CrossTenantAccess(t *testing.T) {
	tc := baseTC()
	tc.Identities[1].TenantID = "tenant-b"
	tc.Resource = &model.Resource{Type: "invoice", ObjectID: "1", TenantID: "tenant-a"}

	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 200}})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Category != model.CategoryCrossTenantAccess {
		t.Errorf("expected cross_tenant_access, got %q", f.Category)
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected critical severity, got %q", f.Severity)
	}
}

func TestRun_PotentialBOLA(t *testing.T) {
	tc := baseTC()
	tc.Resource = &model.Resource{Type: "user_profile", ObjectID: "42", OwnerIdentity: "admin"}

	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 200}})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Category != model.CategoryPotentialBOLA {
		t.Errorf("expected potential_bola, got %q", result.Findings[0].Category)
	}
}

func TestRun_PrivilegeEscalation(t *testing.T) {
	tc := baseTC()
	tc.Identities[0].Role = "admin"
	tc.Identities[1].Role = "user"
	tc.RoleHierarchy = []string{"user", "admin"}
	tc.Resource = &model.Resource{Type: "admin_panel", RequiredRole: "admin"}

	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 200}})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Category != model.CategoryPrivilegeEscalation {
		t.Errorf("expected privilege_escalation, got %q", result.Findings[0].Category)
	}
}

// A resource with owner context but no tenant mismatch and no role gap must not
// over-classify when the offending identity IS the owner-adjacent baseline only.
func TestRun_BOLANotEmittedWhenOwnerContextAbsent(t *testing.T) {
	tc := baseTC()
	tc.Resource = &model.Resource{Type: "user_profile", ObjectID: "42"} // no owner_identity

	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 200}})
	result, _ := eng.Run(context.Background(), tc)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Category != model.CategoryUnexpectedAccess {
		t.Errorf("without owner_identity, expected unexpected_access, got %q", result.Findings[0].Category)
	}
}

func TestRun_ComparisonEvidenceWhenBodiesMatch(t *testing.T) {
	tc := baseTC()
	tc.Resource = &model.Resource{Type: "user_profile", ObjectID: "42", OwnerIdentity: "admin"}

	body := []byte(`{"id":42,"email":"a@b.com"}`)
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 200},
		body:      map[string][]byte{"admin": body, "user": body},
	})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	var matched bool
	for _, e := range result.Findings[0].Evidence {
		if strings.Contains(e, "response_body_matches_baseline") {
			matched = true
		}
	}
	if !matched {
		t.Errorf("expected comparison evidence noting matching bodies, got %+v", result.Findings[0].Evidence)
	}
}

func TestRun_EmitsValueFreeResponseProfiles(t *testing.T) {
	tc := baseTC()
	body := []byte(`{"id":42,"profile":{"email":"secret@example.com"}}`)
	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 403}, body: map[string][]byte{"admin": body, "user": []byte(`{"error":"forbidden"}`)}})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Executions) != 2 || result.Executions[0].ResponseProfile == nil {
		t.Fatalf("missing response profile: %+v", result.Executions)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret@example.com") {
		t.Fatalf("result leaked response value: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"response_profile"`) || !strings.Contains(string(encoded), `"schema_hash"`) {
		t.Fatalf("response profile absent from result JSON: %s", encoded)
	}
}

func TestValidate_DuplicateIdentityID(t *testing.T) {
	tc := baseTC()
	tc.Identities[1].ID = "admin"
	tc.ExpectedAccess[1].IdentityID = "admin"
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestValidate_UnknownExpectedIdentity(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[1].IdentityID = "ghost"
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "unknown identity") {
		t.Fatalf("expected unknown identity error, got %v", err)
	}
}

func TestValidate_BearerRequiresValue(t *testing.T) {
	tc := baseTC()
	tc.Identities[0].Credential = model.Credential{Type: model.CredentialTypeBearer}
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "bearer credential requires a value") {
		t.Fatalf("expected bearer value error, got %v", err)
	}
}

func TestValidate_UnknownCredentialType(t *testing.T) {
	tc := baseTC()
	tc.Identities[0].Credential = model.Credential{Type: "magic"}
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "unknown credential type") {
		t.Fatalf("expected unknown credential type error, got %v", err)
	}
}

func TestValidate_StaticHeaderValueRequiresHeader(t *testing.T) {
	tc := baseTC()
	tc.Identities[0].Credential = model.Credential{Type: model.CredentialTypeStaticHeader, Value: "x"}
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "requires a header name") {
		t.Fatalf("expected static_header header error, got %v", err)
	}
}

func TestValidate_AnonymousStaticHeaderAllowed(t *testing.T) {
	tc := baseTC()
	tc.Identities[1].Credential = model.Credential{Type: model.CredentialTypeStaticHeader}
	_, err := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 403}}).Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("empty static_header (anonymous) should be valid, got %v", err)
	}
}

func TestValidate_RequiredRoleMustBeInHierarchy(t *testing.T) {
	tc := baseTC()
	tc.Resource = &model.Resource{RequiredRole: "superuser"}
	tc.RoleHierarchy = []string{"user", "admin"}
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "role_hierarchy") {
		t.Fatalf("expected required_role hierarchy error, got %v", err)
	}
}

func TestValidate_ResourceOwnerMustExist(t *testing.T) {
	tc := baseTC()
	tc.Resource = &model.Resource{OwnerIdentity: "ghost"}
	_, err := New(&stubExecutor{}).Run(context.Background(), tc)
	if err == nil || !strings.Contains(err.Error(), "owner_identity") {
		t.Fatalf("expected owner_identity error, got %v", err)
	}
}

func TestRun_SensitiveDataExposure(t *testing.T) {
	tc := baseTC()
	// "user" is allowed to call the endpoint but must not receive sensitive fields.
	tc.ExpectedAccess[1].Decision = model.AccessDecisionAllow
	tc.ExpectedAccess[1].ForbidSensitiveData = true

	body := []byte(`{"id":42,"ssn":"123-45-6789"}`)
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 200},
		body:      map[string][]byte{"user": body},
	})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var f *model.Finding
	for i := range result.Findings {
		if result.Findings[i].Category == model.CategorySensitiveDataExposure {
			f = &result.Findings[i]
		}
	}
	if f == nil {
		t.Fatalf("expected sensitive_data_exposure finding, got %+v", result.Findings)
	}
	if f.IdentityID != "user" {
		t.Errorf("expected finding for user, got %q", f.IdentityID)
	}
	// Evidence lists the field name, never the value.
	for _, e := range f.Evidence {
		if strings.Contains(e, "123-45-6789") {
			t.Errorf("evidence leaked sensitive value: %q", e)
		}
	}
	joined := strings.Join(f.Evidence, " ")
	if !strings.Contains(joined, "ssn") {
		t.Errorf("evidence should name the leaked field, got %v", f.Evidence)
	}
}

func TestRun_NoSensitiveFindingWhenBodyClean(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[1].Decision = model.AccessDecisionAllow
	tc.ExpectedAccess[1].ForbidSensitiveData = true

	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 200},
		body:      map[string][]byte{"user": []byte(`{"id":42,"name":"ok"}`)},
	})
	result, _ := eng.Run(context.Background(), tc)
	for _, f := range result.Findings {
		if f.Category == model.CategorySensitiveDataExposure {
			t.Errorf("unexpected sensitive_data_exposure finding: %+v", f)
		}
	}
}

func TestRun_SensitiveDataCustomFields(t *testing.T) {
	tc := baseTC()
	tc.SensitiveFields = []string{"dob"}
	tc.ExpectedAccess[1].Decision = model.AccessDecisionAllow
	tc.ExpectedAccess[1].ForbidSensitiveData = true

	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 200},
		body:      map[string][]byte{"user": []byte(`{"dob":"2000-01-01"}`)},
	})
	result, _ := eng.Run(context.Background(), tc)
	var found bool
	for _, f := range result.Findings {
		if f.Category == model.CategorySensitiveDataExposure {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sensitive_data_exposure for custom field, got %+v", result.Findings)
	}
}

func TestRun_MissingAuthentication(t *testing.T) {
	tc := baseTC()
	// Replace "user" with an anonymous identity (static_header, no header/value).
	tc.Identities[1] = model.Identity{ID: "anon", Credential: model.Credential{Type: model.CredentialTypeStaticHeader}}
	tc.ExpectedAccess[1] = model.ExpectedAccess{IdentityID: "anon", Decision: model.AccessDecisionDeny}

	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "anon": 200}})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(result.Findings), result.Findings)
	}
	f := result.Findings[0]
	if f.Category != model.CategoryMissingAuthentication {
		t.Errorf("expected missing_authentication, got %q", f.Category)
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected critical severity, got %q", f.Severity)
	}
}

func TestRun_AuthenticatedStaysUnexpectedAccess(t *testing.T) {
	// An authenticated (bearer) identity reaching a resource is unexpected_access,
	// never missing_authentication.
	eng := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 200}})
	result, _ := eng.Run(context.Background(), baseTC())
	if len(result.Findings) != 1 || result.Findings[0].Category != model.CategoryUnexpectedAccess {
		t.Fatalf("expected unexpected_access for authenticated identity, got %+v", result.Findings)
	}
}

func TestRun_CORS_ReflectedWithCredentials(t *testing.T) {
	tc := baseTC()
	tc.CORS = &model.CORSCheck{ProbeOrigin: "https://evil.example"}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 403},
		headers: map[string]map[string]string{"admin": {
			"Access-Control-Allow-Origin":      "https://evil.example",
			"Access-Control-Allow-Credentials": "true",
		}},
	})
	result, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var f *model.Finding
	for i := range result.Findings {
		if result.Findings[i].Category == model.CategoryCORSMisconfiguration {
			f = &result.Findings[i]
		}
	}
	if f == nil {
		t.Fatalf("expected cors_misconfiguration finding, got %+v", result.Findings)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("reflected+credentials should be high, got %q", f.Severity)
	}
}

func TestRun_CORS_ReflectedNoCredentialsIsLow(t *testing.T) {
	tc := baseTC()
	tc.CORS = &model.CORSCheck{ProbeOrigin: "https://evil.example"}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 403},
		headers: map[string]map[string]string{"admin": {
			"Access-Control-Allow-Origin": "https://evil.example",
		}},
	})
	result, _ := eng.Run(context.Background(), tc)
	var f *model.Finding
	for i := range result.Findings {
		if result.Findings[i].Category == model.CategoryCORSMisconfiguration {
			f = &result.Findings[i]
		}
	}
	if f == nil || f.Severity != model.SeverityLow {
		t.Fatalf("expected low-severity cors finding, got %+v", result.Findings)
	}
}

func TestRun_CORS_NoReflectionNoFinding(t *testing.T) {
	tc := baseTC()
	tc.CORS = &model.CORSCheck{ProbeOrigin: "https://evil.example"}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 403},
		headers: map[string]map[string]string{"admin": {
			"Access-Control-Allow-Origin": "https://trusted.example",
		}},
	})
	result, _ := eng.Run(context.Background(), tc)
	for _, f := range result.Findings {
		if f.Category == model.CategoryCORSMisconfiguration {
			t.Errorf("did not expect cors finding when origin not reflected: %+v", f)
		}
	}
}

func TestRun_CORS_DisabledByDefault(t *testing.T) {
	// No CORS field → no probing, no finding even if headers present.
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": 200, "user": 403},
		headers: map[string]map[string]string{"admin": {
			"Access-Control-Allow-Origin": "*",
		}},
	})
	result, _ := eng.Run(context.Background(), baseTC())
	for _, f := range result.Findings {
		if f.Category == model.CategoryCORSMisconfiguration {
			t.Errorf("CORS must not be evaluated when unset: %+v", f)
		}
	}
}

func TestRun_DenyStatus_404TreatedAsDenyWhenDeclared(t *testing.T) {
	// Without a declared convention a 404 is ambiguous and yields no finding
	// (covered by TestRun_NoFinding_WhenExpectedDenyObservedNotFound). Declaring
	// it makes the same response an evaluated deny decision.
	tc := baseTC()
	tc.DenyStatuses = []int{401, 403, 404}
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusNotFound,
	}})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings for a declared deny, got %+v", res.Findings)
	}
}

func TestRun_DenyStatus_AllowedIdentityGetting404IsAMismatch(t *testing.T) {
	tc := baseTC()
	tc.DenyStatuses = []int{404}
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusNotFound,
		"user":  http.StatusForbidden,
	}})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Category != model.CategoryAuthorizationMismatch {
		t.Errorf("category = %q, want %q", res.Findings[0].Category, model.CategoryAuthorizationMismatch)
	}
}

func TestValidate_RejectsInvalidDenyStatus(t *testing.T) {
	for _, code := range []int{99, 600, 200} {
		tc := baseTC()
		tc.DenyStatuses = []int{code}
		if _, err := New(&stubExecutor{}).Run(context.Background(), tc); err == nil {
			t.Errorf("deny_status %d was accepted", code)
		}
	}
}

func TestRun_TenantFieldReadFromOffendingResponse(t *testing.T) {
	// The resource tenant is not known ahead of time; the policy names the
	// response field carrying it, and the offending caller's own body supplies
	// the value that proves the isolation break.
	tc := baseTC()
	tc.Identities[0].TenantID = "tenant-a"
	tc.Identities[1].TenantID = "tenant-b"
	tc.Resource = &model.Resource{Type: "user_profile", ObjectID: "1", TenantField: "tenant_id"}

	body := []byte(`{"user_id":"1","tenant_id":"tenant-a"}`)
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"admin": body, "user": body},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Category != model.CategoryCrossTenantAccess {
		t.Errorf("category = %q, want %q", f.Category, model.CategoryCrossTenantAccess)
	}
	if !hasEvidence(f, "resource_tenant=tenant-a") {
		t.Errorf("evidence did not name the tenant read from the body: %v", f.Evidence)
	}
}

func TestRun_TenantFieldAbsentFromBodyDoesNotElevate(t *testing.T) {
	tc := baseTC()
	tc.Identities[1].TenantID = "tenant-b"
	tc.Resource = &model.Resource{
		Type:          "user_profile",
		ObjectID:      "1",
		OwnerIdentity: "admin",
		TenantField:   "tenant_id",
	}

	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"user": []byte(`{"user_id":"1"}`)},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	// No tenant in the body means no tenant evidence: fall back, never guess.
	if got := res.Findings[0].Category; got != model.CategoryPotentialBOLA {
		t.Errorf("category = %q, want %q", got, model.CategoryPotentialBOLA)
	}
}

func TestRun_BoundTenantWinsOverResponseField(t *testing.T) {
	tc := baseTC()
	tc.Identities[1].TenantID = "tenant-b"
	tc.Resource = &model.Resource{
		Type:        "user_profile",
		ObjectID:    "1",
		TenantID:    "tenant-a",
		TenantField: "tenant_id",
	}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"user": []byte(`{"tenant_id":"tenant-b"}`)},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Category != model.CategoryCrossTenantAccess {
		t.Fatalf("expected cross_tenant_access, got %+v", res.Findings)
	}
	if !hasEvidence(res.Findings[0], "resource_tenant=tenant-a") {
		t.Errorf("bound tenant did not win: %v", res.Findings[0].Evidence)
	}
}

func hasEvidence(f model.Finding, want string) bool {
	for _, ev := range f.Evidence {
		if strings.Contains(ev, want) {
			return true
		}
	}
	return false
}

func TestRun_CORS_FindingIsAttributedToAnIdentity(t *testing.T) {
	// The policy is endpoint-level, but the finding must still say whose
	// response it was read from — every other category populates IdentityID.
	tc := baseTC()
	tc.CORS = &model.CORSCheck{ProbeOrigin: "https://evil.example"}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusForbidden},
		headers: map[string]map[string]string{
			"admin": {
				"Access-Control-Allow-Origin":      "https://evil.example",
				"Access-Control-Allow-Credentials": "true",
			},
		},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Category != model.CategoryCORSMisconfiguration {
			continue
		}
		found = true
		if f.IdentityID != "admin" {
			t.Errorf("IdentityID = %q, want %q", f.IdentityID, "admin")
		}
		if !hasEvidence(f, "observed_on_identity=admin") {
			t.Errorf("evidence did not record the observing identity: %v", f.Evidence)
		}
	}
	if !found {
		t.Fatalf("expected a cors_misconfiguration finding, got %+v", res.Findings)
	}
}

// A result document must not contradict itself: the execution record and the
// evidence drawn from it have to report the same observed outcome.
func TestRun_DenyStatus_ExecutionRecordAgreesWithEvidence(t *testing.T) {
	tc := baseTC()
	tc.DenyStatuses = []int{404}
	eng := New(&stubExecutor{responses: map[string]int{
		"admin": http.StatusNotFound,
		"user":  http.StatusForbidden,
	}})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var adminOutcome model.ObservedOutcome
	for _, ex := range res.Executions {
		if ex.IdentityID == "admin" {
			adminOutcome = ex.ObservedOutcome
		}
	}
	if adminOutcome != model.OutcomeDeny {
		t.Errorf("execution outcome = %q, want %q (404 is a declared deny)", adminOutcome, model.OutcomeDeny)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if !hasEvidence(res.Findings[0], "observed_outcome=deny") {
		t.Errorf("evidence disagrees with the execution record: %v", res.Findings[0].Evidence)
	}
	if !hasEvidence(res.Findings[0], "deny_status_declared=404") {
		t.Errorf("evidence does not disclose the declared convention: %v", res.Findings[0].Evidence)
	}
}

func TestRun_NoDenyStatus_EvidenceOmitsTheConvention(t *testing.T) {
	eng := New(&stubExecutor{responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK}})
	res, err := eng.Run(context.Background(), baseTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasEvidence(res.Findings[0], "deny_status_declared") {
		t.Errorf("evidence claimed a convention that was never declared: %v", res.Findings[0].Evidence)
	}
}

func TestRun_ExecutionErrorKeepsItsOutcome(t *testing.T) {
	tc := baseTC()
	tc.DenyStatuses = []int{404}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK},
		err:       map[string]string{"user": "connection refused"},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, ex := range res.Executions {
		if ex.IdentityID == "user" && ex.ObservedOutcome != model.OutcomeError {
			t.Errorf("errored execution outcome = %q, want %q", ex.ObservedOutcome, model.OutcomeError)
		}
	}
}

// The bug deny_when exists for: an API that refuses by returning 200 with an
// error body used to produce a false missing_authentication at critical
// severity, which is the exact failure the conservative classification is
// supposed to prevent.
func TestRun_DenyWhen_PreventsFalseCriticalOn200ErrorBody(t *testing.T) {
	body := []byte(`{"error":"forbidden"}`)
	tc := baseTC()
	tc.Identities[1].Credential = model.Credential{Type: model.CredentialTypeStaticHeader}
	tc.DenyWhen = &model.DenyCondition{
		JSONField: &model.JSONFieldMatch{Path: "error", Equals: "forbidden"},
	}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"admin": []byte(`{"id":1}`), "user": body},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("a correctly-refused caller must produce no finding, got %+v", res.Findings)
	}
	for _, ex := range res.Executions {
		if ex.IdentityID == "user" && ex.ObservedOutcome != model.OutcomeDeny {
			t.Errorf("execution outcome = %q, want %q", ex.ObservedOutcome, model.OutcomeDeny)
		}
	}
}

func TestRun_WithoutDenyWhen_The200ErrorBodyStillMisreads(t *testing.T) {
	// Documents why the declaration is required: without it the engine has no
	// way to know a 200 was a refusal.
	tc := baseTC()
	tc.Identities[1].Credential = model.Credential{Type: model.CredentialTypeStaticHeader}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"user": []byte(`{"error":"forbidden"}`)},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Category != model.CategoryMissingAuthentication {
		t.Fatalf("expected the undeclared case to still report, got %+v", res.Findings)
	}
}

func TestRun_DenyWhen_AllowedIdentityRefusedIsAMismatch(t *testing.T) {
	tc := baseTC()
	tc.DenyWhen = &model.DenyCondition{BodyContains: []string{"forbidden"}}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusForbidden},
		body:      map[string][]byte{"admin": []byte(`{"error":"forbidden"}`)},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Category != model.CategoryAuthorizationMismatch {
		t.Errorf("category = %q, want %q", f.Category, model.CategoryAuthorizationMismatch)
	}
	if !hasEvidence(f, "deny_when_matched") {
		t.Errorf("evidence must disclose why a 200 was read as a refusal: %v", f.Evidence)
	}
}

func TestRun_DenyWhen_OutranksASuccessStatus(t *testing.T) {
	// A declared body condition beats the status line; that is the whole point.
	tc := baseTC()
	tc.DenyWhen = &model.DenyCondition{BodyContains: []string{"denied"}}
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"user": []byte(`{"msg":"access denied"}`)},
	})
	res, _ := eng.Run(context.Background(), tc)
	for _, ex := range res.Executions {
		if ex.IdentityID == "user" && ex.ObservedOutcome != model.OutcomeDeny {
			t.Errorf("outcome = %q, want deny despite HTTP 200", ex.ObservedOutcome)
		}
	}
}

func TestValidate_RefusesUnsafeMethodWithoutOptIn(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "delete"} {
		tc := baseTC()
		tc.Request.Method = method
		_, err := New(&stubExecutor{}).Run(context.Background(), tc)
		if err == nil {
			t.Errorf("%s was accepted without mutating:true", method)
			continue
		}
		if !strings.Contains(err.Error(), "changes server state") {
			t.Errorf("%s: unhelpful error: %v", method, err)
		}
	}
}

func TestValidate_AllowsUnsafeMethodWhenAcknowledged(t *testing.T) {
	tc := baseTC()
	tc.Request.Method = "DELETE"
	tc.Mutating = true
	if _, err := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 403}}).Run(context.Background(), tc); err != nil {
		t.Fatalf("mutating:true must permit an unsafe method: %v", err)
	}
}

func TestValidate_SafeMethodsNeedNoOptIn(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		tc := baseTC()
		tc.Request.Method = method
		if _, err := New(&stubExecutor{responses: map[string]int{"admin": 200, "user": 403}}).Run(context.Background(), tc); err != nil {
			t.Errorf("%s should need no opt-in: %v", method, err)
		}
	}
}

func TestRun_ElevatedPropertyIsReportedAsObjectPropertyExposure(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[1].ForbidSensitiveData = true
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"user": []byte(`{"id":2,"is_admin":false,"balance":100}`)},
	})
	res, err := eng.Run(context.Background(), tc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Category == model.CategoryObjectPropertyExposure {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Errorf("severity = %q, want high", f.Severity)
			}
			if !hasEvidence(f, "is_admin") || !hasEvidence(f, "balance") {
				t.Errorf("evidence missing the properties: %v", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected object_property_exposure, got %+v", res.Findings)
	}
}

func TestRun_SensitiveTiersSplitIntoTwoCategories(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[1].ForbidSensitiveData = true
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"user": []byte(`{"api_key":"x","is_admin":true}`)},
	})
	res, _ := eng.Run(context.Background(), tc)

	cats := map[model.FindingCategory]model.Severity{}
	for _, f := range res.Findings {
		cats[f.Category] = f.Severity
	}
	if cats[model.CategoryObjectPropertyExposure] != model.SeverityHigh {
		t.Errorf("expected a high object_property_exposure, got %v", cats)
	}
	// api_key is critical, so the data-exposure finding takes that severity.
	if cats[model.CategorySensitiveDataExposure] != model.SeverityCritical {
		t.Errorf("expected a critical sensitive_data_exposure, got %v", cats)
	}
}

func TestRun_SensitiveEvidenceUsesPaths(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[1].ForbidSensitiveData = true
	eng := New(&stubExecutor{
		responses: map[string]int{"admin": http.StatusOK, "user": http.StatusOK},
		body:      map[string][]byte{"user": []byte(`{"user":{"profile":{"ssn":"x"}}}`)},
	})
	res, _ := eng.Run(context.Background(), tc)
	for _, f := range res.Findings {
		if f.Category != model.CategorySensitiveDataExposure {
			continue
		}
		if !hasEvidence(f, "user.profile.ssn") {
			t.Errorf("evidence should locate the leak by path: %v", f.Evidence)
		}
		return
	}
	t.Fatalf("expected a sensitive_data_exposure finding, got %+v", res.Findings)
}
