package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

const samplePolicy = `
api:
  endpoint: GET /users/{user_id}/profile
  owner: identity:owner
  resource:
    type: user_profile
    id_param: user_id
    tenant_field: tenant_id
expect:
  owner: allow
  other_user: deny
  anonymous: deny
response:
  deny_status: [401, 403, 404]
  sensitive_fields:
    forbidden_for:
      - other_user
      - anonymous
`

func TestParse_Valid(t *testing.T) {
	p, err := Parse([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.API.Endpoint != "GET /users/{user_id}/profile" {
		t.Errorf("endpoint not parsed: %q", p.API.Endpoint)
	}
	if p.Expect["owner"] != "allow" {
		t.Errorf("expect not parsed: %+v", p.Expect)
	}
	if p.API.Resource.IDParam != "user_id" {
		t.Errorf("resource id_param not parsed: %q", p.API.Resource.IDParam)
	}
}

func TestParse_RejectsMissingEndpoint(t *testing.T) {
	_, err := Parse([]byte("expect:\n  owner: allow\n"))
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("expected endpoint error, got %v", err)
	}
}

func TestParse_RejectsBadDecision(t *testing.T) {
	y := "api:\n  endpoint: GET /x\nexpect:\n  owner: maybe\n"
	_, err := Parse([]byte(y))
	if err == nil || !strings.Contains(err.Error(), "invalid decision") {
		t.Fatalf("expected invalid decision error, got %v", err)
	}
}

func TestParse_RejectsUnknownField(t *testing.T) {
	y := "api:\n  endpoint: GET /x\n  bogus: 1\nexpect:\n  owner: allow\n"
	_, err := Parse([]byte(y))
	if err == nil {
		t.Fatalf("expected unknown-field error")
	}
}

func bindings() Bindings {
	return Bindings{
		BaseURL:    "https://api.example.com/",
		PathParams: map[string]string{"user_id": "42"},
		Identities: []model.Identity{
			{ID: "u-owner", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t1"}},
			{ID: "u-other", Role: "other_user", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t2"}},
			{ID: "u-anon", Role: "anonymous", Credential: model.Credential{Type: model.CredentialTypeStaticHeader}},
		},
	}
}

func TestCompile_ProducesRunnableTestCase(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	tc, err := p.Compile(bindings())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tc.Request.Method != "GET" {
		t.Errorf("method: got %q", tc.Request.Method)
	}
	if tc.Request.URL != "https://api.example.com/users/42/profile" {
		t.Errorf("url not compiled: %q", tc.Request.URL)
	}
	if tc.Resource == nil || tc.Resource.OwnerIdentity != "u-owner" {
		t.Fatalf("owner identity not resolved: %+v", tc.Resource)
	}
	if tc.Resource.ObjectID != "42" {
		t.Errorf("object id: got %q", tc.Resource.ObjectID)
	}

	want := map[string]model.AccessDecision{
		"u-owner": model.AccessDecisionAllow,
		"u-other": model.AccessDecisionDeny,
		"u-anon":  model.AccessDecisionDeny,
	}
	got := map[string]model.AccessDecision{}
	for _, ea := range tc.ExpectedAccess {
		got[ea.IdentityID] = ea.Decision
	}
	for id, dec := range want {
		if got[id] != dec {
			t.Errorf("expected %s=%s, got %s", id, dec, got[id])
		}
	}
}

// The compiled test case must be accepted and evaluated by the engine unchanged.
func TestCompile_OutputPassesEngine(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	tc, err := p.Compile(bindings())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	eng := engine.New(&fakeExec{code: map[string]int{
		"u-owner": 200, "u-other": 200, "u-anon": 401,
	}})
	res, err := eng.Run(t.Context(), tc)
	if err != nil {
		t.Fatalf("engine rejected compiled case: %v", err)
	}
	// u-other reached another owner's object → potential_bola.
	if len(res.Findings) != 1 || res.Findings[0].Category != model.CategoryPotentialBOLA {
		t.Fatalf("expected one potential_bola finding, got %+v", res.Findings)
	}
}

func TestCompile_MissingPathParam(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	b := bindings()
	b.PathParams = nil
	_, err := p.Compile(b)
	if err == nil || !strings.Contains(err.Error(), "path parameter") {
		t.Fatalf("expected missing path param error, got %v", err)
	}
}

func TestCompile_UnmappedRole(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	b := bindings()
	b.Identities[1].Role = "stranger"
	_, err := p.Compile(b)
	if err == nil || !strings.Contains(err.Error(), "expect map") {
		t.Fatalf("expected unmapped role error, got %v", err)
	}
}

func TestCompile_CrossTenantWhenBound(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	b := bindings()
	b.ResourceTenantID = "tenant-a"
	b.Identities[1].TenantID = "tenant-b"
	tc, err := p.Compile(b)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	eng := engine.New(&fakeExec{code: map[string]int{
		"u-owner": 200, "u-other": 200, "u-anon": 401,
	}})
	res, _ := eng.Run(t.Context(), tc)
	if len(res.Findings) != 1 || res.Findings[0].Category != model.CategoryCrossTenantAccess {
		t.Fatalf("expected cross_tenant_access, got %+v", res.Findings)
	}
}

type fakeExec struct {
	code map[string]int
	body map[string][]byte
}

func (f *fakeExec) Execute(_ context.Context, id model.Identity, _ model.RequestTemplate) model.ExecutionResult {
	c := f.code[id.ID]
	r := model.ExecutionResult{IdentityID: id.ID, StatusCode: c, ObservedOutcome: model.ClassifyOutcome(c, false)}
	if f.body != nil {
		r.Body = f.body[id.ID]
	}
	return r
}

func TestCompile_SetsForbidSensitiveData(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	tc, err := p.Compile(bindings())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// samplePolicy forbids sensitive fields for other_user and anonymous, not owner.
	want := map[string]bool{"u-owner": false, "u-other": true, "u-anon": true}
	got := map[string]bool{}
	for _, ea := range tc.ExpectedAccess {
		got[ea.IdentityID] = ea.ForbidSensitiveData
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: ForbidSensitiveData=%v, want %v", id, got[id], w)
		}
	}
}

func TestCompile_SensitiveExposureThroughEngine(t *testing.T) {
	p, _ := Parse([]byte(samplePolicy))
	tc, _ := p.Compile(bindings())
	// other_user is allowed here but the response leaks a password field.
	eng := engine.New(&fakeExec{
		code: map[string]int{"u-owner": 200, "u-other": 200, "u-anon": 401},
		body: map[string][]byte{"u-other": []byte(`{"id":1,"password":"x"}`)},
	})
	res, _ := eng.Run(t.Context(), tc)
	var found bool
	for _, f := range res.Findings {
		if f.Category == model.CategorySensitiveDataExposure && f.IdentityID == "u-other" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected sensitive_data_exposure for u-other, got %+v", res.Findings)
	}
}
