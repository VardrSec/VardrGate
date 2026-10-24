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

func TestCompile_CarriesDenyStatusesAndTenantField(t *testing.T) {
	// Both fields were parsed but dropped on the floor before ADR 0007: a policy
	// could declare them and the engine would never see them.
	p, err := Parse([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tc, err := p.Compile(Bindings{
		BaseURL:    "https://api.example.com",
		PathParams: map[string]string{"user_id": "42"},
		Identities: []model.Identity{
			{ID: "o", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t"}},
		},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(tc.DenyStatuses) != 3 || tc.DenyStatuses[2] != 404 {
		t.Errorf("deny_status not compiled: %v", tc.DenyStatuses)
	}
	if tc.Resource == nil || tc.Resource.TenantField != "tenant_id" {
		t.Errorf("tenant_field not compiled: %+v", tc.Resource)
	}
}

func TestParseIdentities_ExpandsEnvReferences(t *testing.T) {
	t.Setenv("VARDRGATE_TEST_TOKEN", "s3cret")
	ids, err := ParseIdentities([]byte(`[
	  {"id":"owner","role":"owner","credential":{"type":"bearer","value":"${VARDRGATE_TEST_TOKEN}"}}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ids[0].Credential.Value != "s3cret" {
		t.Errorf("value = %q, want %q", ids[0].Credential.Value, "s3cret")
	}
}

func TestParseIdentities_ExpandsWithSurroundingText(t *testing.T) {
	t.Setenv("VARDRGATE_TEST_TOKEN", "abc")
	ids, err := ParseIdentities([]byte(`[
	  {"id":"o","role":"owner","credential":{"type":"bearer","value":"prefix-${VARDRGATE_TEST_TOKEN}-suffix"}}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ids[0].Credential.Value != "prefix-abc-suffix" {
		t.Errorf("value = %q", ids[0].Credential.Value)
	}
}

func TestParseIdentities_UnsetEnvIsAnError(t *testing.T) {
	// A blank token silently turns an authenticated identity into an anonymous
	// one, which inverts the meaning of the test. Fail loudly instead.
	_, err := ParseIdentities([]byte(`[
	  {"id":"o","role":"owner","credential":{"type":"bearer","value":"${VARDRGATE_DEFINITELY_UNSET}"}}
	]`))
	if err == nil || !strings.Contains(err.Error(), "unset or empty") {
		t.Fatalf("expected unset-variable error, got %v", err)
	}
}

func TestParseIdentities_RejectsMissingRole(t *testing.T) {
	_, err := ParseIdentities([]byte(`[{"id":"o","credential":{"type":"bearer","value":"t"}}]`))
	if err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("expected role error, got %v", err)
	}
}

func TestParseIdentities_RejectsEmptyDocument(t *testing.T) {
	if _, err := ParseIdentities([]byte(`[]`)); err == nil {
		t.Fatal("expected an error for an empty identities file")
	}
}

func TestParseIdentities_RejectsUnterminatedReference(t *testing.T) {
	_, err := ParseIdentities([]byte(`[{"id":"o","role":"owner","credential":{"type":"bearer","value":"${OPEN"}}]`))
	if err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("expected unterminated error, got %v", err)
	}
}

func TestCompile_CarriesDenyWhenAndMutating(t *testing.T) {
	y := `
api:
  endpoint: DELETE /users/{user_id}
  mutating: true
expect:
  owner: allow
response:
  deny_when:
    body_contains: ["forbidden"]
    json_field: { path: error.code, equals: DENIED }
`
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tc, err := p.Compile(Bindings{
		BaseURL:    "https://api.example.com",
		PathParams: map[string]string{"user_id": "42"},
		Identities: []model.Identity{
			{ID: "o", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t"}},
		},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !tc.Mutating {
		t.Error("mutating not compiled")
	}
	if tc.DenyWhen == nil {
		t.Fatal("deny_when not compiled")
	}
	if len(tc.DenyWhen.BodyContains) != 1 || tc.DenyWhen.BodyContains[0] != "forbidden" {
		t.Errorf("body_contains = %v", tc.DenyWhen.BodyContains)
	}
	if tc.DenyWhen.JSONField == nil || tc.DenyWhen.JSONField.Path != "error.code" || tc.DenyWhen.JSONField.Equals != "DENIED" {
		t.Errorf("json_field = %+v", tc.DenyWhen.JSONField)
	}
}

func TestCompile_AllowMutatingBindingOverridesThePolicy(t *testing.T) {
	y := "api:\n  endpoint: DELETE /x/{id}\nexpect:\n  owner: allow\n"
	p, _ := Parse([]byte(y))
	tc, err := p.Compile(Bindings{
		BaseURL:       "https://api.example.com",
		PathParams:    map[string]string{"id": "1"},
		Identities:    []model.Identity{{ID: "o", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t"}}},
		AllowMutating: true,
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !tc.Mutating {
		t.Error("--allow-mutating should set Mutating on the compiled case")
	}
}

func TestParse_RejectsTheDraftMarker(t *testing.T) {
	// The enforceable half of the discover invariant: a proposed policy is
	// inert until a human replaces every placeholder.
	y := "api:\n  endpoint: GET /x/{id}\nexpect:\n  owner: TODO\n"
	_, err := Parse([]byte(y))
	if err == nil {
		t.Fatal("a draft expectation must not parse")
	}
	if !strings.Contains(err.Error(), DraftMarker) {
		t.Errorf("error should name the marker: %v", err)
	}
	if !strings.Contains(err.Error(), "allow, deny, or skip") {
		t.Errorf("error should say what to do about it: %v", err)
	}
}

func TestParse_DraftMarkerIsCaseInsensitive(t *testing.T) {
	for _, marker := range []string{"todo", "ToDo", " TODO "} {
		y := "api:\n  endpoint: GET /x/{id}\nexpect:\n  owner: " + marker + "\n"
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%q was accepted as a decision", marker)
		}
	}
}

func TestCompileSetup_BindsPathsAndResolvesRoles(t *testing.T) {
	y := `
api:
  endpoint: GET /objects/{{new_id}}
  mutating: true
setup:
  - name: create
    as: owner
    request:
      method: POST
      path: /objects
      body: '{"title":"t"}'
    capture:
      new_id: id
expect:
  owner: allow
`
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tc, err := p.Compile(Bindings{
		BaseURL:    "https://api.example.com",
		Identities: []model.Identity{{ID: "owner-1", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t"}}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(tc.Setup) != 1 {
		t.Fatalf("setup not compiled: %+v", tc.Setup)
	}
	s := tc.Setup[0]
	if s.As != "owner-1" {
		t.Errorf("as = %q, want the concrete identity id", s.As)
	}
	if s.Request.URL != "https://api.example.com/objects" {
		t.Errorf("url = %q", s.Request.URL)
	}
	if s.Capture["new_id"] != "id" {
		t.Errorf("capture = %v", s.Capture)
	}
	// A {{var}} in the endpoint is resolved at run time, not at compile time.
	if !strings.HasSuffix(tc.Request.URL, "/objects/{{new_id}}") {
		t.Errorf("runtime reference should survive compilation: %q", tc.Request.URL)
	}
}

func TestCompileSetup_RejectsUnknownRole(t *testing.T) {
	y := `
api:
  endpoint: GET /x/{id}
setup:
  - name: s
    as: ghost
    request: { method: GET, path: /login }
expect:
  owner: allow
`
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = p.Compile(Bindings{
		BaseURL:    "https://api.example.com",
		PathParams: map[string]string{"id": "1"},
		Identities: []model.Identity{{ID: "o", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t"}}},
	})
	if err == nil || !strings.Contains(err.Error(), "no bound identity has") {
		t.Fatalf("got %v, want an unknown-role error", err)
	}
}

func TestSubstitutePath_LeavesRuntimeReferencesAlone(t *testing.T) {
	got, err := substitutePath("/orgs/{org}/objects/{{captured}}", map[string]string{"org": "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/orgs/acme/objects/{{captured}}" {
		t.Errorf("got %q", got)
	}
}

const assertionPolicy = `
api:
  endpoint: GET /books/{title}
expect:
  owner: allow
  peer: deny
  anonymous: deny
response:
  assertions:
    - json_pointer: /secret
      equals: owner-secret
      decision: allow
    - json_pointer: /status
      equals: fail
      decision: deny
      roles: [peer]
    - json_pointer: /id
      equals: 9007199254740993
      decision: allow
      roles: [owner]
`

func assertionBindings() Bindings {
	return Bindings{BaseURL: "http://localhost:5000", PathParams: map[string]string{"title": "b1"}, Identities: []model.Identity{
		{ID: "o", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t1"}},
		{ID: "p", Role: "peer", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t2"}},
		{ID: "a", Role: "anonymous", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "t3"}},
	}}
}

func TestCompile_ResponseAssertions(t *testing.T) {
	p, err := Parse([]byte(assertionPolicy))
	if err != nil {
		t.Fatal(err)
	}
	tc, err := p.Compile(assertionBindings())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Validate(tc); err != nil {
		t.Fatalf("compiled assertions do not validate: %v", err)
	}
	got := map[string][]string{}
	for _, ea := range tc.ExpectedAccess {
		for _, r := range ea.ResponseAssertions {
			got[ea.IdentityID] = append(got[ea.IdentityID], r.JSONPointer+"="+string(r.Equals)+":"+string(r.Decision))
		}
	}
	want := map[string][]string{
		"o": {`/secret="owner-secret":allow`, `/id=9007199254740993:allow`},
		"p": {`/secret="owner-secret":allow`, `/status="fail":deny`},
		"a": {`/secret="owner-secret":allow`},
	}
	for id, w := range want {
		if strings.Join(got[id], " ") != strings.Join(w, " ") {
			t.Errorf("%s: got %v, want %v", id, got[id], w)
		}
	}
}

func TestCompile_RejectsBadAssertions(t *testing.T) {
	for name, tail := range map[string]string{
		"missing equals": "    - json_pointer: /x\n      decision: allow\n",
		"bad decision":   "    - json_pointer: /x\n      equals: 1\n      decision: skip\n",
		"unknown role":   "    - json_pointer: /x\n      equals: 1\n      decision: deny\n      roles: [admin]\n",
		"bad pointer":    "    - json_pointer: x\n      equals: 1\n      decision: deny\n",
	} {
		t.Run(name, func(t *testing.T) {
			doc := "api:\n  endpoint: GET /x\nexpect:\n  owner: allow\nresponse:\n  assertions:\n" + tail
			p, err := Parse([]byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			b := assertionBindings()
			b.Identities = b.Identities[:1]
			tc, err := p.Compile(b)
			if err == nil {
				err = engine.Validate(tc)
			}
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
