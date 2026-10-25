package policy

import (
	"context"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

type profileExecutor struct {
	status int
	body   string
}

func (e profileExecutor) Execute(_ context.Context, id model.Identity, _ model.RequestTemplate) model.ExecutionResult {
	return model.ExecutionResult{IdentityID: id.ID, StatusCode: e.status, Body: []byte(e.body)}
}

func TestScopedDenialProfile(t *testing.T) {
	p, err := Parse([]byte(`api:
  endpoint: GET /books/{id}
expect: {peer: deny}
denial_profiles:
  concealed:
    confirmed: true
    endpoints: ["GET /books/{id}", "GET /notes/{id}"]
    rules:
      - status_codes: [404, 409, 422]
        json_pointer: /error/code
        equals: PRIVATE
      - status_codes: [200]
        json_pointer: /error/code
        equals: REFUSED
response:
  denial_profiles: [concealed]
  assertions:
    - json_pointer: /secret
      equals: private-value
      decision: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	b := Bindings{BaseURL: "https://example.test", PathParams: map[string]string{"id": "1"}, Identities: []model.Identity{{ID: "peer", Role: "peer", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "token"}}}}
	tc, err := p.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		status int
		body   string
		want   model.AssessmentDecision
	}{
		{404, `{"error":{"code":"PRIVATE"}}`, model.AssessmentDenied},
		{409, `{"error":{"code":"PRIVATE"}}`, model.AssessmentDenied},
		{422, `{"error":{"code":"PRIVATE"}}`, model.AssessmentDenied},
		{200, `{"error":{"code":"REFUSED"}}`, model.AssessmentDenied},
		{200, `{"error":{"code":"PRIVATE"}}`, model.AssessmentInconclusive},
		{404, `{"error":{"code":"NOT_FOUND"}}`, model.AssessmentInconclusive},
		{404, `{"secret":"private-value"}`, model.AssessmentAllowed},
		{404, `{"secret":"private-value","error":{"code":"PRIVATE"}}`, model.AssessmentInconclusive},
	} {
		r, err := engine.New(profileExecutor{tt.status, tt.body}).Run(context.Background(), tc)
		if err != nil || r.Assessments[0].Decision != tt.want {
			t.Fatalf("%d %s: %+v %v", tt.status, tt.body, r, err)
		}
	}
	profile := p.DenialProfiles["concealed"]
	profile.Confirmed = false
	p.DenialProfiles["concealed"] = profile
	if _, err := p.Compile(b); err == nil {
		t.Fatal("unconfirmed profile compiled")
	}
	profile.Confirmed = true
	p.DenialProfiles["concealed"] = profile
	p.API.Endpoint = "GET /unrelated/{id}"
	if _, err := p.Compile(b); err == nil {
		t.Fatal("out-of-scope profile compiled")
	}
}

func TestStatusOnlyDenialValidation(t *testing.T) {
	for _, code := range []int{200, 302, 500, 99, 600} {
		p := Policy{API: APISpec{Endpoint: "GET /x"}, Expect: map[string]string{"peer": "deny"}, Response: ResponseSpec{Assertions: []AssertionSpec{{Decision: "deny", StatusCodes: []int{code}}}}}
		tc, err := p.Compile(Bindings{BaseURL: "https://example.test", Identities: []model.Identity{{ID: "peer", Role: "peer", Credential: model.Credential{Type: model.CredentialTypeStaticHeader}}}})
		if err == nil && engine.Validate(tc) == nil {
			t.Fatalf("accepted status-only denial %d", code)
		}
	}
}
