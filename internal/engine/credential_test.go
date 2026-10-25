package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func credentialCase(cred model.Credential, expect model.AccessDecision) model.AuthorizationTestCase {
	return model.AuthorizationTestCase{
		ID:             "dead-token",
		Identities:     []model.Identity{{ID: "peer", Credential: cred}},
		Request:        model.RequestTemplate{Method: http.MethodGet, URL: "https://api.example.com/books/1"},
		ExpectedAccess: []model.ExpectedAccess{{IdentityID: "peer", Decision: expect}},
	}
}

var (
	bearer    = model.Credential{Type: model.CredentialTypeBearer, Value: "tok-peer"}
	anonymous = model.Credential{Type: model.CredentialTypeStaticHeader}
)

// A 401 to a caller that sent credentials cannot be told apart from a dead
// token, so it must never read as a verified denial. See ADR 0019.
func TestCredentialRejectedDenials(t *testing.T) {
	for _, tt := range []struct {
		name         string
		cred         model.Credential
		expect       model.AccessDecision
		status       int
		denyStatuses []int
		declared401  bool
		assertions   []model.ResponseAssertion
		body         string
		decision     model.AssessmentDecision
		reason       string
	}{
		{name: "credentialed 401", cred: bearer, expect: model.AccessDecisionDeny, status: 401,
			decision: model.AssessmentInconclusive, reason: reasonCredentialRejected},
		{name: "anonymous 401", cred: anonymous, expect: model.AccessDecisionDeny, status: 401,
			decision: model.AssessmentDenied, reason: "status_only"},
		{name: "credentialed 403", cred: bearer, expect: model.AccessDecisionDeny, status: 403,
			decision: model.AssessmentDenied, reason: "status_only"},
		{name: "401 declared as this API's denial", cred: bearer, expect: model.AccessDecisionDeny, status: 401, declared401: true,
			decision: model.AssessmentDenied, reason: "status_only"},
		// The documented convention lists 401 in deny_status; that was always
		// redundant and must not switch the dead-token protection off.
		{name: "401 in the copied deny_status convention", cred: bearer, expect: model.AccessDecisionDeny, status: 401, denyStatuses: []int{401, 403, 404},
			decision: model.AssessmentInconclusive, reason: reasonCredentialRejected},
		{name: "declared 401 with a matching deny assertion", cred: bearer, expect: model.AccessDecisionDeny, status: 401, declared401: true,
			assertions: []model.ResponseAssertion{rule("/status", `"fail"`, model.AccessDecisionDeny)}, body: `{"status":"fail"}`,
			decision: model.AssessmentDenied, reason: "assertion_matched"},
		{name: "deny assertion matching a 401 body", cred: bearer, expect: model.AccessDecisionDeny, status: 401,
			assertions: []model.ResponseAssertion{rule("/status", `"fail"`, model.AccessDecisionDeny)}, body: `{"status":"fail"}`,
			decision: model.AssessmentInconclusive, reason: reasonCredentialRejected},
		{name: "allow-expected 401 keeps its assessment", cred: bearer, expect: model.AccessDecisionAllow, status: 401,
			decision: model.AssessmentDenied, reason: "status_only"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := credentialCase(tt.cred, tt.expect)
			tc.DenyStatuses = tt.denyStatuses
			tc.UnauthorizedIsDenial = tt.declared401
			tc.ExpectedAccess[0].ResponseAssertions = tt.assertions
			exec := &stubExecutor{responses: map[string]int{"peer": tt.status}, body: map[string][]byte{"peer": []byte(tt.body)}}
			res, err := New(exec).Run(context.Background(), tc)
			if err != nil {
				t.Fatal(err)
			}
			if a := res.Assessments[0]; a.Decision != tt.decision || a.Reason != tt.reason {
				t.Fatalf("assessment = %s/%s, want %s/%s", a.Decision, a.Reason, tt.decision, tt.reason)
			}
		})
	}
}

// The demotion changes the assessment only: an allow-expected 401 still raises
// its mismatch finding, and a deny-expected one still raises nothing.
func TestCredentialRejectedKeepsFindings(t *testing.T) {
	for expect, want := range map[model.AccessDecision]int{model.AccessDecisionAllow: 1, model.AccessDecisionDeny: 0} {
		res, err := New(&stubExecutor{responses: map[string]int{"peer": 401}}).Run(context.Background(), credentialCase(bearer, expect))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != want {
			t.Errorf("expect %s: %d findings, want %d", expect, len(res.Findings), want)
		}
	}
}

// ownerWritesExecutor lets only the owner change the record; every other
// writer gets 401, as a dead token would.
type ownerWritesExecutor struct{ value string }

func (x *ownerWritesExecutor) Execute(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	if req.Method == "" || req.Method == http.MethodGet {
		b, _ := json.Marshal(map[string]any{"record": map[string]string{"value": x.value}})
		return model.ExecutionResult{IdentityID: id.ID, StatusCode: 200, Body: b}
	}
	if id.ID != "owner" {
		return model.ExecutionResult{IdentityID: id.ID, StatusCode: 401}
	}
	x.value = "owner-new"
	return model.ExecutionResult{IdentityID: id.ID, StatusCode: 204}
}

// With a working owner control the positive-control guard passes; the peer's
// unchanged state is still not a denial, and the reason points at its token
// rather than at the verifier.
func TestVerifiedWriteWithRejectedPeerCredential(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.Identities = append(tc.Identities, model.Identity{ID: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-o"}})
	tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: "owner", Decision: model.AccessDecisionAllow})
	tc.WriteVerification.ChangedTo = json.RawMessage(`"owner-new"`)
	res, err := New(&ownerWritesExecutor{value: "original"}).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Assessment{}
	for _, a := range res.Assessments {
		got[a.IdentityID] = a
	}
	if a := got["peer"]; a.Decision != model.AssessmentInconclusive || a.Reason != reasonCredentialRejected {
		t.Fatalf("peer = %s/%s, want inconclusive/%s", a.Decision, a.Reason, reasonCredentialRejected)
	}
	if a := got["owner"]; a.Decision != model.AssessmentAllowed {
		t.Fatalf("owner control = %s/%s, want allowed", a.Decision, a.Reason)
	}
}
