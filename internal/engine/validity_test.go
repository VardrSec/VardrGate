package engine

import (
	"context"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func TestCredentialValidityReportsOnlyObservedAssurance(t *testing.T) {
	id := model.Identity{ID: "peer", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "secret"}}
	if got := credentialStatus(id, nil, model.ExecutionResult{StatusCode: 200}); got != "not_checked" {
		t.Fatal(got)
	}
	passed := []model.PreflightResult{{IdentityID: "peer", Status: "passed"}}
	if got := credentialStatus(id, passed, model.ExecutionResult{StatusCode: 401}); got != "preflight_passed_resource_401" {
		t.Fatal(got)
	}
	if got := credentialStatus(id, nil, model.ExecutionResult{StatusCode: 401}); got != "resource_401_unverified" {
		t.Fatal(got)
	}
	id.Credential = model.Credential{Type: model.CredentialTypeStaticHeader}
	if got := credentialStatus(id, nil, model.ExecutionResult{}); got != "anonymous_identity" {
		t.Fatal(got)
	}
}

func TestVerificationRetainsOnlyStatusProvenance(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	s := &stateTarget{value: "private-before", writes: true, writeTo: "private-after", writeStatus: 500}
	r, err := New(s).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Assessments[0]
	if a.ExecutionIndex == nil || *a.ExecutionIndex != 0 || a.WriteVerification != "verified_effect" || a.CredentialStatus != "not_checked" {
		t.Fatalf("missing assessment provenance: %+v", a)
	}
	if v := a.Verification; v == nil || len(v.BeforeStatuses) != 2 || v.BeforeStatuses[0] != 200 || v.AfterStatus != 200 || v.ReaderIdentityID != "verifier" {
		t.Fatalf("missing readback: %+v", a)
	}
}

func TestVerifierPreflightFailureExplainsWithheldCallers(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.WriteVerification.Identity.Preflight = &model.IdentityPreflight{URL: "https://api.example.com/session", ExpectedStatus: 200, JSONFields: map[string]string{"id": "verifier"}}
	x := &bodyExecutor{result: model.ExecutionResult{StatusCode: 401}}
	r, err := New(x).Run(context.Background(), tc)
	if err != nil || x.calls != 1 || len(r.Executions) != 0 || len(r.Assessments) != 1 || r.Assessments[0].Reason != "identity_preflight_failed" || !r.PreflightFailed() {
		t.Fatalf("lost failed reader diagnostics: %+v %v", r, err)
	}
}
