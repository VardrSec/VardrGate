package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

type reviewMixedExecutor struct{ value string }

func (x *reviewMixedExecutor) Execute(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	if req.Method == "GET" || req.Method == "" {
		b, _ := json.Marshal(map[string]any{"record": map[string]string{"value": x.value}})
		return model.ExecutionResult{IdentityID: id.ID, StatusCode: 200, Body: b}
	}
	if id.ID == "peer" {
		return model.ExecutionResult{IdentityID: id.ID, Error: "connection refused", ErrorKind: model.ErrorKindNetwork}
	}
	x.value = "owner-new"
	return model.ExecutionResult{IdentityID: id.ID, StatusCode: 204}
}
func TestReviewMixedCaseHidesUnreachedPeer(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.Identities = append(tc.Identities, model.Identity{ID: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "test"}})
	tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: "owner", Decision: model.AccessDecisionAllow})
	tc.WriteVerification.ChangedTo = json.RawMessage(`"owner-new"`)
	r, err := New(&reviewMixedExecutor{value: "original"}).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inconclusive()) == 0 {
		t.Fatalf("failed peer hidden even with positive control: unreached=%t inconclusive=%d findings=%d assessments=%+v", r.Unreached(), len(r.Inconclusive()), len(r.Findings), r.Assessments)
	}
}

func TestReviewVerifierRedirectIsNotAWrite(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	target := &stateTarget{value: "unchanged", writeStatus: 403, readStatus: []int{200, 200, 302}}
	result, err := New(target).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	a := result.Assessments[0]
	if a.Decision != model.AssessmentInconclusive || len(result.Findings) != 0 {
		t.Fatalf("verifier redirect wrongly proves a write: assessment=%+v findings=%+v", a, result.Findings)
	}
}

func TestReviewUnsentWriteIsNotVerifiedDenial(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	target := &funcExecutor{fn: func(req model.RequestTemplate) model.ExecutionResult {
		if req.URL == tc.WriteVerification.Request.URL {
			return model.ExecutionResult{StatusCode: 200, Body: []byte(`{"record":{"value":"unchanged"}}`)}
		}
		return model.ExecutionResult{Error: "connection refused", ErrorKind: model.ErrorKindNetwork}
	}}
	result, err := New(target).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if result.Assessments[0].Decision != model.AssessmentInconclusive {
		t.Fatalf("unreached write called a verified denial: %+v", result.Assessments[0])
	}
}

func TestReviewWrongOracleDenyOnlyCannotPass(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	target := &stateTarget{value: "victim-private", writeStatus: 204, writes: true, writeTo: "compromised", readBody: func(string) string { return `{"record":{"value":"wrong-constant-field"}}` }}
	result, err := New(target).Run(context.Background(), tc)
	if err != nil {
		return
	}
	if result.Assessments[0].Decision != model.AssessmentInconclusive {
		t.Fatalf("real unauthorized write is silently clean: actual=%s assessment=%+v findings=%d", target.value, result.Assessments[0], len(result.Findings))
	}
}

func TestVerifierUnreadableAfterStates(t *testing.T) {
	for _, code := range []int{0, 301, 302, 307, 400, 405, 429} {
		tc := verifiedCase(model.AccessDecisionDeny)
		x := &stateTarget{value: "original", writeStatus: 403, readStatus: []int{200, 200, code}}
		r, err := New(x).Run(context.Background(), tc)
		if err != nil {
			t.Fatal(err)
		}
		if r.Assessments[0].Decision != model.AssessmentInconclusive || r.Assessments[0].Reason != reasonVerifierStatus || len(r.Findings) != 0 {
			t.Fatalf("status %d: %+v", code, r)
		}
	}
}

func TestVerifierSuccessfulStatusChangeAloneIsNotAMutation(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	x := &stateTarget{value: "original", writeStatus: 403, readStatus: []int{200, 200, 201}}
	r, err := New(x).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if r.Assessments[0].Decision != model.AssessmentInconclusive || r.Assessments[0].Reason != reasonNoPositiveControl || len(r.Findings) != 0 {
		t.Fatalf("status-only change became access: %+v", r)
	}
}

type calibrationExecutor struct {
	value string
	good  bool
}

func (x *calibrationExecutor) Execute(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	if req.Method == "GET" || req.Method == "" {
		b, _ := json.Marshal(map[string]any{"record": map[string]string{"value": x.value}})
		return model.ExecutionResult{StatusCode: 200, Body: b}
	}
	if id.ID == "owner" && x.good {
		x.value = "new"
	}
	return model.ExecutionResult{StatusCode: 204}
}

func TestPositiveControlMustActuallyDemonstrateChange(t *testing.T) {
	for _, good := range []bool{false, true} {
		tc := verifiedCase(model.AccessDecisionDeny)
		tc.Identities = append(tc.Identities, model.Identity{ID: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "test"}})
		tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: "owner", Decision: model.AccessDecisionAllow})
		tc.WriteVerification.ChangedTo = json.RawMessage(`"new"`)
		r, err := New(&calibrationExecutor{value: "old", good: good}).Run(context.Background(), tc)
		if err != nil {
			t.Fatal(err)
		}
		peer := r.Assessments[0]
		if good {
			if peer.Decision != model.AssessmentDenied || len(r.Findings) != 0 {
				t.Fatalf("working control not credited: %+v", r)
			}
		} else if peer.Decision != model.AssessmentInconclusive || peer.Reason != reasonPositiveControlFailed || len(r.Findings) != 1 {
			t.Fatalf("broken control hid incorrect oracle: %+v", r)
		}
	}
}

func TestObservedChangeStillProvesAccessAfterWriteError(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.WriteVerification.ChangedTo = json.RawMessage(`"changed"`)
	value := "old"
	x := &funcExecutor{fn: func(req model.RequestTemplate) model.ExecutionResult {
		if req.URL == tc.WriteVerification.Request.URL {
			b, _ := json.Marshal(map[string]any{"record": map[string]string{"value": value}})
			return model.ExecutionResult{StatusCode: 200, Body: b}
		}
		value = "changed"
		return model.ExecutionResult{Error: "connection closed after commit", ErrorKind: model.ErrorKindNetwork}
	}}
	r, err := New(x).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if r.Assessments[0].Decision != model.AssessmentAllowed || len(r.Findings) != 1 {
		t.Fatalf("independently proven effect lost: %+v", r)
	}
}
