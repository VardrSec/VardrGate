package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

type interruptionExecutor struct {
	fn func(context.Context, model.Identity, model.RequestTemplate) model.ExecutionResult
}

func (x interruptionExecutor) Execute(ctx context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	r := x.fn(ctx, id, req)
	r.IdentityID = id.ID
	return r
}

func resetCase() model.AuthorizationTestCase {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.WriteVerification.Strategy = "changed"
	tc.WriteVerification.Environment = "synchronous_isolated"
	tc.WriteVerification.Reset = &model.SetupStep{As: "peer", Request: model.RequestTemplate{Method: "PUT", URL: "https://api.example.com/reset"}}
	return tc
}

func TestVerificationCancellationWithholdsFurtherTraffic(t *testing.T) {
	for _, at := range []string{"before reset", "after reset", "during read", "after baseline", "during write"} {
		t.Run(at, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc := resetCase()
			calls, writes, reads := 0, 0, 0
			if at == "before reset" {
				cancel()
			}
			x := interruptionExecutor{fn: func(_ context.Context, _ model.Identity, req model.RequestTemplate) model.ExecutionResult {
				calls++
				switch {
				case strings.HasSuffix(req.URL, "/reset"):
					if at == "after reset" {
						cancel()
					}
				case req.URL == tc.WriteVerification.Request.URL:
					reads++
					if at == "during read" {
						cancel()
					}
					if at == "after baseline" && reads == 2 {
						cancel()
					}
					return model.ExecutionResult{StatusCode: 200, Body: []byte(`{"record":{"value":"initial"}}`)}
				default:
					writes++
					cancel() // The server may already have committed this write.
				}
				return model.ExecutionResult{StatusCode: 204}
			}}
			r, err := New(x).Run(ctx, tc)
			if err != nil || len(r.Assessments) != 1 || r.Assessments[0].Reason != reasonCancelled || r.Assessments[0].Decision != model.AssessmentInconclusive || len(r.Findings) != 0 {
				t.Fatalf("cancellation: %+v %v", r, err)
			}
			wantCalls := map[string]int{"before reset": 0, "after reset": 1, "during read": 2, "after baseline": 3, "during write": 4}[at]
			if calls != wantCalls || (at != "during write" && writes != 0) || reads > 2 {
				t.Fatalf("traffic continued after cancellation: calls=%d writes=%d reads=%d", calls, writes, reads)
			}
		})
	}
}

func TestPartialResetFailureWithholdsWrite(t *testing.T) {
	tc := resetCase()
	calls := 0
	r, err := New(interruptionExecutor{fn: func(_ context.Context, _ model.Identity, _ model.RequestTemplate) model.ExecutionResult {
		calls++
		// A partial reset may have changed state before losing the response.
		return model.ExecutionResult{StatusCode: 204, Error: "response interrupted", ErrorKind: model.ErrorKindNetwork}
	}}).Run(context.Background(), tc)
	if err != nil || calls != 1 || r.Assessments[0].Reason != reasonResetFailed || len(r.Findings) != 0 {
		t.Fatalf("partial reset: %+v calls=%d %v", r, calls, err)
	}
}

func TestInterruptedWriteRequiresIndependentReadback(t *testing.T) {
	for _, outcome := range []string{"committed", "partial", "readback failed"} {
		t.Run(outcome, func(t *testing.T) {
			tc := verifiedCase(model.AccessDecisionDeny)
			tc.WriteVerification.ChangedTo = json.RawMessage(`"changed"`)
			value, wrote := "initial", false
			r, err := New(interruptionExecutor{fn: func(_ context.Context, _ model.Identity, req model.RequestTemplate) model.ExecutionResult {
				if req.URL == tc.WriteVerification.Request.URL {
					if wrote && outcome == "readback failed" {
						return model.ExecutionResult{Error: "read timed out", ErrorKind: model.ErrorKindNetwork}
					}
					body, _ := json.Marshal(map[string]any{"record": map[string]string{"value": value}})
					return model.ExecutionResult{StatusCode: 200, Body: body}
				}
				wrote, value = true, "changed"
				if outcome == "partial" {
					value = "partial"
				}
				return model.ExecutionResult{Error: "write response interrupted", ErrorKind: model.ErrorKindNetwork}
			}}).Run(context.Background(), tc)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"committed": reasonStateChanged, "partial": reasonChangedUnexpectedly, "readback failed": reasonVerifierReadFailed}[outcome]
			if r.Assessments[0].Reason != want || (outcome == "committed") != (len(r.Findings) > 0) {
				t.Fatalf("readback: %+v", r)
			}
		})
	}
}

func TestResetMustRestoreBaselineAcrossIdentities(t *testing.T) {
	tc := resetCase()
	tc.Identities = append(tc.Identities, model.Identity{ID: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "owner-token"}})
	tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: "owner", Decision: model.AccessDecisionAllow})
	tc.WriteVerification.Reset.As = "owner"
	value, resets, writes := "initial", 0, 0
	r, err := New(interruptionExecutor{fn: func(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
		switch {
		case strings.HasSuffix(req.URL, "/reset"):
			resets++
			if id.ID != "owner" {
				t.Fatalf("wrong reset identity: %s", id.ID)
			}
			// The second reset reports success but restores the wrong state.
			if resets > 1 {
				value = "contaminated"
			}
		case req.URL == tc.WriteVerification.Request.URL:
			body, _ := json.Marshal(map[string]any{"record": map[string]string{"value": value}})
			return model.ExecutionResult{StatusCode: 200, Body: body}
		default:
			writes++ // Peer cannot write; owner's write must be withheld.
		}
		return model.ExecutionResult{StatusCode: 204}
	}}).Run(context.Background(), tc)
	if err != nil || writes != 1 || resets != 2 || len(r.Findings) != 0 || r.Assessments[0].Reason != reasonPositiveControlFailed || r.Assessments[1].Reason != reasonResetBaseline {
		t.Fatalf("reset contamination: %+v writes=%d resets=%d %v", r, writes, resets, err)
	}
}
