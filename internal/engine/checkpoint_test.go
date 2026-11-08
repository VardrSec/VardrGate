package engine

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func TestCheckpointCopyDoesNotChangeHealthyEvaluation(t *testing.T) {
	tc := model.AuthorizationTestCase{ID: "checkpoint", Request: model.RequestTemplate{Method: "GET", URL: "https://api.example.test/resource"}}
	for _, id := range []string{"owner", "peer"} {
		tc.Identities = append(tc.Identities, model.Identity{ID: id, Credential: model.Credential{Type: model.CredentialTypeStaticHeader}})
		tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: id, Decision: model.AccessDecisionAllow})
	}
	requests := 0
	x := interruptionExecutor{fn: func(context.Context, model.Identity, model.RequestTemplate) model.ExecutionResult {
		requests++
		return model.ExecutionResult{StatusCode: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{"public":true}`)}
	}}
	want, err := New(x).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	got, err := New(x).RunWithCheckpoint(context.Background(), tc, func(value Result) error {
		writes++
		if value.Error != "execution_in_progress" || len(value.Executions) != 2 || len(value.Assessments) != 2 || len(value.Findings) != 0 {
			t.Fatal("invalid progress shape")
		}
		for i := range value.Executions {
			ex := &value.Executions[i]
			if ex.Body != nil {
				t.Fatal("checkpoint retained a response value")
			}
			if ex.Headers != nil {
				ex.Headers["Content-Type"] = "changed"
			}
			if ex.ResponseProfile != nil && len(ex.ResponseProfile.Fields) > 0 {
				ex.ResponseProfile.Fields[0] = "changed"
			}
		}
		return nil
	})
	if err != nil || writes != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("checkpoint changed healthy evaluation: %v", err)
	}
	writes = 0
	requests = 0
	_, err = New(x).RunWithCheckpoint(context.Background(), tc, func(Result) error { writes++; return context.Canceled })
	if err == nil || !strings.Contains(err.Error(), "checkpoint unavailable") || writes != 1 || requests != 0 {
		t.Fatal("failed checkpoint did not fail closed")
	}
}

func TestCheckpointPendingWriteDoesNotAssertEffect(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	completed := map[string]model.ExecutionResult{
		tc.Identities[0].ID: {IdentityID: tc.Identities[0].ID, StatusCode: 204, ObservedOutcome: model.OutcomeAllow},
	}
	value := checkpointResult(tc, nil, completed)
	if value.Error != "execution_in_progress" || len(value.Findings) != 0 {
		t.Fatal("pending write claimed a final finding")
	}
	for _, assessment := range value.Assessments {
		if assessment.Decision != model.AssessmentInconclusive || assessment.Source != "none" || assessment.Reason != "execution_in_progress" || assessment.WriteVerification != "inconclusive" {
			t.Fatal("pending write claimed a verified effect")
		}
	}
}
