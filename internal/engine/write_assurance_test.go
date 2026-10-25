package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// These schedules are deterministic: the delayed peer commit is released only
// after Gate returns; interference occurs at the first post-write observation.
// Ground truth is the fixture's peerCommitted flag, not Gate's assessment.
type scheduledWriteTarget struct {
	value         string
	scenario      string
	reads, writes int
	peerCommitted bool
}

func (x *scheduledWriteTarget) Execute(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	if strings.HasSuffix(req.URL, "/record") {
		x.reads++
		if x.reads == 3 && x.scenario == "interference" {
			x.value = "new" // An unrelated writer, never the peer.
		}
		b, _ := json.Marshal(map[string]any{"record": map[string]string{"value": x.value}})
		return model.ExecutionResult{IdentityID: id.ID, StatusCode: 200, Body: b}
	}
	x.writes++
	if id.ID == "owner" || x.scenario == "committed_error" {
		x.value = "new"
	}
	if id.ID == "peer" {
		switch x.scenario {
		case "accepted":
			return model.ExecutionResult{IdentityID: id.ID, StatusCode: 202}
		case "committed_error":
			x.peerCommitted = true
			return model.ExecutionResult{IdentityID: id.ID, Error: "fixture connection closed after commit", ErrorKind: model.ErrorKindNetwork}
		case "delayed_error":
			return model.ExecutionResult{IdentityID: id.ID, Error: "fixture timeout before commit", ErrorKind: model.ErrorKindNetwork}
		}
	}
	return model.ExecutionResult{IdentityID: id.ID, StatusCode: 204}
}

func assuranceCase(t *testing.T, environment string) model.AuthorizationTestCase {
	t.Helper()
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.Identities = append(tc.Identities, model.Identity{ID: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "owner-secret"}})
	tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: "owner", Decision: model.AccessDecisionAllow})
	tc.WriteVerification.ChangedTo = json.RawMessage(`"new"`)
	// Decode through the public JSON contract so this regression can run on the
	// pre-change engine, which silently ignores the new environment setting.
	if err := json.Unmarshal([]byte(`{"environment":"`+environment+`"}`), tc.WriteVerification); err != nil {
		t.Fatal(err)
	}
	return tc
}

func TestWriteEnvironmentSchedules(t *testing.T) {
	for _, tt := range []struct {
		name, environment, scenario, decision, reason string
		findings                                      int
	}{
		{"accepted legacy", "", "accepted", "inconclusive", "write_completion_unconfirmed", 0},
		{"accepted declared synchronous", "synchronous_isolated", "accepted", "inconclusive", "write_completion_unconfirmed", 0},
		{"delayed commit", "unknown", "delayed", "inconclusive", "write_environment_unverified", 0},
		{"delayed after timeout", "unknown", "delayed_error", "inconclusive", "write_execution_error", 0},
		{"concurrent writer", "unknown", "interference", "inconclusive", "write_environment_unverified", 0},
		{"unknown protected", "unknown", "protected", "inconclusive", "write_environment_unverified", 0},
		{"reviewed protected", "synchronous_isolated", "protected", "denied", "state_unchanged", 0},
		{"legacy protected", "", "protected", "denied", "state_unchanged", 0},
		{"committed despite error", "synchronous_isolated", "committed_error", "allowed", "state_changed", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			x := &scheduledWriteTarget{value: "old", scenario: tt.scenario}
			r, err := New(x).Run(context.Background(), assuranceCase(t, tt.environment))
			if err != nil {
				t.Fatal(err)
			}
			if tt.scenario == "delayed" || tt.scenario == "delayed_error" || tt.scenario == "accepted" {
				x.peerCommitted, x.value = true, "new" // Release the queued write.
			}
			a := r.Assessments[0]
			observation, err := json.Marshal(map[string]any{"environment": tt.environment, "scenario": tt.scenario, "peer_committed": x.peerCommitted, "decision": a.Decision, "reason": a.Reason, "findings": len(r.Findings), "reads": x.reads, "writes": x.writes})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("schedule_observation=%s", observation)
			if string(a.Decision) != tt.decision || a.Reason != tt.reason || len(r.Findings) != tt.findings {
				t.Fatalf("peerCommitted=%t, assessment=%+v, findings=%d; want %s/%s, findings=%d", x.peerCommitted, a, len(r.Findings), tt.decision, tt.reason, tt.findings)
			}
			if x.writes > 2 || x.reads > 6 {
				t.Fatalf("unexpected retries: writes=%d reads=%d", x.writes, x.reads)
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"owner-secret", "tok-p", "tok-v"} {
				if strings.Contains(string(b), secret) {
					t.Fatalf("result leaks %q", secret)
				}
			}
		})
	}
}

func TestWriteEnvironmentValidationBeforeTraffic(t *testing.T) {
	tc := assuranceCase(t, "synchronous-isolated-typo")
	x := &scheduledWriteTarget{value: "old"}
	if _, err := New(x).Run(context.Background(), tc); err == nil {
		t.Fatal("unknown environment accepted")
	}
	if x.reads != 0 || x.writes != 0 {
		t.Fatal("invalid environment sent traffic")
	}
}

func TestReviewedEnvironmentRetainsObservedEffectsAfterErrorStatus(t *testing.T) {
	for _, status := range []int{202, 401, 403, 500} {
		tc := assuranceCase(t, "synchronous_isolated")
		x := &stateTarget{value: "old", writeStatus: status, writes: true, writeTo: "new"}
		r, err := New(x).Run(context.Background(), tc)
		if err != nil {
			t.Fatal(err)
		}
		if a := r.Assessments[0]; a.Decision != model.AssessmentAllowed || a.Reason != "state_changed" || len(r.Findings) != 1 {
			t.Fatalf("status %d lost observed peer write: %+v", status, r)
		}
	}
}

func TestUnknownEnvironmentKeepsSpecificVerifierDiagnostics(t *testing.T) {
	for _, tt := range []struct {
		name, reason string
		target       stateTarget
	}{
		{"unavailable", "verifier_read_failed", stateTarget{value: "old", readStatus: []int{503}}},
		{"already present", "target_value_already_present", stateTarget{value: "new"}},
		{"unexpected change", "state_changed_unexpectedly", stateTarget{value: "old", writes: true, writeTo: "unrelated", writeStatus: 204}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(&tt.target).Run(context.Background(), assuranceCase(t, "unknown"))
			if err != nil {
				t.Fatal(err)
			}
			if a := r.Assessments[0]; a.Decision != model.AssessmentInconclusive || a.Reason != tt.reason {
				t.Fatalf("specific diagnostic lost: %+v", a)
			}
		})
	}
}
