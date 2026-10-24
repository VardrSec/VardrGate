package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// stateTarget is a fake API holding one record. The request under test may
// change it; the verifier reads it at /record.
type stateTarget struct {
	value       string
	writeStatus int
	writes      bool // whether the request under test changes value
	writeTo     string
	readStatus  []int // successive verifier statuses; last repeats
	readBody    func(value string) string
	onRead      func(n int, t *stateTarget)
	reads, sent int
}

func (t *stateTarget) Execute(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	if strings.HasSuffix(req.URL, "/record") {
		t.reads++
		if t.onRead != nil {
			t.onRead(t.reads, t)
		}
		status := 200
		if len(t.readStatus) > 0 {
			status = t.readStatus[min(t.reads, len(t.readStatus))-1]
		}
		body := `{"record":{"value":"` + t.value + `"}}`
		if t.readBody != nil {
			body = t.readBody(t.value)
		}
		return model.ExecutionResult{IdentityID: id.ID, StatusCode: status, ObservedOutcome: model.ClassifyOutcome(status, false), Body: []byte(body)}
	}
	t.sent++
	if t.writes {
		t.value = t.writeTo
	}
	return model.ExecutionResult{IdentityID: id.ID, StatusCode: t.writeStatus, ObservedOutcome: model.ClassifyOutcome(t.writeStatus, false)}
}

func verifiedCase(expect model.AccessDecision) model.AuthorizationTestCase {
	return model.AuthorizationTestCase{
		ID:             "write",
		Identities:     []model.Identity{{ID: "peer", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-p"}}},
		Request:        model.RequestTemplate{Method: http.MethodPut, URL: "https://api.example.com/users/alice/email"},
		ExpectedAccess: []model.ExpectedAccess{{IdentityID: "peer", Decision: expect}},
		Mutating:       true,
		WriteVerification: &model.WriteVerification{
			Identity:    model.Identity{ID: "verifier", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-v"}},
			Request:     model.RequestTemplate{URL: "https://api.example.com/record"},
			JSONPointer: "/record/value",
		},
	}
}

func TestWriteVerificationOutcomes(t *testing.T) {
	for _, tt := range []struct {
		name     string
		expect   model.AccessDecision
		target   stateTarget
		changeTo string
		decision model.AssessmentDecision
		reason   string
		sent     int
		findings []model.FindingCategory
	}{
		{name: "unchanged state is a denial", expect: model.AccessDecisionDeny,
			target:   stateTarget{value: "a@x.io", writeStatus: 204},
			decision: model.AssessmentInconclusive, reason: "no_positive_control", sent: 1},
		{name: "a write that took effect before a 500 is access", expect: model.AccessDecisionDeny,
			target:   stateTarget{value: "a@x.io", writeStatus: 500, writes: true, writeTo: "p@x.io"},
			decision: model.AssessmentAllowed, reason: "state_changed", sent: 1, findings: []model.FindingCategory{model.CategoryUnexpectedAccess}},
		{name: "204 that changed only the caller's own record is not access", expect: model.AccessDecisionDeny,
			target:   stateTarget{value: "a@x.io", writeStatus: 204},
			decision: model.AssessmentInconclusive, reason: "no_positive_control", sent: 1},
		{name: "legitimate write", expect: model.AccessDecisionAllow,
			target:   stateTarget{value: "a@x.io", writeStatus: 204, writes: true, writeTo: "new@x.io"},
			decision: model.AssessmentAllowed, reason: "state_changed", sent: 1},
		{name: "legitimate write that did not happen", expect: model.AccessDecisionAllow,
			target:   stateTarget{value: "a@x.io", writeStatus: 204},
			decision: model.AssessmentDenied, reason: "state_unchanged", sent: 1, findings: []model.FindingCategory{model.CategoryAuthorizationMismatch}},
		{name: "before-read fails: request withheld", expect: model.AccessDecisionDeny,
			target:   stateTarget{value: "a@x.io", writeStatus: 204, writes: true, writeTo: "p@x.io", readStatus: []int{503}},
			decision: model.AssessmentInconclusive, reason: "verifier_read_failed", sent: 0},
		{name: "verifier refused", expect: model.AccessDecisionDeny,
			target:   stateTarget{value: "a@x.io", writeStatus: 204, readStatus: []int{401}},
			decision: model.AssessmentInconclusive, reason: "verifier_denied", sent: 0},
		{name: "after-read fails", expect: model.AccessDecisionDeny,
			target:   stateTarget{value: "a@x.io", writeStatus: 204, writes: true, writeTo: "p@x.io", readStatus: []int{200, 200, 500}},
			decision: model.AssessmentInconclusive, reason: "verifier_read_failed", sent: 1},
		{name: "state changing between the two before-reads", expect: model.AccessDecisionDeny,
			target: stateTarget{value: "a@x.io", writeStatus: 204, onRead: func(n int, t *stateTarget) {
				if n == 2 {
					t.value = "someone-else@x.io"
				}
			}},
			decision: model.AssessmentInconclusive, reason: "state_changing_concurrently", sent: 0},
		{name: "target value already present", expect: model.AccessDecisionDeny, changeTo: `"p@x.io"`,
			target:   stateTarget{value: "p@x.io", writeStatus: 204, writes: true, writeTo: "p@x.io"},
			decision: model.AssessmentInconclusive, reason: "target_value_already_present", sent: 0},
		{name: "changed to something other than the attempted value", expect: model.AccessDecisionDeny, changeTo: `"p@x.io"`,
			target:   stateTarget{value: "a@x.io", writeStatus: 204, writes: true, writeTo: "other@x.io"},
			decision: model.AssessmentInconclusive, reason: "state_changed_unexpectedly", sent: 1},
		{name: "changed to the attempted value", expect: model.AccessDecisionDeny, changeTo: `"p@x.io"`,
			target:   stateTarget{value: "a@x.io", writeStatus: 204, writes: true, writeTo: "p@x.io"},
			decision: model.AssessmentAllowed, reason: "state_changed", sent: 1, findings: []model.FindingCategory{model.CategoryUnexpectedAccess}},
		{name: "unreadable value", expect: model.AccessDecisionDeny,
			target:   stateTarget{value: "a@x.io", writeStatus: 204, readBody: func(string) string { return "not json" }},
			decision: model.AssessmentInconclusive, reason: "verifier_value_unavailable", sent: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := verifiedCase(tt.expect)
			if tt.changeTo != "" {
				tc.WriteVerification.ChangedTo = json.RawMessage(tt.changeTo)
			}
			target := tt.target
			res, err := New(&target).Run(context.Background(), tc)
			if err != nil {
				t.Fatal(err)
			}
			a := res.Assessments[0]
			if a.Decision != tt.decision || a.Reason != tt.reason || a.Source != "write_verification" {
				t.Fatalf("assessment = %+v", a)
			}
			if target.sent != tt.sent {
				t.Fatalf("request sent %d times, want %d", target.sent, tt.sent)
			}
			var got []model.FindingCategory
			for _, f := range res.Findings {
				got = append(got, f.Category)
			}
			if len(got) != len(tt.findings) || (len(got) > 0 && got[0] != tt.findings[0]) {
				t.Fatalf("findings = %v, want %v", got, tt.findings)
			}
		})
	}
}

func TestWriteVerificationDetectsDeletion(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.WriteVerification.JSONPointer = "/username"
	deleted := false
	target := &funcExecutor{fn: func(req model.RequestTemplate) model.ExecutionResult {
		if strings.HasSuffix(req.URL, "/record") {
			if deleted {
				return model.ExecutionResult{StatusCode: 404, Body: []byte(`{"status":"fail"}`)}
			}
			return model.ExecutionResult{StatusCode: 200, Body: []byte(`{"username":"carol"}`)}
		}
		deleted = true
		return model.ExecutionResult{StatusCode: 401}
	}}
	res, err := New(target).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if a := res.Assessments[0]; a.Decision != model.AssessmentAllowed || len(res.Findings) != 1 {
		t.Fatalf("a delete answered with 401 that removed the record must be access: %+v, %d findings", a, len(res.Findings))
	}
}

type funcExecutor struct {
	fn func(model.RequestTemplate) model.ExecutionResult
}

func (f *funcExecutor) Execute(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	r := f.fn(req)
	r.IdentityID = id.ID
	r.ObservedOutcome = model.ClassifyOutcome(r.StatusCode, false)
	return r
}

// Verification outranks response assertions and declared deny conventions:
// a write's own response cannot prove its effect.
func TestWriteVerificationOutranksAssertionsAndDenyStatus(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.DenyStatuses = []int{500}
	tc.ExpectedAccess[0].ResponseAssertions = []model.ResponseAssertion{rule("/status", `"fail"`, model.AccessDecisionDeny)}
	target := &stateTarget{value: "a@x.io", writeStatus: 500, writes: true, writeTo: "p@x.io"}
	res, err := New(target).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if a := res.Assessments[0]; a.Source != "write_verification" || a.Decision != model.AssessmentAllowed || len(res.Findings) != 1 {
		t.Fatalf("assessment=%+v findings=%d", a, len(res.Findings))
	}
}

// Observed values never reach the result: not in assessments, evidence or executions.
func TestWriteVerificationNeverEmitsObservedValues(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	target := &stateTarget{value: "victim-private-value", writeStatus: 204, writes: true, writeTo: "attacker-written-value"}
	res, err := New(target).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(res)
	for _, v := range []string{"victim-private-value", "attacker-written-value", "tok-v"} {
		if strings.Contains(string(out), v) {
			t.Fatalf("result contains %q: %s", v, out)
		}
	}
}

func TestWriteVerificationValidation(t *testing.T) {
	for name, mutate := range map[string]func(*model.AuthorizationTestCase){
		"requires mutating":   func(tc *model.AuthorizationTestCase) { tc.Mutating = false },
		"verifier under test": func(tc *model.AuthorizationTestCase) { tc.WriteVerification.Identity.ID = "peer" },
		"verifier without id": func(tc *model.AuthorizationTestCase) { tc.WriteVerification.Identity.ID = "" },
		"cross-origin verifier": func(tc *model.AuthorizationTestCase) {
			tc.WriteVerification.Request.URL = "https://other.example.com/record"
		},
		"unacknowledged POST": func(tc *model.AuthorizationTestCase) { tc.WriteVerification.Request.Method = http.MethodPost },
		"changed_to w/o pointer": func(tc *model.AuthorizationTestCase) {
			tc.WriteVerification.JSONPointer = ""
			tc.WriteVerification.ChangedTo = json.RawMessage(`1`)
		},
		"invalid pointer":         func(tc *model.AuthorizationTestCase) { tc.WriteVerification.JSONPointer = "record" },
		"invalid changed_to":      func(tc *model.AuthorizationTestCase) { tc.WriteVerification.ChangedTo = json.RawMessage(`{`) },
		"bad verifier credential": func(tc *model.AuthorizationTestCase) { tc.WriteVerification.Identity.Credential.Value = "" },
	} {
		t.Run(name, func(t *testing.T) {
			tc := verifiedCase(model.AccessDecisionDeny)
			mutate(&tc)
			target := &stateTarget{value: "a", writeStatus: 204}
			if _, err := New(target).Run(context.Background(), tc); err == nil {
				t.Fatal("expected a validation error")
			}
			if target.reads+target.sent != 0 {
				t.Fatal("requests were sent before validation failed")
			}
		})
	}
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.WriteVerification.Request.Method = http.MethodPost
	tc.WriteVerification.AllowUnsafeMethod = true
	if _, err := New(&stateTarget{value: "a", writeStatus: 204}).Run(context.Background(), tc); err != nil {
		t.Fatalf("acknowledged POST verifier rejected: %v", err)
	}
}

// A shared body across identities: the owner is listed first, as in a typical
// identities file. A vulnerable target lets the peer write too. The peer's
// write must not be hidden by the owner's earlier write of the same value.
func TestWriteVerificationMultipleIdentitiesSharedBody(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.Identities = []model.Identity{
		{ID: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-o"}},
		{ID: "peer", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-p"}},
	}
	tc.ExpectedAccess = []model.ExpectedAccess{
		{IdentityID: "owner", Decision: model.AccessDecisionAllow},
		{IdentityID: "peer", Decision: model.AccessDecisionDeny},
	}
	tc.WriteVerification.ChangedTo = json.RawMessage(`"p@x.io"`)
	target := &stateTarget{value: "a@x.io", writeStatus: 204, writes: true, writeTo: "p@x.io"}
	res, err := New(target).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]model.Assessment{}
	for _, a := range res.Assessments {
		byID[a.IdentityID] = a
	}
	if a := byID["peer"]; a.Decision != model.AssessmentAllowed {
		t.Fatalf("peer's unauthorized write was hidden: %+v", a)
	}
	if a := byID["owner"]; a.Decision != model.AssessmentInconclusive || a.Reason != "target_value_already_present" {
		t.Fatalf("owner after the peer's write must be inconclusive, got %+v", a)
	}
	if len(res.Findings) != 1 || res.Findings[0].IdentityID != "peer" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Executions[0].IdentityID != "owner" || res.Executions[1].IdentityID != "peer" {
		t.Fatal("executions must keep the declared identity order")
	}
}

// Without changed_to, a second writer of the same value would read as
// unchanged. Verifying more than one identity therefore requires it.
func TestWriteVerificationMultipleIdentitiesRequireChangedTo(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	tc.Identities = append(tc.Identities, model.Identity{ID: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-o"}})
	tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: "owner", Decision: model.AccessDecisionAllow})
	if _, err := New(&stateTarget{value: "a", writeStatus: 204}).Run(context.Background(), tc); err == nil {
		t.Fatal("expected a validation error")
	}
}

// A before-read that is not 2xx is not a baseline: a mistyped verifier path
// would otherwise read 404 twice and look like a refused write.
func TestWriteVerificationRequiresSuccessfulBaseline(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	target := &stateTarget{value: "a@x.io", writeStatus: 204, writes: true, writeTo: "p@x.io", readStatus: []int{404}}
	res, err := New(target).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if a := res.Assessments[0]; a.Decision != model.AssessmentInconclusive || a.Reason != "verifier_baseline_missing" {
		t.Fatalf("assessment = %+v", a)
	}
	if target.sent != 0 {
		t.Fatal("the request must be withheld without a baseline")
	}
}
