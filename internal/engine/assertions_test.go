package engine

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

type bodyExecutor struct {
	result model.ExecutionResult
	calls  int
}

func (e *bodyExecutor) Execute(_ context.Context, id model.Identity, _ model.RequestTemplate) model.ExecutionResult {
	e.calls++
	r := e.result
	r.IdentityID = id.ID
	return r
}

func rule(pointer, value string, decision model.AccessDecision) model.ResponseAssertion {
	return model.ResponseAssertion{JSONPointer: pointer, Equals: json.RawMessage(value), Decision: decision}
}

func TestResponseAssertions(t *testing.T) {
	rules := []model.ResponseAssertion{
		rule("/record/private", `"confidential-value"`, model.AccessDecisionAllow),
		rule("/error/code", `"ACCESS_DENIED"`, model.AccessDecisionDeny),
	}
	for _, tt := range []struct {
		name     string
		status   int
		body     string
		expected model.AccessDecision
		decision model.AssessmentDecision
		reason   string
		findings int
	}{
		{"leak with 403", 403, `{"record":{"private":"confidential-value"}}`, model.AccessDecisionDeny, model.AssessmentAllowed, "assertion_matched", 1},
		{"leak with 404", 404, `{"record":{"private":"confidential-value"}}`, model.AccessDecisionDeny, model.AssessmentAllowed, "assertion_matched", 1},
		{"leak with 500", 500, `{"record":{"private":"confidential-value"}}`, model.AccessDecisionDeny, model.AssessmentAllowed, "assertion_matched", 1},
		{"soft denial", 200, `{"error":{"code":"ACCESS_DENIED"}}`, model.AccessDecisionDeny, model.AssessmentDenied, "assertion_matched", 0},
		{"wrongly denied owner", 200, `{"error":{"code":"ACCESS_DENIED"}}`, model.AccessDecisionAllow, model.AssessmentDenied, "assertion_matched", 1},
		{"authorized data", 200, `{"record":{"private":"confidential-value"}}`, model.AccessDecisionAllow, model.AssessmentAllowed, "assertion_matched", 0},
		{"unmatched 200", 200, `{"record":{"private":"different"}}`, model.AccessDecisionDeny, model.AssessmentInconclusive, "no_assertion_matched", 0},
		{"unmatched 403", 403, `{}`, model.AccessDecisionDeny, model.AssessmentInconclusive, "no_assertion_matched", 0},
		{"conflicting evidence", 200, `{"record":{"private":"confidential-value"},"error":{"code":"ACCESS_DENIED"}}`, model.AccessDecisionDeny, model.AssessmentInconclusive, "conflicting_assertions", 0},
		{"invalid JSON", 200, `not JSON`, model.AccessDecisionDeny, model.AssessmentInconclusive, "invalid_or_unsupported_json", 0},
		{"truncated JSON", 200, `{"record":`, model.AccessDecisionDeny, model.AssessmentInconclusive, "invalid_or_unsupported_json", 0},
		{"duplicate keys", 200, `{"record":{},"record":{"private":"confidential-value"}}`, model.AccessDecisionDeny, model.AssessmentInconclusive, "invalid_or_unsupported_json", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := baseTC()
			tc.Identities = tc.Identities[:1]
			tc.ExpectedAccess = []model.ExpectedAccess{{IdentityID: "admin", Decision: tt.expected, ResponseAssertions: rules}}
			ex := &bodyExecutor{result: model.ExecutionResult{StatusCode: tt.status, ObservedOutcome: model.ClassifyOutcome(tt.status, false), Body: []byte(tt.body)}}
			result, err := New(ex).Run(context.Background(), tc)
			if err != nil {
				t.Fatal(err)
			}
			a := result.Assessments[0]
			if a.Decision != tt.decision || a.Reason != tt.reason || len(result.Findings) != tt.findings {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.Executions[0].ObservedOutcome != model.ClassifyOutcome(tt.status, false) {
				t.Fatal("raw HTTP outcome changed")
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"confidential-value", "ACCESS_DENIED", "/record/private", "tok-a"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("result exposed assertion/body data: %s", encoded)
				}
			}
			for _, f := range result.Findings {
				if f.Confidence != model.ConfidenceHigh {
					t.Error("assertion finding should have high confidence")
				}
			}
		})
	}
}

func TestAssertionsValidateBeforeExecuting(t *testing.T) {
	for _, rules := range [][]model.ResponseAssertion{
		{rule("secret", `1`, model.AccessDecisionAllow)},
		{rule("/bad~2", `1`, model.AccessDecisionAllow)},
		{rule("/bad~", `1`, model.AccessDecisionAllow)},
		{rule("/x", ``, model.AccessDecisionAllow)},
		{rule("/x", `1 2`, model.AccessDecisionAllow)},
		{rule("/x", `{"a":1,"a":2}`, model.AccessDecisionAllow)},
		{rule("/x", `1`, model.AccessDecisionSkip)},
		{rule("/"+strings.Repeat("x", 1024), `1`, model.AccessDecisionAllow)},
		{rule("/x", `"`+strings.Repeat("x", 8192)+`"`, model.AccessDecisionAllow)},
		make([]model.ResponseAssertion, 33),
	} {
		tc := baseTC()
		tc.ExpectedAccess[0].ResponseAssertions = rules
		ex := &bodyExecutor{}
		if _, err := New(ex).Run(context.Background(), tc); err == nil {
			t.Fatal("invalid assertions accepted")
		}
		if ex.calls != 0 {
			t.Fatal("request executed before assertion validation")
		}
	}
}

func TestAssessmentSkipAndExecutionErrors(t *testing.T) {
	for _, kind := range []string{"skip", "missing", "error", "body_limit"} {
		t.Run(kind, func(t *testing.T) {
			tc := baseTC()
			tc.Identities = tc.Identities[:1]
			tc.ExpectedAccess = tc.ExpectedAccess[:1]
			tc.ExpectedAccess[0].ResponseAssertions = []model.ResponseAssertion{rule("/private", `true`, model.AccessDecisionAllow)}
			ex := &bodyExecutor{result: model.ExecutionResult{StatusCode: 200, Body: []byte(`{"private":true}`)}}
			want := model.AssessmentSkipped
			switch kind {
			case "skip":
				tc.ExpectedAccess[0].Decision = model.AccessDecisionSkip
			case "missing":
				tc.ExpectedAccess = nil
			case "error":
				ex.result.Error = "connection failure"
				want = model.AssessmentInconclusive
			case "body_limit":
				ex.result.ErrorKind = model.ErrorKindBodySizeExceeded
				want = model.AssessmentInconclusive
			}
			r, err := New(ex).Run(context.Background(), tc)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Assessments) != 1 || r.Assessments[0].Decision != want || len(r.Findings) != 0 {
				t.Fatalf("unexpected result: %+v", r)
			}
		})
	}
}

func TestPointerAndJSONEquality(t *testing.T) {
	for _, tt := range []struct {
		body, pointer, want string
		match               bool
	}{
		{`{"a/b":{"~key":[null,false,9007199254740993]}}`, "/a~1b/~0key/2", `9007199254740993`, true},
		{`{"id":9007199254740993}`, "/id", `9007199254740992`, false},
		{`{"id":1e0}`, "/id", `1.00`, true},
		{`{"id":-0.00}`, "/id", `0`, true},
		{`{"id":123e10000}`, "/id", `1.23e10002`, true},
		{`{"id":-123.40}`, "/id", `-1234e-1`, true},
		{`{"id":"1"}`, "/id", `1`, false},
		{`{"id":null}`, "/id", `null`, true},
		{`{}`, "/missing", `null`, false},
		{`{"items":[]}`, "/items", `[]`, true},
		{`{"":false}`, "/", `false`, true},
		{`{"b":2,"a":1}`, "", `{"a":1.0,"b":2}`, true},
		{`[true]`, "/0", `true`, true},
		{`[true]`, "/00", `true`, false},
		{`[true]`, "/+0", `true`, false},
		{`[true]`, "/-1", `true`, false},
		{`[true]`, "/1", `true`, false},
		{`[true]`, "/999999999999999999999999", `true`, false},
	} {
		t.Run(tt.body+tt.pointer+tt.want, func(t *testing.T) {
			body, err := decodeAssertionJSON([]byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			want, err := decodeAssertionJSON([]byte(tt.want))
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := pointerTokens(tt.pointer)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := pointerValue(body, tokens)
			if (ok && reflect.DeepEqual(got, want)) != tt.match {
				t.Fatalf("got %v (exists %v), want %v, match %v", got, ok, want, tt.match)
			}
		})
	}
	for _, invalid := range []string{`{} {}`, `{"a":1,"a":1}`, `{"a":{"x":1,"x":2}}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), "1e" + strings.Repeat("9", 129), string([]byte{'"', 255, '"'})} {
		if _, err := decodeAssertionJSON([]byte(invalid)); err == nil {
			t.Fatalf("accepted invalid/unsupported JSON")
		}
	}
}

func TestAssertionRulesAreIdentityScoped(t *testing.T) {
	tc := baseTC()
	tc.ExpectedAccess[0].ResponseAssertions = []model.ResponseAssertion{rule("/owner", `"alice"`, model.AccessDecisionAllow)}
	tc.ExpectedAccess[1].ResponseAssertions = []model.ResponseAssertion{rule("/owner", `"bob"`, model.AccessDecisionAllow)}
	ex := &bodyExecutor{result: model.ExecutionResult{StatusCode: 200, Body: []byte(`{"owner":"alice"}`)}}
	r, err := New(ex).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if r.Assessments[0].Decision != model.AssessmentAllowed || r.Assessments[1].Decision != model.AssessmentInconclusive || len(r.Findings) != 0 {
		t.Fatalf("rules crossed identity boundaries: %+v", r)
	}
}
