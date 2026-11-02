package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/requestguard"
)

type projectionExecutor struct {
	guard *requestguard.Guard
	calls int
	value int
}

func (x *projectionExecutor) Execute(ctx context.Context, identity model.Identity, req model.RequestTemplate) model.ExecutionResult {
	if err := x.guard.Allow(ctx, identity, req); err != nil {
		return model.ExecutionResult{IdentityID: identity.ID, Error: "projection denied", ErrorKind: model.ErrorKindURLValidation}
	}
	x.calls++
	body := `{"value":0}`
	switch req.URL {
	case "https://api.example.test/prepare", "https://api.example.test/reset":
		x.value = 0
	case "https://api.example.test/me":
		body = `{"id":"` + identity.ID + `"}`
	case "https://api.example.test/object":
		if req.Method == "PATCH" && identity.ID == "owner" {
			x.value = 1
		}
		if x.value == 1 {
			body = `{"value":1}`
		}
	}
	return model.ExecutionResult{IdentityID: identity.ID, StatusCode: 200, Body: []byte(body), ObservedOutcome: model.OutcomeAllow}
}

func TestProjectionIncludesSetupPreflightReadbackAndReset(t *testing.T) {
	person := func(id string) model.Identity {
		return model.Identity{ID: id, Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "synthetic-" + id}, Preflight: &model.IdentityPreflight{URL: "https://api.example.test/me", ExpectedStatus: 200, JSONFields: map[string]string{"id": id}}}
	}
	primary := model.RequestTemplate{Method: "PATCH", URL: "https://api.example.test/object", Body: json.RawMessage(`{"value":1}`)}
	reset := model.SetupStep{Name: "reset", As: "owner", Request: model.RequestTemplate{Method: "POST", URL: "https://api.example.test/reset"}}
	tc := model.AuthorizationTestCase{ID: "guarded", Mutating: true, Identities: []model.Identity{person("owner"), person("peer")}, Request: primary,
		Setup:             []model.SetupStep{{Name: "prepare", Request: model.RequestTemplate{Method: "POST", URL: "https://api.example.test/prepare"}}},
		ExpectedAccess:    []model.ExpectedAccess{{IdentityID: "owner", Decision: model.AccessDecisionAllow}, {IdentityID: "peer", Decision: model.AccessDecisionDeny}},
		WriteVerification: &model.WriteVerification{Strategy: "changed", Environment: "synchronous_isolated", Identity: person("reader"), Request: model.RequestTemplate{Method: "GET", URL: primary.URL}, JSONPointer: "/value", ChangedTo: json.RawMessage(`1`), Reset: &reset}}
	p := requestguard.Plan{Schema: "vardr.execution-plan/1", Profile: requestguard.Profile, ToolHash: strings.Repeat("a", 64), CaseHash: strings.Repeat("b", 64), Max: 14}
	p.Execution.Timeout, p.Execution.MaxBytes = 30, 1000
	add := func(phase, id string, req model.RequestTemplate, max int) {
		p.Dispatches = append(p.Dispatches, requestguard.Dispatch{Phase: phase, IdentityID: id, Max: max, Request: requestguard.Request{Method: req.Method, URL: req.URL, Headers: req.Headers, Query: req.QueryParams, Body: req.Body}})
	}
	add("setup", "setup:prepare", tc.Setup[0].Request, 1)
	for _, id := range []string{"owner", "peer", "reader"} {
		add("preflight", id, model.RequestTemplate{Method: "GET", URL: "https://api.example.test/me"}, 1)
	}
	for _, id := range []string{"owner", "peer"} {
		add("resource", id, primary, 1)
	}
	add("verification", "reader", tc.WriteVerification.Request, 6)
	add("reset", "owner", reset.Request, 2)
	g, err := requestguard.New(p)
	if err != nil {
		t.Fatal(err)
	}
	x := &projectionExecutor{guard: g}
	result, err := New(x).Run(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if x.calls != 14 || result.PreflightFailed() || len(result.Inconclusive()) > 0 {
		t.Fatalf("incomplete guarded execution: calls=%d result=%+v", x.calls, result)
	}
}
