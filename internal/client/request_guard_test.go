package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/requestguard"
)

func TestGuardRefusesChangedRequestAndReplayBeforeTargetTraffic(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	plan := requestguard.Plan{
		Schema: "vardr.execution-plan/1", Profile: requestguard.Profile,
		ToolHash: strings.Repeat("a", 64), CaseHash: strings.Repeat("b", 64), Max: 1,
		Dispatches: []requestguard.Dispatch{{Phase: "resource", IdentityID: "owner", Max: 1,
			Request: requestguard.Request{Method: "GET", URL: server.URL + "/approved"}}},
	}
	plan.Execution.Timeout, plan.Execution.MaxBytes = 30, 1000
	guard, err := requestguard.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	client := NewWithConfig(nil, Config{AllowPrivateTargets: true, RequestGuard: guard})
	ctx := requestguard.WithPhase(context.Background(), "resource")
	actor := model.Identity{ID: "owner"}
	request := model.RequestTemplate{Method: "GET", URL: server.URL + "/outside"}
	if result := client.Execute(ctx, actor, request); result.Error != "authorization request projection denied" || calls.Load() != 0 {
		t.Fatal("changed request reached the target")
	}
	request.URL = server.URL + "/approved"
	if result := client.Execute(ctx, actor, request); result.Error != "" || calls.Load() != 1 {
		t.Fatal("approved dispatch failed")
	}
	if result := client.Execute(ctx, actor, request); result.Error == "" || calls.Load() != 1 {
		t.Fatal("replayed dispatch reached the target")
	}
}

// projectionTransport observes requests without opening a socket or resolving DNS.
type projectionTransport func(*http.Request) (*http.Response, error)

func (f projectionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDuplicateJSONDeniedBeforeTransport(t *testing.T) {
	for _, tc := range []struct{ name, approved, duplicate string }{
		{"root", `{"role":"reader"}`, `{"role":"admin","role":"reader"}`},
		{"nested", `{"user":{"role":"reader"}}`, `{"user":{"role":"admin","role":"reader"}}`},
		{"array", `[{"role":"reader"}]`, `[{"role":"admin","role":"reader"}]`},
		{"escaped", `{"role":"reader"}`, `{"role":"admin","\u0072ole":"reader"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var sent string
			transport := projectionTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				data, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				sent = string(data)
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			plan := requestguard.Plan{
				Schema: "vardr.execution-plan/1", Profile: requestguard.Profile,
				ToolHash: strings.Repeat("a", 64), CaseHash: strings.Repeat("b", 64), Max: 1,
				Dispatches: []requestguard.Dispatch{{Phase: "resource", IdentityID: "owner", Max: 1,
					Request: requestguard.Request{Method: "POST", URL: "https://api.example.test/approved", Body: json.RawMessage(tc.approved)}}},
			}
			plan.Execution.Timeout, plan.Execution.MaxBytes = 30, 1000
			guard, err := requestguard.New(plan)
			if err != nil {
				t.Fatal(err)
			}
			c := NewWithConfig(&http.Client{Transport: transport}, Config{RequestGuard: guard})
			ctx := requestguard.WithPhase(context.Background(), "resource")
			actor := model.Identity{ID: "owner"}
			req := model.RequestTemplate{Method: "POST", URL: plan.Dispatches[0].Request.URL, Body: json.RawMessage(tc.duplicate)}
			if result := c.Execute(ctx, actor, req); result.Error != "authorization request projection denied" || result.ErrorKind != model.ErrorKindURLValidation || result.ObservedOutcome != model.OutcomeError || calls != 0 {
				t.Fatal("duplicate body was not denied before transport")
			}
			req.Body = json.RawMessage(tc.approved)
			if result := c.Execute(ctx, actor, req); result.Error != "" || calls != 1 || sent != tc.approved {
				t.Fatal("valid subsequent dispatch failed")
			}
			if result := c.Execute(ctx, actor, req); result.Error == "" || calls != 1 {
				t.Fatal("dispatch limit changed")
			}
			unguarded := NewWithConfig(&http.Client{Transport: transport}, Config{})
			req.Body = json.RawMessage(tc.duplicate)
			if result := unguarded.Execute(ctx, actor, req); result.Error != "" || calls != 2 || sent != tc.duplicate {
				t.Fatal("unguarded raw body behavior changed")
			}
		})
	}
}
