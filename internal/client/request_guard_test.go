package client

import (
	"context"
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
