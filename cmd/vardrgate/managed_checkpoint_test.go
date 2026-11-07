package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/job"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/requestguard"
)

// Read the actual atomic file while ordinary HTTP is still active; no OS signal,
// process-control exercise or final-output write is needed to establish this witness.
func TestManagedCheckpointPrecedesResourceAndHealthyFinal(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(fmt.Sprint(interrupted), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var output atomic.Value
			var resources, witnessed atomic.Int32
			var invalid atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/session/") {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"subject": strings.TrimPrefix(r.URL.Path, "/session/")})
					return
				}
				n := resources.Add(1)
				data, err := os.ReadFile(output.Load().(string))
				var progress engine.Result
				if err != nil || json.Unmarshal(data, &progress) != nil || progress.Error != "execution_in_progress" || len(progress.Preflight) != 2 || len(progress.Executions) != 3 || len(progress.Assessments) != 3 || len(progress.Findings) != 0 {
					invalid.Store(true)
				} else {
					for i, ex := range progress.Executions {
						if int32(i) >= n-1 && (ex.Error != "execution_in_progress" || progress.Assessments[i].Decision != model.AssessmentInconclusive) {
							invalid.Store(true)
						}
					}
					for _, private := range []string{"query-private-sentinel", "credential-private-sentinel", "response-private-sentinel"} {
						if strings.Contains(string(data), private) {
							invalid.Store(true)
						}
					}
					witnessed.Add(1)
				}
				if interrupted {
					cancel()
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"private":"response-private-sentinel"}`))
			}))
			defer srv.Close()
			args, path := managedCancelJob(t, srv.URL, "checkpoint")
			literal, loadErr := job.LoadLiteral(args[1])
			plan, planErr := requestguard.Load(args[4])
			if loadErr != nil || planErr != nil {
				t.Fatal("fixture input did not load")
			}
			guard, guardErr := requestguard.New(plan)
			if guardErr != nil {
				t.Fatal("fixture projection refused")
			}
			for _, identity := range literal.TestCase().Identities {
				if identity.Preflight != nil && guard.Allow(requestguard.WithPhase(ctx, "preflight"), identity, model.RequestTemplate{Method: "GET", URL: identity.Preflight.URL}) != nil {
					t.Fatal("fixture preflight projection refused")
				}
			}
			output.Store(path)
			stdout, err := captureStdout(t, func() error { return runCasesContext(ctx, args) })
			data, readErr := os.ReadFile(path)
			var final engine.Result
			_ = json.Unmarshal(data, &final)
			if stdout != "" || invalid.Load() || witnessed.Load() != resources.Load() || witnessed.Load() == 0 {
				t.Fatalf("checkpoint missing before dispatch: resources=%d witnesses=%d invalid=%t preflight=%v error=%v", resources.Load(), witnessed.Load(), invalid.Load(), final.Preflight, err)
			}
			if readErr != nil || json.Unmarshal(data, &final) != nil || final.Error == "execution_in_progress" {
				t.Fatal("checkpoint survived final output")
			}
			if interrupted {
				if exitCode(t, err) != exitNotExecuted || resources.Load() != 1 || final.Error != "execution_cancelled" {
					t.Fatal("interrupted completion changed")
				}
			} else if err != nil || resources.Load() != 3 || final.Error != "" || len(final.Executions) != 3 {
				t.Fatal("healthy final completion changed")
			}
		})
	}
}
