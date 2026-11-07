package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/job"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/requestguard"
)

// This is an ordinary local HTTP cancellation fixture, not an OS-signal or
// containment test. The projection binds the actual test executable as Runner
// binds the installed Gate binary.
func managedCancelJob(t *testing.T, base string, mode string) ([]string, string) {
	t.Helper()
	tc := model.AuthorizationTestCase{ID: "cancel-fixture", Request: model.RequestTemplate{Method: "GET", URL: base + "/resource?token=query-private-sentinel"}}
	for _, id := range []string{"owner", "peer", "anonymous"} {
		tc.Identities = append(tc.Identities, model.Identity{ID: id, Credential: model.Credential{Type: model.CredentialTypeStaticHeader, Header: "X-Identity", Value: id + "-credential-private-sentinel"}})
		tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: id, Decision: model.AccessDecisionAllow})
	}
	if mode == "setup" || mode == "setup_failure" {
		tc.Setup = []model.SetupStep{{Name: "prepare", Request: model.RequestTemplate{Method: "GET", URL: base + "/setup?token=query-private-sentinel"}}}
	}
	if mode == "preflight" {
		tc.Identities[0].Preflight = &model.IdentityPreflight{URL: base + "/session", ExpectedStatus: 200, JSONFields: map[string]string{"subject": "owner"}}
	}
	if mode == "checkpoint" {
		for i := 0; i < 2; i++ {
			id := tc.Identities[i].ID
			tc.Identities[i].Preflight = &model.IdentityPreflight{URL: base + "/session/" + id, ExpectedStatus: 200, JSONFields: map[string]string{"subject": id}}
		}
	}
	if mode == "invalid" {
		tc.Identities[0].Credential.Type = "invalid"
	}
	env := job.Envelope{Config: job.Config{TestCase: tc, Execution: job.Execution{TimeoutSeconds: 10, MaxResponseBytes: 1000, AllowPrivateTargets: true}}}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	// Credential.Value is deliberately excluded by the production marshaler.
	// Add literal fixture credentials only to the private input envelope.
	var input map[string]any
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	identities := input["config"].(map[string]any)["test_case"].(map[string]any)["identities"].([]any)
	for i, id := range tc.Identities {
		identities[i].(map[string]any)["credential"].(map[string]any)["value"] = id.Credential.Value
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tool, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(tool)
	plan := requestguard.Plan{Schema: "vardr.execution-plan/1", Profile: requestguard.Profile, ToolHash: hex.EncodeToString(h[:]), CaseHash: strings.Repeat("a", 64)}
	plan.Execution.Timeout, plan.Execution.MaxBytes, plan.Execution.AllowPrivate = 10, 1000, true
	appendDispatch := func(phase, id string, req model.RequestTemplate) {
		plan.Dispatches = append(plan.Dispatches, requestguard.Dispatch{Phase: phase, IdentityID: id, Max: 1, Request: requestguard.Request{Method: req.Method, URL: req.URL}})
		plan.Max++
	}
	for _, step := range tc.Setup {
		appendDispatch("setup", "setup:"+step.Name, step.Request)
	}
	for _, id := range tc.Identities {
		if id.Preflight != nil {
			appendDispatch("preflight", id.ID, model.RequestTemplate{Method: "GET", URL: id.Preflight.URL})
		}
		appendDispatch("resource", id.ID, tc.Request)
	}
	dir := t.TempDir()
	for name, value := range map[string]any{"job.json": input, "guard.json": plan} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "result.json")
	return []string{"--job", filepath.Join(dir, "job.json"), "--literal-job", "--request-guard", filepath.Join(dir, "guard.json"), "--out", out}, out
}

func TestManagedCancellationRetainsPartialEvidence(t *testing.T) {
	for _, mode := range []string{"partial", "before_dispatch", "setup", "preflight"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := requests.Add(1)
				if mode == "partial" && count == 1 {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"private":"response-private-sentinel"}`))
					return
				}
				cancel()
				<-r.Context().Done()
			}))
			defer srv.Close()
			args, out := managedCancelJob(t, srv.URL, mode)
			if mode == "before_dispatch" {
				cancel()
			}
			stdout, err := captureStdout(t, func() error { return runCasesContext(ctx, args) })
			if stdout != "" {
				t.Fatal("managed --out wrote stdout")
			}
			code, reached := exitNotExecuted, int32(1)
			if mode == "partial" {
				code, reached = exitInconclusive, 2
			} else if mode == "before_dispatch" {
				reached = 0
			}
			if exitCode(t, err) != code || requests.Load() != reached {
				t.Fatalf("exit=%v requests=%d; want exit=%d requests=%d", err, requests.Load(), code, reached)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var result engine.Result
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.TestCaseID != "cancel-fixture" || result.Error != "execution_cancelled" || result.Executions == nil || result.Findings == nil || result.Assessments == nil || len(result.Findings) != 0 {
				t.Fatalf("invalid interrupted result: %s", data)
			}
			for _, secret := range []string{"query-private-sentinel", "credential-private-sentinel", "response-private-sentinel"} {
				if strings.Contains(string(data), secret) {
					t.Fatal("partial evidence contains a private fixture value")
				}
			}
			if mode == "partial" {
				if len(result.Executions) != 3 || result.Executions[0].StatusCode != 200 || result.Assessments[0].Decision != model.AssessmentAllowed {
					t.Fatal("completed first observation was discarded")
				}
				for _, a := range result.Assessments[1:] {
					if a.Decision != model.AssessmentInconclusive {
						t.Fatal("interrupted identity was presented as judged")
					}
				}
			} else if mode == "setup" && (len(result.Executions) != 0 || len(result.Assessments) != 0) {
				t.Fatal("interrupted setup fabricated resource evidence")
			} else if mode == "preflight" && (len(result.Executions) != 0 || !result.PreflightFailed()) {
				t.Fatal("interrupted preflight did not withhold resource work")
			}
			info, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatal("guarded output is not private")
			}
			if files, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".vardrgate-result-*")); len(files) != 0 {
				t.Fatal("completed publication left temporary files")
			}
		})
	}
}

func TestManagedCancellationDoesNotConcealInputOrSetupFailure(t *testing.T) {
	for _, mode := range []string{"invalid", "setup_failure", "complete"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "setup_failure" {
					w.WriteHeader(503)
					return
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			args, out := managedCancelJob(t, srv.URL, mode)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "invalid" {
				cancel()
			}
			err := runCasesContext(ctx, args)
			if mode == "complete" {
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(out)
				if err != nil || strings.Contains(string(data), `"error"`) {
					t.Fatal("healthy managed result changed or was labelled cancelled")
				}
			} else {
				if err == nil || strings.Contains(err.Error(), "managed execution interrupted") {
					t.Fatal("input/setup failure was concealed as cancellation")
				}
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Fatal("ordinary input/setup failure emitted an interrupted artifact")
				}
			}
		})
	}
}

func TestManagedOutputPublicationPreservesDestinationOnFailure(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "result.json")
	if err := os.WriteFile(out, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(out, make(chan int)); err == nil {
		t.Fatal("unencodable output was accepted")
	}
	if data, _ := os.ReadFile(out); string(data) != "retained" {
		t.Fatal("encoding failure truncated retained destination")
	}
	if err := writeJSONAtomic(dir, map[string]string{"status": "partial"}); err == nil {
		t.Fatal("directory destination was replaced")
	}
	if files, _ := filepath.Glob(filepath.Join(dir, ".vardrgate-result-*")); len(files) != 0 {
		t.Fatal("failed rename left temporary files")
	}
	if err := writeJSONAtomic(out, map[string]string{"status": "partial"}); err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	data, _ := os.ReadFile(out)
	if err := json.Unmarshal(data, &result); err != nil || result["status"] != "partial" {
		t.Fatal("complete JSON was not published")
	}
}
