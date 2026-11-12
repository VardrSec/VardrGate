package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/scaffold"
)

// This is a disposable, synchronous fixture, not a production authentication
// service. Only the paired deliberately vulnerable mode omits policy checks.
type authorizationFixture struct {
	mu         sync.Mutex
	vulnerable bool
	state      string
	attempts   int
	requests   int
}

func (f *authorizationFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	w.Header().Set("Content-Type", "application/json")
	actor := "anonymous"
	for _, id := range []string{"owner", "peer", "outsider", "admin", "reader"} {
		if r.Header.Get("Authorization") == "Bearer fixture-"+id {
			actor = id
		}
	}
	deny := func() {
		status := http.StatusForbidden
		if actor == "anonymous" {
			status = http.StatusUnauthorized
		}
		w.WriteHeader(status)
		fmt.Fprint(w, `{"access":"denied"}`)
	}
	if r.URL.Path == "/me" && r.Method == http.MethodGet {
		if actor == "anonymous" {
			deny()
			return
		}
		role, tenant := "user", "A"
		if actor == "admin" {
			role = "admin"
		}
		if actor == "outsider" {
			tenant = "B"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": actor, "role": role, "tenant": tenant})
		return
	}
	if r.URL.Path == "/invoice/reset" && r.Method == http.MethodPost {
		if actor != "owner" {
			deny()
			return
		}
		var body struct{ State string }
		if json.NewDecoder(r.Body).Decode(&body) != nil || (body.State != "draft" && body.State != "approved") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.state = body.State
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path == "/invoice" && r.Method == http.MethodGet {
		if actor != "reader" {
			deny()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"state": f.state})
		return
	}
	f.attempts++
	if r.URL.Path == "/invoice/publish" && r.Method == http.MethodPost {
		if actor != "owner" && !(actor == "peer" && (f.vulnerable || f.state == "approved")) {
			deny()
			return
		}
		f.state = "published"
		if f.vulnerable && actor == "peer" {
			// The mutation committed despite the error response. The separate
			// reader, not this status code, must establish the observed access.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	allowed := false
	if r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/records/1":
			allowed = f.vulnerable || actor == "owner"
		case "/tenants/A/records/1":
			allowed = f.vulnerable || actor == "owner" || actor == "peer"
		case "/admin/export":
			allowed = f.vulnerable || actor == "admin"
		default:
			http.NotFound(w, r)
			return
		}
	}
	if !allowed {
		deny()
		return
	}
	fmt.Fprint(w, `{"access":"allowed","record_id":"1","tenant_id":"A"}`)
}

func TestCompactAuthorizationCases(t *testing.T) {
	data, err := os.ReadFile("../../examples/authorization-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []model.AuthorizationTestCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 6 {
		t.Fatalf("expected six reviewed runnable cases, got %d", len(cases))
	}
	unsupported, err := os.ReadFile("../../examples/authorization-unsupported.json")
	if err != nil {
		t.Fatal(err)
	}
	var unsupportedCases []model.AuthorizationTestCase
	if err := json.Unmarshal(unsupported, &unsupportedCases); err != nil || len(unsupportedCases) != 1 {
		t.Fatalf("one explicit unsupported contract required: %v", err)
	}
	cases = append(cases, unsupportedCases...)
	for _, id := range []string{"owner", "peer", "outsider", "admin", "reader"} {
		t.Setenv("AUTHCASE_"+strings.ToUpper(id)+"_TOKEN", "fixture-"+id)
	}
	t.Setenv("AUTHCASE_EXPIRED_TOKEN", "fixture-expired")
	for _, mode := range []string{"vulnerable", "fixed"} {
		t.Run(mode, func(t *testing.T) {
			fixture := &authorizationFixture{vulnerable: mode == "vulnerable", state: "draft"}
			srv := httptest.NewServer(fixture)
			defer srv.Close()
			t.Setenv("AUTHCASE_URL", srv.URL)
			for _, tc := range cases {
				t.Run(tc.ID, func(t *testing.T) {
					dir := t.TempDir()
					input, output := filepath.Join(dir, "cases.json"), filepath.Join(dir, "result.json")
					unresolved, err := scaffold.MarshalCases([]model.AuthorizationTestCase{tc})
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(input, unresolved, 0600); err != nil {
						t.Fatal(err)
					}
					before := fixture.attemptCount()
					requestsBefore := fixture.requestCount()
					runErr := runCases([]string{"--cases", input, "--out", output, "--allow-private-targets", "--fail-on", "high", "--fail-on-inconclusive"})
					if tc.ID == "unverified-write-environment" {
						if runErr == nil || !strings.Contains(runErr.Error(), "explicit verification strategy requires environment synchronous_isolated") {
							t.Fatalf("unsupported contract was not refused: %v", runErr)
						}
						if _, err := os.Stat(output); !os.IsNotExist(err) || fixture.requestCount() != requestsBefore {
							t.Fatal("unsupported contract produced a result or sent traffic")
						}
						for _, expected := range tc.ExpectedAccess {
							t.Logf("identity=%s expected=%s observed=not executed support=unsupported explicit change/reset with unknown timing/isolation; validation refused", expected.IdentityID, expected.Decision)
						}
						return
					}
					code := exitCode(t, runErr)
					data, err := os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
					var results []engine.Result
					if err := json.Unmarshal(data, &results); err != nil || len(results) != 1 {
						t.Fatalf("one ordinary Gate result required: %v", err)
					}
					result := results[0]
					wantExit := 0
					uncertain := tc.ID == "credential-failure"
					if uncertain {
						wantExit = 3
					} else if mode == "vulnerable" && tc.ID != "approved-publish" {
						wantExit = 2
					}
					if code != wantExit {
						t.Fatalf("CLI exit %d, expected %d: %s", code, wantExit, data)
					}
					if result.InputDigest == "" || len(result.Assessments) != len(tc.ExpectedAccess) {
						t.Fatal("missing source binding or identity assessments")
					}
					expectations := make(map[string]model.AccessDecision)
					for _, expected := range tc.ExpectedAccess {
						expectations[expected.IdentityID] = expected.Decision
					}
					for _, a := range result.Assessments {
						expected, ok := expectations[a.IdentityID]
						if !ok || a.ExpectedAccess != expected {
							t.Fatalf("assessment does not match reviewed policy: %+v", a)
						}
						delete(expectations, a.IdentityID)
						want := model.AssessmentDenied
						if uncertain {
							want = model.AssessmentInconclusive
						} else if a.ExpectedAccess == model.AccessDecisionAllow || mode == "vulnerable" {
							want = model.AssessmentAllowed
						}
						if a.Decision != want {
							t.Fatalf("%s expected=%s observed=%s, want observed=%s (%s)", a.IdentityID, a.ExpectedAccess, a.Decision, want, a.Reason)
						}
						t.Logf("identity=%s expected=%s observed=%s reason=%s verification=%s", a.IdentityID, a.ExpectedAccess, a.Decision, a.Reason, a.WriteVerification)
						if tc.WriteVerification != nil {
							if a.Verification == nil || a.Verification.ReaderIdentityID != "reader" || a.Verification.ResetStatus != 204 || (a.WriteVerification != "verified_effect" && a.WriteVerification != "verified_no_effect") {
								t.Fatalf("missing separate-reader/reset/effect evidence: %+v", a)
							}
						}
					}
					if tc.ID == "credential-failure" {
						if !result.PreflightFailed() || len(result.Executions) != 0 || fixture.attemptCount() != before {
							t.Fatal("failed credential reached the resource")
						}
						for _, p := range result.Preflight {
							if p.IdentityID == "owner" && p.Status != "passed" {
								t.Fatal("owner control credential did not pass")
							}
							if p.IdentityID == "peer" && (p.Status != "failed" || p.StatusCode != 401 || p.Reason != "credential_rejected") {
								t.Fatalf("expired credential not identified: %+v", p)
							}
						}
					}
					if wantExit != 2 && len(result.Findings) != 0 {
						t.Fatalf("control produced findings: %+v", result.Findings)
					}
					if wantExit == 2 {
						category := map[string]model.FindingCategory{"ownership": model.CategoryPotentialBOLA, "tenant": model.CategoryCrossTenantAccess, "privileged-function": model.CategoryPrivilegeEscalation, "draft-publish": model.CategoryUnexpectedAccess}[tc.ID]
						actor := "peer"
						if tc.ID == "tenant" {
							actor = "outsider"
						}
						found := false
						for _, finding := range result.Findings {
							found = found || (finding.IdentityID == actor && finding.Category == category)
						}
						if !found {
							t.Fatalf("missing %s candidate for %s: %+v", category, actor, result.Findings)
						}
					}
					if tc.ID == "draft-publish" && mode == "vulnerable" {
						for _, ex := range result.Executions {
							if ex.IdentityID == "peer" && ex.StatusCode != 500 {
								t.Fatal("missing committed-write/error-response control")
							}
						}
					}
					for _, id := range []string{"owner", "peer", "outsider", "admin", "reader", "expired"} {
						if strings.Contains(string(data), "fixture-"+id) {
							t.Fatal("credential leaked into result")
						}
					}
				})
			}
		})
	}
}

func (f *authorizationFixture) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

func (f *authorizationFixture) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}
