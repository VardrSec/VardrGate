package engine

import (
	"context"
	"encoding/json"
	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStrictPreflightRequiresEveryAssessedCredential(t *testing.T) {
	tc := preflightTC("https://api.example.com")
	tc.RequireIdentityPreflight = true
	tc.Identities[1].Preflight = nil
	calls := 0
	ex := &funcExecutor{fn: func(model.RequestTemplate) model.ExecutionResult {
		calls++
		return model.ExecutionResult{StatusCode: 200}
	}}
	if _, err := New(ex).Run(context.Background(), tc); err == nil || !strings.Contains(err.Error(), tc.Identities[1].ID) {
		t.Fatalf("missing peer accepted: %v", err)
	}
	if calls != 0 {
		t.Fatal("traffic before validation")
	}
	tc.Identities[1].Credential = model.Credential{Type: model.CredentialTypeStaticHeader}
	if err := Validate(tc); err != nil {
		t.Fatalf("anonymous identity should be exempt: %v", err)
	}
	tc.Identities[1].Credential = model.Credential{Type: model.CredentialTypeBearer, Value: "test"}
	tc.ExpectedAccess[1].Decision = model.AccessDecisionSkip
	if err := Validate(tc); err != nil {
		t.Fatalf("skipped assessment should be exempt: %v", err)
	}
	tc.RequireIdentityPreflight = false
	tc.ExpectedAccess[1].Decision = model.AccessDecisionDeny
	if err := Validate(tc); err != nil {
		t.Fatalf("compatibility changed: %v", err)
	}
	tc.RequireIdentityPreflight = true
	for i := range tc.ExpectedAccess {
		tc.ExpectedAccess[i].Decision = model.AccessDecisionSkip
	}
	if err := Validate(tc); err == nil {
		t.Fatal("strict case tested no expectations")
	}
}

func TestStrictPreflightLivePrincipalChecks(t *testing.T) {
	for _, mode := range []string{"valid", "invalid", "expired", "wrong-user", "soft-denial"} {
		t.Run(mode, func(t *testing.T) {
			var resource atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/session" {
					if mode == "invalid" || mode == "expired" {
						w.WriteHeader(401)
						return
					}
					if mode == "soft-denial" {
						w.Write([]byte(`{"status":"fail"}`))
						return
					}
					who := "user"
					if r.Header.Get("Authorization") == "Bearer tok-a" {
						who = "admin"
					}
					if mode == "wrong-user" {
						who = "someone-else"
					}
					json.NewEncoder(w).Encode(map[string]any{"user": map[string]string{"id": who}, "tenant": "tenant-a"})
					return
				}
				resource.Add(1)
				w.WriteHeader(403)
			}))
			defer srv.Close()
			tc := preflightTC(srv.URL)
			tc.RequireIdentityPreflight = true
			r, err := New(client.NewWithConfig(nil, client.Config{AllowPrivateTargets: true})).Run(context.Background(), tc)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "valid" {
				if r.PreflightFailed() || resource.Load() != 2 {
					t.Fatalf("valid principals not tested: %+v", r)
				}
			} else if !r.PreflightFailed() || resource.Load() != 0 || len(r.Executions) != 0 {
				t.Fatalf("bad principal reached resource: %+v", r)
			}
		})
	}
}
