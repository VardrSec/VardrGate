package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSuiteStrictGatePrecedence(t *testing.T) {
	for _, tt := range []struct {
		name         string
		strict, fail bool
		flags        []string
		code         int
		blocked      bool
	}{
		{name: "missing preflight blocks", strict: true, blocked: true},
		{name: "explicit false overrides strict", strict: true, flags: []string{"--strict-identity-preflight=false"}},
		{name: "suite fails unknown", fail: true, code: 4},
		{name: "explicit false overrides fail", fail: true, flags: []string{"--fail-on-inconclusive=false"}},
		{name: "explicit true overrides compatibility", flags: []string{"--fail-on-inconclusive"}, code: 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(404) }))
			defer srv.Close()
			dir := t.TempDir()
			files := map[string]string{"p.yaml": "api:\n  endpoint: GET /private\nexpect:\n  peer: deny\n", "ids.json": `[{"id":"peer","role":"peer","credential":{"type":"bearer","value":"test"}}]`, "suite.yaml": fmt.Sprintf("base: %s\nidentities: ids.json\nrequire_identity_preflight: %t\nfail_on_inconclusive: %t\npolicies:\n  - policy: p.yaml\n", srv.URL, tt.strict, tt.fail)}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{"--suite", filepath.Join(dir, "suite.yaml"), "--allow-private-targets", "--out", filepath.Join(dir, "result.json")}, tt.flags...)
			err := runPolicy(append([]string{"run"}, args...))
			if tt.blocked {
				if err == nil || !strings.Contains(err.Error(), "requires a declared principal preflight") || requests.Load() != 0 {
					t.Fatalf("strict validation failed: %v requests=%d", err, requests.Load())
				}
				return
			}
			if tt.code == 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var ex exitError
				if !errors.As(err, &ex) || ex.code != tt.code {
					t.Fatalf("expected exit %d, got %v", tt.code, err)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "result.json")); err != nil {
				t.Fatal("diagnostics not written")
			}
		})
	}
}
