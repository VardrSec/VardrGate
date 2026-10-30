package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeLiteralJob writes a job whose credential, URL and header all carry a
// ${VAR} reference, and returns its path.
func writeLiteralJob(t *testing.T, url string) string {
	t.Helper()
	job := map[string]any{"config": map[string]any{
		"test_case": map[string]any{
			"id": "literal",
			"identities": []map[string]any{{
				"id":         "owner",
				"credential": map[string]string{"type": "bearer", "value": "resolved-${VARDRGATE_TEST_LITERAL_SECRET}"},
			}},
			"request": map[string]any{
				"method":  "GET",
				"url":     url + "/x?k=${VARDRGATE_TEST_LITERAL_SECRET}",
				"headers": map[string]string{"X-Probe": "${VARDRGATE_TEST_LITERAL_SECRET}"},
			},
			"expected_access": []map[string]string{{"identity_id": "owner", "decision": "allow"}},
		},
		"execution": map[string]any{"allow_private_targets": true},
	}}
	data, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "job.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRun_LiteralJobSendsTheEnvelopeAsWritten(t *testing.T) {
	t.Setenv("VARDRGATE_TEST_LITERAL_SECRET", "gate-environment-value")
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"), r.Header.Get("X-Probe"), r.URL.RawQuery)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "result.json")
	if err := runCases([]string{"--job", writeLiteralJob(t, srv.URL), "--literal-job", "--out", out}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the target was never contacted")
	}
	for _, value := range seen {
		if strings.Contains(value, "gate-environment-value") {
			t.Fatalf("a literal job was expanded from Gate's environment: %q", seen)
		}
	}
	if seen[0] != "Bearer resolved-${VARDRGATE_TEST_LITERAL_SECRET}" {
		t.Errorf("credential = %q, want the resolved value unchanged", seen[0])
	}
}

func TestRun_JobWithoutLiteralFlagStillExpands(t *testing.T) {
	t.Setenv("VARDRGATE_TEST_LITERAL_SECRET", "expanded")
	var (
		mu   sync.Mutex
		auth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "result.json")
	if err := runCases([]string{"--job", writeLiteralJob(t, srv.URL), "--out", out}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if auth != "Bearer resolved-expanded" {
		t.Errorf("credential = %q, want ${VAR} expanded as before", auth)
	}
}

func TestRun_LiteralJobRequiresAJob(t *testing.T) {
	err := runCases([]string{"--cases", "cases.json", "--literal-job"})
	if err == nil || !strings.Contains(err.Error(), "--literal-job requires --job") {
		t.Fatalf("expected --literal-job to be refused with --cases, got %v", err)
	}
}
