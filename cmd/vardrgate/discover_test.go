package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const discoverSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "T", "version": "1"},
  "paths": {"/users/{user_id}": {"get": {"operationId": "getUser"}}}
}`

func TestRunDiscover_WritesDraftsThatCannotRun(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, []byte(discoverSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "policies")

	if err := runDiscover([]string{"--spec", specPath, "--out", outDir}); err != nil {
		t.Fatalf("discover: %v", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 draft, got %d", len(entries))
	}
	body, err := os.ReadFile(filepath.Join(outDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "TODO") {
		t.Errorf("draft has no placeholder:\n%s", body)
	}
	if !strings.HasSuffix(entries[0].Name(), ".policy.yaml") {
		t.Errorf("unexpected filename %q", entries[0].Name())
	}
}

func TestRunDiscover_RequiresASpec(t *testing.T) {
	if err := runDiscover(nil); err == nil {
		t.Error("expected an error when --spec is missing")
	}
}

func TestRunDiscover_ReportsWhenNothingIsDraftable(t *testing.T) {
	// A spec whose operations take no path parameter has no object-level
	// control to draft; saying so beats writing zero files silently.
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")
	spec := `{"openapi":"3.0.0","info":{"title":"T","version":"1"},"paths":{"/health":{"get":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runDiscover([]string{"--spec", specPath})
	if err == nil || !strings.Contains(err.Error(), "no object-level control") {
		t.Fatalf("got %v, want an explanatory error", err)
	}
}

func TestSplitRoles(t *testing.T) {
	got := splitRoles(" owner , other_user ,, anonymous ")
	want := []string{"owner", "other_user", "anonymous"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
