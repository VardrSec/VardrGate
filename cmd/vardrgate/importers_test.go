package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

const miniSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Mini", "version": "1.0"},
  "paths": {
    "/users/{id}": {
      "get": {"operationId": "getUser", "summary": "Read a user"}
    }
  }
}`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The whole point of the gen → run loop: what gen writes must be something run
// can read back.
func TestGenTestCases_OutputIsRunnableInput(t *testing.T) {
	specPath := writeTemp(t, "spec.json", miniSpec)
	outPath := filepath.Join(t.TempDir(), "cases.json")

	if err := genTestCases([]string{"--spec", specPath, "--base", "https://api.example.com", "--out", outPath}); err != nil {
		t.Fatalf("gen: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read generated cases: %v", err)
	}
	if !strings.Contains(string(raw), "${VARDRGATE_AUTHENTICATED_TOKEN}") {
		t.Errorf("generated file has no credential placeholder:\n%s", raw)
	}

	t.Setenv("VARDRGATE_AUTHENTICATED_TOKEN", "a-token")
	cases, err := loadCases(outPath)
	if err != nil {
		t.Fatalf("generated file is not loadable by run --cases: %v", err)
	}
	if len(cases) != 1 || cases[0].ID != "getUser" {
		t.Fatalf("unexpected cases: %+v", cases)
	}
	if got := cases[0].Identities[0].Credential.Value; got != "a-token" {
		t.Errorf("placeholder was not resolved: %q", got)
	}
	if err := validateSuite(cases, genScaffoldHint); err != nil {
		t.Errorf("a generated suite with credentials set must validate: %v", err)
	}
}

func TestGenTestCases_RequiresExactlyOneSource(t *testing.T) {
	if err := genTestCases(nil); err == nil {
		t.Error("expected an error when neither --spec nor --postman is given")
	}
	if err := genTestCases([]string{"--spec", "a.json", "--postman", "b.json"}); err == nil {
		t.Error("expected an error when both --spec and --postman are given")
	}
}

func TestGenTestCases_ReportsAMissingSpec(t *testing.T) {
	if err := genTestCases([]string{"--spec", filepath.Join(t.TempDir(), "nope.json")}); err == nil {
		t.Error("expected a read error for a missing spec")
	}
}

func TestReportCoverage_WritesAReport(t *testing.T) {
	specPath := writeTemp(t, "spec.json", miniSpec)

	cases := []model.AuthorizationTestCase{{
		ID:      "getUser",
		Request: model.RequestTemplate{Method: "GET", URL: "https://api.example.com/users/1"},
	}}
	encoded, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	casesPath := writeTemp(t, "cases.json", string(encoded))
	outPath := filepath.Join(t.TempDir(), "coverage.json")

	if err := reportCoverage([]string{"--spec", specPath, "--cases", casesPath, "--out", outPath}); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if len(report) == 0 {
		t.Error("coverage report is empty")
	}
}

func TestReportCoverage_RequiresBothFlags(t *testing.T) {
	if err := reportCoverage([]string{"--spec", "a.json"}); err == nil {
		t.Error("expected an error when --cases is missing")
	}
	if err := reportCoverage([]string{"--cases", "b.json"}); err == nil {
		t.Error("expected an error when --spec is missing")
	}
}
