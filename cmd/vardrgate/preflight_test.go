package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

func TestGate_PreflightFailureAlwaysExitsThree(t *testing.T) {
	res := engine.Result{TestCaseID: "session", Preflight: []model.PreflightResult{{IdentityID: "owner", Status: "failed", Reason: "credential_rejected", StatusCode: 401}}}
	for _, threshold := range []model.Severity{"", model.SeverityCritical} {
		var ex exitError
		if err := gate([]engine.Result{res}, threshold); !errors.As(err, &ex) || ex.code != 3 {
			t.Fatalf("%v", err)
		}
	}
}

func TestRun_RequiredPreflightGuardRejectsBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.json")
	data, _ := json.Marshal(map[string]any{"config": map[string]any{"test_case": map[string]any{"id": "legacy", "request": map[string]string{"method": "GET", "url": "https://must-not-be-contacted.invalid"}}}})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runCases([]string{"--job", path, "--require-identity-preflight"}); err == nil {
		t.Fatal("accepted case without required preflight")
	}
}
