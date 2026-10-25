package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

func TestRegressionRequiresExactInputAndRelevantFinding(t *testing.T) {
	template := `{"id":"reused-id","identities":[{"id":"peer","credential":{"type":"bearer","value":"${PEER_TOKEN}"}}],"request":{"method":"GET","url":"https://example.test/private/1"},"expected_access":[{"identity_id":"peer","decision":"deny"}]}`
	cases, hashes, err := caseTemplates([]byte(template))
	if err != nil {
		t.Fatal(err)
	}
	good := engine.Result{TestCaseID: "reused-id", InputDigest: hashes["reused-id"], Executions: []model.ExecutionResult{{IdentityID: "peer", StatusCode: 200}}, Findings: []model.Finding{{IdentityID: "peer", Category: model.CategoryUnexpectedAccess}}}
	for _, tt := range []struct {
		name   string
		change func(*engine.Result)
		input  string
		manual bool
		want   bool
	}{
		{name: "bound result", want: true},
		{name: "same id changed request", input: strings.Replace(template, "private/1", "private/2", 1)},
		{name: "changed permission", input: strings.Replace(template, `"deny"`, `"allow"`, 1)},
		{name: "unknown identity", change: func(r *engine.Result) { r.Findings[0].IdentityID = "foreign" }},
		{name: "wrong finding category", change: func(r *engine.Result) { r.Findings[0].Category = model.CategoryAuthorizationMismatch }},
		{name: "not executed", change: func(r *engine.Result) { r.Executions = nil }},
		{name: "failed execution result", change: func(r *engine.Result) { r.Error = "setup failed" }},
		{name: "failed principal check", change: func(r *engine.Result) { r.Preflight = []model.PreflightResult{{IdentityID: "peer", Status: "failed"}} }},
		{name: "legacy implicit rejected", change: func(r *engine.Result) { r.InputDigest = "" }},
		{name: "legacy explicit manual", change: func(r *engine.Result) { r.InputDigest = "" }, manual: true, want: true},
		{name: "manual cannot override mismatch", change: func(r *engine.Result) { r.InputDigest = "wrong" }, manual: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			r.Findings = append([]model.Finding{}, good.Findings...)
			if tt.change != nil {
				tt.change(&r)
			}
			input := template
			if tt.input != "" {
				input = tt.input
			}
			source := writeTemp(t, "cases.json", input)
			raw, _ := json.Marshal(r)
			result := writeTemp(t, "result.json", string(raw))
			out := filepath.Join(t.TempDir(), "saved")
			args := []string{"save", "--cases", source, "--result", result, "--case", "reused-id", "--out", out, "--confirmed"}
			if tt.manual {
				args = append(args, "--allow-unbound-result")
			}
			err := saveRegression(args)
			if (err == nil) != tt.want {
				t.Fatalf("unexpected save: %v", err)
			}
			if !tt.want {
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Fatal("rejected result wrote an artifact")
				}
				return
			}
			manifest, _ := os.ReadFile(filepath.Join(out, "confirmation.json"))
			binding := "exact_input_digest"
			if tt.manual {
				binding = "operator_confirmed_unbound"
			}
			if !strings.Contains(string(manifest), binding) {
				t.Fatalf("lost binding limitation: %s", manifest)
			}
		})
	}
	if relevantRegressionFinding(cases[0], good, model.Finding{IdentityID: "peer", Category: model.CategorySensitiveDataExposure}) {
		t.Fatal("undeclared sensitive-data finding accepted")
	}
	duplicated, _ := json.Marshal([]engine.Result{good, good})
	err = saveRegression([]string{"save", "--cases", writeTemp(t, "cases.json", template), "--result", writeTemp(t, "result.json", string(duplicated)), "--case", "reused-id", "--out", filepath.Join(t.TempDir(), "saved"), "--confirmed"})
	if err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("duplicate result accepted: %v", err)
	}
}

func TestInputDigestUsesOnlyUnresolvedPortableSource(t *testing.T) {
	t.Setenv("DIGEST_TOKEN", "resolved-token-one")
	path := writeTemp(t, "cases.json", `{"id":"x","identities":[{"id":"peer","credential":{"type":"bearer","value":"${DIGEST_TOKEN}"}}],"expected_access":[{"identity_id":"peer","decision":"deny"}]}`)
	first, a, err := loadCasesWithDigests(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DIGEST_TOKEN", "resolved-token-two")
	second, b, err := loadCasesWithDigests(path)
	if err != nil {
		t.Fatal(err)
	}
	if a["x"] == "" || a["x"] != b["x"] || first[0].Identities[0].Credential.Value == second[0].Identities[0].Credential.Value {
		t.Fatal("digest included resolved credentials")
	}
	_, literal, err := caseTemplates([]byte(`{"id":"literal","identities":[{"id":"peer","credential":{"type":"bearer","value":"literal-token"}}]}`))
	if err != nil || literal["literal"] != "" {
		t.Fatal("literal credential was hashed")
	}
	if inputDigest([]byte(`{ "n":9007199254740993 }`)) != inputDigest([]byte(`{"n":9007199254740993}`)) || inputDigest([]byte(`{"n":9007199254740993}`)) == inputDigest([]byte(`{"n":9007199254740992}`)) {
		t.Fatal("digest lost number precision or whitespace normalization")
	}
}
