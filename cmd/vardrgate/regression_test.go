package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/scaffold"
)

func TestSavedRegressionCatchesReintroduction(t *testing.T) {
	vulnerable := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/owner":
			fmt.Fprint(w, `{"token":"fixture-owner-token"}`)
		case "/login/peer":
			fmt.Fprint(w, `{"token":"fixture-peer-token"}`)
		case "/me":
			principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer fixture-")
			principal = strings.TrimSuffix(principal, "-token")
			fmt.Fprintf(w, `{"id":%q}`, principal)
		case "/objects":
			fmt.Fprint(w, `{"id":"1"}`)
		case "/objects/1":
			if !vulnerable && r.Header.Get("Authorization") != "Bearer fixture-owner-token" {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"error":"PRIVATE"}`)
				return
			}
			fmt.Fprint(w, `{"private":"protected-response-value"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("LOGIN_PASSWORD", "fixture-password")
	t.Setenv("EXPECTED_SECRET", "protected-response-value")
	tc := model.AuthorizationTestCase{ID: "confirmed-object-read", RequireIdentityPreflight: true,
		Request: model.RequestTemplate{Method: "GET", URL: srv.URL + "/objects/{{object}}"}, Mutating: true,
		Resource: &model.Resource{Type: "object", ObjectID: "{{object}}", OwnerIdentity: "owner"}}
	for _, id := range []string{"owner", "peer"} {
		tc.Identities = append(tc.Identities, model.Identity{ID: id, Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "{{" + id + "_token}}"}, Preflight: &model.IdentityPreflight{URL: srv.URL + "/me", ExpectedStatus: 200, JSONFields: map[string]string{"id": id}}})
		tc.Setup = append(tc.Setup, model.SetupStep{Name: "login-" + id, Request: model.RequestTemplate{Method: "POST", URL: srv.URL + "/login/" + id, Body: json.RawMessage(`{"password":"${LOGIN_PASSWORD}"}`)}, Capture: map[string]string{id + "_token": "token"}})
		expected := model.AccessDecisionDeny
		if id == "owner" {
			expected = model.AccessDecisionAllow
		}
		tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: id, Decision: expected, ResponseAssertions: []model.ResponseAssertion{{JSONPointer: "/private", Equals: json.RawMessage(`"${EXPECTED_SECRET}"`), Decision: model.AccessDecisionAllow}, {JSONPointer: "/error", Equals: json.RawMessage(`"PRIVATE"`), Decision: model.AccessDecisionDeny}}})
	}
	tc.Setup = append(tc.Setup, model.SetupStep{Name: "create-object", As: "owner", Request: model.RequestTemplate{Method: "POST", URL: srv.URL + "/objects"}, Capture: map[string]string{"object": "id"}})
	data, err := scaffold.MarshalCases([]model.AuthorizationTestCase{tc})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "reviewed.json")
	result := filepath.Join(dir, "result.json")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(path string, want int) {
		t.Helper()
		err := runCases([]string{"--cases", path, "--out", result, "--allow-private-targets", "--fail-on", "high", "--fail-on-inconclusive"})
		if want == 0 {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		ee, ok := err.(exitError)
		if !ok || ee.code != want {
			t.Fatalf("want exit %d, got %v", want, err)
		}
	}
	check(input, 2)
	saved := filepath.Join(dir, "permanent")
	if err := saveRegression([]string{"save", "--cases", input, "--result", result, "--case", tc.ID, "--out", saved, "--confirmed"}); err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(filepath.Join(saved, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-password", "fixture-owner-token", "protected-response-value"} {
		if strings.Contains(string(artifact), secret) {
			t.Fatal("resolved secret copied into regression")
		}
	}
	vulnerable = false
	check(filepath.Join(saved, "cases.json"), 0)
	vulnerable = true
	check(filepath.Join(saved, "cases.json"), 2)
	if err := saveRegression([]string{"save", "--cases", input, "--result", result, "--case", tc.ID, "--out", saved, "--confirmed"}); err == nil {
		t.Fatal("existing regression overwritten")
	}
}

func TestRegressionRejectsUnconfirmedOrLiteralSecrets(t *testing.T) {
	if err := saveRegression([]string{"save"}); err == nil {
		t.Fatal("missing confirmation accepted")
	}
	tc := model.AuthorizationTestCase{Identities: []model.Identity{{Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "literal-token"}}}}
	if err := portableRegression(tc); err == nil {
		t.Fatal("literal token accepted")
	}
	tc.Identities[0].Credential.Value = "${TOKEN}"
	for _, body := range []string{`{"nested":{"password":"literal-password"}}`, `{"secret":42}`} {
		tc.Request = model.RequestTemplate{URL: "https://example.test", Body: json.RawMessage(body)}
		if err := portableRegression(tc); err == nil {
			t.Fatal("literal request secret accepted")
		}
	}
}
