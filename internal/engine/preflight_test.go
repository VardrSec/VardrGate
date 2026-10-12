package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/model"
)

func preflightTC(base string) model.AuthorizationTestCase {
	tc := baseTC()
	tc.Request.URL = base + "/resource/1"
	for i := range tc.Identities {
		tc.Identities[i].Preflight = &model.IdentityPreflight{URL: base + "/session", ExpectedStatus: 200, JSONFields: map[string]string{"user.id": tc.Identities[i].ID, "tenant": "tenant-a"}}
	}
	return tc
}

func TestPreflight_RealHTTP(t *testing.T) {
	for _, mode := range []string{"valid", "rejected", "wrong-principal", "wrong-tenant", "html-login", "missing-field", "redirect", "rate-limited", "server-error"} {
		t.Run(mode, func(t *testing.T) {
			var requests []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.Method+" "+r.URL.Path)
				who := "user"
				if r.Header.Get("Authorization") == "Bearer tok-a" {
					who = "admin"
				}
				if r.URL.Path == "/session" {
					if r.Header.Get("Origin") != "" || r.Header.Get("X-Probe") != "" {
						t.Error("authorization request headers leaked into session check")
					}
					switch mode {
					case "rejected":
						w.WriteHeader(401)
						return
					case "redirect":
						w.Header().Set("Location", "/other")
						w.WriteHeader(302)
						return
					case "rate-limited":
						w.WriteHeader(429)
						return
					case "server-error":
						w.WriteHeader(503)
						return
					case "html-login":
						w.Write([]byte("<html>login secret-response</html>"))
						return
					case "missing-field":
						w.Write([]byte(`{"tenant":"tenant-a"}`))
						return
					}
					tenant := "tenant-a"
					if mode == "wrong-principal" {
						who = "somebody-else"
					}
					if mode == "wrong-tenant" {
						tenant = "tenant-b"
					}
					w.Header().Set("Set-Cookie", "secret-cookie")
					json.NewEncoder(w).Encode(map[string]any{"user": map[string]string{"id": who}, "tenant": tenant, "token": "secret-response"})
					return
				}
				if who == "user" {
					w.WriteHeader(403)
				}
			}))
			defer srv.Close()
			tc := preflightTC(srv.URL)
			tc.Request.Headers = map[string]string{"X-Probe": "yes"}
			tc.CORS = &model.CORSCheck{ProbeOrigin: "https://foreign.test"}
			res, err := New(client.NewWithConfig(nil, client.Config{AllowPrivateTargets: true})).Run(context.Background(), tc)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Preflight) != 2 || len(requests) < 2 || requests[0] != "GET /session" || requests[1] != "GET /session" {
				t.Fatalf("wrong ordering: %+v %+v", requests, res)
			}
			if mode == "valid" {
				if len(requests) != 4 || len(res.Executions) != 2 || len(res.Findings) != 0 {
					t.Fatalf("%+v %+v", requests, res)
				}
			} else if len(requests) != 2 || len(res.Executions) != 0 || len(res.Findings) != 0 {
				t.Fatalf("failed preflight reached authorization request: %+v %+v", requests, res)
			}
			wire, _ := json.Marshal(res)
			for _, secret := range []string{"tok-a", "tok-u", "secret-response", "secret-cookie", "somebody-else", "tenant-b"} {
				if strings.Contains(string(wire), secret) {
					t.Fatalf("leaked %s", secret)
				}
			}
		})
	}
}

func TestPreflight_InvalidDeclarationsMakeNoRequests(t *testing.T) {
	changes := map[string]func(*model.AuthorizationTestCase){
		"cross-origin": func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.URL = "https://other.test/session" },
		"port": func(tc *model.AuthorizationTestCase) {
			tc.Identities[0].Preflight.URL = "https://example.com:444/session"
		},
		"userinfo": func(tc *model.AuthorizationTestCase) {
			tc.Identities[0].Preflight.URL = "https://token@example.com/session"
		},
		"fragment":    func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.URL += "#secret" },
		"relative":    func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.URL = "/session" },
		"variable":    func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.URL += "?x={{token}}" },
		"status":      func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.ExpectedStatus = 401 },
		"no-fields":   func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.JSONFields = nil },
		"empty-value": func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.JSONFields["user.id"] = "" },
		"empty-path":  func(tc *model.AuthorizationTestCase) { tc.Identities[0].Preflight.JSONFields["user..id"] = "x" },
		"anonymous": func(tc *model.AuthorizationTestCase) {
			tc.Identities[0].Credential = model.Credential{Type: model.CredentialTypeStaticHeader}
		},
		"empty-header": func(tc *model.AuthorizationTestCase) {
			tc.Identities[0].Credential = model.Credential{Type: model.CredentialTypeStaticHeader, Header: "X-Auth"}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			tc := preflightTC("https://example.com")
			change(&tc)
			if err := Validate(tc); err == nil {
				t.Fatal("accepted invalid declaration")
			}
		})
	}
}

func TestPreflight_DefaultPortsAndUnknownOptions(t *testing.T) {
	tc := preflightTC("https://example.com")
	tc.Identities[0].Preflight.URL = "https://EXAMPLE.com:443/session"
	if err := Validate(tc); err != nil {
		t.Fatal(err)
	}
	var identity model.Identity
	if err := json.Unmarshal([]byte(`{"id":"owner","credential":{"type":"bearer","value":"token"},"preflight":{"url":"https://example.com/session","expected_status":200,"json_fields":{"id":"owner"},"ignore_errors":true}}`), &identity); err == nil {
		t.Fatal("accepted unknown preflight option")
	}
}

func TestPreflight_JSONMatching(t *testing.T) {
	for _, body := range []string{`{"id":null}`, `{"id":["42"]}`, `{"ID":"42"}`, `{"id":{"value":"42"}}`, `{"id":"42"} {}`, `not json`} {
		if matchesPrincipal([]byte(body), map[string]string{"id": "42"}) {
			t.Fatalf("accepted %s", body)
		}
	}
	if !matchesPrincipal([]byte(`{"id":9007199254740993,"active":true}`), map[string]string{"id": "9007199254740993", "active": "true"}) {
		t.Fatal("lost scalar precision")
	}
}

func TestPreflight_UsesSetupCredentialWithoutMutatingSpec(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Write([]byte(`{"token":"fresh-secret"}`))
		case "/session":
			auth = r.Header.Get("Authorization")
			w.Write([]byte(`{"user":{"id":"admin"},"tenant":"tenant-a"}`))
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	tc := preflightTC(srv.URL)
	tc.Identities = tc.Identities[:1]
	tc.ExpectedAccess = tc.ExpectedAccess[:1]
	tc.Identities[0].Credential.Value = "{{access}}"
	tc.Setup = []model.SetupStep{{Name: "login", Request: model.RequestTemplate{Method: "POST", URL: srv.URL + "/login"}, Capture: map[string]string{"access": "token"}}}
	tc.Mutating = true
	res, err := New(client.NewWithConfig(nil, client.Config{AllowPrivateTargets: true})).Run(context.Background(), tc)
	if err != nil || res.Preflight[0].Status != "passed" || auth != "Bearer fresh-secret" {
		t.Fatalf("%v %+v %s", err, res, auth)
	}
	if tc.Identities[0].Credential.Value != "{{access}}" {
		t.Fatal("spec mutated")
	}
}
