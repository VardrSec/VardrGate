package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// clientForTest returns a Client that allows loopback targets,
// enabling tests that use httptest.Server (which binds to 127.0.0.1).
func clientForTest() *Client {
	return NewWithConfig(nil, Config{AllowPrivateTargets: true})
}

// clientForTestWithBodyLimit returns a Client with a custom body size limit.
func clientForTestWithBodyLimit(maxBytes int64) *Client {
	return NewWithConfig(nil, Config{AllowPrivateTargets: true, MaxBodyBytes: maxBytes})
}

func TestExecute_StatusCodeCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	result := clientForTest().Execute(context.Background(), model.Identity{ID: "id1"},
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if result.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", result.StatusCode)
	}
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.IdentityID != "id1" {
		t.Fatalf("expected identity id1, got %q", result.IdentityID)
	}
}

func TestExecute_ObservedOutcomeSet(t *testing.T) {
	cases := []struct {
		code int
		want model.ObservedOutcome
	}{
		{200, model.OutcomeAllow},
		{201, model.OutcomeAllow},
		{401, model.OutcomeDeny},
		{403, model.OutcomeDeny},
		{404, model.OutcomeNotFound},
		{302, model.OutcomeRedirect},
		{500, model.OutcomeServerError},
		{422, model.OutcomeClientError},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.code)
		}))
		result := clientForTest().Execute(context.Background(), model.Identity{ID: "u"},
			model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})
		srv.Close()
		if result.ObservedOutcome != c.want {
			t.Errorf("code %d: expected outcome %q, got %q", c.code, c.want, result.ObservedOutcome)
		}
	}
}

func TestExecute_BearerCredentialApplied(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	identity := model.Identity{
		ID:         "user1",
		Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-secret"},
	}
	clientForTest().Execute(context.Background(), identity,
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if gotAuth != "Bearer tok-secret" {
		t.Fatalf("expected Bearer tok-secret, got %q", gotAuth)
	}
}

func TestExecute_APIKeyHeaderCredentialApplied(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	identity := model.Identity{
		ID:         "svc1",
		Credential: model.Credential{Type: model.CredentialTypeAPIKeyHeader, Value: "key-abc"},
	}
	clientForTest().Execute(context.Background(), identity,
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if gotKey != "key-abc" {
		t.Fatalf("expected key-abc in X-API-Key, got %q", gotKey)
	}
}

func TestExecute_APIKeyHeader_DefaultsToXAPIKey(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	identity := model.Identity{
		ID:         "svc2",
		Credential: model.Credential{Type: model.CredentialTypeAPIKeyHeader, Value: "mykey"},
	}
	clientForTest().Execute(context.Background(), identity,
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if gotKey != "mykey" {
		t.Fatalf("expected mykey in X-API-Key (default), got %q", gotKey)
	}
}

func TestExecute_StaticHeaderCredentialApplied(t *testing.T) {
	var gotVal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVal = r.Header.Get("X-Custom-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	identity := model.Identity{
		ID: "svc3",
		Credential: model.Credential{
			Type:   model.CredentialTypeStaticHeader,
			Header: "X-Custom-Token",
			Value:  "static-val",
		},
	}
	clientForTest().Execute(context.Background(), identity,
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if gotVal != "static-val" {
		t.Fatalf("expected static-val in X-Custom-Token, got %q", gotVal)
	}
}

func TestExecute_QueryParamsApplied(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("resource_id")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmpl := model.RequestTemplate{
		Method:      http.MethodGet,
		URL:         srv.URL,
		QueryParams: map[string]string{"resource_id": "42"},
	}
	clientForTest().Execute(context.Background(), model.Identity{ID: "u"}, tmpl)

	if gotQuery != "42" {
		t.Fatalf("expected query param resource_id=42, got %q", gotQuery)
	}
}

func TestExecute_JSONBodyForwarded(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	var got payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	body, _ := json.Marshal(payload{Name: "test"})
	clientForTest().Execute(context.Background(), model.Identity{ID: "u"}, model.RequestTemplate{
		Method: http.MethodPost,
		URL:    srv.URL,
		Body:   body,
	})

	if got.Name != "test" {
		t.Fatalf("expected body name=test, got %q", got.Name)
	}
}

func TestExecute_RedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer srv.Close()

	result := clientForTest().Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if result.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (no redirect follow), got %d", result.StatusCode)
	}
}

func TestExecute_BodyCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	result := clientForTest().Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if string(result.Body) != `{"id":1}` {
		t.Fatalf("expected body {\"id\":1}, got %q", string(result.Body))
	}
}

func TestExecute_NetworkErrorCaptured(t *testing.T) {
	// Use allowPrivate=true so the loopback address passes URL validation,
	// then test that a connection-refused error is captured in the result.
	c := clientForTest()
	result := c.Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: "http://127.0.0.1:0/"})

	if result.Error == "" {
		t.Fatal("expected an error for unreachable URL")
	}
	if result.ErrorKind != model.ErrorKindNetwork {
		t.Fatalf("expected ErrorKind %q, got %q", model.ErrorKindNetwork, result.ErrorKind)
	}
	if result.ObservedOutcome != model.OutcomeError {
		t.Fatalf("expected ObservedOutcome error, got %q", result.ObservedOutcome)
	}
}

func TestExecute_URLValidation_BlocksLoopbackByDefault(t *testing.T) {
	c := New(nil) // AllowPrivateTargets defaults to false
	result := c.Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: "http://127.0.0.1/"})

	if result.ErrorKind != model.ErrorKindURLValidation {
		t.Fatalf("expected ErrorKind %q, got %q", model.ErrorKindURLValidation, result.ErrorKind)
	}
	if !strings.Contains(result.Error, "loopback") {
		t.Errorf("expected loopback in error, got %q", result.Error)
	}
}

func TestExecute_URLValidation_BlocksPrivateByDefault(t *testing.T) {
	c := New(nil)
	result := c.Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: "http://192.168.1.1/"})

	if result.ErrorKind != model.ErrorKindURLValidation {
		t.Fatalf("expected ErrorKind %q, got %q", model.ErrorKindURLValidation, result.ErrorKind)
	}
}

func TestExecute_URLValidation_BlocksBadScheme(t *testing.T) {
	c := New(nil)
	result := c.Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: "ftp://example.com/"})

	if result.ErrorKind != model.ErrorKindURLValidation {
		t.Fatalf("expected ErrorKind %q, got %q", model.ErrorKindURLValidation, result.ErrorKind)
	}
}

func TestExecute_BodySizeExceeded(t *testing.T) {
	const limit = 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", limit+1)))
	}))
	defer srv.Close()

	result := clientForTestWithBodyLimit(limit).Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if result.ErrorKind != model.ErrorKindBodySizeExceeded {
		t.Fatalf("expected ErrorKind %q, got %q", model.ErrorKindBodySizeExceeded, result.ErrorKind)
	}
	if result.ObservedOutcome != model.OutcomeError {
		t.Fatalf("expected ObservedOutcome error, got %q", result.ObservedOutcome)
	}
}

func TestExecute_BodyWithinLimit(t *testing.T) {
	const limit = 100
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("small"))
	}))
	defer srv.Close()

	result := clientForTestWithBodyLimit(limit).Execute(context.Background(), model.Identity{ID: "u"},
		model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if result.ErrorKind != "" {
		t.Fatalf("expected no error, got %q (%s)", result.ErrorKind, result.Error)
	}
	if string(result.Body) != "small" {
		t.Fatalf("expected body small, got %q", string(result.Body))
	}
}

func TestRedact_ReplacesValue(t *testing.T) {
	cred := model.Credential{Type: model.CredentialTypeBearer, Value: "super-secret"}
	redacted := Redact(cred)

	if redacted.Value != "[REDACTED]" {
		t.Fatalf("expected [REDACTED], got %q", redacted.Value)
	}
	if cred.Value != "super-secret" {
		t.Fatal("Redact must not mutate the original credential")
	}
}

func TestRedact_EmptyValueUnchanged(t *testing.T) {
	cred := model.Credential{Type: model.CredentialTypeBearer}
	if Redact(cred).Value != "" {
		t.Fatal("empty value must remain empty after redaction")
	}
}
