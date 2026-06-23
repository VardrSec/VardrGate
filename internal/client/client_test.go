package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

// roundTripFunc lets tests inject a custom RoundTripper without a real server.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newClientWithTransport(rt http.RoundTripper) *Client {
	return New(&http.Client{Transport: rt})
}

func TestExecute_StatusCodeCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := New(nil)
	tmpl := model.RequestTemplate{Method: http.MethodGet, URL: srv.URL}
	result := c.Execute(context.Background(), model.Identity{ID: "id1"}, tmpl)

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

func TestExecute_BearerCredentialApplied(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(nil)
	identity := model.Identity{
		ID: "user1",
		Credential: model.Credential{
			Type:  model.CredentialTypeBearer,
			Value: "tok-secret",
		},
	}
	c.Execute(context.Background(), identity, model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

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

	c := New(nil)
	identity := model.Identity{
		ID: "svc1",
		Credential: model.Credential{
			Type:  model.CredentialTypeAPIKeyHeader,
			Value: "key-abc",
		},
	}
	c.Execute(context.Background(), identity, model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if gotKey != "key-abc" {
		t.Fatalf("expected key-abc in X-API-Key, got %q", gotKey)
	}
}

func TestExecute_StaticHeaderCredentialApplied(t *testing.T) {
	var gotVal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVal = r.Header.Get("X-Custom-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(nil)
	identity := model.Identity{
		ID: "svc2",
		Credential: model.Credential{
			Type:   model.CredentialTypeStaticHeader,
			Header: "X-Custom-Token",
			Value:  "static-val",
		},
	}
	c.Execute(context.Background(), identity, model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if gotVal != "static-val" {
		t.Fatalf("expected static-val in X-Custom-Token, got %q", gotVal)
	}
}

func TestExecute_APIKeyHeader_DefaultsToXAPIKey(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(nil)
	identity := model.Identity{
		ID: "svc3",
		Credential: model.Credential{
			Type:  model.CredentialTypeAPIKeyHeader,
			Value: "mykey",
			// Header intentionally empty — should default to X-API-Key
		},
	}
	c.Execute(context.Background(), identity, model.RequestTemplate{Method: http.MethodGet, URL: srv.URL})

	if gotKey != "mykey" {
		t.Fatalf("expected mykey in X-API-Key (default), got %q", gotKey)
	}
}

func TestExecute_QueryParamsApplied(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("resource_id")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(nil)
	tmpl := model.RequestTemplate{
		Method:      http.MethodGet,
		URL:         srv.URL,
		QueryParams: map[string]string{"resource_id": "42"},
	}
	c.Execute(context.Background(), model.Identity{ID: "u"}, tmpl)

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
	tmpl := model.RequestTemplate{
		Method: http.MethodPost,
		URL:    srv.URL,
		Body:   body,
	}
	c := New(nil)
	c.Execute(context.Background(), model.Identity{ID: "u"}, tmpl)

	if got.Name != "test" {
		t.Fatalf("expected body name=test, got %q", got.Name)
	}
}

func TestExecute_ErrorCapturedOnBadURL(t *testing.T) {
	c := New(nil)
	tmpl := model.RequestTemplate{Method: http.MethodGet, URL: "http://127.0.0.1:0/"}
	result := c.Execute(context.Background(), model.Identity{ID: "u"}, tmpl)

	if result.Error == "" {
		t.Fatal("expected an error for unreachable URL")
	}
	if result.StatusCode != 0 {
		t.Fatalf("expected zero status code on error, got %d", result.StatusCode)
	}
}

func TestExecute_RedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer srv.Close()

	c := New(nil) // default client; redirect policy blocks following
	result := c.Execute(context.Background(), model.Identity{ID: "u"}, model.RequestTemplate{
		Method: http.MethodGet, URL: srv.URL,
	})

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

	c := New(nil)
	result := c.Execute(context.Background(), model.Identity{ID: "u"}, model.RequestTemplate{
		Method: http.MethodGet, URL: srv.URL,
	})

	if string(result.Body) != `{"id":1}` {
		t.Fatalf("expected body {\"id\":1}, got %q", string(result.Body))
	}
}

func TestRedact(t *testing.T) {
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
	redacted := Redact(cred)
	if redacted.Value != "" {
		t.Fatalf("expected empty value unchanged, got %q", redacted.Value)
	}
}
