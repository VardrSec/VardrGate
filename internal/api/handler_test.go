package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler() *Handler {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestHealthStatus(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHealthContentType(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}

func TestHealthBody(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	body := strings.TrimSpace(rr.Body.String())
	want := `{"status":"ok"}`
	if body != want {
		t.Fatalf("expected body %q, got %q", want, body)
	}
}

func TestHealthUnsupportedMethods(t *testing.T) {
	methods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
	}
	h := newTestHandler()
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/health", nil)
			rr := httptest.NewRecorder()

			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s /health: expected 405, got %d", method, rr.Code)
			}
		})
	}
}
