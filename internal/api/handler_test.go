package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

// stubExecutor returns a fixed status code per identity ID.
type stubExecutor struct {
	responses map[string]int
}

func (s *stubExecutor) Execute(_ context.Context, identity model.Identity, _ model.RequestTemplate) model.ExecutionResult {
	return model.ExecutionResult{
		IdentityID: identity.ID,
		StatusCode: s.responses[identity.ID],
	}
}

func newTestHandler() *Handler {
	eng := engine.New(&stubExecutor{responses: map[string]int{}})
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), eng)
}

func newTestHandlerWithResponses(responses map[string]int) *Handler {
	eng := engine.New(&stubExecutor{responses: responses})
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), eng)
}

// --- GET /health ---

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

// --- POST /tests/execute ---

func validTestCase() model.AuthorizationTestCase {
	return model.AuthorizationTestCase{
		ID: "tc-api-1",
		Identities: []model.Identity{
			{ID: "admin", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-a"}},
			{ID: "user", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "tok-u"}},
		},
		Request: model.RequestTemplate{
			Method: http.MethodGet,
			URL:    "https://example.com/resource/1",
		},
		ExpectedAccess: []model.ExpectedAccess{
			{IdentityID: "admin", Decision: model.AccessDecisionAllow},
			{IdentityID: "user", Decision: model.AccessDecisionDeny},
		},
	}
}

func TestTestsExecute_Returns200OnSuccess(t *testing.T) {
	h := newTestHandlerWithResponses(map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusForbidden,
	})
	body, _ := json.Marshal(validTestCase())
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTestsExecute_ContentTypeJSON(t *testing.T) {
	h := newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 403})
	body, _ := json.Marshal(validTestCase())
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json, got %q", ct)
	}
}

func TestTestsExecute_ResponseContainsExecutionsAndFindings(t *testing.T) {
	h := newTestHandlerWithResponses(map[string]int{
		"admin": http.StatusOK,
		"user":  http.StatusOK, // should have been denied → finding
	})
	body, _ := json.Marshal(validTestCase())
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := resp["Executions"]; !ok {
		if _, ok2 := resp["executions"]; !ok2 {
			t.Error("response missing executions field")
		}
	}
	if _, ok := resp["Findings"]; !ok {
		if _, ok2 := resp["findings"]; !ok2 {
			t.Error("response missing findings field")
		}
	}
}

func TestTestsExecute_InvalidBody_Returns400(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader("not json"))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestTestsExecute_InvalidTestCase_Returns422(t *testing.T) {
	h := newTestHandler()
	tc := validTestCase()
	tc.ID = "" // triggers validation error
	body, _ := json.Marshal(tc)
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
}

func TestTestsExecute_UnsupportedMethods(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	h := newTestHandler()
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/tests/execute", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s /tests/execute: expected 405, got %d", method, rr.Code)
			}
		})
	}
}

func TestTestsExecute_NoFindingsWhenExpectationsMet(t *testing.T) {
	h := newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 403})
	body, _ := json.Marshal(validTestCase())
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	var result engine.Result
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(result.Findings))
	}
}
