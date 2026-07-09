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
	"github.com/VardrSec/vardrgate/internal/store"
)

// stubExecutor returns a fixed status code per identity ID.
type stubExecutor struct {
	responses map[string]int
}

func (s *stubExecutor) Execute(_ context.Context, identity model.Identity, _ model.RequestTemplate) model.ExecutionResult {
	code := s.responses[identity.ID]
	return model.ExecutionResult{
		IdentityID:      identity.ID,
		StatusCode:      code,
		ObservedOutcome: model.ClassifyOutcome(code, false),
	}
}

func newTestHandler() *Handler {
	eng := engine.New(&stubExecutor{responses: map[string]int{}})
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), eng, store.NewMemory(), "")
}

func newTestHandlerWithResponses(responses map[string]int) *Handler {
	eng := engine.New(&stubExecutor{responses: responses})
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), eng, store.NewMemory(), "")
}

// --- GET /health ---

func TestHealthStatus(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHealthContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rr, req)
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}

func TestHealthBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rr, req)
	body := strings.TrimSpace(rr.Body.String())
	if body != `{"status":"ok"}` {
		t.Fatalf("expected {\"status\":\"ok\"}, got %q", body)
	}
}

func TestHealthUnsupportedMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/health", nil)
			rr := httptest.NewRecorder()
			newTestHandler().ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s /health: expected 405, got %d", method, rr.Code)
			}
		})
	}
}

// --- POST /tests/execute ---

// validTestCaseJSON is raw request JSON including credential "value" fields.
// Marshalling a model.AuthorizationTestCase drops credential values (json:"-"),
// so requests that must pass validation are built as raw JSON instead.
func validTestCaseJSON() string {
	return `{
		"id":"tc-api-1",
		"identities":[
			{"id":"admin","credential":{"type":"bearer","value":"tok-a"}},
			{"id":"user","credential":{"type":"bearer","value":"tok-u"}}
		],
		"request":{"method":"GET","url":"https://example.com/resource/1"},
		"expected_access":[
			{"identity_id":"admin","decision":"allow"},
			{"identity_id":"user","decision":"deny"}
		]
	}`
}

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
	h := newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 403})
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader(validTestCaseJSON()))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTestsExecute_ContentTypeJSON(t *testing.T) {
	h := newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 403})
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader(validTestCaseJSON()))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected application/json, got %q", rr.Header().Get("Content-Type"))
	}
}

func TestTestsExecute_ResponseContainsSnakeCaseFields(t *testing.T) {
	h := newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 200})
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader(validTestCaseJSON()))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, field := range []string{"test_case_id", "executions", "findings"} {
		if _, ok := resp[field]; !ok {
			t.Errorf("response missing field %q", field)
		}
	}
}

func TestTestsExecute_InvalidBody_Returns400(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestTestsExecute_InvalidTestCase_Returns422(t *testing.T) {
	tc := validTestCase()
	tc.ID = ""
	body, _ := json.Marshal(tc)
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
}

func TestTestsExecute_UnsupportedMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/tests/execute", nil)
			rr := httptest.NewRecorder()
			newTestHandler().ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s /tests/execute: expected 405, got %d", method, rr.Code)
			}
		})
	}
}

func TestTestsExecute_NoFindingsWhenExpectationsMet(t *testing.T) {
	h := newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 403})
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader(validTestCaseJSON()))
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

// Issue 9: request body exceeding maxRequestBodyBytes must return 413.
func TestTestsExecute_RequestBodyTooLarge_Returns413(t *testing.T) {
	large := strings.Repeat("x", maxRequestBodyBytes+1)
	body := `{"id":"t","padding":"` + large + `"}`
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader(body))
	rr := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

// Issue 5: a body containing more than one JSON value must be rejected.
func TestTestsExecute_TrailingJSON_Returns400(t *testing.T) {
	body := validTestCaseJSON() + `{"extra":"trailing"}`
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader(body))
	rr := httptest.NewRecorder()
	newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 403}).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing JSON, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTestsExecute_ErrorEnvelopeHasStableCode(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		method   string
		wantCode string
	}{
		{"invalid_json", "not json", http.MethodPost, codeInvalidJSON},
		{"method_not_allowed", "", http.MethodGet, codeMethodNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "/tests/execute", strings.NewReader(c.body))
			rr := httptest.NewRecorder()
			newTestHandler().ServeHTTP(rr, req)
			var resp map[string]string
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp["code"] != c.wantCode {
				t.Errorf("expected code %q, got %q (body=%s)", c.wantCode, resp["code"], rr.Body.String())
			}
		})
	}
}

func TestTestsExecute_ValidationError_HasValidationCode(t *testing.T) {
	tc := validTestCase()
	tc.ID = ""
	body, _ := json.Marshal(tc)
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rr, req)
	var resp map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != codeValidationFailed {
		t.Errorf("expected code %q, got %q", codeValidationFailed, resp["code"])
	}
}

// Issue 1: credential value supplied in request JSON must reach the identity
// without appearing in the response JSON.
func TestTestsExecute_CredentialValueNotInResponse(t *testing.T) {
	// Build raw JSON with an explicit credential "value" field.
	payload := `{
		"id":"tc-cred",
		"identities":[{"id":"u","credential":{"type":"bearer","value":"super-secret"}}],
		"request":{"method":"GET","url":"https://example.com/"},
		"expected_access":[{"identity_id":"u","decision":"skip"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/tests/execute", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	newTestHandlerWithResponses(map[string]int{"u": 200}).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	respBody := rr.Body.String()
	if strings.Contains(respBody, "super-secret") {
		t.Errorf("credential value leaked into response: %s", respBody)
	}
}
