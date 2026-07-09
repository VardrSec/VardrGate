package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/store"
)

// maxRequestBodyBytes limits the size of a POST /tests/execute request body.
const maxRequestBodyBytes = 1 << 20 // 1 MB

// Stable error codes. These are part of the API contract: clients may branch on
// them, so they must not change without a version bump.
const (
	codeMethodNotAllowed = "method_not_allowed"
	codeBodyTooLarge     = "body_too_large"
	codeInvalidJSON      = "invalid_json"
	codeTrailingContent  = "trailing_content"
	codeValidationFailed = "validation_failed"
	codeUnauthorized     = "unauthorized"
	codeNotFound         = "not_found"
	codeConflict         = "conflict"
)

// Handler owns the ServeMux and all route registrations.
type Handler struct {
	log    *slog.Logger
	mux    *http.ServeMux
	engine *engine.Engine
	store  store.Store
	apiKey string
}

// New wires routes and returns a ready-to-serve Handler.
//
// st backs the runner job queue. apiKey, when non-empty, is required as a bearer
// token on the /jobs and /runner endpoints; the synchronous /health and
// /tests/execute endpoints are always open. An empty apiKey disables auth
// (dev only) — main logs a warning in that case.
func New(log *slog.Logger, eng *engine.Engine, st store.Store, apiKey string) *Handler {
	h := &Handler{log: log, mux: http.NewServeMux(), engine: eng, store: st, apiKey: apiKey}

	h.mux.HandleFunc("/health", h.handleHealth)
	h.mux.HandleFunc("/tests/execute", h.handleTestsExecute)

	// Runner job queue (Bearer-protected). Method+path patterns require Go 1.22+.
	h.mux.HandleFunc("POST /jobs", h.protected(h.handleCreateJob))
	h.mux.HandleFunc("GET /jobs/pending", h.protected(h.handlePendingJobs))
	h.mux.HandleFunc("GET /jobs/{id}", h.protected(h.handleGetJob))
	h.mux.HandleFunc("POST /jobs/{id}/claim", h.protected(h.handleClaimJob))
	h.mux.HandleFunc("PATCH /jobs/{id}", h.protected(h.handleCompleteJob))
	h.mux.HandleFunc("POST /jobs/{id}/done", h.protected(h.handleDoneJob))
	h.mux.HandleFunc("POST /jobs/{id}/failed", h.protected(h.handleFailedJob))
	h.mux.HandleFunc("POST /jobs/{id}/events", h.protected(h.handleJobEvent))
	h.mux.HandleFunc("POST /jobs/{id}/upload", h.protected(h.handleJobUpload))
	h.mux.HandleFunc("POST /runner/heartbeat", h.protected(h.handleHeartbeat))

	return h
}

// protected rejects a request unless it carries the configured bearer token.
// When no key is configured, requests pass through (dev mode).
func (h *Handler) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.authOK(r) {
			h.writeError(w, codeUnauthorized, "missing or invalid API key", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (h *Handler) authOK(r *http.Request) bool {
	if h.apiKey == "" {
		return true
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	token := strings.TrimPrefix(auth, prefix)
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.apiKey)) == 1
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, codeMethodNotAllowed, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleTestsExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, codeMethodNotAllowed, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)

	var tc model.AuthorizationTestCase
	if err := dec.Decode(&tc); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.writeError(w, codeBodyTooLarge, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.writeError(w, codeInvalidJSON, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Require exactly one JSON value; trailing content is rejected.
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		h.writeError(w, codeTrailingContent, "request body must contain exactly one JSON value", http.StatusBadRequest)
		return
	}

	result, err := h.engine.Run(r.Context(), tc)
	if err != nil {
		h.writeError(w, codeValidationFailed, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.log.Error("encode response", "error", err)
	}
}

// writeError emits the stable error envelope {"code","error"}.
func (h *Handler) writeError(w http.ResponseWriter, code, msg string, status int) {
	h.writeJSON(w, status, map[string]string{"code": code, "error": msg})
}
