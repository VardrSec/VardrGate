package api

import (
	"context"
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

// defaultTenant owns all jobs when authentication is disabled or a single key is
// configured without an explicit tenant.
const defaultTenant = "default"

type ctxKey int

const tenantCtxKey ctxKey = 0

// Handler owns the ServeMux and all route registrations.
type Handler struct {
	log    *slog.Logger
	mux    *http.ServeMux
	engine *engine.Engine
	store  store.Store
	// keys maps a bearer token to the tenant it authenticates. An empty/nil map
	// disables auth (dev only); every caller is then the default tenant.
	keys map[string]string
}

// New wires routes and returns a ready-to-serve Handler.
//
// st backs the runner job queue. keys maps each accepted bearer token to a
// tenant; a token is required on the /jobs, /runner, and /audit endpoints, and
// scopes the caller to that tenant's jobs. The synchronous /health and
// /tests/execute endpoints are always open. An empty keys map disables auth
// (dev only) — main logs a warning in that case.
func New(log *slog.Logger, eng *engine.Engine, st store.Store, keys map[string]string) *Handler {
	h := &Handler{log: log, mux: http.NewServeMux(), engine: eng, store: st, keys: keys}

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
	h.mux.HandleFunc("GET /audit", h.protected(h.handleAuditLog))

	return h
}

// protected rejects a request unless it carries a configured bearer token, and
// tags it with the resolved tenant. When no keys are configured, requests pass
// through as the default tenant (dev mode).
func (h *Handler) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := h.resolveTenant(r)
		if !ok {
			h.writeError(w, codeUnauthorized, "missing or invalid API key", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), tenantCtxKey, tenant)))
	}
}

// resolveTenant returns the tenant a request authenticates as. The bearer token
// is compared against every configured key in constant time so a mismatch does
// not leak which key was closest.
func (h *Handler) resolveTenant(r *http.Request) (string, bool) {
	if len(h.keys) == 0 {
		return defaultTenant, true
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	token := []byte(strings.TrimPrefix(auth, prefix))
	tenant, matched := "", false
	for key, t := range h.keys {
		if subtle.ConstantTimeCompare(token, []byte(key)) == 1 {
			tenant, matched = t, true
		}
	}
	return tenant, matched
}

// tenant returns the tenant tagged onto the request by protected.
func (h *Handler) tenant(r *http.Request) string {
	if t, ok := r.Context().Value(tenantCtxKey).(string); ok {
		return t
	}
	return defaultTenant
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
