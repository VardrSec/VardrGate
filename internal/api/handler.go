package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
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
)

// Handler owns the ServeMux and all route registrations.
type Handler struct {
	log    *slog.Logger
	mux    *http.ServeMux
	engine *engine.Engine
}

// New wires routes and returns a ready-to-serve Handler.
func New(log *slog.Logger, eng *engine.Engine) *Handler {
	h := &Handler{log: log, mux: http.NewServeMux(), engine: eng}
	h.mux.HandleFunc("/health", h.handleHealth)
	h.mux.HandleFunc("/tests/execute", h.handleTestsExecute)
	return h
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
