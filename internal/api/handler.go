package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
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
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleTestsExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tc model.AuthorizationTestCase
	if err := json.NewDecoder(r.Body).Decode(&tc); err != nil {
		h.writeError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	result, err := h.engine.Run(r.Context(), tc)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusUnprocessableEntity)
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

func (h *Handler) writeError(w http.ResponseWriter, msg string, status int) {
	h.writeJSON(w, status, map[string]string{"error": msg})
}
