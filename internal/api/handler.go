package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Handler owns the ServeMux and all route registrations.
type Handler struct {
	log *slog.Logger
	mux *http.ServeMux
}

// New wires routes and returns a ready-to-serve Handler.
func New(log *slog.Logger) *Handler {
	h := &Handler{log: log, mux: http.NewServeMux()}
	h.mux.HandleFunc("/health", h.handleHealth)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		h.log.Error("health encode", "error", err)
	}
}
