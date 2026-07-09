package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/VardrSec/vardrgate/internal/store"
)

// maxUploadBytes caps a job result upload.
const maxUploadBytes = 10 << 20 // 10 MB

// handleCreateJob enqueues a new job for runners to poll.
func (h *Handler) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ToolType     string          `json:"tool_type"`
		TargetSource string          `json:"target_source"`
		ProgramID    string          `json:"program_id"`
		Config       json.RawMessage `json:"config"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if req.ToolType == "" {
		h.writeError(w, codeValidationFailed, "tool_type is required", http.StatusUnprocessableEntity)
		return
	}
	if req.TargetSource == "" {
		req.TargetSource = "config"
	}
	job, err := h.store.Create(store.Job{
		ToolType:     req.ToolType,
		TargetSource: req.TargetSource,
		ProgramID:    req.ProgramID,
		Config:       req.Config,
	})
	if err != nil {
		h.writeError(w, codeValidationFailed, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	h.audit(r, "job_created", job.ID, job.ToolType)
	h.writeJSON(w, http.StatusCreated, job)
}

// handlePendingJobs returns the queue of pending jobs.
func (h *Handler) handlePendingJobs(w http.ResponseWriter, r *http.Request) {
	jobs := h.store.Pending()
	if jobs == nil {
		jobs = []store.Job{}
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

// handleGetJob returns a single job, including its result once uploaded.
func (h *Handler) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		h.writeError(w, codeNotFound, "job not found", http.StatusNotFound)
		return
	}
	h.writeJSON(w, http.StatusOK, job)
}

// handleClaimJob atomically claims a pending job for the calling runner.
func (h *Handler) handleClaimJob(w http.ResponseWriter, r *http.Request) {
	runner := r.Header.Get("User-Agent")
	job, err := h.store.Claim(r.PathValue("id"), runner)
	switch err {
	case nil:
		h.audit(r, "job_claimed", job.ID, runner)
		h.writeJSON(w, http.StatusOK, job)
	case store.ErrNotFound:
		h.writeError(w, codeNotFound, "job not found", http.StatusNotFound)
	case store.ErrAlreadyClaimed:
		h.writeError(w, codeConflict, "job already claimed", http.StatusConflict)
	default:
		h.writeError(w, codeValidationFailed, err.Error(), http.StatusInternalServerError)
	}
}

// handleCompleteJob is the PATCH /jobs/{id} completion path VardrRunner uses.
func (h *Handler) handleCompleteJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"error_message"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	h.complete(w, r, r.PathValue("id"), req.Status, req.ErrorMessage)
}

// handleDoneJob marks a job done (POST /jobs/{id}/done).
func (h *Handler) handleDoneJob(w http.ResponseWriter, r *http.Request) {
	h.complete(w, r, r.PathValue("id"), store.StatusDone, "")
}

// handleFailedJob marks a job failed with a reason (POST /jobs/{id}/failed).
func (h *Handler) handleFailedJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	// Body is optional; ignore decode errors and fall back to empty reason.
	_ = json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes)).Decode(&req)
	reason := req.Error
	if reason == "" {
		reason = req.Reason
	}
	h.complete(w, r, r.PathValue("id"), store.StatusFailed, reason)
}

func (h *Handler) complete(w http.ResponseWriter, r *http.Request, id, status, errMsg string) {
	err := h.store.Complete(id, status, errMsg)
	switch err {
	case nil:
		job, _ := h.store.Get(id)
		h.audit(r, "job_completed", id, status)
		h.writeJSON(w, http.StatusOK, job)
	case store.ErrNotFound:
		h.writeError(w, codeNotFound, "job not found", http.StatusNotFound)
	case store.ErrInvalidStatus:
		h.writeError(w, codeValidationFailed, "status must be done or failed", http.StatusUnprocessableEntity)
	default:
		h.writeError(w, codeValidationFailed, err.Error(), http.StatusInternalServerError)
	}
}

// handleJobEvent records a lifecycle event streamed by a runner.
func (h *Handler) handleJobEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if req.Kind == "" {
		h.writeError(w, codeValidationFailed, "kind is required", http.StatusUnprocessableEntity)
		return
	}
	if err := h.store.AppendEvent(r.PathValue("id"), store.Event{Kind: req.Kind, Text: req.Text}); err != nil {
		h.writeError(w, codeNotFound, "job not found", http.StatusNotFound)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleJobUpload stores the sanitized result artifact for a job. It accepts
// either a raw JSON body or a multipart form with a "file" field, so both a
// direct POST and VardrRunner's file-upload style work.
func (h *Handler) handleJobUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.store.Get(id); !ok {
		h.writeError(w, codeNotFound, "job not found", http.StatusNotFound)
		return
	}

	var result []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
			h.writeError(w, codeInvalidJSON, "invalid multipart upload", http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			h.writeError(w, codeValidationFailed, "missing file field", http.StatusUnprocessableEntity)
			return
		}
		defer file.Close()
		result, err = io.ReadAll(io.LimitReader(file, maxUploadBytes))
		if err != nil {
			h.writeError(w, codeInvalidJSON, "cannot read upload", http.StatusBadRequest)
			return
		}
	} else {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxUploadBytes))
		if err != nil {
			h.writeError(w, codeInvalidJSON, "cannot read body", http.StatusBadRequest)
			return
		}
		result = body
	}

	if !json.Valid(result) {
		h.writeError(w, codeInvalidJSON, "result must be valid JSON", http.StatusBadRequest)
		return
	}
	if err := h.store.SetResult(id, result); err != nil {
		h.writeError(w, codeNotFound, "job not found", http.StatusNotFound)
		return
	}
	h.audit(r, "job_result_uploaded", id, "")
	h.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleHeartbeat records a runner's reported status and capabilities.
func (h *Handler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hostname string   `json:"hostname"`
		Version  string   `json:"version"`
		OS       string   `json:"os"`
		Tools    []string `json:"tools"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if req.Hostname == "" {
		h.writeError(w, codeValidationFailed, "hostname is required", http.StatusUnprocessableEntity)
		return
	}
	h.store.Heartbeat(store.RunnerInfo{
		Hostname: req.Hostname,
		Version:  req.Version,
		OS:       req.OS,
		Tools:    req.Tools,
	})
	h.audit(r, "runner_heartbeat", "", req.Hostname)
	h.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAuditLog returns the append-only audit trail, newest last. An optional
// ?limit=N caps the number of most-recent entries returned.
func (h *Handler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	entries := h.store.AuditLog(limit)
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

// audit records one append-only action. actor falls back to the caller's
// User-Agent when the specific detail does not already identify who acted.
func (h *Handler) audit(r *http.Request, action, jobID, detail string) {
	h.store.Audit(store.AuditEntry{
		Action: action,
		JobID:  jobID,
		Actor:  r.Header.Get("User-Agent"),
		Detail: detail,
	})
}

// decodeJSON reads exactly one JSON value from a size-limited body into v.
// It writes the appropriate error response and returns false on failure.
func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.writeError(w, codeBodyTooLarge, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		h.writeError(w, codeInvalidJSON, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}
