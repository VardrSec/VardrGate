package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/store"
)

func newJobHandler(apiKey string) (*Handler, store.Store) {
	st := store.NewMemory()
	eng := engine.New(&stubExecutor{responses: map[string]int{}})
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), eng, st, apiKey)
	return h, st
}

func do(h *Handler, method, path, auth string, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

func createJob(t *testing.T, h *Handler, auth string) store.Job {
	t.Helper()
	body := `{"tool_type":"vardrgate_api_test","program_id":"p1","config":{"test_case":{"id":"x"}}}`
	rr := do(h, http.MethodPost, "/jobs", auth, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create job: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var job store.Job
	if err := json.NewDecoder(rr.Body).Decode(&job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	return job
}

func TestJobs_FullLifecycle(t *testing.T) {
	h, _ := newJobHandler("")

	job := createJob(t, h, "")
	if job.Status != store.StatusPending {
		t.Fatalf("expected pending, got %q", job.Status)
	}

	// Pending list contains it.
	rr := do(h, http.MethodGet, "/jobs/pending", "", "")
	var pending struct {
		Jobs []store.Job `json:"jobs"`
	}
	json.NewDecoder(rr.Body).Decode(&pending)
	if len(pending.Jobs) != 1 || pending.Jobs[0].ID != job.ID {
		t.Fatalf("expected job in pending list, got %+v", pending.Jobs)
	}

	// Claim succeeds, second claim conflicts.
	if rr := do(h, http.MethodPost, "/jobs/"+job.ID+"/claim", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("claim: expected 200, got %d", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/jobs/"+job.ID+"/claim", "", ""); rr.Code != http.StatusConflict {
		t.Fatalf("second claim: expected 409, got %d", rr.Code)
	}

	// Event, upload result, mark done.
	if rr := do(h, http.MethodPost, "/jobs/"+job.ID+"/events", "", `{"kind":"running","text":"go"}`); rr.Code != http.StatusOK {
		t.Fatalf("event: expected 200, got %d", rr.Code)
	}
	if rr := do(h, http.MethodPost, "/jobs/"+job.ID+"/upload", "", `{"test_case_id":"x","findings":[]}`); rr.Code != http.StatusOK {
		t.Fatalf("upload: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr := do(h, http.MethodPost, "/jobs/"+job.ID+"/done", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("done: expected 200, got %d", rr.Code)
	}

	// Fetch reflects final state.
	rr = do(h, http.MethodGet, "/jobs/"+job.ID, "", "")
	var got store.Job
	json.NewDecoder(rr.Body).Decode(&got)
	if got.Status != store.StatusDone {
		t.Errorf("expected done, got %q", got.Status)
	}
	if string(got.Result) != `{"test_case_id":"x","findings":[]}` {
		t.Errorf("result not stored: %s", got.Result)
	}
	if len(got.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(got.Events))
	}
}

func TestJobs_PatchCompletion(t *testing.T) {
	h, _ := newJobHandler("")
	job := createJob(t, h, "")
	do(h, http.MethodPost, "/jobs/"+job.ID+"/claim", "", "")
	rr := do(h, http.MethodPatch, "/jobs/"+job.ID, "", `{"status":"failed","error_message":"boom"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d", rr.Code)
	}
	got, _ := storeGet(h, job.ID)
	if got.Status != store.StatusFailed || got.ErrorMessage != "boom" {
		t.Errorf("expected failed/boom, got %q/%q", got.Status, got.ErrorMessage)
	}
}

func TestJobs_PatchInvalidStatus(t *testing.T) {
	h, _ := newJobHandler("")
	job := createJob(t, h, "")
	rr := do(h, http.MethodPatch, "/jobs/"+job.ID, "", `{"status":"banana"}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
}

func TestJobs_ClaimNotFound(t *testing.T) {
	h, _ := newJobHandler("")
	rr := do(h, http.MethodPost, "/jobs/ghost/claim", "", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestJobs_UploadRejectsNonJSON(t *testing.T) {
	h, _ := newJobHandler("")
	job := createJob(t, h, "")
	rr := do(h, http.MethodPost, "/jobs/"+job.ID+"/upload", "", "not json")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestJobs_CreateRequiresToolType(t *testing.T) {
	h, _ := newJobHandler("")
	rr := do(h, http.MethodPost, "/jobs", "", `{"program_id":"p"}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
}

func TestHeartbeat(t *testing.T) {
	h, st := newJobHandler("")
	rr := do(h, http.MethodPost, "/runner/heartbeat", "", `{"hostname":"box-1","version":"1.0","tools":["vardrgate"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if len(st.Runners()) != 1 {
		t.Errorf("expected runner registered")
	}
}

func TestHeartbeat_RequiresHostname(t *testing.T) {
	h, _ := newJobHandler("")
	rr := do(h, http.MethodPost, "/runner/heartbeat", "", `{"version":"1.0"}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
}

func TestAuth_RequiredWhenKeySet(t *testing.T) {
	h, _ := newJobHandler("s3cr3t")

	// No token → 401.
	if rr := do(h, http.MethodGet, "/jobs/pending", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: expected 401, got %d", rr.Code)
	}
	// Wrong token → 401.
	if rr := do(h, http.MethodGet, "/jobs/pending", "wrong", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: expected 401, got %d", rr.Code)
	}
	// Correct token → 200.
	if rr := do(h, http.MethodGet, "/jobs/pending", "s3cr3t", ""); rr.Code != http.StatusOK {
		t.Fatalf("correct token: expected 200, got %d", rr.Code)
	}
}

func TestAuth_OpenEndpointsUnaffectedByKey(t *testing.T) {
	h, _ := newJobHandler("s3cr3t")
	// /health needs no token even when a key is configured.
	if rr := do(h, http.MethodGet, "/health", "", ""); rr.Code != http.StatusOK {
		t.Fatalf("/health: expected 200, got %d", rr.Code)
	}
}

func TestJobs_UploadMultipart(t *testing.T) {
	h, _ := newJobHandler("")
	job := createJob(t, h, "")

	var buf bytes.Buffer
	boundary := "BOUND"
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"result.json\"\r\n")
	buf.WriteString("Content-Type: application/json\r\n\r\n")
	buf.WriteString(`{"findings":[]}`)
	buf.WriteString("\r\n--" + boundary + "--\r\n")

	r := httptest.NewRequest(http.MethodPost, "/jobs/"+job.ID+"/upload", &buf)
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("multipart upload: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	got, _ := storeGet(h, job.ID)
	if string(got.Result) != `{"findings":[]}` {
		t.Errorf("multipart result not stored: %s", got.Result)
	}
}

// storeGet reaches the handler's store for assertions.
func storeGet(h *Handler, id string) (store.Job, bool) {
	return h.store.Get(id)
}

func TestAudit_RecordsLifecycleAndEndpointReturnsIt(t *testing.T) {
	h, _ := newJobHandler("")

	job := createJob(t, h, "")
	do(h, http.MethodPost, "/jobs/"+job.ID+"/claim", "", "")
	do(h, http.MethodPost, "/jobs/"+job.ID+"/upload", "", `{"findings":[]}`)
	do(h, http.MethodPost, "/jobs/"+job.ID+"/done", "", "")
	do(h, http.MethodPost, "/runner/heartbeat", "", `{"hostname":"box-1"}`)

	rr := do(h, http.MethodGet, "/audit", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("audit: expected 200, got %d", rr.Code)
	}
	var resp struct {
		Audit []store.AuditEntry `json:"audit"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	got := make(map[string]bool)
	for _, e := range resp.Audit {
		got[e.Action] = true
	}
	for _, want := range []string{
		"job_created", "job_claimed", "job_result_uploaded", "job_completed", "runner_heartbeat",
	} {
		if !got[want] {
			t.Errorf("audit log missing action %q; got %+v", want, resp.Audit)
		}
	}
}

func TestAudit_LimitParam(t *testing.T) {
	h, _ := newJobHandler("")
	createJob(t, h, "")
	createJob(t, h, "")
	createJob(t, h, "")

	rr := do(h, http.MethodGet, "/audit?limit=2", "", "")
	var resp struct {
		Audit []store.AuditEntry `json:"audit"`
	}
	json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Audit) != 2 {
		t.Fatalf("expected 2 entries with limit=2, got %d", len(resp.Audit))
	}
}

func TestAudit_RequiresAuthWhenKeySet(t *testing.T) {
	h, _ := newJobHandler("s3cr3t")
	if rr := do(h, http.MethodGet, "/audit", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rr.Code)
	}
}
