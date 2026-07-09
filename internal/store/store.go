// Package store holds the job queue that VardrRunner drives: jobs are enqueued,
// runners poll and claim them, stream events, upload results, and mark them
// done or failed.
//
// The data model is defined here behind a Store interface with an in-memory
// implementation. Persistence (PostgreSQL) is a later Phase 3 step; modelling
// the queue first — as enterprise-platform.md directs ("add storage only after
// the data model is clear enough to survive enterprise use") — lets the runner
// lifecycle be built and tested end to end before a database is introduced.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Job lifecycle statuses.
const (
	StatusPending = "pending"
	StatusClaimed = "claimed"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// Sentinel errors returned by Store operations.
var (
	ErrNotFound       = errors.New("job not found")
	ErrAlreadyClaimed = errors.New("job already claimed")
	ErrInvalidStatus  = errors.New("invalid status")
)

// Event is a single lifecycle event streamed by a runner.
type Event struct {
	Kind string    `json:"kind"`
	Text string    `json:"text,omitempty"`
	At   time.Time `json:"at"`
}

// Job is a unit of work for a runner. Config carries the opaque tool config
// (for vardrgate_api_test jobs, a job.Config with test_case and execution).
type Job struct {
	ID           string          `json:"id"`
	ToolType     string          `json:"tool_type"`
	TargetSource string          `json:"target_source"`
	ProgramID    string          `json:"program_id"`
	Config       json.RawMessage `json:"config,omitempty"`
	Status       string          `json:"status"`
	ErrorMessage string          `json:"error_message,omitempty"`
	ClaimedBy    string          `json:"claimed_by,omitempty"`
	Events       []Event         `json:"events,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// RunnerInfo is the last-reported status of a runner (from heartbeats).
type RunnerInfo struct {
	Hostname string    `json:"hostname"`
	Version  string    `json:"version,omitempty"`
	OS       string    `json:"os,omitempty"`
	Tools    []string  `json:"tools,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// Store is the job queue and runner registry.
type Store interface {
	Create(job Job) (Job, error)
	Get(id string) (Job, bool)
	Pending() []Job
	Claim(id, runner string) (Job, error)
	AppendEvent(id string, ev Event) error
	SetResult(id string, result json.RawMessage) error
	Complete(id, status, errMsg string) error
	Heartbeat(info RunnerInfo)
	Runners() []RunnerInfo
}

// Memory is a thread-safe in-memory Store. It is the default backend until a
// persistent implementation is added.
type Memory struct {
	mu      sync.Mutex
	jobs    map[string]*Job
	runners map[string]RunnerInfo
	now     func() time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		jobs:    make(map[string]*Job),
		runners: make(map[string]RunnerInfo),
		now:     func() time.Time { return time.Now().UTC() },
	}
}

func (m *Memory) Create(job Job) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if job.ID == "" {
		job.ID = newID()
	}
	if _, exists := m.jobs[job.ID]; exists {
		return Job{}, errors.New("job id already exists")
	}
	now := m.now()
	job.Status = StatusPending
	job.CreatedAt = now
	job.UpdatedAt = now
	stored := job
	m.jobs[job.ID] = &stored
	return stored, nil
}

func (m *Memory) Get(id string) (Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, false
	}
	return *j, true
}

func (m *Memory) Pending() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Job
	for _, j := range m.jobs {
		if j.Status == StatusPending {
			out = append(out, *j)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].CreatedAt.Before(out[k].CreatedAt) })
	return out
}

func (m *Memory) Claim(id, runner string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, ErrNotFound
	}
	if j.Status != StatusPending {
		return Job{}, ErrAlreadyClaimed
	}
	j.Status = StatusClaimed
	j.ClaimedBy = runner
	j.UpdatedAt = m.now()
	return *j, nil
}

func (m *Memory) AppendEvent(id string, ev Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if ev.At.IsZero() {
		ev.At = m.now()
	}
	j.Events = append(j.Events, ev)
	// A "running" event advances a claimed job's status for observability.
	if ev.Kind == "running" && j.Status == StatusClaimed {
		j.Status = StatusRunning
	}
	j.UpdatedAt = m.now()
	return nil
}

func (m *Memory) SetResult(id string, result json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	j.Result = result
	j.UpdatedAt = m.now()
	return nil
}

func (m *Memory) Complete(id, status, errMsg string) error {
	if status != StatusDone && status != StatusFailed {
		return ErrInvalidStatus
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	j.Status = status
	j.ErrorMessage = errMsg
	j.UpdatedAt = m.now()
	return nil
}

func (m *Memory) Heartbeat(info RunnerInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info.LastSeen.IsZero() {
		info.LastSeen = m.now()
	}
	m.runners[info.Hostname] = info
}

func (m *Memory) Runners() []RunnerInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RunnerInfo, 0, len(m.runners))
	for _, r := range m.runners {
		out = append(out, r)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Hostname < out[k].Hostname })
	return out
}

// newID returns a random 128-bit hex identifier prefixed for readability.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is not recoverable in practice; fall back to time.
		return "job_" + hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return "job_" + hex.EncodeToString(b[:])
}
