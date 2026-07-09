package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)
)

// SQLite is a durable Store backed by a SQLite database file. Jobs survive a
// process restart. It implements the same Store interface as Memory, so it is a
// drop-in replacement selected at startup.
//
// Jobs and runners are stored as JSON documents keyed by id/hostname, with the
// few fields the queue needs to sort and filter (status, created_at) promoted to
// columns. A single mutex serializes access; the queue's throughput needs are
// modest and this keeps the SQLite access free of "database is locked" races.
// A PostgreSQL implementation of Store can replace this without touching callers.
type SQLite struct {
	mu  sync.Mutex
	db  *sql.DB
	now func() time.Time
}

// NewSQLite opens (creating if needed) a SQLite-backed store at path.
// Use ":memory:" for an ephemeral database.
func NewSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Serialize access; SQLite allows one writer at a time.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	schema := `
CREATE TABLE IF NOT EXISTS jobs (
	id         TEXT PRIMARY KEY,
	status     TEXT NOT NULL,
	created_at TEXT NOT NULL,
	data       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE TABLE IF NOT EXISTS runners (
	hostname TEXT PRIMARY KEY,
	data     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	seq    INTEGER PRIMARY KEY AUTOINCREMENT,
	at     TEXT NOT NULL,
	action TEXT NOT NULL,
	job_id TEXT,
	actor  TEXT,
	detail TEXT
);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &SQLite{db: db, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Close releases the underlying database handle.
func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) Create(job Job) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if job.ID == "" {
		job.ID = newID()
	}
	var exists int
	if err := s.db.QueryRow(`SELECT 1 FROM jobs WHERE id = ?`, job.ID).Scan(&exists); err != sql.ErrNoRows {
		if err == nil {
			return Job{}, fmt.Errorf("job id already exists")
		}
		return Job{}, err
	}
	now := s.now()
	job.Status = StatusPending
	job.CreatedAt = now
	job.UpdatedAt = now
	if err := s.insert(job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (s *SQLite) Get(id string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.load(id)
	if err != nil {
		return Job{}, false
	}
	return job, true
}

func (s *SQLite) Pending() []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT data FROM jobs WHERE status = ? ORDER BY created_at, id`, StatusPending)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var j Job
		if err := json.Unmarshal([]byte(data), &j); err == nil {
			out = append(out, j)
		}
	}
	return out
}

func (s *SQLite) Claim(id, runner string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.load(id)
	if err == sql.ErrNoRows {
		return Job{}, ErrNotFound
	} else if err != nil {
		return Job{}, err
	}
	if job.Status != StatusPending {
		return Job{}, ErrAlreadyClaimed
	}
	job.Status = StatusClaimed
	job.ClaimedBy = runner
	job.UpdatedAt = s.now()
	if err := s.update(job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (s *SQLite) AppendEvent(id string, ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.load(id)
	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if ev.At.IsZero() {
		ev.At = s.now()
	}
	job.Events = append(job.Events, ev)
	if ev.Kind == "running" && job.Status == StatusClaimed {
		job.Status = StatusRunning
	}
	job.UpdatedAt = s.now()
	return s.update(job)
}

func (s *SQLite) SetResult(id string, result json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.load(id)
	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	job.Result = result
	job.UpdatedAt = s.now()
	return s.update(job)
}

func (s *SQLite) Complete(id, status, errMsg string) error {
	if status != StatusDone && status != StatusFailed {
		return ErrInvalidStatus
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.load(id)
	if err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	job.Status = status
	job.ErrorMessage = errMsg
	job.UpdatedAt = s.now()
	return s.update(job)
}

func (s *SQLite) Heartbeat(info RunnerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info.LastSeen.IsZero() {
		info.LastSeen = s.now()
	}
	data, err := json.Marshal(info)
	if err != nil {
		return
	}
	_, _ = s.db.Exec(
		`INSERT INTO runners(hostname, data) VALUES(?, ?)
		 ON CONFLICT(hostname) DO UPDATE SET data = excluded.data`,
		info.Hostname, string(data),
	)
}

func (s *SQLite) Runners() []RunnerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT data FROM runners ORDER BY hostname`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []RunnerInfo{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var r RunnerInfo
		if err := json.Unmarshal([]byte(data), &r); err == nil {
			out = append(out, r)
		}
	}
	return out
}

func (s *SQLite) Audit(entry AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.At.IsZero() {
		entry.At = s.now()
	}
	_, _ = s.db.Exec(
		`INSERT INTO audit(at, action, job_id, actor, detail) VALUES(?, ?, ?, ?, ?)`,
		entry.At.Format(time.RFC3339Nano), entry.Action, entry.JobID, entry.Actor, entry.Detail,
	)
}

func (s *SQLite) AuditLog(limit int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Fetch the newest rows, then reverse to oldest→newest for a stable timeline.
	query := `SELECT at, action, job_id, actor, detail FROM audit ORDER BY seq DESC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var desc []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at string
		var jobID, actor, detail sql.NullString
		if err := rows.Scan(&at, &e.Action, &jobID, &actor, &detail); err != nil {
			continue
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		e.JobID, e.Actor, e.Detail = jobID.String, actor.String, detail.String
		desc = append(desc, e)
	}
	// Reverse to oldest→newest.
	for i, j := 0, len(desc)-1; i < j; i, j = i+1, j-1 {
		desc[i], desc[j] = desc[j], desc[i]
	}
	return desc
}

// load reads and decodes a job. Returns sql.ErrNoRows when absent.
func (s *SQLite) load(id string) (Job, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM jobs WHERE id = ?`, id).Scan(&data); err != nil {
		return Job{}, err
	}
	var j Job
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return Job{}, err
	}
	return j, nil
}

func (s *SQLite) insert(job Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO jobs(id, status, created_at, data) VALUES(?, ?, ?, ?)`,
		job.ID, job.Status, job.CreatedAt.Format(time.RFC3339Nano), string(data),
	)
	return err
}

func (s *SQLite) update(job Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`UPDATE jobs SET status = ?, data = ? WHERE id = ?`,
		job.Status, string(data), job.ID,
	)
	return err
}
