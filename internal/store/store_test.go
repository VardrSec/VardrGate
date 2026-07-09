package store

import (
	"encoding/json"
	"testing"
)

func TestCreate_AssignsIDAndPending(t *testing.T) {
	m := NewMemory()
	j, err := m.Create(Job{ToolType: "vardrgate_api_test", ProgramID: "p1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if j.ID == "" {
		t.Error("expected generated id")
	}
	if j.Status != StatusPending {
		t.Errorf("expected pending, got %q", j.Status)
	}
	if j.CreatedAt.IsZero() {
		t.Error("expected created_at set")
	}
}

func TestPending_OnlyPendingSortedByCreation(t *testing.T) {
	m := NewMemory()
	a, _ := m.Create(Job{ProgramID: "p"})
	b, _ := m.Create(Job{ProgramID: "p"})
	if _, err := m.Claim(a.ID, "r1"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	pending := m.Pending()
	if len(pending) != 1 || pending[0].ID != b.ID {
		t.Fatalf("expected only b pending, got %+v", pending)
	}
}

func TestClaim_AtomicAndRejectsDouble(t *testing.T) {
	m := NewMemory()
	j, _ := m.Create(Job{ProgramID: "p"})

	if _, err := m.Claim(j.ID, "r1"); err != nil {
		t.Fatalf("first claim should succeed: %v", err)
	}
	_, err := m.Claim(j.ID, "r2")
	if err != ErrAlreadyClaimed {
		t.Fatalf("expected ErrAlreadyClaimed, got %v", err)
	}
}

func TestClaim_NotFound(t *testing.T) {
	if _, err := NewMemory().Claim("ghost", "r"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAppendEvent_RunningAdvancesStatus(t *testing.T) {
	m := NewMemory()
	j, _ := m.Create(Job{ProgramID: "p"})
	_, _ = m.Claim(j.ID, "r1")
	if err := m.AppendEvent(j.ID, Event{Kind: "running", Text: "go"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, _ := m.Get(j.ID)
	if got.Status != StatusRunning {
		t.Errorf("expected running, got %q", got.Status)
	}
	if len(got.Events) != 1 || got.Events[0].At.IsZero() {
		t.Errorf("event not recorded with timestamp: %+v", got.Events)
	}
}

func TestSetResultAndComplete(t *testing.T) {
	m := NewMemory()
	j, _ := m.Create(Job{ProgramID: "p"})
	_, _ = m.Claim(j.ID, "r1")
	if err := m.SetResult(j.ID, json.RawMessage(`{"findings":[]}`)); err != nil {
		t.Fatalf("set result: %v", err)
	}
	if err := m.Complete(j.ID, StatusDone, ""); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, _ := m.Get(j.ID)
	if got.Status != StatusDone {
		t.Errorf("expected done, got %q", got.Status)
	}
	if string(got.Result) != `{"findings":[]}` {
		t.Errorf("result not stored: %s", got.Result)
	}
}

func TestComplete_RejectsInvalidStatus(t *testing.T) {
	m := NewMemory()
	j, _ := m.Create(Job{ProgramID: "p"})
	if err := m.Complete(j.ID, "banana", ""); err != ErrInvalidStatus {
		t.Fatalf("expected ErrInvalidStatus, got %v", err)
	}
}

func TestComplete_Failed_CarriesError(t *testing.T) {
	m := NewMemory()
	j, _ := m.Create(Job{ProgramID: "p"})
	if err := m.Complete(j.ID, StatusFailed, "boom"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, _ := m.Get(j.ID)
	if got.ErrorMessage != "boom" {
		t.Errorf("expected error message, got %q", got.ErrorMessage)
	}
}

func TestHeartbeat_UpsertsAndLists(t *testing.T) {
	m := NewMemory()
	m.Heartbeat(RunnerInfo{Hostname: "box-1", Version: "1.0", Tools: []string{"vardrgate"}})
	m.Heartbeat(RunnerInfo{Hostname: "box-1", Version: "1.1"}) // upsert
	m.Heartbeat(RunnerInfo{Hostname: "box-2"})
	runners := m.Runners()
	if len(runners) != 2 {
		t.Fatalf("expected 2 runners, got %d", len(runners))
	}
	if runners[0].Hostname != "box-1" || runners[0].Version != "1.1" {
		t.Errorf("expected upserted box-1 v1.1 first, got %+v", runners[0])
	}
	if runners[0].LastSeen.IsZero() {
		t.Error("expected last_seen set")
	}
}
