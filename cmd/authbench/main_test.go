package main

import (
	"encoding/json"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

func TestScoringDoesNotHideInconclusiveMisses(t *testing.T) {
	s := scenario{Actor: "bob", Decision: model.AccessDecisionDeny, Violation: true}
	result := engine.Result{Executions: []model.ExecutionResult{{IdentityID: "bob", StatusCode: 500, ObservedOutcome: model.OutcomeServerError}}}
	verdict, inconclusive := classify(s, result)
	if verdict != "false_negative" || !inconclusive {
		t.Fatalf("got %s, inconclusive=%v", verdict, inconclusive)
	}
	m := summarize([]assessment{{Scenario: s, Verdict: verdict, Inconclusive: inconclusive}})
	if m.FN != 1 || m.Inconclusive != 1 || m.KnownFailures != 1 || m.Recall != 0 || m.TN != 0 {
		t.Fatalf("incorrect metrics: %+v", m)
	}
}

func TestScoringRequiresMatchingIdentityAndCategory(t *testing.T) {
	s := scenario{Actor: "bob", Decision: model.AccessDecisionDeny, Violation: true}
	result := engine.Result{
		Executions: []model.ExecutionResult{{IdentityID: "bob", StatusCode: 200, ObservedOutcome: model.OutcomeAllow}},
		Findings:   []model.Finding{{IdentityID: "alice", Category: model.CategoryUnexpectedAccess}, {IdentityID: "bob", Category: model.CategoryAuthorizationMismatch}},
	}
	verdict, _ := classify(s, result)
	if verdict != "false_negative" {
		t.Fatalf("unrelated finding credited as detection: %s", verdict)
	}
}

func TestLiveLabAndScoring(t *testing.T) {
	rows, err := runSuite()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 22 {
		t.Fatalf("got %d assessments", len(rows))
	}
	m := summarize(rows)
	if m.TP != 6 || m.FP != 2 || m.FN != 3 || m.TN != 6 || m.Inconclusive != 7 {
		t.Fatalf("legacy behavior changed: %+v", m)
	}
	// Structural invariants allow future engine improvements without pinning bugs.
	if m.TP+m.FN != m.KnownFailures || m.KnownFailures != 9 {
		t.Fatalf("failures missing from recall: %+v", m)
	}
	if m.TP+m.FP+m.FN+m.TN+m.InconclusiveControls != m.Total {
		t.Fatalf("assessments unaccounted for: %+v", m)
	}
	for _, row := range rows {
		var result engine.Result
		if err := json.Unmarshal(row.Gate, &result); err != nil {
			t.Fatal(err)
		}
		switch row.Scenario.ID {
		case "bola-peer", "bola-cross-tenant", "bola-anonymous", "admin-role-bypass", "write-bypass", "owner-wrongly-denied":
			if row.Verdict != "true_positive" {
				t.Errorf("%s: expected detection, got %s", row.Scenario.ID, row.Verdict)
			}
		case "write-before-500":
			if row.Oracle.Writes != 1 || row.Oracle.DocumentBefore == row.Oracle.DocumentAfter || row.Oracle.Status != 500 {
				t.Errorf("mutation evidence missing: %+v", row.Oracle)
			}
		case "write-protected":
			if row.Oracle.Writes != 0 || row.Oracle.Accessed {
				t.Error("protected write mutated data")
			}
		case "connection-aborted":
			if !row.Inconclusive || result.Executions[0].ErrorKind != model.ErrorKindNetwork {
				t.Error("network failure was not inconclusive")
			}
		}
	}
}

func TestAssertionBenchmarkRegressionBudget(t *testing.T) {
	rows, err := runSuiteWithAssertions(true)
	if err != nil {
		t.Fatal(err)
	}
	m := summarize(rows)
	if m.Total != 22 || m.KnownFailures != 9 || m.TP < 8 || m.FP != 0 || m.FN > 1 || m.Inconclusive > 6 {
		t.Fatalf("accuracy regression: %+v", m)
	}
	for _, row := range rows {
		switch row.Scenario.ID {
		case "soft-denial-200", "filtered-empty-200":
			if row.Verdict != "true_negative" {
				t.Errorf("%s remains a false alarm or became inconclusive", row.Scenario.ID)
			}
		case "secret-in-403", "secret-in-404":
			if row.Verdict != "true_positive" || row.Inconclusive {
				t.Errorf("%s disclosure not detected conclusively", row.Scenario.ID)
			}
		case "write-before-500":
			if row.Verdict != "false_negative" || !row.Inconclusive {
				t.Error("unverified write must remain a measured miss")
			}
		}
	}
	groups := summarizeGroups(rows)
	if groups["unauthorized_reads"].KnownFailures != 6 || groups["unauthorized_writes"].KnownFailures != 2 || groups["legitimate_access"].KnownFailures != 1 {
		t.Fatalf("incorrect split: %+v", groups)
	}
}
