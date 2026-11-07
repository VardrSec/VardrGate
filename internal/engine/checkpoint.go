package engine

import (
	"context"
	"maps"

	"github.com/VardrSec/vardrgate/internal/model"
)

// RunWithCheckpoint synchronously preserves guarded local progress before each
// resource identity. The callback receives a copy, never permission or a final result.
func (e *Engine) RunWithCheckpoint(ctx context.Context, tc model.AuthorizationTestCase, checkpoint func(Result) error) (Result, error) {
	return e.run(ctx, tc, checkpoint)
}

func checkpointResult(tc model.AuthorizationTestCase, preflight []model.PreflightResult, completed map[string]model.ExecutionResult) Result {
	r := Result{TestCaseID: tc.ID, Error: "execution_in_progress", Executions: []model.ExecutionResult{}, Findings: []model.Finding{}, Assessments: []model.Assessment{}, Preflight: append([]model.PreflightResult(nil), preflight...)}
	for index, identity := range tc.Identities {
		ex, reached := completed[identity.ID]
		if !reached {
			ex = model.ExecutionResult{IdentityID: identity.ID, ObservedOutcome: model.OutcomeError, Error: "execution_in_progress"}
		}
		ea, expected := expectedFor(tc, identity.ID)
		a := demoteRejectedCredential(tc, identity, ex, assess(identity.ID, ex, ea, expected))
		a.CredentialStatus = credentialStatus(identity, preflight, ex)
		a.ExecutionIndex, a.WriteVerification = &index, "not_configured"
		if !reached && a.Decision == model.AssessmentInconclusive {
			a.Reason = "execution_in_progress"
		}
		// A write's response cannot stand in for unfinished readback/control work.
		if tc.WriteVerification != nil && a.Decision != model.AssessmentSkipped {
			a.Decision, a.Source, a.Reason, a.WriteVerification = model.AssessmentInconclusive, "none", "execution_in_progress", "inconclusive"
		}
		ex.Body, ex.Headers = nil, maps.Clone(ex.Headers)
		if ex.ResponseProfile != nil {
			profile := *ex.ResponseProfile
			profile.Fields = append([]string(nil), profile.Fields...)
			ex.ResponseProfile = &profile
		}
		if reached && ex.Error != "" {
			ex.Error = "execution_error" // Never persist a raw transport URL/error.
		}
		r.Executions, r.Assessments = append(r.Executions, ex), append(r.Assessments, a)
	}
	return r
}
