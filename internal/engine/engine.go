package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/model"
)

// Executor abstracts HTTP execution so the engine can be tested without a real network.
type Executor interface {
	Execute(ctx context.Context, identity model.Identity, tmpl model.RequestTemplate) model.ExecutionResult
}

// Engine coordinates authorization test execution.
type Engine struct {
	exec Executor
}

// New returns an Engine backed by the provided Executor.
func New(exec Executor) *Engine {
	return &Engine{exec: exec}
}

// DefaultEngine returns an Engine wired to a production HTTP client.
func DefaultEngine() *Engine {
	return New(client.New(nil))
}

// Result is the complete output of a single test case run.
type Result struct {
	TestCaseID string
	Executions []model.ExecutionResult
	Findings   []model.Finding
}

// Run validates the test case, executes the request for each identity,
// evaluates expected versus observed access, and returns findings.
func (e *Engine) Run(ctx context.Context, tc model.AuthorizationTestCase) (Result, error) {
	if err := validate(tc); err != nil {
		return Result{}, err
	}

	// Index expected decisions by identity ID for O(1) lookup.
	expected := make(map[string]model.AccessDecision, len(tc.ExpectedAccess))
	for _, ea := range tc.ExpectedAccess {
		expected[ea.IdentityID] = ea.Decision
	}

	result := Result{TestCaseID: tc.ID}

	for _, identity := range tc.Identities {
		exec := e.exec.Execute(ctx, identity, tc.Request)
		result.Executions = append(result.Executions, exec)

		decision, hasExpected := expected[identity.ID]
		if !hasExpected || decision == model.AccessDecisionSkip {
			continue
		}

		finding, ok := evaluate(tc, identity, exec, decision)
		if ok {
			result.Findings = append(result.Findings, finding)
		}
	}

	return result, nil
}

// evaluate compares the observed result against the expected decision and
// returns a Finding when the behavior warrants one.
func evaluate(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, expected model.AccessDecision) (model.Finding, bool) {
	// Execution errors are evidence but not definitive findings on their own.
	if exec.Error != "" {
		return model.Finding{}, false
	}

	observed := observedDecision(exec.StatusCode)

	if observed == expected {
		return model.Finding{}, false
	}

	finding := model.Finding{
		IdentityID: identity.ID,
		DetectedAt: time.Now().UTC(),
		Evidence: []string{
			fmt.Sprintf("expected=%s observed=%s", expected, observed),
			fmt.Sprintf("status_code=%d", exec.StatusCode),
			fmt.Sprintf("identity=%s", identity.ID),
			fmt.Sprintf("url=%s %s", tc.Request.Method, tc.Request.URL),
		},
	}

	switch {
	case expected == model.AccessDecisionDeny && observed == model.AccessDecisionAllow:
		finding.Category = model.CategoryPotentialBOLA
		finding.Severity = model.SeverityHigh
		finding.Confidence = model.ConfidenceMedium
		finding.Message = fmt.Sprintf(
			"identity %q received access that should have been denied", identity.ID,
		)
	case expected == model.AccessDecisionAllow && observed == model.AccessDecisionDeny:
		finding.Category = model.CategoryAuthorizationMismatch
		finding.Severity = model.SeverityLow
		finding.Confidence = model.ConfidenceHigh
		finding.Message = fmt.Sprintf(
			"identity %q was denied access that should have been allowed", identity.ID,
		)
	default:
		finding.Category = model.CategoryUnexpectedAccess
		finding.Severity = model.SeverityMedium
		finding.Confidence = model.ConfidenceLow
		finding.Message = fmt.Sprintf(
			"identity %q received unexpected access decision (expected %s, got %s)",
			identity.ID, expected, observed,
		)
	}

	return finding, true
}

// observedDecision maps an HTTP status code to an AccessDecision.
// 2xx → allow; 401/403 → deny; anything else → deny (conservative).
func observedDecision(code int) model.AccessDecision {
	if code >= http.StatusOK && code < http.StatusMultipleChoices {
		return model.AccessDecisionAllow
	}
	return model.AccessDecisionDeny
}

// validate ensures the test case has the minimum required fields before execution.
func validate(tc model.AuthorizationTestCase) error {
	if tc.ID == "" {
		return errors.New("test case must have an id")
	}
	if len(tc.Identities) == 0 {
		return errors.New("test case must have at least one identity")
	}
	if tc.Request.Method == "" {
		return errors.New("request template must have a method")
	}
	if tc.Request.URL == "" {
		return errors.New("request template must have a url")
	}
	for i, ea := range tc.ExpectedAccess {
		if ea.IdentityID == "" {
			return fmt.Errorf("expected_access[%d] must reference an identity_id", i)
		}
		switch ea.Decision {
		case model.AccessDecisionAllow, model.AccessDecisionDeny, model.AccessDecisionSkip:
		default:
			return fmt.Errorf("expected_access[%d] has invalid decision %q", i, ea.Decision)
		}
	}
	return nil
}
