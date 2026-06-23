package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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
	TestCaseID string                  `json:"test_case_id"`
	Executions []model.ExecutionResult `json:"executions"`
	Findings   []model.Finding         `json:"findings"`
}

// Run validates the test case, executes the request for each identity,
// evaluates expected versus observed access, and returns findings.
func (e *Engine) Run(ctx context.Context, tc model.AuthorizationTestCase) (Result, error) {
	if err := validate(tc); err != nil {
		return Result{}, err
	}

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

// evaluate compares the observed outcome against the expected decision.
// Findings are only emitted for clear allow/deny signals; ambiguous outcomes
// (404, 5xx, redirect) are not classified as authorization decisions.
func evaluate(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, expected model.AccessDecision) (model.Finding, bool) {
	if exec.Error != "" {
		return model.Finding{}, false
	}

	// Use the classified outcome set by the executor; fall back to classification
	// when the executor did not set it (e.g. test stubs that only set StatusCode).
	outcome := exec.ObservedOutcome
	if outcome == "" {
		outcome = model.ClassifyOutcome(exec.StatusCode, false)
	}

	switch {
	case expected == model.AccessDecisionDeny && outcome == model.OutcomeAllow:
		return unexpectedAccessFinding(tc, identity, exec, outcome), true
	case expected == model.AccessDecisionAllow && outcome == model.OutcomeDeny:
		return accessDeniedFinding(tc, identity, exec, outcome), true
	default:
		// Ambiguous outcomes (not_found, server_error, redirect, client_error)
		// are not sufficient to classify an authorization finding alone.
		return model.Finding{}, false
	}
}

// unexpectedAccessFinding emits an unexpected_access finding.
// potential_bola requires explicit resource-ownership context (owner identity,
// target tenant, object ID) that is not yet modelled; TenantID alone is
// insufficient to establish a cross-tenant object-access relationship.
func unexpectedAccessFinding(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, outcome model.ObservedOutcome) model.Finding {
	return model.Finding{
		Category:   model.CategoryUnexpectedAccess,
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceMedium,
		IdentityID: identity.ID,
		Message:    fmt.Sprintf("identity %q received access that should have been denied", identity.ID),
		DetectedAt: time.Now().UTC(),
		Evidence:   buildEvidence(tc, identity, exec, outcome),
	}
}

func accessDeniedFinding(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, outcome model.ObservedOutcome) model.Finding {
	return model.Finding{
		Category:   model.CategoryAuthorizationMismatch,
		Severity:   model.SeverityLow,
		Confidence: model.ConfidenceHigh,
		IdentityID: identity.ID,
		Message:    fmt.Sprintf("identity %q was denied access that should have been allowed", identity.ID),
		DetectedAt: time.Now().UTC(),
		Evidence:   buildEvidence(tc, identity, exec, outcome),
	}
}

func buildEvidence(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, outcome model.ObservedOutcome) []string {
	return []string{
		fmt.Sprintf("observed_outcome=%s", outcome),
		fmt.Sprintf("status_code=%d", exec.StatusCode),
		fmt.Sprintf("identity_id=%s", identity.ID),
		fmt.Sprintf("url=%s %s", tc.Request.Method, sanitizeURL(tc.Request.URL)),
	}
}

// sensitiveQueryParams are redacted from URLs appearing in evidence strings.
var sensitiveQueryParams = []string{
	"api_key", "apikey", "token", "access_token",
	"secret", "key", "password", "auth", "authorization",
}

// sanitizeURL removes known sensitive query parameters from URLs before
// they are written into evidence strings.
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid-url]"
	}
	q := u.Query()
	redacted := false
	for _, p := range sensitiveQueryParams {
		if q.Has(p) {
			q.Set(p, "[REDACTED]")
			redacted = true
		}
	}
	if redacted {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// validate ensures the test case has the minimum required fields.
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
