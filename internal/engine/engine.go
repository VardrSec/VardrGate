package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
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
	TestCaseID  string                  `json:"test_case_id"`
	Executions  []model.ExecutionResult `json:"executions"`
	Findings    []model.Finding         `json:"findings"`
	Assessments []model.Assessment      `json:"assessments"`
}

// Run validates the test case, executes the request for each identity,
// evaluates expected versus observed access, and returns findings.
func (e *Engine) Run(ctx context.Context, tc model.AuthorizationTestCase) (Result, error) {
	if err := validate(tc); err != nil {
		return Result{}, err
	}

	expected := make(map[string]model.ExpectedAccess, len(tc.ExpectedAccess))
	for _, ea := range tc.ExpectedAccess {
		expected[ea.IdentityID] = ea
	}

	result := Result{TestCaseID: tc.ID}

	for _, identity := range tc.Identities {
		exec := e.exec.Execute(ctx, identity, tc.Request)
		result.Executions = append(result.Executions, exec)

		ea, hasExpected := expected[identity.ID]
		assessment := assess(identity.ID, exec, ea, hasExpected)
		result.Assessments = append(result.Assessments, assessment)
		if assessment.Decision == model.AssessmentSkipped || assessment.Decision == model.AssessmentInconclusive {
			continue
		}

		// Retain the raw execution and legacy finding evidence. Only the copy
		// used for evaluation receives the assertion-derived decision.
		evaluated := exec
		if assessment.Decision == model.AssessmentAllowed {
			evaluated.ObservedOutcome = model.OutcomeAllow
		} else {
			evaluated.ObservedOutcome = model.OutcomeDeny
		}
		finding, ok := evaluate(tc, identity, evaluated, ea.Decision)
		if ok {
			if assessment.Source == "response_assertion" {
				finding.Confidence = model.ConfidenceHigh
				finding.Evidence = buildEvidence(tc, identity, exec, exec.ObservedOutcome)
				finding.Evidence = append(finding.Evidence, "assessment="+string(assessment.Decision), "source=response_assertion", fmt.Sprintf("matched_assertions=%v", assessment.MatchedAssertions))
			}
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

	if u.User != nil {
		u.User = url.User("REDACTED")
	}

	q := u.Query()
	redacted := false
	for key := range q {
		if isSensitiveQueryParam(key) {
			q.Set(key, "[REDACTED]")
			redacted = true
		}
	}
	if redacted {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func isSensitiveQueryParam(key string) bool {
	for _, p := range sensitiveQueryParams {
		if strings.EqualFold(key, p) {
			return true
		}
	}
	return false
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

	identityIDs := make(map[string]struct{}, len(tc.Identities))
	for i, identity := range tc.Identities {
		if identity.ID == "" {
			return fmt.Errorf("identities[%d] must have an id", i)
		}
		if _, exists := identityIDs[identity.ID]; exists {
			return fmt.Errorf("identities[%d] has duplicate id %q", i, identity.ID)
		}
		identityIDs[identity.ID] = struct{}{}

		if err := validateCredential(i, identity.Credential); err != nil {
			return err
		}
	}

	expectedIDs := make(map[string]struct{}, len(tc.ExpectedAccess))
	for i, ea := range tc.ExpectedAccess {
		if ea.IdentityID == "" {
			return fmt.Errorf("expected_access[%d] must reference an identity_id", i)
		}
		if _, exists := identityIDs[ea.IdentityID]; !exists {
			return fmt.Errorf("expected_access[%d] references unknown identity_id %q", i, ea.IdentityID)
		}
		if _, exists := expectedIDs[ea.IdentityID]; exists {
			return fmt.Errorf("expected_access[%d] duplicates identity_id %q", i, ea.IdentityID)
		}
		expectedIDs[ea.IdentityID] = struct{}{}
		switch ea.Decision {
		case model.AccessDecisionAllow, model.AccessDecisionDeny, model.AccessDecisionSkip:
		default:
			return fmt.Errorf("expected_access[%d] has invalid decision %q", i, ea.Decision)
		}
		if err := validateAssertions(ea.ResponseAssertions); err != nil {
			return fmt.Errorf("expected_access[%d]: %w", i, err)
		}
	}
	return nil
}

func validateCredential(identityIndex int, cred model.Credential) error {
	switch cred.Type {
	case model.CredentialTypeBearer:
		if cred.Header != "" {
			return fmt.Errorf("identities[%d].credential.header must be empty for bearer credentials", identityIndex)
		}
		if cred.Value == "" {
			return fmt.Errorf("identities[%d].credential.value is required for bearer credentials", identityIndex)
		}
	case model.CredentialTypeAPIKeyHeader:
		if cred.Value == "" {
			return fmt.Errorf("identities[%d].credential.value is required for api_key_header credentials", identityIndex)
		}
	case model.CredentialTypeStaticHeader:
		if cred.Header == "" && cred.Value != "" {
			return fmt.Errorf("identities[%d].credential.header is required when static_header has a value", identityIndex)
		}
		if cred.Header != "" && cred.Value == "" {
			return fmt.Errorf("identities[%d].credential.value is required when static_header has a header", identityIndex)
		}
	default:
		return fmt.Errorf("identities[%d].credential.type has invalid value %q", identityIndex, cred.Type)
	}
	return nil
}
