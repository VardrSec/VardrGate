package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/compare"
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

	// First pass: execute every identity and index the results so finding
	// evaluation can compare an offending response against a legitimate baseline.
	result := Result{TestCaseID: tc.ID}
	execByID := make(map[string]model.ExecutionResult, len(tc.Identities))
	for _, identity := range tc.Identities {
		exec := e.exec.Execute(ctx, identity, tc.Request)
		result.Executions = append(result.Executions, exec)
		execByID[identity.ID] = exec
	}

	// Second pass: evaluate findings with access to all executions.
	expectedByID := make(map[string]model.ExpectedAccess, len(tc.ExpectedAccess))
	for _, ea := range tc.ExpectedAccess {
		expectedByID[ea.IdentityID] = ea
	}
	for _, identity := range tc.Identities {
		ea, hasExpected := expectedByID[identity.ID]
		if !hasExpected || ea.Decision == model.AccessDecisionSkip {
			continue
		}
		if finding, ok := e.evaluate(tc, identity, execByID, ea.Decision); ok {
			result.Findings = append(result.Findings, finding)
		}
		// Sensitive-data exposure is independent of the allow/deny decision: an
		// identity may be permitted to call the endpoint yet still must not
		// receive certain fields.
		if ea.ForbidSensitiveData {
			if finding, ok := sensitiveDataFinding(tc, identity, execByID[identity.ID]); ok {
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	return result, nil
}

// sensitiveDataFinding reports fields that must not have reached this identity
// but appear in its response body. Only field names are recorded as evidence —
// never the sensitive values themselves.
func sensitiveDataFinding(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult) (model.Finding, bool) {
	if exec.Error != "" || len(exec.Body) == 0 {
		return model.Finding{}, false
	}
	fields := tc.SensitiveFields
	if len(fields) == 0 {
		fields = compare.DefaultSensitiveFields
	}
	present := compare.SensitiveFieldsPresent(exec.Body, fields)
	if len(present) == 0 {
		return model.Finding{}, false
	}
	return model.Finding{
		Category:   model.CategorySensitiveDataExposure,
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		IdentityID: identity.ID,
		Message:    fmt.Sprintf("identity %q received sensitive fields it must not see", identity.ID),
		DetectedAt: time.Now().UTC(),
		Evidence: []string{
			fmt.Sprintf("leaked_fields=%s", strings.Join(present, ",")),
			fmt.Sprintf("status_code=%d", exec.StatusCode),
			fmt.Sprintf("identity_id=%s", identity.ID),
			fmt.Sprintf("url=%s %s", tc.Request.Method, sanitizeURL(tc.Request.URL)),
		},
	}, true
}

// evaluate compares the observed outcome against the expected decision.
// Findings are only emitted for clear allow/deny signals; ambiguous outcomes
// (404, 5xx, redirect) are not classified as authorization decisions.
func (e *Engine) evaluate(tc model.AuthorizationTestCase, identity model.Identity, execByID map[string]model.ExecutionResult, expected model.AccessDecision) (model.Finding, bool) {
	exec := execByID[identity.ID]
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
		return unexpectedAccessFinding(tc, identity, exec, outcome, execByID), true
	case expected == model.AccessDecisionAllow && outcome == model.OutcomeDeny:
		return accessDeniedFinding(tc, identity, exec, outcome), true
	default:
		// Ambiguous outcomes (not_found, server_error, redirect, client_error)
		// are not sufficient to classify an authorization finding alone.
		return model.Finding{}, false
	}
}

// unexpectedAccessFinding classifies an identity that reached a resource it
// should have been denied. The category is refined using the resource's
// ownership and tenant context; without that context it stays unexpected_access.
// The engine never guesses a higher-severity category from a weak signal.
func unexpectedAccessFinding(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, outcome model.ObservedOutcome, execByID map[string]model.ExecutionResult) model.Finding {
	category, severity, confidence, reason := classifyUnexpectedAccess(tc, identity)

	f := model.Finding{
		Category:   category,
		Severity:   severity,
		Confidence: confidence,
		IdentityID: identity.ID,
		Message:    fmt.Sprintf("identity %q received access that should have been denied", identity.ID),
		DetectedAt: time.Now().UTC(),
		Evidence:   buildEvidence(tc, identity, exec, outcome),
	}
	if reason != "" {
		f.Evidence = append(f.Evidence, reason)
	}
	f.Evidence = append(f.Evidence, comparisonEvidence(tc, exec, execByID)...)
	return f
}

// classifyUnexpectedAccess refines an expected-deny/observed-allow result into
// the most specific category the available context supports.
//
// Precedence, most to least specific:
//  1. cross_tenant_access — identity's tenant differs from the resource's tenant.
//  2. potential_bola      — a non-owner identity reached an identified object.
//  3. privilege_escalation — identity's role ranks below the required role.
//  4. unexpected_access   — no ownership context; conservative fallback.
func classifyUnexpectedAccess(tc model.AuthorizationTestCase, identity model.Identity) (model.FindingCategory, model.Severity, model.Confidence, string) {
	res := tc.Resource

	if res != nil && res.TenantID != "" && identity.TenantID != "" && identity.TenantID != res.TenantID {
		return model.CategoryCrossTenantAccess, model.SeverityCritical, model.ConfidenceHigh,
			fmt.Sprintf("tenant_isolation_broken: identity_tenant=%s resource_tenant=%s", identity.TenantID, res.TenantID)
	}

	if res != nil && res.OwnerIdentity != "" && identity.ID != res.OwnerIdentity && (res.ObjectID != "" || res.Type != "") {
		return model.CategoryPotentialBOLA, model.SeverityHigh, model.ConfidenceHigh,
			fmt.Sprintf("object_ownership_violated: owner=%s object=%s", res.OwnerIdentity, resourceLabel(res))
	}

	if res != nil && res.RequiredRole != "" && len(tc.RoleHierarchy) > 0 {
		reqRank, reqOK := roleRank(tc.RoleHierarchy, res.RequiredRole)
		idRank, idOK := roleRank(tc.RoleHierarchy, identity.Role)
		if reqOK && idOK && idRank < reqRank {
			return model.CategoryPrivilegeEscalation, model.SeverityHigh, model.ConfidenceHigh,
				fmt.Sprintf("privilege_escalation: role=%s required_role=%s", identity.Role, res.RequiredRole)
		}
	}

	return model.CategoryUnexpectedAccess, model.SeverityHigh, model.ConfidenceMedium, ""
}

// roleRank returns the index of role within hierarchy (least→most privileged)
// and whether it was found.
func roleRank(hierarchy []string, role string) (int, bool) {
	for i, r := range hierarchy {
		if r == role {
			return i, true
		}
	}
	return 0, false
}

func resourceLabel(res *model.Resource) string {
	if res.ObjectID != "" {
		return res.ObjectID
	}
	return res.Type
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

// comparisonEvidence compares the offending response against a legitimate
// baseline (the resource owner, or any identity expected to be allowed) and
// returns evidence strings. When the bodies match, the offending identity
// almost certainly received the same protected data — a strong signal.
func comparisonEvidence(tc model.AuthorizationTestCase, offending model.ExecutionResult, execByID map[string]model.ExecutionResult) []string {
	baseline, ok := baselineExecution(tc, offending.IdentityID, execByID)
	if !ok {
		return nil
	}
	cr := compare.Results(baseline, offending)
	ev := compare.Evidence(baseline, offending, cr)
	if cr.BodyMatch && len(offending.Body) > 0 {
		ev = append(ev, fmt.Sprintf("response_body_matches_baseline: identity %q received the same body as %q", offending.IdentityID, baseline.IdentityID))
	}
	return ev
}

// baselineExecution picks a legitimate response to compare against: the resource
// owner if it has a usable response, otherwise the first identity expected to be
// allowed. Returns false when no suitable baseline exists.
func baselineExecution(tc model.AuthorizationTestCase, offendingID string, execByID map[string]model.ExecutionResult) (model.ExecutionResult, bool) {
	usable := func(id string) (model.ExecutionResult, bool) {
		if id == "" || id == offendingID {
			return model.ExecutionResult{}, false
		}
		ex, ok := execByID[id]
		if !ok || ex.Error != "" {
			return model.ExecutionResult{}, false
		}
		return ex, true
	}

	if tc.Resource != nil {
		if ex, ok := usable(tc.Resource.OwnerIdentity); ok {
			return ex, true
		}
	}
	for _, ea := range tc.ExpectedAccess {
		if ea.Decision != model.AccessDecisionAllow {
			continue
		}
		if ex, ok := usable(ea.IdentityID); ok {
			return ex, true
		}
	}
	return model.ExecutionResult{}, false
}

func buildEvidence(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, outcome model.ObservedOutcome) []string {
	ev := []string{
		fmt.Sprintf("observed_outcome=%s", outcome),
		fmt.Sprintf("status_code=%d", exec.StatusCode),
		fmt.Sprintf("identity_id=%s", identity.ID),
		fmt.Sprintf("url=%s %s", tc.Request.Method, sanitizeURL(tc.Request.URL)),
	}
	if identity.Role != "" {
		ev = append(ev, fmt.Sprintf("identity_role=%s", identity.Role))
	}
	if identity.TenantID != "" {
		ev = append(ev, fmt.Sprintf("identity_tenant=%s", identity.TenantID))
	}
	return ev
}

// sensitiveQueryParams are redacted from URLs appearing in evidence strings.
var sensitiveQueryParams = []string{
	"api_key", "apikey", "token", "access_token",
	"secret", "key", "password", "auth", "authorization",
}

// sanitizeURL removes credentials from URLs before they are written into
// evidence: userinfo (user:pass@host) is stripped entirely and known sensitive
// query parameters are redacted.
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid-url]"
	}
	if u.User != nil {
		u.User = nil
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

// validate ensures the test case is internally consistent before execution.
func validate(tc model.AuthorizationTestCase) error {
	if tc.ID == "" {
		return errors.New("test case must have an id")
	}
	if len(tc.Identities) == 0 {
		return errors.New("test case must have at least one identity")
	}

	ids := make(map[string]struct{}, len(tc.Identities))
	for i, identity := range tc.Identities {
		if identity.ID == "" {
			return fmt.Errorf("identities[%d] must have an id", i)
		}
		if _, dup := ids[identity.ID]; dup {
			return fmt.Errorf("identities[%d] has duplicate id %q", i, identity.ID)
		}
		ids[identity.ID] = struct{}{}
		if err := validateCredential(identity); err != nil {
			return err
		}
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
		if _, ok := ids[ea.IdentityID]; !ok {
			return fmt.Errorf("expected_access[%d] references unknown identity %q", i, ea.IdentityID)
		}
		switch ea.Decision {
		case model.AccessDecisionAllow, model.AccessDecisionDeny, model.AccessDecisionSkip:
		default:
			return fmt.Errorf("expected_access[%d] has invalid decision %q", i, ea.Decision)
		}
	}

	if tc.Resource != nil {
		if owner := tc.Resource.OwnerIdentity; owner != "" {
			if _, ok := ids[owner]; !ok {
				return fmt.Errorf("resource.owner_identity references unknown identity %q", owner)
			}
		}
		if req := tc.Resource.RequiredRole; req != "" {
			if _, ok := roleRank(tc.RoleHierarchy, req); !ok {
				return fmt.Errorf("resource.required_role %q is not present in role_hierarchy", req)
			}
		}
	}

	return nil
}

// validateCredential enforces the header/value rules for each credential type.
// Empty static_header credentials are permitted so an anonymous identity can be
// modelled explicitly.
func validateCredential(identity model.Identity) error {
	cred := identity.Credential
	switch cred.Type {
	case model.CredentialTypeBearer:
		if cred.Value == "" {
			return fmt.Errorf("identity %q: bearer credential requires a value", identity.ID)
		}
	case model.CredentialTypeAPIKeyHeader:
		if cred.Value == "" {
			return fmt.Errorf("identity %q: api_key_header credential requires a value", identity.ID)
		}
	case model.CredentialTypeStaticHeader:
		if cred.Value != "" && cred.Header == "" {
			return fmt.Errorf("identity %q: static_header credential with a value requires a header name", identity.ID)
		}
	default:
		return fmt.Errorf("identity %q: unknown credential type %q", identity.ID, cred.Type)
	}
	return nil
}
