package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
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

	// Setup runs first: it may supply the credentials the identities present or
	// create the object the request under test targets.
	vars, err := e.runSetup(ctx, tc)
	if err != nil {
		return Result{}, err
	}
	tc, err = applySetupVars(tc, vars)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrSetupFailed, err)
	}

	expected := make(map[string]model.AccessDecision, len(tc.ExpectedAccess))
	for _, ea := range tc.ExpectedAccess {
		expected[ea.IdentityID] = ea.Decision
	}

	// When CORS probing is enabled, send an Origin header so the server reveals
	// its cross-origin policy in the response headers.
	req := tc.Request
	if tc.CORS != nil && tc.CORS.ProbeOrigin != "" {
		req = withHeader(req, "Origin", tc.CORS.ProbeOrigin)
	}

	// First pass: execute every identity and index the results so finding
	// evaluation can compare an offending response against a legitimate baseline.
	result := Result{TestCaseID: tc.ID}
	execByID := make(map[string]model.ExecutionResult, len(tc.Identities))
	for _, identity := range tc.Identities {
		exec := e.exec.Execute(ctx, identity, req)
		exec.ResponseProfile = compare.Profile(exec.Body)
		// The executor classifies against the default status mapping; it knows
		// nothing about a policy-declared deny convention. Reclassify here so
		// the execution record and the findings drawn from it cannot disagree
		// inside a single result document.
		if exec.Error == "" {
			exec.ObservedOutcome, _ = classify(tc, exec)
		}
		result.Executions = append(result.Executions, exec)
		execByID[identity.ID] = exec
	}

	// CORS policy is endpoint-level, so evaluate it once from the first usable
	// response.
	if tc.CORS != nil && tc.CORS.ProbeOrigin != "" {
		if finding, ok := corsFinding(tc, execByID); ok {
			result.Findings = append(result.Findings, finding)
		}
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
			result.Findings = append(result.Findings, sensitiveDataFindings(tc, identity, execByID[identity.ID])...)
		}
	}

	return result, nil
}

// sensitiveDataFindings reports fields that must not have reached this identity
// but appear in its response body. Only field names and paths are recorded —
// never the values, so a findings report cannot itself become the breach.
//
// Hits are grouped by finding category so an authorization-bearing property
// (role, is_admin, balance) is reported as object_property_exposure rather than
// being averaged into generic data exposure. Severity comes from the most
// serious tier in each group.
func sensitiveDataFindings(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult) []model.Finding {
	if exec.Error != "" || len(exec.Body) == 0 {
		return nil
	}
	hits := compare.ScanSensitive(exec.Body, tc.SensitiveFields)
	if len(hits) == 0 {
		return nil
	}

	byCategory := map[model.FindingCategory][]compare.SensitiveHit{}
	for _, h := range hits {
		cat := h.Tier.Category()
		byCategory[cat] = append(byCategory[cat], h)
	}

	// Report the more serious category first for a stable, useful ordering.
	categories := []model.FindingCategory{
		model.CategoryObjectPropertyExposure,
		model.CategorySensitiveDataExposure,
	}

	var findings []model.Finding
	for _, cat := range categories {
		group := byCategory[cat]
		if len(group) == 0 {
			continue
		}
		severity := model.SeverityLow
		paths := make([]string, 0, len(group))
		tiers := map[model.SensitivityTier]struct{}{}
		for _, h := range group {
			if s := h.Tier.Severity(); s.Rank() > severity.Rank() {
				severity = s
			}
			paths = append(paths, h.Path)
			tiers[h.Tier] = struct{}{}
		}

		message := fmt.Sprintf("identity %q received sensitive fields it must not see", identity.ID)
		if cat == model.CategoryObjectPropertyExposure {
			message = fmt.Sprintf("identity %q received object properties that govern authorization or value", identity.ID)
		}

		findings = append(findings, model.Finding{
			Category:   cat,
			Severity:   severity,
			Confidence: model.ConfidenceHigh,
			IdentityID: identity.ID,
			Message:    message,
			DetectedAt: time.Now().UTC(),
			Evidence: []string{
				fmt.Sprintf("leaked_fields=%s", strings.Join(paths, ",")),
				fmt.Sprintf("sensitivity=%s", strings.Join(sortedTiers(tiers), ",")),
				fmt.Sprintf("status_code=%d", exec.StatusCode),
				fmt.Sprintf("identity_id=%s", identity.ID),
				fmt.Sprintf("url=%s %s", tc.Request.Method, sanitizeURL(tc.Request.URL)),
			},
		})
	}
	return findings
}

func sortedTiers(tiers map[model.SensitivityTier]struct{}) []string {
	out := make([]string, 0, len(tiers))
	for t := range tiers {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}

// evaluate compares the observed outcome against the expected decision.
// Findings are only emitted for clear allow/deny signals; ambiguous outcomes
// (404, 5xx, redirect) are not classified as authorization decisions.
func (e *Engine) evaluate(tc model.AuthorizationTestCase, identity model.Identity, execByID map[string]model.ExecutionResult, expected model.AccessDecision) (model.Finding, bool) {
	exec := execByID[identity.ID]
	if exec.Error != "" {
		return model.Finding{}, false
	}

	outcome, denyReason := classify(tc, exec)

	switch {
	case expected == model.AccessDecisionDeny && outcome == model.OutcomeAllow:
		return unexpectedAccessFinding(tc, identity, exec, outcome, execByID), true
	case expected == model.AccessDecisionAllow && outcome == model.OutcomeDeny:
		return accessDeniedFinding(tc, identity, exec, outcome, denyReason), true
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
	category, severity, confidence, reason := classifyUnexpectedAccess(tc, identity, exec)

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
//  1. missing_authentication — the caller sent no credentials at all.
//  2. cross_tenant_access — identity's tenant differs from the resource's tenant.
//  3. potential_bola      — a non-owner identity reached an identified object.
//  4. privilege_escalation — identity's role ranks below the required role.
//  5. unexpected_access   — no ownership context; conservative fallback.
func classifyUnexpectedAccess(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult) (model.FindingCategory, model.Severity, model.Confidence, string) {
	res := tc.Resource

	// An unauthenticated caller reaching a resource it should be denied is the
	// most specific signal: authentication is missing or not enforced.
	if identity.Credential.SendsNoAuth() {
		return model.CategoryMissingAuthentication, model.SeverityCritical, model.ConfidenceHigh,
			"unauthenticated_access: request carried no credentials"
	}

	if resTenant, ok := resourceTenant(res, exec); ok && identity.TenantID != "" && identity.TenantID != resTenant {
		return model.CategoryCrossTenantAccess, model.SeverityCritical, model.ConfidenceHigh,
			fmt.Sprintf("tenant_isolation_broken: identity_tenant=%s resource_tenant=%s", identity.TenantID, resTenant)
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

// resourceTenant determines which tenant the object belongs to. A tenant bound
// on the resource wins; otherwise, when the policy names the response field
// carrying the tenant, it is read out of this identity's own response body.
// Reading it from the offending response is what makes the finding
// self-evidencing: the caller received an object stamped with another tenant.
func resourceTenant(res *model.Resource, exec model.ExecutionResult) (string, bool) {
	if res == nil {
		return "", false
	}
	if res.TenantID != "" {
		return res.TenantID, true
	}
	if res.TenantField == "" || len(exec.Body) == 0 {
		return "", false
	}
	return compare.FieldValue(exec.Body, res.TenantField)
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

func accessDeniedFinding(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, outcome model.ObservedOutcome, denyReason string) model.Finding {
	ev := buildEvidence(tc, identity, exec, outcome)
	if denyReason != "" {
		ev = append(ev, "deny_when_matched: "+denyReason)
	}
	return model.Finding{
		Category:   model.CategoryAuthorizationMismatch,
		Severity:   model.SeverityLow,
		Confidence: model.ConfidenceHigh,
		IdentityID: identity.ID,
		Message:    fmt.Sprintf("identity %q was denied access that should have been allowed", identity.ID),
		DetectedAt: time.Now().UTC(),
		Evidence:   ev,
	}
}

// classify determines the observed outcome for one execution, honouring the
// deny conventions the policy declared. It returns a description of a matched
// body condition so a finding can disclose why a 2xx was read as a refusal.
//
// Order matters: a declared body condition outranks the status line, because
// the whole reason it exists is APIs that answer 200 while refusing the caller.
func classify(tc model.AuthorizationTestCase, exec model.ExecutionResult) (model.ObservedOutcome, string) {
	if exec.Error != "" {
		return model.OutcomeError, ""
	}
	if reason, ok := compare.MatchesDeny(exec.Body, tc.DenyWhen); ok {
		return model.OutcomeDeny, reason
	}
	return model.ClassifyOutcomeWith(exec.StatusCode, false, tc.DenyStatuses), ""
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
	cr := compare.Results(baseline, offending, tc.SensitiveFields)
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

// withHeader returns a copy of tmpl with an extra header set, without mutating
// the caller's header map.
func withHeader(tmpl model.RequestTemplate, key, value string) model.RequestTemplate {
	headers := make(map[string]string, len(tmpl.Headers)+1)
	for k, v := range tmpl.Headers {
		headers[k] = v
	}
	headers[key] = value
	tmpl.Headers = headers
	return tmpl
}

// corsFinding inspects the first usable response for a cross-origin policy that
// reflects the arbitrary probe origin (or is a wildcard). Reflecting an origin
// while also allowing credentials is the dangerous case (high); a reflected or
// wildcard origin without credentials is reported at low severity.
func corsFinding(tc model.AuthorizationTestCase, execByID map[string]model.ExecutionResult) (model.Finding, bool) {
	var headers map[string]string
	var observedBy string
	for _, identity := range tc.Identities {
		ex := execByID[identity.ID]
		if ex.Error == "" && len(ex.Headers) > 0 {
			headers = ex.Headers
			observedBy = identity.ID
			break
		}
	}
	if headers == nil {
		return model.Finding{}, false
	}

	acao := headerValue(headers, "Access-Control-Allow-Origin")
	if acao == "" {
		return model.Finding{}, false
	}
	credentials := strings.EqualFold(headerValue(headers, "Access-Control-Allow-Credentials"), "true")
	reflected := acao == tc.CORS.ProbeOrigin
	wildcard := acao == "*"
	if !reflected && !wildcard {
		return model.Finding{}, false
	}

	severity := model.SeverityLow
	confidence := model.ConfidenceMedium
	reason := "permissive_cors: origin " + describeACAO(reflected, wildcard)
	if reflected && credentials {
		severity = model.SeverityHigh
		confidence = model.ConfidenceHigh
		reason = "credentialed_cors: arbitrary origin reflected with credentials allowed"
	}

	// The policy is endpoint-level, not per-caller, but the finding still records
	// which identity's response it was read from so the observation is traceable.
	return model.Finding{
		Category:   model.CategoryCORSMisconfiguration,
		Severity:   severity,
		Confidence: confidence,
		IdentityID: observedBy,
		Message:    fmt.Sprintf("endpoint returned a permissive CORS policy for probe origin %q", tc.CORS.ProbeOrigin),
		DetectedAt: time.Now().UTC(),
		Evidence: []string{
			reason,
			fmt.Sprintf("access_control_allow_origin=%s", acao),
			fmt.Sprintf("access_control_allow_credentials=%t", credentials),
			fmt.Sprintf("probe_origin=%s", tc.CORS.ProbeOrigin),
			fmt.Sprintf("observed_on_identity=%s", observedBy),
			fmt.Sprintf("url=%s %s", tc.Request.Method, sanitizeURL(tc.Request.URL)),
		},
	}, true
}

func describeACAO(reflected, wildcard bool) string {
	if reflected {
		return "reflected"
	}
	if wildcard {
		return "wildcard"
	}
	return "unknown"
}

// headerValue does a case-insensitive lookup in a header map.
func headerValue(headers map[string]string, key string) string {
	if v, ok := headers[key]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func buildEvidence(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, outcome model.ObservedOutcome) []string {
	ev := []string{
		fmt.Sprintf("observed_outcome=%s", outcome),
		fmt.Sprintf("status_code=%d", exec.StatusCode),
		fmt.Sprintf("identity_id=%s", identity.ID),
		fmt.Sprintf("url=%s %s", tc.Request.Method, sanitizeURL(tc.Request.URL)),
	}
	// A declared deny convention changes what a status code means, so the
	// reader of a finding can see why (say) a 404 was read as a denial.
	if len(tc.DenyStatuses) > 0 {
		ev = append(ev, fmt.Sprintf("deny_status_declared=%s", joinInts(tc.DenyStatuses)))
	}
	if identity.Role != "" {
		ev = append(ev, fmt.Sprintf("identity_role=%s", identity.Role))
	}
	if identity.TenantID != "" {
		ev = append(ev, fmt.Sprintf("identity_tenant=%s", identity.TenantID))
	}
	return ev
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
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

// Validate reports whether a test case is internally consistent, without
// executing it. Run applies the same check; this is exported so a caller
// holding a suite can report every authoring error at once instead of
// discovering them one execution at a time.
func Validate(tc model.AuthorizationTestCase) error { return validate(tc) }

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

	// A test case replays one request as every identity. For an unsafe method
	// that means performing the mutation once per caller — deleting the same
	// object three times, or creating three of something. Refuse until the
	// author says they meant it.
	if model.IsUnsafeMethod(tc.Request.Method) && !tc.Mutating {
		return fmt.Errorf(
			"request method %s changes server state and would be replayed once per identity (%d times); set mutating: true on the policy, or pass --allow-mutating, to confirm that is intended",
			strings.ToUpper(tc.Request.Method), len(tc.Identities))
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

	if err := validateSetup(tc); err != nil {
		return err
	}

	for i, code := range tc.DenyStatuses {
		if code < 100 || code > 599 {
			return fmt.Errorf("deny_status[%d] is not a valid HTTP status code: %d", i, code)
		}
		if code >= 200 && code < 300 {
			return fmt.Errorf("deny_status[%d] is a success code (%d); a 2xx cannot mean denied", i, code)
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
