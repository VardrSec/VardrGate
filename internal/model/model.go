package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// CredentialType identifies how a credential is applied to a request.
type CredentialType string

// AccessDecision is the expected authorization outcome for an identity.
type AccessDecision string

// ObservedOutcome is the classified result of executing a request.
type ObservedOutcome string

// ExecutionErrorKind classifies why an execution failed before a response was received.
type ExecutionErrorKind string

// Confidence expresses how certain a finding is.
type Confidence string

// Severity rates the impact of a finding.
type Severity string

// FindingCategory classifies the type of authorization anomaly detected.
type FindingCategory string

const (
	CredentialTypeBearer       CredentialType = "bearer"
	CredentialTypeAPIKeyHeader CredentialType = "api_key_header"
	CredentialTypeStaticHeader CredentialType = "static_header"

	// AccessDecisionSkip instructs the engine to record execution but emit no finding.
	AccessDecisionAllow AccessDecision = "allow"
	AccessDecisionDeny  AccessDecision = "deny"
	AccessDecisionSkip  AccessDecision = "skip"

	OutcomeAllow       ObservedOutcome = "allow"        // 2xx
	OutcomeDeny        ObservedOutcome = "deny"         // 401, 403
	OutcomeNotFound    ObservedOutcome = "not_found"    // 404
	OutcomeRedirect    ObservedOutcome = "redirect"     // 3xx
	OutcomeServerError ObservedOutcome = "server_error" // 5xx
	OutcomeClientError ObservedOutcome = "client_error" // 4xx other than 401/403/404
	OutcomeError       ObservedOutcome = "error"        // network/timeout/validation failure

	ErrorKindURLValidation    ExecutionErrorKind = "url_validation"
	ErrorKindBuildRequest     ExecutionErrorKind = "build_request"
	ErrorKindNetwork          ExecutionErrorKind = "network"
	ErrorKindBodySizeExceeded ExecutionErrorKind = "body_size_exceeded"
	ErrorKindBodyRead         ExecutionErrorKind = "body_read"
	// ErrorKindVerification: the request was withheld because write
	// verification could not establish the state before it.
	ErrorKindVerification ExecutionErrorKind = "verification_unavailable"

	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"

	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"

	CategoryPotentialBOLA         FindingCategory = "potential_bola"
	CategoryMissingAuthentication FindingCategory = "missing_authentication"
	CategoryCrossTenantAccess     FindingCategory = "cross_tenant_access"
	CategoryPrivilegeEscalation   FindingCategory = "privilege_escalation"
	CategoryUnexpectedAccess      FindingCategory = "unexpected_access"
	CategoryAuthorizationMismatch FindingCategory = "authorization_mismatch"
	CategorySensitiveDataExposure FindingCategory = "sensitive_data_exposure"
	CategoryCORSMisconfiguration  FindingCategory = "cors_misconfiguration"
	// CategoryObjectPropertyExposure is OWASP API3:2023, broken object property
	// level authorization: a caller received a property that governs
	// authorization or value, such as role, is_admin, or balance.
	CategoryObjectPropertyExposure FindingCategory = "object_property_exposure"
)

// severityRank orders severities from least to most impactful. Unknown values
// rank below info so an unrecognized severity never trips a threshold.
var severityRank = map[Severity]int{
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

// Rank returns the ordinal of a severity for threshold comparison.
// An unrecognized severity ranks 0, below every named level.
func (s Severity) Rank() int { return severityRank[s] }

// ParseSeverity converts a case-insensitive severity name into a Severity.
func ParseSeverity(s string) (Severity, bool) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := severityRank[sev]; ok {
		return sev, true
	}
	return "", false
}

// ClassifyOutcome maps an HTTP status code to an ObservedOutcome.
// Pass hasError=true when execution failed before a response was received.
func ClassifyOutcome(statusCode int, hasError bool) ObservedOutcome {
	return ClassifyOutcomeWith(statusCode, hasError, nil)
}

// ClassifyOutcomeWith maps an HTTP status code to an ObservedOutcome, treating
// any code in denyStatuses as an explicit deny.
//
// APIs commonly return 404 rather than 403 to avoid revealing that an object
// exists. Under the default mapping that is an ambiguous not_found and no
// finding is emitted, which is correct when the deny convention is unknown. A
// policy that declares `response.deny_status` states the convention, so those
// codes become deny decisions the engine can evaluate against.
func ClassifyOutcomeWith(statusCode int, hasError bool, denyStatuses []int) ObservedOutcome {
	if hasError {
		return OutcomeError
	}
	for _, code := range denyStatuses {
		if code == statusCode {
			return OutcomeDeny
		}
	}
	switch {
	case statusCode >= 200 && statusCode < 300:
		return OutcomeAllow
	case statusCode == 401 || statusCode == 403:
		return OutcomeDeny
	case statusCode == 404:
		return OutcomeNotFound
	case statusCode >= 300 && statusCode < 400:
		return OutcomeRedirect
	case statusCode >= 500:
		return OutcomeServerError
	case statusCode >= 400:
		return OutcomeClientError
	default:
		return OutcomeError
	}
}

// Identity represents a principal (user, role, service account) used in a test.
type Identity struct {
	ID          string             `json:"id"`
	Name        string             `json:"name,omitempty"`
	Role        string             `json:"role,omitempty"`
	TenantID    string             `json:"tenant_id,omitempty"`
	Description string             `json:"description,omitempty"`
	Credential  Credential         `json:"credential"`
	Preflight   *IdentityPreflight `json:"preflight,omitempty"`
}

// IdentityPreflight verifies a reviewed session endpoint with the same credential.
// JSONFields contains public principal metadata, never credentials or response secrets.
type IdentityPreflight struct {
	URL            string            `json:"url"`
	ExpectedStatus int               `json:"expected_status"`
	JSONFields     map[string]string `json:"json_fields"`
}

// Reject misspelled options instead of silently weakening an identity check.
func (p *IdentityPreflight) UnmarshalJSON(data []byte) error {
	type wire IdentityPreflight
	var value wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*p = IdentityPreflight(value)
	return nil
}

// PreflightResult contains only bounded diagnostics, never response values or headers.
type PreflightResult struct {
	IdentityID string `json:"identity_id"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	StatusCode int    `json:"status_code"`
}

// Credential carries type and header metadata.
// Value is excluded from JSON output via json:"-" on the struct field.
// UnmarshalJSON allows API callers to supply "value" in request JSON;
// the default MarshalJSON never writes it to any response.
type Credential struct {
	Type   CredentialType `json:"type"`
	Header string         `json:"header,omitempty"`
	Value  string         `json:"-"`
}

// SendsNoAuth reports whether applying this credential adds no authentication to
// the request — an anonymous identity. After validation, bearer and
// api_key_header always carry a value; only a static_header with no header name
// sends nothing.
func (c Credential) SendsNoAuth() bool {
	return c.Type == CredentialTypeStaticHeader && c.Header == ""
}

// UnmarshalJSON reads "value" from API input without ever writing it to output.
func (c *Credential) UnmarshalJSON(data []byte) error {
	type wire struct {
		Type   CredentialType `json:"type"`
		Header string         `json:"header"`
		Value  string         `json:"value"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	c.Type = w.Type
	c.Header = w.Header
	c.Value = w.Value
	return nil
}

// RequestTemplate describes the HTTP request to execute for each identity.
type RequestTemplate struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Body        json.RawMessage   `json:"body,omitempty"`
}

// ExpectedAccess pairs an identity with its expected authorization outcome.
type ExpectedAccess struct {
	IdentityID string         `json:"identity_id"`
	Decision   AccessDecision `json:"decision"`
	Note       string         `json:"note,omitempty"`
	// ForbidSensitiveData marks an identity that must never receive sensitive
	// fields in the response body, even when it is allowed to call the endpoint.
	ForbidSensitiveData bool `json:"forbid_sensitive_data,omitempty"`
	// ResponseAssertions supply explicit JSON evidence for the access decision,
	// so a denial returned with HTTP 200 or protected data leaked in an error
	// body is judged by content rather than status alone. When empty, the
	// status-based evaluation is used unchanged.
	ResponseAssertions []ResponseAssertion `json:"response_assertions,omitempty"`
}

// ResponseAssertion supplies explicit evidence for an access decision. Equals
// must be present (JSON null is valid). JSONPointer uses /-separated JSON keys
// or array indices; an empty pointer selects the complete document.
type ResponseAssertion struct {
	StatusCodes []int           `json:"status_codes,omitempty"`
	JSONPointer string          `json:"json_pointer"`
	Equals      json.RawMessage `json:"equals"`
	Decision    AccessDecision  `json:"decision"`
}

// AssessmentDecision is the semantic access conclusion for one identity,
// separate from the raw HTTP outcome.
type AssessmentDecision string

const (
	AssessmentAllowed      AssessmentDecision = "allowed"
	AssessmentDenied       AssessmentDecision = "denied"
	AssessmentInconclusive AssessmentDecision = "inconclusive"
	AssessmentSkipped      AssessmentDecision = "skipped"
)

// Assessment separates semantic access evidence from the raw HTTP outcome.
// Assertion indices are safe to return; response data and asserted values are not.
type Assessment struct {
	IdentityID        string             `json:"identity_id"`
	ExpectedAccess    AccessDecision     `json:"expected_access,omitempty"`
	Decision          AssessmentDecision `json:"decision"`
	Source            string             `json:"source"`
	Reason            string             `json:"reason"`
	MatchedAssertions []int              `json:"matched_assertions,omitempty"`
}

// ExecutionResult captures the HTTP response for one identity.
// Body is excluded from JSON; callers access it directly for comparison.
type ExecutionResult struct {
	IdentityID      string             `json:"identity_id"`
	StatusCode      int                `json:"status_code"`
	ObservedOutcome ObservedOutcome    `json:"observed_outcome,omitempty"`
	Headers         map[string]string  `json:"headers,omitempty"`
	Body            []byte             `json:"-"`
	DurationMS      int64              `json:"duration_ms"`
	Error           string             `json:"error,omitempty"`
	ErrorKind       ExecutionErrorKind `json:"error_kind,omitempty"`
	ResponseProfile *ResponseProfile   `json:"response_profile,omitempty"`
}

// ResponseProfile is a value-free description of a retained response body.
// It lets control planes compare API shape across identities without receiving
// the body or a reversible hash of its values.
type ResponseProfile struct {
	Kind       string   `json:"kind"`
	SchemaHash string   `json:"schema_hash,omitempty"`
	Fields     []string `json:"fields,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
}

// ComparisonResult summarizes differences observed across identity executions.
type ComparisonResult struct {
	StatusCodeMatch  bool     `json:"status_code_match"`
	BodyMatch        bool     `json:"body_match"`
	SchemaMatch      bool     `json:"schema_match"`
	SharedFieldRatio float64  `json:"shared_field_ratio"`
	FieldsOnlyInA    []string `json:"fields_only_in_a,omitempty"`
	FieldsOnlyInB    []string `json:"fields_only_in_b,omitempty"`
	SizeDiff         int64    `json:"size_diff"`
	Notes            []string `json:"notes,omitempty"`
}

// Finding records a single authorization anomaly with evidence.
type Finding struct {
	Category   FindingCategory `json:"category"`
	Severity   Severity        `json:"severity"`
	Confidence Confidence      `json:"confidence"`
	IdentityID string          `json:"identity_id"`
	Message    string          `json:"message"`
	Evidence   []string        `json:"evidence,omitempty"`
	DetectedAt time.Time       `json:"detected_at"`
}

// Resource describes the object an authorization test targets. It gives the
// engine the ownership and tenant context needed to distinguish a plain
// unexpected_access from a potential_bola or cross_tenant_access finding.
//
// All fields are optional. When Resource is nil or its context fields are
// empty, the engine falls back to unexpected_access — it never guesses a
// higher-severity category without explicit context.
type Resource struct {
	// Type is a human label for the object class, e.g. "user_profile".
	Type string `json:"type,omitempty"`
	// ObjectID is the concrete identifier of the object under test.
	ObjectID string `json:"object_id,omitempty"`
	// OwnerIdentity is the id of the identity that legitimately owns the object.
	// A non-owner identity that reaches the object is a potential_bola signal.
	OwnerIdentity string `json:"owner_identity,omitempty"`
	// TenantID is the tenant the object belongs to. An identity whose TenantID
	// differs is a cross_tenant_access signal.
	TenantID string `json:"tenant_id,omitempty"`
	// RequiredRole is the least-privileged role permitted to access the object.
	// Combined with RoleHierarchy it establishes privilege_escalation.
	RequiredRole string `json:"required_role,omitempty"`
	// TenantField names the response-body field carrying the object's tenant.
	// When TenantID is not known ahead of time, the engine reads this field from
	// the offending identity's own response: a caller in tenant A that received
	// an object whose tenant field says B proves the isolation break directly.
	TenantField string `json:"tenant_field,omitempty"`
}

// DenyCondition recognizes a refusal that the status line does not express.
//
// An API that answers "200 OK {"error":"forbidden"}" denies the caller while
// reporting success. Under status-code classification alone that reads as an
// allow, so an identity that was correctly refused produces a false finding at
// critical severity. The condition is declared rather than inferred: the engine
// still never guesses what a denial looks like.
//
// A body that satisfies any populated field is a denial.
type DenyCondition struct {
	// BodyContains matches when the raw body contains any of these substrings
	// (case-insensitive).
	BodyContains []string `json:"body_contains,omitempty"`
	// JSONField matches on a specific field in a JSON body.
	JSONField *JSONFieldMatch `json:"json_field,omitempty"`
}

// JSONFieldMatch locates a field by dotted path and tests it.
// Equals takes precedence; with Equals empty, the field merely has to exist.
type JSONFieldMatch struct {
	Path   string `json:"path"`
	Equals string `json:"equals,omitempty"`
}

// IsZero reports whether the condition would match nothing.
func (d *DenyCondition) IsZero() bool {
	return d == nil || (len(d.BodyContains) == 0 && d.JSONField == nil)
}

// unsafeMethods change server state. A test case replays one request as every
// identity, so running these without an explicit opt-in would repeat the
// mutation once per caller.
var unsafeMethods = map[string]struct{}{
	"POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {},
}

// IsUnsafeMethod reports whether a method is expected to change server state.
func IsUnsafeMethod(method string) bool {
	_, ok := unsafeMethods[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

// CORSCheck enables cross-origin policy probing. When set, the engine sends an
// Origin header with ProbeOrigin on the request and inspects the CORS response
// headers for a policy that reflects arbitrary origins.
type CORSCheck struct {
	ProbeOrigin string `json:"probe_origin"`
}

// SetupStep is a request executed before the one under test, whose response
// can supply values the main request needs.
//
// It covers the two cases a single stateless request cannot reach: obtaining a
// token when authentication is a handshake rather than a static string, and
// creating an object as one identity so another can attempt to read it. Both
// are "run a request first and capture something from the response", so they
// are one mechanism rather than two.
type SetupStep struct {
	// Name labels the step in errors and evidence.
	Name string `json:"name"`
	// As is the id of the identity to run this step as. Empty sends no
	// credentials, which is what a login request needs.
	As string `json:"as,omitempty"`
	// Request is the step's HTTP request. It may reference variables captured
	// by earlier steps.
	Request RequestTemplate `json:"request"`
	// Capture maps a variable name to a dotted path in the step's JSON
	// response, e.g. {"token": "data.access_token"}.
	Capture map[string]string `json:"capture,omitempty"`
}

// SensitivityTier groups sensitive fields by what their exposure means, so a
// leaked password and a leaked "created_by" are not reported identically.
type SensitivityTier string

const (
	// TierCritical is a secret: exposure is compromise on its own.
	TierCritical SensitivityTier = "critical"
	// TierElevated is an authorization-bearing property — role, is_admin,
	// balance. A caller that must not see these reaching them is broken object
	// property level authorization (OWASP API3), not merely data exposure.
	TierElevated SensitivityTier = "elevated"
	// TierPII identifies a person.
	TierPII SensitivityTier = "pii"
	// TierInternal is implementation detail that aids an attacker without being
	// harmful alone.
	TierInternal SensitivityTier = "internal"
	// TierDeclared is a field the test case named explicitly. The author said
	// it matters; the engine does not second-guess which tier it belongs to.
	TierDeclared SensitivityTier = "declared"
)

// Severity returns the severity a finding takes from this tier.
func (t SensitivityTier) Severity() Severity {
	switch t {
	case TierCritical:
		return SeverityCritical
	case TierElevated, TierPII, TierDeclared:
		return SeverityHigh
	case TierInternal:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// Category returns the finding category exposure of this tier produces.
func (t SensitivityTier) Category() FindingCategory {
	if t == TierElevated {
		return CategoryObjectPropertyExposure
	}
	return CategorySensitiveDataExposure
}

// AuthorizationTestCase is the top-level input to the engine.
type AuthorizationTestCase struct {
	RequireIdentityPreflight bool            `json:"require_identity_preflight,omitempty"`
	ID                       string          `json:"id"`
	Description              string          `json:"description,omitempty"`
	Identities               []Identity      `json:"identities"`
	Request                  RequestTemplate `json:"request"`
	// Resource supplies optional ownership/tenant context for classification.
	Resource *Resource `json:"resource,omitempty"`
	// RoleHierarchy lists roles from least to most privileged. It is only used
	// to evaluate Resource.RequiredRole for privilege_escalation findings.
	RoleHierarchy []string `json:"role_hierarchy,omitempty"`
	// SensitiveFields names the response fields that must not reach an identity
	// marked ForbidSensitiveData. Empty means use the default sensitive set.
	SensitiveFields []string `json:"sensitive_fields,omitempty"`
	// DenyStatuses lists the status codes this API uses to refuse a caller, for
	// APIs whose deny convention is not the default 401/403 (a 404 that hides
	// existence is the common case). Empty uses the default mapping.
	DenyStatuses []int `json:"deny_status,omitempty"`
	// UnauthorizedIsDenial states that this API refuses authenticated callers
	// with 401. Without it a 401 to a caller that sent credentials is
	// indistinguishable from a dead token and is never a verified denial. It is
	// separate from DenyStatuses because listing 401 there was always redundant
	// and is copied widely, so it cannot carry intent. See ADR 0019.
	UnauthorizedIsDenial bool `json:"unauthorized_is_denial,omitempty"`
	// DenyWhen recognizes a refusal expressed in the response body rather than
	// the status line. Nil leaves classification to the status code alone.
	DenyWhen *DenyCondition `json:"deny_when,omitempty"`
	// Mutating acknowledges that the request changes server state. Required
	// before the engine will replay an unsafe method once per identity.
	Mutating bool `json:"mutating,omitempty"`
	// WriteVerification reads the target's state before and after each
	// identity's request, so a write is judged by its effect rather than by
	// its own response. Requires Mutating.
	WriteVerification *WriteVerification `json:"write_verification,omitempty"`
	// Setup runs before the request under test, in order, so an authorization
	// test can log in or create the object it is about to probe.
	Setup []SetupStep `json:"setup,omitempty"`
	// CORS, when set, enables cross-origin misconfiguration probing.
	CORS           *CORSCheck       `json:"cors,omitempty"`
	ExpectedAccess []ExpectedAccess `json:"expected_access"`
}

// WriteVerification observes whether a write took effect. Its identity is a
// separate reader, never one of the identities under test, so it cannot
// perform the mutation itself. Only the comparison outcome is reported:
// observed values stay in memory and never reach results or evidence.
type WriteVerification struct {
	Identity Identity        `json:"identity"`
	Request  RequestTemplate `json:"request"`
	// Environment declares the reviewed write/read contract: "unknown" keeps
	// observations inconclusive; "synchronous_isolated" asserts completion and
	// exclusive fixture access. Empty retains legacy behavior. Gate cannot
	// establish remote isolation or synchronous visibility itself.
	Environment string `json:"environment,omitempty"`
	// AllowUnsafeMethod acknowledges a verifier that uses POST or similar,
	// such as logging in as the victim, and asserts it changes no state.
	AllowUnsafeMethod bool `json:"allow_unsafe_method,omitempty"`
	// JSONPointer selects the observed value in a 2xx response. Successful
	// statuses are equivalent; a 404 after a delete represents absent state.
	JSONPointer string `json:"json_pointer,omitempty"`
	// ChangedTo is the value the attempted write would set, when known. A
	// change to anything else is inconclusive, and a state that already holds
	// it cannot show a change.
	ChangedTo json.RawMessage `json:"changed_to,omitempty"`
}
