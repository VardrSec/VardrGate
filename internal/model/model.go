package model

import (
	"encoding/json"
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
)

// ClassifyOutcome maps an HTTP status code to an ObservedOutcome.
// Pass hasError=true when execution failed before a response was received.
func ClassifyOutcome(statusCode int, hasError bool) ObservedOutcome {
	if hasError {
		return OutcomeError
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
	ID          string     `json:"id"`
	Name        string     `json:"name,omitempty"`
	Role        string     `json:"role,omitempty"`
	TenantID    string     `json:"tenant_id,omitempty"`
	Description string     `json:"description,omitempty"`
	Credential  Credential `json:"credential"`
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
}

// ComparisonResult summarizes differences observed across identity executions.
type ComparisonResult struct {
	StatusCodeMatch bool     `json:"status_code_match"`
	BodyMatch       bool     `json:"body_match"`
	SizeDiff        int64    `json:"size_diff"`
	Notes           []string `json:"notes,omitempty"`
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
}

// CORSCheck enables cross-origin policy probing. When set, the engine sends an
// Origin header with ProbeOrigin on the request and inspects the CORS response
// headers for a policy that reflects arbitrary origins.
type CORSCheck struct {
	ProbeOrigin string `json:"probe_origin"`
}

// AuthorizationTestCase is the top-level input to the engine.
type AuthorizationTestCase struct {
	ID          string          `json:"id"`
	Description string          `json:"description,omitempty"`
	Identities  []Identity      `json:"identities"`
	Request     RequestTemplate `json:"request"`
	// Resource supplies optional ownership/tenant context for classification.
	Resource *Resource `json:"resource,omitempty"`
	// RoleHierarchy lists roles from least to most privileged. It is only used
	// to evaluate Resource.RequiredRole for privilege_escalation findings.
	RoleHierarchy []string `json:"role_hierarchy,omitempty"`
	// SensitiveFields names the response fields that must not reach an identity
	// marked ForbidSensitiveData. Empty means use the default sensitive set.
	SensitiveFields []string `json:"sensitive_fields,omitempty"`
	// CORS, when set, enables cross-origin misconfiguration probing.
	CORS           *CORSCheck       `json:"cors,omitempty"`
	ExpectedAccess []ExpectedAccess `json:"expected_access"`
}
