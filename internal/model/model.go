package model

import (
	"encoding/json"
	"time"
)

// CredentialType identifies how a credential is applied to a request.
type CredentialType string

// AccessDecision is the expected or observed authorization outcome for an identity.
type AccessDecision string

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

	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"

	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"

	CategoryPotentialBOLA         FindingCategory = "potential_bola"
	CategoryUnexpectedAccess      FindingCategory = "unexpected_access"
	CategoryAuthorizationMismatch FindingCategory = "authorization_mismatch"
)

// Identity represents a principal (user, role, service account) used in a test.
type Identity struct {
	ID          string     `json:"id"`
	Description string     `json:"description,omitempty"`
	Credential  Credential `json:"credential"`
}

// Credential holds the type and header name for applying an identity's secret.
// Value is intentionally excluded from JSON to prevent credential leakage.
type Credential struct {
	Type   CredentialType `json:"type"`
	Header string         `json:"header,omitempty"`
	Value  string         `json:"-"`
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
}

// ExecutionResult captures the raw HTTP response for one identity.
// Body is excluded from JSON; callers access it directly for comparison.
type ExecutionResult struct {
	IdentityID string            `json:"identity_id"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"-"`
	DurationMS int64             `json:"duration_ms"`
	Error      string            `json:"error,omitempty"`
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

// AuthorizationTestCase is the top-level input to the engine.
type AuthorizationTestCase struct {
	ID             string           `json:"id"`
	Description    string           `json:"description,omitempty"`
	Identities     []Identity       `json:"identities"`
	Request        RequestTemplate  `json:"request"`
	ExpectedAccess []ExpectedAccess `json:"expected_access"`
}
