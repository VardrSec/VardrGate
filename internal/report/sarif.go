package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

// SARIF 2.1.0, the subset code-scanning tools read. Built with encoding/json
// rather than a SARIF library: the shape is small and stable, and a dependency
// would need its own ADR.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          sarifResultProps  `json:"properties"`
}

type sarifResultProps struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	TestCaseID string `json:"testCaseId"`
	IdentityID string `json:"identityId,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// ruleInfo describes a finding category for code-scanning dashboards.
type ruleInfo struct {
	category model.FindingCategory
	name     string
	short    string
	full     string
	// severity is the category's highest severity. Code scanning ranks alerts
	// by the rule, not the result, so a rule takes its worst case.
	severity model.Severity
}

var knownRules = []ruleInfo{
	{model.CategoryMissingAuthentication, "MissingAuthentication",
		"Unauthenticated caller reached a protected resource",
		"An identity that sent no credentials received a successful response from an endpoint the policy requires it to be denied.",
		model.SeverityCritical},
	{model.CategoryCrossTenantAccess, "CrossTenantAccess",
		"Identity from another tenant reached the resource",
		"An identity whose tenant differs from the object's tenant received access the policy denies. Tenant isolation is broken for this endpoint.",
		model.SeverityCritical},
	{model.CategoryPotentialBOLA, "PotentialBOLA",
		"Non-owner reached an identified object (OWASP API1:2023)",
		"An identity that does not own the object received a successful response. This is broken object-level authorization; verify before reporting.",
		model.SeverityHigh},
	{model.CategoryPrivilegeEscalation, "PrivilegeEscalation",
		"Identity below the required role reached the resource",
		"An identity ranked below the resource's required role in the declared role hierarchy received access (OWASP API5:2023, function-level authorization).",
		model.SeverityHigh},
	{model.CategoryUnexpectedAccess, "UnexpectedAccess",
		"Denied identity received a success response",
		"An identity the policy denies received a 2xx response. No ownership, tenant or role context was declared to refine the category.",
		model.SeverityHigh},
	{model.CategorySensitiveDataExposure, "SensitiveDataExposure",
		"Identity received response fields it must not see",
		"The response carried fields in a sensitive tier to an identity marked as forbidden from receiving them. Evidence names field paths, never values. Severity follows the field's tier.",
		model.SeverityCritical},
	{model.CategoryObjectPropertyExposure, "ObjectPropertyExposure",
		"Identity received authorization-governing properties (OWASP API3:2023)",
		"The response carried properties such as role, is_admin, permissions or balance to an identity forbidden from receiving them. This is broken object property-level authorization.",
		model.SeverityHigh},
	{model.CategoryCORSMisconfiguration, "CORSMisconfiguration",
		"Endpoint reflects an arbitrary Origin",
		"The endpoint reflected a probe Origin in Access-Control-Allow-Origin. High when credentials are also allowed.",
		model.SeverityHigh},
	{model.CategoryAuthorizationMismatch, "AuthorizationMismatch",
		"Allowed identity was refused",
		"An identity the policy allows received 401 or 403. Either the policy or the credential is wrong, or the endpoint is over-restricted.",
		model.SeverityLow},
}

// securitySeverity maps a severity to the 0–10 score code scanning uses to
// bucket alerts: >= 9 critical, 7–8.9 high, 4–6.9 medium, < 4 low.
func securitySeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func newRule(r ruleInfo) sarifRule {
	return sarifRule{
		ID:                   string(r.category),
		Name:                 r.name,
		ShortDescription:     sarifText{Text: r.short},
		FullDescription:      sarifText{Text: r.full},
		Help:                 sarifText{Text: r.full + " Findings are candidates: reproduce with the recorded identities before reporting."},
		DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(r.severity)},
		Properties:           sarifRuleProps{Tags: []string{"security", "authorization"}, SecuritySeverity: securitySeverity(r.severity)},
	}
}

// artifactURI turns a source path into a SARIF artifact URI. A relative path is
// already a valid URI reference, which is what code scanning maps to a file in
// the repository. An absolute path such as C:/x or /x is not, so it becomes a
// file URI rather than an invalid reference.
func artifactURI(source string) string {
	s := strings.ReplaceAll(source, `\`, "/")
	switch {
	case strings.HasPrefix(s, "/"):
		return "file://" + s
	case len(s) >= 3 && s[1] == ':' && s[2] == '/':
		return "file:///" + s
	default:
		return s
	}
}

func location(source string) []sarifLocation {
	if source == "" {
		return nil
	}
	return []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifact{URI: artifactURI(source)},
		Region:           sarifRegion{StartLine: 1},
	}}}
}

// fingerprint identifies a finding across runs so code scanning can track it.
// It uses only stable values: never the timestamp, and never evidence, which
// can carry a loopback port that changes on every run.
func fingerprint(caseID string, f model.Finding) string {
	sum := sha256.Sum256([]byte(caseID + "\x00" + string(f.Category) + "\x00" + f.IdentityID))
	return hex.EncodeToString(sum[:])
}

// SARIF writes the cases as one SARIF 2.1.0 run. Source should already be a
// repository-relative path with forward slashes; code scanning rejects
// absolute paths.
//
// A case that tested nothing marks the invocation unsuccessful and adds an
// error notification. An upload with zero results would otherwise show as a
// clean scan.
func SARIF(w io.Writer, cases []Case, toolVersion string) error {
	rules := make([]sarifRule, 0, len(knownRules))
	index := map[model.FindingCategory]int{}
	for i, r := range knownRules {
		rules = append(rules, newRule(r))
		index[r.category] = i
	}

	inv := sarifInvocation{ExecutionSuccessful: true}
	results := []sarifResult{}
	for _, c := range cases {
		id := c.Result.TestCaseID
		if reason := notTested(c.Result); reason != "" {
			inv.ExecutionSuccessful = false
			inv.Notifications = append(inv.Notifications, sarifNotification{
				Level:     "error",
				Message:   sarifText{Text: fmt.Sprintf("Case %s was not tested: %s.", id, reason)},
				Locations: location(c.Source),
			})
		}
		for _, f := range c.Result.Findings {
			ri, ok := index[f.Category]
			if !ok {
				// A category added to the engine after this list: still report it.
				ri = len(rules)
				index[f.Category] = ri
				rules = append(rules, newRule(ruleInfo{category: f.Category, name: string(f.Category),
					short: string(f.Category), full: "VardrGate finding category " + string(f.Category) + ".", severity: f.Severity}))
			}
			text := fmt.Sprintf("%s (case %s).", f.Message, id)
			if len(f.Evidence) > 0 {
				text += " Evidence: " + strings.Join(f.Evidence, "; ")
			}
			results = append(results, sarifResult{
				RuleID:              string(f.Category),
				RuleIndex:           ri,
				Level:               sarifLevel(f.Severity),
				Message:             sarifText{Text: text},
				Locations:           location(c.Source),
				PartialFingerprints: map[string]string{"vardrgateFinding/v1": fingerprint(id, f)},
				Properties: sarifResultProps{
					Severity:   string(f.Severity),
					Confidence: string(f.Confidence),
					TestCaseID: id,
					IdentityID: f.IdentityID,
				},
			})
		}
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "VardrGate",
				Version:        toolVersion,
				InformationURI: "https://github.com/VardrSec/VardrGate",
				Rules:          rules,
			}},
			Invocations: []sarifInvocation{inv},
			Results:     results,
		}},
	}
	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	_, err = w.Write(append(out, '\n'))
	return err
}
