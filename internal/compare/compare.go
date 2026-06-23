package compare

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/VardrSec/vardrgate/internal/model"
)

// sensitiveFields is the default set of field names whose presence in a
// response body is noted as evidence regardless of the access decision.
var sensitiveFields = []string{
	"password", "secret", "token", "api_key", "access_token",
	"refresh_token", "private_key", "ssn", "credit_card",
}

// Results compares two ExecutionResults and returns a ComparisonResult
// with structured notes and evidence strings.
func Results(a, b model.ExecutionResult) model.ComparisonResult {
	cr := model.ComparisonResult{}
	var notes []string

	// Status code comparison.
	cr.StatusCodeMatch = a.StatusCode == b.StatusCode
	if !cr.StatusCodeMatch {
		notes = append(notes, fmt.Sprintf(
			"status code mismatch: %s=%d %s=%d",
			a.IdentityID, a.StatusCode, b.IdentityID, b.StatusCode,
		))
	}

	// Raw body equality.
	cr.BodyMatch = bytes.Equal(a.Body, b.Body)

	// Normalised JSON equality (order-independent key comparison).
	if !cr.BodyMatch && looksLikeJSON(a.Body) && looksLikeJSON(b.Body) {
		if normalizedEqual(a.Body, b.Body) {
			cr.BodyMatch = true
			notes = append(notes, "bodies differ in whitespace/key order only")
		} else {
			notes = append(notes, fmt.Sprintf(
				"json body mismatch: %s and %s returned different content",
				a.IdentityID, b.IdentityID,
			))
		}
	} else if !cr.BodyMatch {
		cr.SizeDiff = int64(len(b.Body)) - int64(len(a.Body))
		notes = append(notes, fmt.Sprintf(
			"body size difference: %d bytes (%s=%d %s=%d)",
			abs(cr.SizeDiff), a.IdentityID, len(a.Body), b.IdentityID, len(b.Body),
		))
	}

	// Sensitive field presence in each body.
	for _, field := range sensitiveFields {
		inA := containsField(a.Body, field)
		inB := containsField(b.Body, field)
		if inA != inB {
			holder := b.IdentityID
			if inA {
				holder = a.IdentityID
			}
			notes = append(notes, fmt.Sprintf(
				"sensitive field %q present only in response for %s", field, holder,
			))
		}
	}

	cr.Notes = notes
	return cr
}

// Evidence returns a slice of strings that can be attached to a Finding,
// summarising the most security-relevant differences.
func Evidence(a, b model.ExecutionResult, cr model.ComparisonResult) []string {
	var ev []string
	if !cr.StatusCodeMatch {
		ev = append(ev, fmt.Sprintf("status_codes: %s=%d %s=%d",
			a.IdentityID, a.StatusCode, b.IdentityID, b.StatusCode))
	}
	if !cr.BodyMatch {
		ev = append(ev, fmt.Sprintf("bodies_differ: size_delta=%d", cr.SizeDiff))
	}
	for _, note := range cr.Notes {
		ev = append(ev, note)
	}
	return ev
}

// looksLikeJSON returns true when the payload starts with a JSON object or array.
func looksLikeJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return false
	}
	return t[0] == '{' || t[0] == '['
}

// normalizedEqual unmarshals both payloads into interface{} and re-marshals
// them to a canonical form for comparison.
func normalizedEqual(a, b []byte) bool {
	var va, vb interface{}
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	na, err := json.Marshal(va)
	if err != nil {
		return false
	}
	nb, err := json.Marshal(vb)
	if err != nil {
		return false
	}
	return bytes.Equal(na, nb)
}

// containsField reports whether body is a JSON object that contains the
// top-level key field (case-insensitive).
func containsField(body []byte, field string) bool {
	if !looksLikeJSON(body) {
		return false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	needle := []byte(field)
	for k := range m {
		if bytes.EqualFold([]byte(k), needle) {
			return true
		}
	}
	return false
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
