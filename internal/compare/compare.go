package compare

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

const (
	maxProfileFields = 2048
	maxProfileDepth  = 64
)

// Profile returns a deterministic, value-free description of a response body.
// JSON object keys, array shape, and scalar types participate in the schema
// hash; scalar values do not. Arrays collapse repeated element shapes.
func Profile(body []byte) *model.ResponseProfile {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var value interface{}
	if err := json.Unmarshal(body, &value); err != nil {
		return &model.ResponseProfile{Kind: "text"}
	}
	seen := map[string]struct{}{}
	truncated := false
	walkProfile(value, "$", 0, seen, &truncated)
	tokens := make([]string, 0, len(seen))
	for token := range seen {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	fieldSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if i := strings.LastIndexByte(token, ':'); i > 0 {
			fieldSet[token[:i]] = struct{}{}
		}
	}
	fields := make([]string, 0, len(fieldSet))
	for field := range fieldSet {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	sum := sha256.Sum256([]byte(strings.Join(tokens, "\n")))
	return &model.ResponseProfile{
		Kind: "json", SchemaHash: fmt.Sprintf("%x", sum), Fields: fields, Truncated: truncated,
	}
}

func walkProfile(value interface{}, path string, depth int, seen map[string]struct{}, truncated *bool) {
	if depth > maxProfileDepth || len(seen) >= maxProfileFields {
		*truncated = true
		return
	}
	add := func(kind string) bool {
		if len(seen) >= maxProfileFields {
			*truncated = true
			return false
		}
		seen[path+":"+kind] = struct{}{}
		return true
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		if !add("object") {
			return
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walkProfile(typed[key], path+"."+key, depth+1, seen, truncated)
		}
	case []interface{}:
		if !add("array") {
			return
		}
		for _, child := range typed {
			walkProfile(child, path+"[]", depth+1, seen, truncated)
		}
	case string:
		add("string")
	case float64:
		add("number")
	case bool:
		add("boolean")
	case nil:
		add("null")
	}
}

// SensitiveTiers groups field names by what their exposure means. A leaked
// password and a leaked "created_by" are both worth knowing about and are not
// the same finding, so severity and category come from the tier rather than
// from a single flat list.
//
// TierElevated is the one that earns its own category: a property that governs
// authorization or value (role, is_admin, balance) reaching a caller who must
// not see it is broken object property level authorization, OWASP API3:2023.
//
// Matching is on the whole field name, case-insensitively, after normalizing
// separators — "isAdmin", "is_admin", and "IS-ADMIN" are the same field.
// Substring matching is deliberately not used: it classifies "username" as an
// identifier because it contains "user", which is acceptable noise in a prober
// generating probes and unacceptable in something that emits findings.
var SensitiveTiers = map[model.SensitivityTier][]string{
	model.TierCritical: {
		"password", "passwd", "pwd", "secret", "token", "access_token",
		"refresh_token", "api_key", "apikey", "private_key", "client_secret",
		"session_token", "salt", "password_hash", "cvv", "pin", "credit_card",
		"card_number", "security_answer",
	},
	model.TierElevated: {
		"role", "roles", "permission", "permissions", "privilege", "privileges",
		"scope", "scopes", "is_admin", "is_superuser", "is_staff", "admin",
		"access_level", "tier", "plan", "subscription", "balance",
		"account_balance", "credit_limit", "salary", "compensation",
	},
	model.TierPII: {
		"email", "email_address", "phone", "phone_number", "mobile", "address",
		"street_address", "postal_code", "ssn", "social_security_number",
		"date_of_birth", "dob", "birth_date", "passport", "passport_number",
		"drivers_license", "national_id", "tax_id",
	},
	model.TierInternal: {
		"created_by", "updated_by", "deleted_by", "created_by_id",
		"updated_by_id", "internal_id", "internal_notes", "debug", "trace",
		"stack_trace", "raw_query", "sql",
	},
}

// DefaultSensitiveFields is the flat union of every tier, retained for callers
// that only need the names.
var DefaultSensitiveFields = flattenTiers()

func flattenTiers() []string {
	var out []string
	for _, names := range SensitiveTiers {
		out = append(out, names...)
	}
	sort.Strings(out)
	return out
}

// SensitiveHit records one sensitive field found in a response body.
type SensitiveHit struct {
	// Path is where the field was found, e.g. "user.profile.ssn" or
	// "orders[].payment.card_number". A path locates the leak; a bare name only
	// says one exists.
	Path string `json:"path"`
	// Field is the field name itself.
	Field string `json:"field"`
	// Tier drives the finding's severity and category.
	Tier model.SensitivityTier `json:"tier"`
}

// ScanSensitive walks a JSON body and reports every sensitive field it holds,
// with the path to each. Field *names* and paths are recorded; values never
// are, so a findings report cannot itself become the breach.
//
// When declared is non-empty it replaces the built-in tiers entirely: the
// author has said which fields matter for this endpoint, and every hit is
// reported at TierDeclared rather than being sorted into a tier the engine
// guessed at.
func ScanSensitive(body []byte, declared []string) []SensitiveHit {
	if len(body) == 0 {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}

	want := map[string]model.SensitivityTier{}
	if len(declared) > 0 {
		for _, f := range declared {
			want[normalizeField(f)] = model.TierDeclared
		}
	} else {
		for tier, names := range SensitiveTiers {
			for _, f := range names {
				want[normalizeField(f)] = tier
			}
		}
	}

	var hits []SensitiveHit
	seen := map[string]struct{}{}
	walkSensitive(v, "", want, seen, &hits)
	sort.Slice(hits, func(i, j int) bool { return hits[i].Path < hits[j].Path })
	return hits
}

func walkSensitive(v interface{}, path string, want map[string]model.SensitivityTier, seen map[string]struct{}, hits *[]SensitiveHit) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			if tier, ok := want[normalizeField(k)]; ok {
				if _, dup := seen[childPath]; !dup {
					seen[childPath] = struct{}{}
					*hits = append(*hits, SensitiveHit{Path: childPath, Field: k, Tier: tier})
				}
			}
			walkSensitive(child, childPath, want, seen, hits)
		}
	case []interface{}:
		// Collapse arrays to one representative path: a leak in every element of
		// a 500-item list is one finding, not five hundred.
		arrayPath := path + "[]"
		for _, child := range t {
			walkSensitive(child, arrayPath, want, seen, hits)
		}
	}
}

// normalizeField lowercases a field name and strips separators so camelCase,
// snake_case, and kebab-case spellings of the same field compare equal.
func normalizeField(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r == '_' || r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// FieldValue returns the first value found for the named field anywhere in a
// JSON body (at any nesting depth), rendered as a string. Only scalar values
// are returned; objects and arrays report false.
//
// Matching uses the same normalization as ScanSensitive: case-insensitive and
// separator-insensitive, so a policy naming "tenant_id" matches a response that
// spells it "tenantId" or "tenant-id". Without this, a tenant-isolation break
// against a camelCase API would be reported as potential_bola or unexpected_access
// rather than the more specific (and more severe) cross_tenant_access.
//
// Field order within a JSON object is not preserved by decoding, so a body with
// the same key at several depths has no defined winner. Callers use this for
// identifiers that appear once, such as a tenant field.
func FieldValue(body []byte, field string) (string, bool) {
	if len(body) == 0 || field == "" {
		return "", false
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", false
	}
	return findScalar(v, normalizeField(field))
}

// ValueAtPath resolves a dotted path against a JSON body and returns the scalar
// there, e.g. "error.code" or "data.status". Unlike FieldValue it navigates
// exactly rather than searching, so a caller that knows the shape gets a
// deterministic answer instead of the first match at any depth.
//
// A single-element array is transparent, since APIs commonly wrap a lone object.
func ValueAtPath(body []byte, path string) (string, bool) {
	if len(body) == 0 || path == "" {
		return "", false
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", false
	}
	for _, segment := range strings.Split(path, ".") {
		if arr, ok := v.([]interface{}); ok && len(arr) == 1 {
			v = arr[0]
		}
		obj, ok := v.(map[string]interface{})
		if !ok {
			return "", false
		}
		next, ok := lookupInsensitive(obj, segment)
		if !ok {
			return "", false
		}
		v = next
	}
	if arr, ok := v.([]interface{}); ok && len(arr) == 1 {
		v = arr[0]
	}
	return scalarString(v)
}

func lookupInsensitive(obj map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := obj[key]; ok {
		return v, true
	}
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// MatchesDeny reports whether a response body satisfies a declared deny
// condition, and returns a description of what matched for use as evidence.
//
// The condition is authored, never inferred: this only answers a question the
// policy already asked.
func MatchesDeny(body []byte, cond *model.DenyCondition) (string, bool) {
	if cond.IsZero() || len(body) == 0 {
		return "", false
	}
	lower := strings.ToLower(string(body))
	for _, needle := range cond.BodyContains {
		if needle == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(needle)) {
			return fmt.Sprintf("body_contains=%q", needle), true
		}
	}
	if m := cond.JSONField; m != nil && m.Path != "" {
		val, ok := ValueAtPath(body, m.Path)
		if !ok {
			return "", false
		}
		if m.Equals == "" {
			return fmt.Sprintf("json_field=%s present", m.Path), true
		}
		if strings.EqualFold(val, m.Equals) {
			return fmt.Sprintf("json_field=%s equals %q", m.Path, m.Equals), true
		}
	}
	return "", false
}

func findScalar(v interface{}, want string) (string, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			if normalizeField(k) == want {
				if s, ok := scalarString(child); ok {
					return s, true
				}
			}
		}
		for _, child := range t {
			if s, ok := findScalar(child, want); ok {
				return s, true
			}
		}
	case []interface{}:
		for _, child := range t {
			if s, ok := findScalar(child, want); ok {
				return s, true
			}
		}
	}
	return "", false
}

// scalarString renders a JSON scalar as a string. Numbers decode as float64;
// integral values are rendered without a decimal point so an id like 42 does
// not become "42".
func scalarString(v interface{}) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false
	}
}

// SensitiveFieldsPresent returns the sorted field names from fields that appear
// anywhere in the JSON body. Retained for callers that only need names;
// ScanSensitive returns paths and tiers and is what the engine uses.
func SensitiveFieldsPresent(body []byte, fields []string) []string {
	hits := ScanSensitive(body, fields)
	if len(hits) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if _, dup := seen[h.Field]; dup {
			continue
		}
		seen[h.Field] = struct{}{}
		out = append(out, h.Field)
	}
	sort.Strings(out)
	return out
}

// Results compares two ExecutionResults and returns a ComparisonResult
// with structured notes and evidence strings. fields names the sensitive field
// set to look for; nil uses DefaultSensitiveFields, so a caller that overrode
// the set on its test case gets the same answer here as from the engine's
// sensitive-data check.
func Results(a, b model.ExecutionResult, fields []string) model.ComparisonResult {
	cr := model.ComparisonResult{}
	var notes []string
	if len(fields) == 0 {
		fields = DefaultSensitiveFields
	}

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
	if !cr.BodyMatch {
		cr.SizeDiff = int64(len(b.Body)) - int64(len(a.Body))
	}

	profileA, profileB := Profile(a.Body), Profile(b.Body)
	if profileA != nil && profileB != nil && profileA.Kind == "json" && profileB.Kind == "json" {
		cr.SchemaMatch = profileA.SchemaHash == profileB.SchemaHash && !profileA.Truncated && !profileB.Truncated
		cr.SharedFieldRatio, cr.FieldsOnlyInA, cr.FieldsOnlyInB = compareFields(profileA.Fields, profileB.Fields)
		if cr.SchemaMatch && !cr.BodyMatch {
			notes = append(notes, "response schemas match; only values differ")
		} else if !cr.SchemaMatch {
			notes = append(notes, fmt.Sprintf("response schema overlap: %.0f%%", cr.SharedFieldRatio*100))
		}
	}

	// Normalized JSON equality (order-independent key comparison).
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
		notes = append(notes, fmt.Sprintf(
			"body size difference: %d bytes (%s=%d %s=%d)",
			abs(cr.SizeDiff), a.IdentityID, len(a.Body), b.IdentityID, len(b.Body),
		))
	}

	// Sensitive field presence in each body.
	sensitiveA := sensitiveFieldSet(a.Body, fields)
	sensitiveB := sensitiveFieldSet(b.Body, fields)
	for _, field := range fields {
		_, inA := sensitiveA[normalizeField(field)]
		_, inB := sensitiveB[normalizeField(field)]
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

func compareFields(a, b []string) (float64, []string, []string) {
	setA, setB := map[string]struct{}{}, map[string]struct{}{}
	for _, field := range a {
		setA[field] = struct{}{}
	}
	for _, field := range b {
		setB[field] = struct{}{}
	}
	shared := 0
	var onlyA, onlyB []string
	for field := range setA {
		if _, ok := setB[field]; ok {
			shared++
		} else {
			onlyA = append(onlyA, field)
		}
	}
	for field := range setB {
		if _, ok := setA[field]; !ok {
			onlyB = append(onlyB, field)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	union := len(setA) + len(setB) - shared
	if union == 0 {
		return 1, onlyA, onlyB
	}
	return float64(shared) / float64(union), onlyA, onlyB
}

func sensitiveFieldSet(body []byte, fields []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, hit := range ScanSensitive(body, fields) {
		set[normalizeField(hit.Field)] = struct{}{}
	}
	return set
}

// Evidence returns a slice of strings that can be attached to a Finding,
// summarizing the most security-relevant differences.
func Evidence(a, b model.ExecutionResult, cr model.ComparisonResult) []string {
	var ev []string
	if !cr.StatusCodeMatch {
		ev = append(ev, fmt.Sprintf("status_codes: %s=%d %s=%d",
			a.IdentityID, a.StatusCode, b.IdentityID, b.StatusCode))
	}
	if !cr.BodyMatch {
		ev = append(ev, fmt.Sprintf("bodies_differ: size_delta=%d", cr.SizeDiff))
	}
	if cr.SchemaMatch && !cr.BodyMatch {
		ev = append(ev, fmt.Sprintf("response_schema_matches_baseline: field_overlap=%.0f%%", cr.SharedFieldRatio*100))
	}
	if len(cr.FieldsOnlyInA) > 0 {
		ev = append(ev, "fields_only_in_baseline="+strings.Join(cr.FieldsOnlyInA, ","))
	}
	if len(cr.FieldsOnlyInB) > 0 {
		ev = append(ev, "fields_only_in_compared="+strings.Join(cr.FieldsOnlyInB, ","))
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

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
