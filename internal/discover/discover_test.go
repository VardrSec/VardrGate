package discover

import (
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/openapi"
	"github.com/VardrSec/vardrgate/internal/policy"
)

const spec = `{
  "openapi": "3.0.0",
  "info": {"title": "T", "version": "1"},
  "paths": {
    "/users/{user_id}/profile": {"get": {"operationId": "getProfile"}},
    "/orgs/{org_id}/users/{user_id}": {"delete": {"operationId": "deleteUser"}},
    "/health": {"get": {"operationId": "health"}},
    "/companies/{companyId}": {"get": {"operationId": "getCompany"}}
  }
}`

func parseSpec(t *testing.T) openapi.Spec {
	t.Helper()
	s, err := openapi.Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return s
}

// The invariant the whole design rests on: discovery proposes structure and
// never an expectation, and the parser refuses the placeholder, so a draft
// physically cannot run until a human has decided.
func TestFromSpec_EveryExpectationIsAnUnparseableDraftMarker(t *testing.T) {
	drafts := FromSpec(parseSpec(t), Options{})
	if len(drafts) == 0 {
		t.Fatal("expected drafts")
	}
	for _, d := range drafts {
		if !strings.Contains(d.YAML, policy.DraftMarker) {
			t.Errorf("%s has no %s marker", d.Filename, policy.DraftMarker)
		}
		_, err := policy.Parse([]byte(d.YAML))
		if err == nil {
			t.Errorf("%s parsed successfully; a draft must be inert until completed", d.Filename)
			continue
		}
		if !strings.Contains(err.Error(), policy.DraftMarker) {
			t.Errorf("%s: error should name the marker, got %v", d.Filename, err)
		}
	}
}

func TestFromSpec_CompletedDraftParses(t *testing.T) {
	drafts := FromSpec(parseSpec(t), Options{})
	completed := strings.ReplaceAll(drafts[0].YAML, policy.DraftMarker, "deny")
	if _, err := policy.Parse([]byte(completed)); err != nil {
		t.Fatalf("a draft with decisions filled in must parse: %v\n%s", err, completed)
	}
}

func TestFromSpec_SkipsOperationsWithNoPathParameter(t *testing.T) {
	// /health addresses no object, so it has no object-level control to state.
	for _, d := range FromSpec(parseSpec(t), Options{}) {
		if strings.Contains(d.Endpoint, "/health") {
			t.Errorf("drafted a policy for an endpoint with no object: %s", d.Endpoint)
		}
	}
}

func TestFromSpec_InfersTheLastIdentifierInThePath(t *testing.T) {
	// /orgs/{org_id}/users/{user_id} addresses a user, not an org.
	for _, d := range FromSpec(parseSpec(t), Options{}) {
		if !strings.Contains(d.Endpoint, "/orgs/") {
			continue
		}
		if !strings.Contains(d.YAML, "id_param: user_id") {
			t.Errorf("id_param should be user_id:\n%s", d.YAML)
		}
		return
	}
	t.Fatal("no draft for the nested path")
}

func TestFromSpec_RecognizesCamelCaseIdentifiers(t *testing.T) {
	for _, d := range FromSpec(parseSpec(t), Options{}) {
		if strings.Contains(d.Endpoint, "/companies/") && !strings.Contains(d.YAML, "id_param: companyId") {
			t.Errorf("companyId not recognized as an identifier:\n%s", d.YAML)
		}
	}
}

// An unsafe method must not arrive pre-approved.
func TestFromSpec_UnsafeMethodDraftsAsNonMutating(t *testing.T) {
	for _, d := range FromSpec(parseSpec(t), Options{}) {
		if !strings.HasPrefix(d.Endpoint, "DELETE") {
			continue
		}
		if !strings.Contains(d.YAML, "mutating: false") {
			t.Errorf("DELETE draft should leave mutating false:\n%s", d.YAML)
		}
		return
	}
	t.Fatal("no DELETE draft")
}

func TestFromSpec_SampleSuppliesTenantFieldAndSensitiveFields(t *testing.T) {
	sample := []byte(`{"user_id":"1","tenant_id":"t-a","email":"a@b.c","is_admin":false}`)
	drafts := FromSpec(parseSpec(t), Options{Sample: sample})
	d := drafts[0]
	if !strings.Contains(d.YAML, "tenant_field: tenant_id") {
		t.Errorf("tenant_field not inferred:\n%s", d.YAML)
	}
	if !strings.Contains(d.YAML, "sensitive_fields") {
		t.Errorf("sensitive fields not proposed:\n%s", d.YAML)
	}
	var mentionsElevated bool
	for _, n := range d.Notes {
		if strings.Contains(n, "authorization-bearing") {
			mentionsElevated = true
		}
	}
	if !mentionsElevated {
		t.Errorf("is_admin in the sample should be called out: %v", d.Notes)
	}
}

func TestFromSpec_WithoutSampleLeavesTenantFieldCommented(t *testing.T) {
	d := FromSpec(parseSpec(t), Options{})[0]
	if strings.Contains(d.YAML, "\n    tenant_field:") {
		t.Errorf("tenant_field should not be asserted without evidence:\n%s", d.YAML)
	}
}

// Notes let a reviewer check the reasoning instead of trusting it.
func TestFromSpec_ExplainsEveryInference(t *testing.T) {
	for _, d := range FromSpec(parseSpec(t), Options{}) {
		if len(d.Notes) == 0 {
			t.Errorf("%s has no notes explaining what was inferred", d.Filename)
		}
	}
}

func TestFromSpec_DeterministicOrder(t *testing.T) {
	first := FromSpec(parseSpec(t), Options{})
	second := FromSpec(parseSpec(t), Options{})
	if len(first) != len(second) {
		t.Fatal("draft count differs between runs")
	}
	for i := range first {
		if first[i].Filename != second[i].Filename {
			t.Errorf("order differs at %d: %q vs %q", i, first[i].Filename, second[i].Filename)
		}
	}
}

func TestFromSpec_CustomRoles(t *testing.T) {
	d := FromSpec(parseSpec(t), Options{Roles: []string{"admin", "member"}})[0]
	if !strings.Contains(d.YAML, "admin: "+policy.DraftMarker) || !strings.Contains(d.YAML, "member: "+policy.DraftMarker) {
		t.Errorf("custom roles not used:\n%s", d.YAML)
	}
	if strings.Contains(d.YAML, "anonymous:") {
		t.Errorf("default roles leaked in:\n%s", d.YAML)
	}
}

func TestResourceTypeFromPath(t *testing.T) {
	tests := map[string]string{
		"/users/{id}":              "user",
		"/users/{user_id}/profile": "profile",
		"/companies/{id}":          "company",
		"/addresses/{id}":          "address",
		"/status/{id}":             "status",
		"/{id}":                    "",
	}
	for path, want := range tests {
		if got := resourceTypeFromPath(path); got != want {
			t.Errorf("resourceTypeFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestIdParamPattern_DoesNotMatchOnSubstrings(t *testing.T) {
	// "username" contains "user"; a prober can afford that noise and a policy
	// proposal a human signs cannot.
	for _, name := range []string{"username", "identity", "video", "hidden"} {
		if idParamPattern.MatchString(normalize(name)) {
			t.Errorf("%q was wrongly classified as an identifier", name)
		}
	}
	for _, name := range []string{"id", "user_id", "companyId", "uuid", "orderRef"} {
		if !idParamPattern.MatchString(normalize(name)) {
			t.Errorf("%q should be an identifier", name)
		}
	}
}
