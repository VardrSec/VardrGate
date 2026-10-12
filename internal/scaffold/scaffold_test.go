package scaffold

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func TestStarterCase(t *testing.T) {
	c := StarterCase("get-users", "List users", "get", "https://api.example.com/users")
	if c.ID != "get-users" || c.Description != "List users" {
		t.Errorf("metadata wrong: %+v", c)
	}
	if c.Request.Method != "GET" { // method upper-cased
		t.Errorf("method not upper-cased: %q", c.Request.Method)
	}
	if c.Request.URL != "https://api.example.com/users" {
		t.Errorf("url wrong: %q", c.Request.URL)
	}
	if len(c.Identities) != 2 || len(c.ExpectedAccess) != 2 {
		t.Fatalf("unexpected shape: %+v", c)
	}
	want := map[string]model.AccessDecision{"authenticated": model.AccessDecisionAllow, "anonymous": model.AccessDecisionDeny}
	for _, ea := range c.ExpectedAccess {
		if want[ea.IdentityID] != ea.Decision {
			t.Errorf("%s: got %s, want %s", ea.IdentityID, ea.Decision, want[ea.IdentityID])
		}
	}
}

func TestSlug(t *testing.T) {
	if got := Slug("/users/{id}/profile"); got != "-users-id-profile" {
		t.Errorf("Slug: got %q", got)
	}
}

func TestMarshalCases_WritesEnvPlaceholderForRealCredentials(t *testing.T) {
	// The scaffold is a file a human edits. model.Credential never marshals a
	// value, so without this the generated file had no key to fill in at all.
	out, err := MarshalCases([]model.AuthorizationTestCase{
		StarterCase("getProfile", "Read a profile", "get", "https://api.example.com/users/1"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, `"value": "${VARDRGATE_AUTHENTICATED_TOKEN}"`) {
		t.Errorf("no placeholder for the authenticated identity:\n%s", got)
	}
}

func TestMarshalCases_AnonymousIdentityGetsNoPlaceholder(t *testing.T) {
	// Filling a value in here would give the anonymous caller a credential and
	// silently delete the missing_authentication check.
	out, err := MarshalCases([]model.AuthorizationTestCase{
		StarterCase("getProfile", "", "get", "https://api.example.com/users/1"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "ANONYMOUS_TOKEN") {
		t.Errorf("anonymous identity was given a credential placeholder:\n%s", out)
	}
}

func TestMarshalCases_RoundTripsBackIntoTestCases(t *testing.T) {
	cases := []model.AuthorizationTestCase{
		StarterCase("getProfile", "Read a profile", "get", "https://api.example.com/users/1"),
	}
	out, err := MarshalCases(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var back []model.AuthorizationTestCase
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("generated file does not parse back as test cases: %v", err)
	}
	if len(back) != 1 || back[0].ID != "getProfile" {
		t.Fatalf("round trip lost the case: %+v", back)
	}
	if back[0].Identities[0].Credential.Value != "${VARDRGATE_AUTHENTICATED_TOKEN}" {
		t.Errorf("placeholder did not survive the round trip: %q", back[0].Identities[0].Credential.Value)
	}
	if len(back[0].ExpectedAccess) != 2 {
		t.Errorf("expected_access lost in round trip: %+v", back[0].ExpectedAccess)
	}
}

func TestEnvSlug(t *testing.T) {
	tests := map[string]string{
		"authenticated": "AUTHENTICATED",
		"other_user":    "OTHER_USER",
		"other-user":    "OTHER_USER",
		"user.1":        "USER_1",
		"__":            "IDENTITY",
		"":              "IDENTITY",
	}
	for in, want := range tests {
		if got := envSlug(in); got != want {
			t.Errorf("envSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

// wireCase exists to control field order in a generated file. This asserts it
// is otherwise a faithful mirror of the model, so a field added to the test
// case cannot be silently dropped on the way to disk.
func TestWireTypesMirrorTheModel(t *testing.T) {
	compareJSONFields(t, "AuthorizationTestCase", reflect.TypeOf(model.AuthorizationTestCase{}), reflect.TypeOf(wireCase{}))
	compareJSONFields(t, "Identity", reflect.TypeOf(model.Identity{}), reflect.TypeOf(wireIdentity{}))
}

func compareJSONFields(t *testing.T, name string, model, wire reflect.Type) {
	t.Helper()
	want := jsonFieldNames(model)
	got := jsonFieldNames(wire)
	for field := range want {
		if _, ok := got[field]; !ok {
			t.Errorf("%s: wire type is missing %q — it would be dropped from generated files", name, field)
		}
	}
	for field := range got {
		if _, ok := want[field]; !ok {
			t.Errorf("%s: wire type has %q which the model does not", name, field)
		}
	}
}

func jsonFieldNames(t reflect.Type) map[string]struct{} {
	out := map[string]struct{}{}
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		// A "-" tag means the field is deliberately never serialized.
		if name == "" || name == "-" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func TestMarshalCases_PreservesEveryTestCaseField(t *testing.T) {
	original := model.AuthorizationTestCase{
		ID:          "rich",
		Description: "a case using every field",
		Identities: []model.Identity{{
			ID:          "owner",
			Name:        "Owner",
			Role:        "owner",
			TenantID:    "tenant-a",
			Description: "the legitimate owner",
			Preflight:   &model.IdentityPreflight{URL: "https://api.example.com/session", ExpectedStatus: 200, JSONFields: map[string]string{"id": "owner"}},
			Credential:  model.Credential{Type: model.CredentialTypeBearer, Value: "literal"},
		}},
		Request:         model.RequestTemplate{Method: "GET", URL: "https://api.example.com/x"},
		Resource:        &model.Resource{Type: "user_profile", ObjectID: "1", OwnerIdentity: "owner", TenantField: "tenant_id"},
		RoleHierarchy:   []string{"viewer", "admin"},
		SensitiveFields: []string{"internal_note"},
		DenyStatuses:    []int{404},
		CORS:            &model.CORSCheck{ProbeOrigin: "https://evil.example"},
		ExpectedAccess:  []model.ExpectedAccess{{IdentityID: "owner", Decision: model.AccessDecisionAllow}},
	}

	out, err := MarshalCases([]model.AuthorizationTestCase{original})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var back []model.AuthorizationTestCase
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("parse back: %v", err)
	}
	if !reflect.DeepEqual(back[0], original) {
		t.Errorf("round trip lost data:\nwant %+v\ngot  %+v", original, back[0])
	}
}
