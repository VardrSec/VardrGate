// Package scaffold builds starter authorization test cases shared by the spec
// importers (OpenAPI, Postman). A scaffold pre-fills the request and adds an
// authenticated (allow) and an anonymous (deny) template identity, so a
// generated case becomes runnable — and exercises the missing_authentication
// check — once a real credential value is added.
package scaffold

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

// StarterCase returns a scaffold test case for one endpoint.
func StarterCase(id, description, method, url string) model.AuthorizationTestCase {
	return model.AuthorizationTestCase{
		ID:          id,
		Description: description,
		Identities: []model.Identity{
			{ID: "authenticated", Role: "user", Credential: model.Credential{Type: model.CredentialTypeBearer}},
			{ID: "anonymous", Credential: model.Credential{Type: model.CredentialTypeStaticHeader}},
		},
		Request: model.RequestTemplate{Method: strings.ToUpper(method), URL: url},
		ExpectedAccess: []model.ExpectedAccess{
			{IdentityID: "authenticated", Decision: model.AccessDecisionAllow},
			{IdentityID: "anonymous", Decision: model.AccessDecisionDeny},
		},
	}
}

// MarshalCases renders generated cases as the JSON a user is meant to edit.
//
// model.Credential deliberately never marshals its value, which is correct for
// every API response — but a scaffold written to disk with no "value" key at
// all gives the reader nowhere to put the token. This writes an explicit
// ${VAR} placeholder for each credential that needs one, so the file shows
// what is missing and steers the answer towards an environment variable
// instead of a secret committed next to the tests.
func MarshalCases(cases []model.AuthorizationTestCase) ([]byte, error) {
	wire := make([]wireCase, 0, len(cases))
	for _, tc := range cases {
		wire = append(wire, toWire(tc))
	}
	out, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode cases: %w", err)
	}
	return append(out, '\n'), nil
}

// wireCase mirrors model.AuthorizationTestCase field for field, differing only
// in the credential, which carries its placeholder. Declaring it explicitly
// keeps the field order a reader sees in the generated file; the round-trip
// test asserts the two structs have identical JSON field sets, so a field added
// to the model cannot be silently dropped here.
type wireCase struct {
	RequireIdentityPreflight bool                   `json:"require_identity_preflight,omitempty"`
	ID                       string                 `json:"id"`
	Description              string                 `json:"description,omitempty"`
	Identities               []wireIdentity         `json:"identities"`
	Request                  model.RequestTemplate  `json:"request"`
	Resource                 *model.Resource        `json:"resource,omitempty"`
	RoleHierarchy            []string               `json:"role_hierarchy,omitempty"`
	SensitiveFields          []string               `json:"sensitive_fields,omitempty"`
	DenyStatuses             []int                  `json:"deny_status,omitempty"`
	Unauthorized             bool                   `json:"unauthorized_is_denial,omitempty"`
	DenyWhen                 *model.DenyCondition   `json:"deny_when,omitempty"`
	Mutating                 bool                   `json:"mutating,omitempty"`
	Verification             *wireVerification      `json:"write_verification,omitempty"`
	Setup                    []model.SetupStep      `json:"setup,omitempty"`
	CORS                     *model.CORSCheck       `json:"cors,omitempty"`
	ExpectedAccess           []model.ExpectedAccess `json:"expected_access"`
}

type wireIdentity struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name,omitempty"`
	Role        string                   `json:"role,omitempty"`
	TenantID    string                   `json:"tenant_id,omitempty"`
	Description string                   `json:"description,omitempty"`
	Credential  wireCredential           `json:"credential"`
	Preflight   *model.IdentityPreflight `json:"preflight,omitempty"`
}

// wireVerification carries the verifier's identity through wireIdentity so its
// credential gets the same placeholder treatment as every other identity.
type wireVerification struct {
	Environment       string                `json:"environment,omitempty"`
	Identity          wireIdentity          `json:"identity"`
	Request           model.RequestTemplate `json:"request"`
	AllowUnsafeMethod bool                  `json:"allow_unsafe_method,omitempty"`
	JSONPointer       string                `json:"json_pointer,omitempty"`
	ChangedTo         json.RawMessage       `json:"changed_to,omitempty"`
}

type wireCredential struct {
	Type   model.CredentialType `json:"type"`
	Header string               `json:"header,omitempty"`
	Value  string               `json:"value,omitempty"`
}

func toWire(tc model.AuthorizationTestCase) wireCase {
	ids := make([]wireIdentity, 0, len(tc.Identities))
	for _, id := range tc.Identities {
		ids = append(ids, toWireIdentity(id))
	}
	var verification *wireVerification
	if wv := tc.WriteVerification; wv != nil {
		verification = &wireVerification{
			Environment:       wv.Environment,
			Identity:          toWireIdentity(wv.Identity),
			Request:           wv.Request,
			AllowUnsafeMethod: wv.AllowUnsafeMethod,
			JSONPointer:       wv.JSONPointer,
			ChangedTo:         wv.ChangedTo,
		}
	}
	return wireCase{
		ID:                       tc.ID,
		Description:              tc.Description,
		RequireIdentityPreflight: tc.RequireIdentityPreflight,
		Identities:               ids,
		Request:                  tc.Request,
		Resource:                 tc.Resource,
		RoleHierarchy:            tc.RoleHierarchy,
		SensitiveFields:          tc.SensitiveFields,
		DenyStatuses:             tc.DenyStatuses,
		Unauthorized:             tc.UnauthorizedIsDenial,
		DenyWhen:                 tc.DenyWhen,
		Mutating:                 tc.Mutating,
		Verification:             verification,
		Setup:                    tc.Setup,
		CORS:                     tc.CORS,
		ExpectedAccess:           tc.ExpectedAccess,
	}
}

func toWireIdentity(id model.Identity) wireIdentity {
	return wireIdentity{
		ID:          id.ID,
		Name:        id.Name,
		Role:        id.Role,
		TenantID:    id.TenantID,
		Description: id.Description,
		Preflight:   id.Preflight,
		Credential: wireCredential{
			Type:   id.Credential.Type,
			Header: id.Credential.Header,
			Value:  placeholder(id),
		},
	}
}

// placeholder names the environment variable a credential should read from.
// An anonymous identity sends nothing, so it gets no placeholder — filling one
// in would turn it into an authenticated caller and silently remove the
// missing_authentication check the scaffold exists to set up.
func placeholder(id model.Identity) string {
	if id.Credential.Value != "" {
		return id.Credential.Value
	}
	if id.Credential.SendsNoAuth() {
		return ""
	}
	return "${VARDRGATE_" + envSlug(id.ID) + "_TOKEN}"
}

// envSlug upper-cases an identity id into an environment-variable fragment.
func envSlug(id string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(id) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	slug := strings.Trim(b.String(), "_")
	if slug == "" {
		return "IDENTITY"
	}
	return slug
}

// Slug turns a path template into an id fragment:
// /users/{id}/profile → -users-id-profile.
func Slug(path string) string {
	return strings.NewReplacer("/", "-", "{", "", "}", "").Replace(path)
}
