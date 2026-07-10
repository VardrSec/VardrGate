// Package scaffold builds starter authorization test cases shared by the spec
// importers (OpenAPI, Postman). A scaffold pre-fills the request and adds an
// authenticated (allow) and an anonymous (deny) template identity, so a
// generated case becomes runnable — and exercises the missing_authentication
// check — once a real credential value is added.
package scaffold

import (
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

// Slug turns a path template into an id fragment:
// /users/{id}/profile → -users-id-profile.
func Slug(path string) string {
	return strings.NewReplacer("/", "-", "{", "", "}", "").Replace(path)
}
