// Package openapi parses a subset of an OpenAPI 3 document and generates starter
// authorization test cases from its operations — one per path+method. The output
// is a scaffold: the request is filled in, and two template identities
// (an authenticated caller and an anonymous one) with default expectations are
// provided so a generated case becomes runnable once real credentials are added.
package openapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

// Spec is the parsed subset of an OpenAPI 3 document.
type Spec struct {
	OpenAPI string              `json:"openapi"`
	Info    Info                `json:"info"`
	Servers []Server            `json:"servers"`
	Paths   map[string]PathItem `json:"paths"`
}

// Info carries document metadata.
type Info struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

// Server is an API base URL.
type Server struct {
	URL string `json:"url"`
}

// PathItem holds the operations defined for a path.
type PathItem struct {
	Get     *Operation `json:"get"`
	Put     *Operation `json:"put"`
	Post    *Operation `json:"post"`
	Delete  *Operation `json:"delete"`
	Patch   *Operation `json:"patch"`
	Head    *Operation `json:"head"`
	Options *Operation `json:"options"`
}

// Operation is a single API operation.
type Operation struct {
	OperationID string                `json:"operationId"`
	Summary     string                `json:"summary"`
	Security    []map[string][]string `json:"security"`
}

// method returns each defined (method, operation) pair in a stable order.
func (p PathItem) operations() []methodOp {
	all := []methodOp{
		{"GET", p.Get}, {"POST", p.Post}, {"PUT", p.Put}, {"PATCH", p.Patch},
		{"DELETE", p.Delete}, {"HEAD", p.Head}, {"OPTIONS", p.Options},
	}
	var out []methodOp
	for _, m := range all {
		if m.op != nil {
			out = append(out, m)
		}
	}
	return out
}

type methodOp struct {
	method string
	op     *Operation
}

// Parse decodes an OpenAPI 3 document, rejecting unknown top-level structure only
// loosely (unknown fields are ignored so real-world specs parse).
func Parse(data []byte) (Spec, error) {
	var s Spec
	if err := json.Unmarshal(data, &s); err != nil {
		return Spec{}, fmt.Errorf("parse openapi: %w", err)
	}
	if len(s.Paths) == 0 {
		return Spec{}, fmt.Errorf("parse openapi: document has no paths")
	}
	return s, nil
}

// GenerateTestCases produces one starter test case per operation, sorted by path
// then method for deterministic output. baseURL overrides the spec's first
// server; when both are empty the path template is used unchanged.
func (s Spec) GenerateTestCases(baseURL string) []model.AuthorizationTestCase {
	base := strings.TrimRight(baseURL, "/")
	if base == "" && len(s.Servers) > 0 {
		base = strings.TrimRight(s.Servers[0].URL, "/")
	}

	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var cases []model.AuthorizationTestCase
	for _, path := range paths {
		for _, mo := range s.Paths[path].operations() {
			cases = append(cases, starterCase(base, path, mo.method, mo.op))
		}
	}
	return cases
}

// starterCase builds a scaffold test case. It includes an authenticated identity
// (expected allow) and an anonymous one (expected deny), so once a real token is
// filled in it exercises the missing_authentication check for the endpoint.
func starterCase(base, path, method string, op *Operation) model.AuthorizationTestCase {
	id := op.OperationID
	if id == "" {
		id = strings.ToLower(method) + slug(path)
	}
	return model.AuthorizationTestCase{
		ID:          id,
		Description: op.Summary,
		Identities: []model.Identity{
			{ID: "authenticated", Role: "user", Credential: model.Credential{Type: model.CredentialTypeBearer}},
			{ID: "anonymous", Credential: model.Credential{Type: model.CredentialTypeStaticHeader}},
		},
		Request: model.RequestTemplate{Method: method, URL: base + path},
		ExpectedAccess: []model.ExpectedAccess{
			{IdentityID: "authenticated", Decision: model.AccessDecisionAllow},
			{IdentityID: "anonymous", Decision: model.AccessDecisionDeny},
		},
	}
}

// slug turns a path template into an id fragment: /users/{id}/profile → -users-id-profile.
func slug(path string) string {
	r := strings.NewReplacer("/", "-", "{", "", "}", "")
	return r.Replace(path)
}
