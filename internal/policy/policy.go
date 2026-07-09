// Package policy parses declarative API authorization policies and compiles
// them into executable authorization test cases.
//
// A policy describes expected security behaviour independent of any concrete
// environment: which logical identity is the owner, which roles may access the
// object, and what the deny statuses are. Binding a policy to a base URL, path
// parameters, and concrete identities produces a model.AuthorizationTestCase
// the engine can run. This is what lets one control be proven repeatedly across
// environments (dev, staging, prod) and over time.
package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
	"gopkg.in/yaml.v3"
)

// Policy is the on-disk representation of an authorization control.
type Policy struct {
	API      APISpec           `yaml:"api"`
	Expect   map[string]string `yaml:"expect"`
	Response ResponseSpec      `yaml:"response"`
}

// APISpec identifies the endpoint under test and its ownership model.
type APISpec struct {
	// Endpoint is "<METHOD> <path>", e.g. "GET /users/{user_id}/profile".
	Endpoint string `yaml:"endpoint"`
	// Owner names the logical identity that owns the object, e.g. "identity:owner".
	Owner    string       `yaml:"owner"`
	Resource ResourceSpec `yaml:"resource"`
}

// ResourceSpec describes the object addressed by the endpoint.
type ResourceSpec struct {
	Type        string `yaml:"type"`
	IDParam     string `yaml:"id_param"`
	TenantField string `yaml:"tenant_field"`
}

// ResponseSpec captures expected response constraints.
type ResponseSpec struct {
	DenyStatus      []int         `yaml:"deny_status"`
	SensitiveFields SensitiveSpec `yaml:"sensitive_fields"`
}

// SensitiveSpec lists logical roles that must not receive sensitive fields.
type SensitiveSpec struct {
	ForbiddenFor []string `yaml:"forbidden_for"`
}

// Bindings supply the concrete values needed to turn a Policy into a runnable
// test case: the environment base URL, path parameter values, and the actual
// identities (each Role set to a logical name that appears in Policy.Expect).
type Bindings struct {
	TestCaseID       string
	BaseURL          string
	PathParams       map[string]string
	Identities       []model.Identity
	ResourceTenantID string // optional; enables cross_tenant_access classification
}

// Load reads and validates a policy file.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse decodes and validates a policy from YAML bytes.
func Parse(data []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) validate() error {
	if strings.TrimSpace(p.API.Endpoint) == "" {
		return fmt.Errorf("policy: api.endpoint is required")
	}
	if _, _, err := p.method(); err != nil {
		return err
	}
	if len(p.Expect) == 0 {
		return fmt.Errorf("policy: expect must define at least one logical identity")
	}
	for role, decision := range p.Expect {
		if _, err := toDecision(decision); err != nil {
			return fmt.Errorf("policy: expect[%s]: %w", role, err)
		}
	}
	return nil
}

// method splits the endpoint into HTTP method and path template.
func (p Policy) method() (string, string, error) {
	fields := strings.Fields(p.API.Endpoint)
	if len(fields) != 2 {
		return "", "", fmt.Errorf("policy: api.endpoint must be \"<METHOD> <path>\", got %q", p.API.Endpoint)
	}
	return strings.ToUpper(fields[0]), fields[1], nil
}

// ownerRole returns the logical role that owns the object, stripping any
// "identity:" prefix. Empty when no owner is declared.
func (p Policy) ownerRole() string {
	owner := strings.TrimSpace(p.API.Owner)
	return strings.TrimPrefix(owner, "identity:")
}

// Compile binds a policy to concrete values and produces a runnable test case.
func (p Policy) Compile(b Bindings) (model.AuthorizationTestCase, error) {
	method, path, err := p.method()
	if err != nil {
		return model.AuthorizationTestCase{}, err
	}

	if strings.TrimSpace(b.BaseURL) == "" {
		return model.AuthorizationTestCase{}, fmt.Errorf("compile: base_url is required")
	}
	if len(b.Identities) == 0 {
		return model.AuthorizationTestCase{}, fmt.Errorf("compile: at least one identity is required")
	}

	path, err = substitutePath(path, b.PathParams)
	if err != nil {
		return model.AuthorizationTestCase{}, err
	}
	url := strings.TrimRight(b.BaseURL, "/") + path

	expected := make([]model.ExpectedAccess, 0, len(b.Identities))
	ownerRole := p.ownerRole()
	var ownerIdentity string
	for _, id := range b.Identities {
		decisionStr, ok := p.Expect[id.Role]
		if !ok {
			return model.AuthorizationTestCase{}, fmt.Errorf("compile: identity %q has role %q which is not in the policy's expect map", id.ID, id.Role)
		}
		decision, err := toDecision(decisionStr)
		if err != nil {
			return model.AuthorizationTestCase{}, err
		}
		expected = append(expected, model.ExpectedAccess{IdentityID: id.ID, Decision: decision})
		if ownerRole != "" && id.Role == ownerRole {
			ownerIdentity = id.ID
		}
	}

	tc := model.AuthorizationTestCase{
		ID:             defaultID(b.TestCaseID, method, path),
		Identities:     b.Identities,
		Request:        model.RequestTemplate{Method: method, URL: url},
		ExpectedAccess: expected,
	}

	if res := p.resource(b, ownerIdentity); res != nil {
		tc.Resource = res
	}
	return tc, nil
}

func (p Policy) resource(b Bindings, ownerIdentity string) *model.Resource {
	rs := p.API.Resource
	res := model.Resource{
		Type:          rs.Type,
		OwnerIdentity: ownerIdentity,
		TenantID:      b.ResourceTenantID,
	}
	if rs.IDParam != "" {
		res.ObjectID = b.PathParams[rs.IDParam]
	}
	if res == (model.Resource{}) {
		return nil
	}
	return &res
}

// substitutePath replaces {param} placeholders with bound values.
func substitutePath(path string, params map[string]string) (string, error) {
	for {
		open := strings.IndexByte(path, '{')
		if open == -1 {
			return path, nil
		}
		end := strings.IndexByte(path[open:], '}')
		if end == -1 {
			return "", fmt.Errorf("compile: unterminated path parameter in %q", path)
		}
		end += open
		name := path[open+1 : end]
		val, ok := params[name]
		if !ok {
			return "", fmt.Errorf("compile: missing value for path parameter %q", name)
		}
		path = path[:open] + val + path[end+1:]
	}
}

func toDecision(s string) (model.AccessDecision, error) {
	switch model.AccessDecision(strings.ToLower(strings.TrimSpace(s))) {
	case model.AccessDecisionAllow:
		return model.AccessDecisionAllow, nil
	case model.AccessDecisionDeny:
		return model.AccessDecisionDeny, nil
	case model.AccessDecisionSkip:
		return model.AccessDecisionSkip, nil
	default:
		return "", fmt.Errorf("invalid decision %q (want allow, deny, or skip)", s)
	}
}

func defaultID(explicit, method, path string) string {
	if explicit != "" {
		return explicit
	}
	slug := strings.ToLower(method + path)
	slug = strings.NewReplacer("/", "-", "{", "", "}", "", " ", "-").Replace(slug)
	return strings.Trim(slug, "-")
}
