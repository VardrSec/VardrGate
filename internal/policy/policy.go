// Package policy parses declarative API authorization policies and compiles
// them into executable authorization test cases.
//
// A policy describes expected security behavior independent of any concrete
// environment: which logical identity is the owner, which roles may access the
// object, and what the deny statuses are. Binding a policy to a base URL, path
// parameters, and concrete identities produces a model.AuthorizationTestCase
// the engine can run. This is what lets one control be proven repeatedly across
// environments (dev, staging, prod) and over time.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
	"gopkg.in/yaml.v3"
)

// Policy is the on-disk representation of an authorization control.
type Policy struct {
	API      APISpec           `yaml:"api"`
	Setup    []SetupSpec       `yaml:"setup"`
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
	// Mutating acknowledges that this endpoint changes state and that replaying
	// it once per identity is intended.
	Mutating bool `yaml:"mutating"`
	// Body is the JSON request body sent by every identity. Without it a policy
	// cannot exercise a write endpoint that reads JSON.
	Body string `yaml:"body"`
	// Headers are sent by every identity; Content-Type defaults to
	// application/json when Body is set.
	Headers map[string]string `yaml:"headers"`
}

// SetupSpec is a request run before the one under test, whose response can
// supply values the main request needs — a token, or the id of an object
// created for the test.
type SetupSpec struct {
	Name string `yaml:"name"`
	// As names the logical role to run the step as. Empty sends no credentials,
	// which is what a login request needs.
	As      string            `yaml:"as"`
	Request SetupRequestSpec  `yaml:"request"`
	Capture map[string]string `yaml:"capture"`
}

// SetupRequestSpec is a setup step's request. Path is relative to the bound
// base URL, matching how api.endpoint is written.
type SetupRequestSpec struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
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
	DenyWhen        *DenyWhenSpec `yaml:"deny_when"`
	SensitiveFields SensitiveSpec `yaml:"sensitive_fields"`
	// Assertions recognize access from response content rather than status.
	Assertions []AssertionSpec `yaml:"assertions"`
}

// AssertionSpec declares one JSON value that proves an access decision, such as
// a private field only an authorized caller should receive, or an error code
// the API returns with HTTP 200 when it refuses. It describes the endpoint's
// response format, so it applies to every role with an allow or deny
// expectation unless Roles narrows it.
type AssertionSpec struct {
	JSONPointer string    `yaml:"json_pointer"`
	Equals      yaml.Node `yaml:"equals"`
	Decision    string    `yaml:"decision"`
	Roles       []string  `yaml:"roles"`
}

// DenyWhenSpec declares a refusal expressed in the response body rather than
// the status line, for APIs that answer 200 while denying the caller.
type DenyWhenSpec struct {
	BodyContains []string       `yaml:"body_contains"`
	JSONField    *JSONFieldSpec `yaml:"json_field"`
}

// condition converts the spec into the engine's form.
func (d *DenyWhenSpec) condition() *model.DenyCondition {
	if d == nil {
		return nil
	}
	cond := &model.DenyCondition{BodyContains: d.BodyContains}
	if d.JSONField != nil {
		cond.JSONField = &model.JSONFieldMatch{Path: d.JSONField.Path, Equals: d.JSONField.Equals}
	}
	if cond.IsZero() {
		return nil
	}
	return cond
}

// JSONFieldSpec tests one field, located by dotted path.
type JSONFieldSpec struct {
	Path   string `yaml:"path"`
	Equals string `yaml:"equals"`
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
	// AllowMutating confirms at run time that replaying an unsafe method once
	// per identity is intended, for a caller that did not want to edit the
	// policy to say so.
	AllowMutating bool
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

	forbidden := make(map[string]struct{}, len(p.Response.SensitiveFields.ForbiddenFor))
	for _, role := range p.Response.SensitiveFields.ForbiddenFor {
		forbidden[role] = struct{}{}
	}

	compiledAssertions, err := p.compileAssertions()
	if err != nil {
		return model.AuthorizationTestCase{}, err
	}

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
		_, forbidSensitive := forbidden[id.Role]
		expected = append(expected, model.ExpectedAccess{
			IdentityID:          id.ID,
			Decision:            decision,
			ForbidSensitiveData: forbidSensitive,
			ResponseAssertions:  assertionsFor(compiledAssertions, id.Role),
		})
		if ownerRole != "" && id.Role == ownerRole {
			ownerIdentity = id.ID
		}
	}

	setup, err := p.compileSetup(b)
	if err != nil {
		return model.AuthorizationTestCase{}, err
	}

	request, err := p.request(method, url)
	if err != nil {
		return model.AuthorizationTestCase{}, err
	}

	tc := model.AuthorizationTestCase{
		ID:             defaultID(b.TestCaseID, method, path),
		Identities:     b.Identities,
		Request:        request,
		ExpectedAccess: expected,
		DenyStatuses:   p.Response.DenyStatus,
		DenyWhen:       p.Response.DenyWhen.condition(),
		Mutating:       p.API.Mutating || b.AllowMutating,
		Setup:          setup,
	}

	if res := p.resource(b, ownerIdentity); res != nil {
		tc.Resource = res
	}
	return tc, nil
}

// compileSetup binds each setup step to the environment: the path joins the
// base URL and the logical role resolves to a concrete identity id.
func (p Policy) compileSetup(b Bindings) ([]model.SetupStep, error) {
	if len(p.Setup) == 0 {
		return nil, nil
	}
	idByRole := make(map[string]string, len(b.Identities))
	for _, id := range b.Identities {
		idByRole[id.Role] = id.ID
	}

	steps := make([]model.SetupStep, 0, len(p.Setup))
	for i, s := range p.Setup {
		label := s.Name
		if label == "" {
			label = fmt.Sprintf("setup[%d]", i)
		}
		if strings.TrimSpace(s.Request.Method) == "" || strings.TrimSpace(s.Request.Path) == "" {
			return nil, fmt.Errorf("compile: setup step %q needs a request method and path", label)
		}

		// Path parameters are substituted, but a {{var}} from an earlier step is
		// resolved at run time and must survive compilation untouched.
		path, err := substitutePath(s.Request.Path, b.PathParams)
		if err != nil {
			return nil, fmt.Errorf("compile: setup step %q: %w", label, err)
		}

		var as string
		if s.As != "" {
			resolved, ok := idByRole[s.As]
			if !ok {
				return nil, fmt.Errorf("compile: setup step %q runs as role %q, which no bound identity has", label, s.As)
			}
			as = resolved
		}

		step := model.SetupStep{
			Name:    label,
			As:      as,
			Capture: s.Capture,
			Request: model.RequestTemplate{
				Method:  strings.ToUpper(s.Request.Method),
				URL:     strings.TrimRight(b.BaseURL, "/") + path,
				Headers: s.Request.Headers,
			},
		}
		if body := strings.TrimSpace(s.Request.Body); body != "" {
			step.Request.Body = json.RawMessage(body)
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func (p Policy) resource(b Bindings, ownerIdentity string) *model.Resource {
	rs := p.API.Resource
	res := model.Resource{
		Type:          rs.Type,
		OwnerIdentity: ownerIdentity,
		TenantID:      b.ResourceTenantID,
		TenantField:   rs.TenantField,
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
//
// A {{var}} reference belongs to a setup step and is resolved at run time from
// a captured value, so it is stepped over rather than treated as an unbound
// path parameter.
func substitutePath(path string, params map[string]string) (string, error) {
	var done strings.Builder
	for {
		open := strings.IndexByte(path, '{')
		if open == -1 {
			done.WriteString(path)
			return done.String(), nil
		}
		if strings.HasPrefix(path[open:], "{{") {
			close := strings.Index(path[open:], "}}")
			if close == -1 {
				return "", fmt.Errorf("compile: unterminated {{ reference in %q", path)
			}
			close += open + 2
			done.WriteString(path[:close])
			path = path[close:]
			continue
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
		done.WriteString(path[:open])
		done.WriteString(val)
		path = path[end+1:]
	}
}

// DraftMarker is the placeholder `vardrgate discover` writes for every
// expectation it could not know.
//
// It is rejected by the parser on purpose. Discovery infers structure — which
// parameter looks like an object id, which response field carries a tenant —
// but it cannot know who *should* be allowed to call an endpoint, and a default
// guess would put a heuristic behind VardrGate's signature. Making the
// placeholder unparseable means a draft policy physically cannot execute until
// a human has typed a decision. That is an enforced invariant rather than a
// documented intention.
const DraftMarker = "TODO"

func toDecision(s string) (model.AccessDecision, error) {
	trimmed := strings.TrimSpace(s)
	if strings.EqualFold(trimmed, DraftMarker) {
		return "", fmt.Errorf(
			"expectation is still %s: this is a draft policy from `vardrgate discover`. Replace every %s with allow, deny, or skip — only you know who should be able to call this endpoint",
			DraftMarker, DraftMarker)
	}
	switch model.AccessDecision(strings.ToLower(trimmed)) {
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

// roleAssertion is a compiled assertion with the roles it applies to; an empty
// role set means every role.
type roleAssertion struct {
	rule  model.ResponseAssertion
	roles map[string]struct{}
}

// compileAssertions converts response.assertions to the engine's form. Pointer
// syntax and value limits are checked by engine validation before any request.
func (p Policy) compileAssertions() ([]roleAssertion, error) {
	out := make([]roleAssertion, 0, len(p.Response.Assertions))
	for i, a := range p.Response.Assertions {
		decision := model.AccessDecision(strings.ToLower(strings.TrimSpace(a.Decision)))
		if decision != model.AccessDecisionAllow && decision != model.AccessDecisionDeny {
			return nil, fmt.Errorf("response.assertions[%d]: decision must be allow or deny, got %q", i, a.Decision)
		}
		if a.Equals.Kind == 0 {
			return nil, fmt.Errorf("response.assertions[%d]: equals is required (use null to match JSON null)", i)
		}
		raw, err := nodeJSON(&a.Equals)
		if err != nil {
			return nil, fmt.Errorf("response.assertions[%d].equals: %w", i, err)
		}
		roles := make(map[string]struct{}, len(a.Roles))
		for _, role := range a.Roles {
			if _, ok := p.Expect[role]; !ok {
				return nil, fmt.Errorf("response.assertions[%d]: role %q is not in the policy's expect map", i, role)
			}
			roles[role] = struct{}{}
		}
		out = append(out, roleAssertion{
			rule:  model.ResponseAssertion{JSONPointer: a.JSONPointer, Equals: raw, Decision: decision},
			roles: roles,
		})
	}
	return out, nil
}

func assertionsFor(all []roleAssertion, role string) []model.ResponseAssertion {
	var out []model.ResponseAssertion
	for _, a := range all {
		if _, ok := a.roles[role]; len(a.roles) == 0 || ok {
			out = append(out, a.rule)
		}
	}
	return out
}

// nodeJSON renders a YAML value as JSON. Numbers keep their literal text so an
// object id beyond float64 precision is compared exactly.
func nodeJSON(n *yaml.Node) (json.RawMessage, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!null":
			return json.RawMessage("null"), nil
		case "!!bool":
			var v bool
			if err := n.Decode(&v); err != nil {
				return nil, err
			}
			return json.Marshal(v)
		case "!!int", "!!float":
			if !json.Valid([]byte(n.Value)) {
				return nil, fmt.Errorf("number %q is not valid JSON; quote it to compare a string", n.Value)
			}
			return json.RawMessage(n.Value), nil
		default:
			return json.Marshal(n.Value)
		}
	case yaml.SequenceNode:
		parts := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := nodeJSON(c)
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(v))
		}
		return json.RawMessage("[" + strings.Join(parts, ",") + "]"), nil
	case yaml.MappingNode:
		parts := make([]string, 0, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := json.Marshal(n.Content[i].Value)
			if err != nil {
				return nil, err
			}
			v, err := nodeJSON(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(k)+":"+string(v))
		}
		return json.RawMessage("{" + strings.Join(parts, ",") + "}"), nil
	case yaml.AliasNode:
		return nodeJSON(n.Alias)
	default:
		return nil, fmt.Errorf("unsupported YAML value")
	}
}

// request builds the request under test, carrying api.body and api.headers.
func (p Policy) request(method, url string) (model.RequestTemplate, error) {
	req := model.RequestTemplate{Method: method, URL: url}
	if len(p.API.Headers) > 0 {
		req.Headers = make(map[string]string, len(p.API.Headers))
		for k, v := range p.API.Headers {
			req.Headers[k] = v
		}
	}
	body := strings.TrimSpace(p.API.Body)
	if body == "" {
		return req, nil
	}
	if !json.Valid([]byte(body)) {
		return model.RequestTemplate{}, fmt.Errorf("compile: api.body is not valid JSON")
	}
	req.Body = json.RawMessage(body)
	if !hasHeader(req.Headers, "Content-Type") {
		if req.Headers == nil {
			req.Headers = map[string]string{}
		}
		req.Headers["Content-Type"] = "application/json"
	}
	return req, nil
}

func hasHeader(h map[string]string, name string) bool {
	for k := range h {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}
