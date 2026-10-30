package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/VardrSec/vardrgate/internal/compare"
	"github.com/VardrSec/vardrgate/internal/model"
)

// ErrSetupFailed reports that a setup step did not complete, so the test case
// never ran. Callers distinguish this from a clean run with no findings: a
// finding count of zero means nothing when the preconditions were not met.
var ErrSetupFailed = errors.New("setup step failed")

// varPattern is the substitution syntax for captured values: {{name}}.
// It is deliberately not ${name}, which secretref already uses for environment
// references — two sources with two syntaxes cannot be confused for each other.
const (
	varOpen  = "{{"
	varClose = "}}"
)

// runSetup executes the setup steps in order and returns the variables they
// captured. Steps run once each, in declared order, as the identity named by
// As; an empty As sends no credentials, which is what a login request needs.
//
// A failed step aborts the run rather than degrading it: every later step and
// the request under test may depend on what this one was supposed to produce,
// and a test that silently proceeds without its precondition reports a clean
// result for something it never checked.
func (e *Engine) runSetup(ctx context.Context, tc model.AuthorizationTestCase) (map[string]string, error) {
	if len(tc.Setup) == 0 {
		return nil, nil
	}

	identityByID := make(map[string]model.Identity, len(tc.Identities))
	for _, id := range tc.Identities {
		identityByID[id.ID] = id
	}

	vars := map[string]string{}
	for i, step := range tc.Setup {
		label := step.Name
		if label == "" {
			label = fmt.Sprintf("setup[%d]", i)
		}

		var actor model.Identity
		if step.As != "" {
			found, ok := identityByID[step.As]
			if !ok {
				return nil, fmt.Errorf("%w: step %q runs as unknown identity %q", ErrSetupFailed, label, step.As)
			}
			actor = found
		} else {
			// No identity named: send nothing. A login request has no credential
			// to present yet.
			actor = model.Identity{
				ID:         "setup:" + label,
				Credential: model.Credential{Type: model.CredentialTypeStaticHeader},
			}
		}

		req, err := substituteRequest(step.Request, vars)
		if err != nil {
			return nil, fmt.Errorf("%w: step %q: %s", ErrSetupFailed, label, err)
		}

		exec := e.exec.Execute(ctx, actor, req)
		if exec.Error != "" {
			return nil, fmt.Errorf("%w: step %q: %s", ErrSetupFailed, label, exec.Error)
		}
		if exec.StatusCode >= 400 {
			return nil, fmt.Errorf("%w: step %q returned %d; the precondition it establishes was not met",
				ErrSetupFailed, label, exec.StatusCode)
		}

		for name, path := range step.Capture {
			value, ok := compare.ValueAtPath(exec.Body, path)
			if !ok {
				return nil, fmt.Errorf("%w: step %q: response has no value at %q to capture as %q",
					ErrSetupFailed, label, path, name)
			}
			vars[name] = value
		}
	}
	return vars, nil
}

// applySetupVars substitutes captured variables everywhere the request under
// test can reference them: the URL, headers, query parameters, body, the
// resource's object id, and each identity's credential value.
//
// Credential values are included so a login step can supply the token an
// identity presents, which is the whole point of setup for APIs where
// authentication is a handshake rather than a static string.
func applySetupVars(tc model.AuthorizationTestCase, vars map[string]string) (model.AuthorizationTestCase, error) {
	if len(vars) == 0 {
		return tc, nil
	}

	req, err := substituteRequest(tc.Request, vars)
	if err != nil {
		return tc, fmt.Errorf("request: %w", err)
	}
	tc.Request = req

	identities := make([]model.Identity, len(tc.Identities))
	copy(identities, tc.Identities)
	for i := range identities {
		value, err := substitute(identities[i].Credential.Value, vars)
		if err != nil {
			// substitute quotes its input, which here is a secret.
			return tc, fmt.Errorf("identity %q credential substitution failed", identities[i].ID)
		}
		identities[i].Credential.Value = value
	}
	tc.Identities = identities
	if tc.WriteVerification != nil {
		wv := *tc.WriteVerification
		wv.Request, err = substituteRequest(wv.Request, vars)
		if err != nil {
			return tc, fmt.Errorf("verification request substitution failed")
		}
		wv.Identity.Credential.Value, err = substitute(wv.Identity.Credential.Value, vars)
		if err != nil {
			return tc, fmt.Errorf("verification credential substitution failed")
		}
		if wv.Reset != nil {
			reset := *wv.Reset
			reset.Request, err = substituteRequest(reset.Request, vars)
			if err != nil {
				return tc, fmt.Errorf("verification reset substitution failed")
			}
			wv.Reset = &reset
		}
		tc.WriteVerification = &wv
	}

	if tc.Resource != nil {
		res := *tc.Resource
		objectID, err := substitute(res.ObjectID, vars)
		if err != nil {
			return tc, fmt.Errorf("resource.object_id: %w", err)
		}
		res.ObjectID = objectID
		tc.Resource = &res
	}

	return tc, nil
}

// substituteRequest returns a copy of tmpl with variables resolved throughout.
func substituteRequest(tmpl model.RequestTemplate, vars map[string]string) (model.RequestTemplate, error) {
	url, err := substitute(tmpl.URL, vars)
	if err != nil {
		return tmpl, fmt.Errorf("url: %w", err)
	}
	tmpl.URL = url

	if len(tmpl.Headers) > 0 {
		headers := make(map[string]string, len(tmpl.Headers))
		for k, v := range tmpl.Headers {
			sv, err := substitute(v, vars)
			if err != nil {
				return tmpl, fmt.Errorf("header %q: %w", k, err)
			}
			headers[k] = sv
		}
		tmpl.Headers = headers
	}

	if len(tmpl.QueryParams) > 0 {
		params := make(map[string]string, len(tmpl.QueryParams))
		for k, v := range tmpl.QueryParams {
			sv, err := substitute(v, vars)
			if err != nil {
				return tmpl, fmt.Errorf("query param %q: %w", k, err)
			}
			params[k] = sv
		}
		tmpl.QueryParams = params
	}

	if len(tmpl.Body) > 0 {
		// Substituting into raw JSON risks producing an invalid document, so
		// values are JSON-escaped and the result is re-validated.
		body, err := substituteJSON(tmpl.Body, vars)
		if err != nil {
			return tmpl, fmt.Errorf("body: %w", err)
		}
		tmpl.Body = body
	}

	return tmpl, nil
}

// substitute replaces every {{name}} in s with the captured value.
// An unknown variable is an error: silently leaving the placeholder in place
// would send the literal characters and produce a misleading result.
func substitute(s string, vars map[string]string) (string, error) {
	if !strings.Contains(s, varOpen) {
		return s, nil
	}
	var b strings.Builder
	for {
		open := strings.Index(s, varOpen)
		if open == -1 {
			b.WriteString(s)
			return b.String(), nil
		}
		end := strings.Index(s[open:], varClose)
		if end == -1 {
			return "", fmt.Errorf("unterminated %s in %q", varOpen, s)
		}
		end += open
		name := strings.TrimSpace(s[open+len(varOpen) : end])
		value, ok := vars[name]
		if !ok {
			return "", fmt.Errorf("no setup step captured a variable named %q", name)
		}
		b.WriteString(s[:open])
		b.WriteString(value)
		s = s[end+len(varClose):]
	}
}

// substituteJSON resolves variables inside a JSON document, escaping each value
// so the result stays valid JSON.
func substituteJSON(raw json.RawMessage, vars map[string]string) (json.RawMessage, error) {
	escaped := make(map[string]string, len(vars))
	for k, v := range vars {
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		// Drop exactly the surrounding quotes json.Marshal added: the placeholder
		// usually sits inside an existing JSON string, so only the inner escaping
		// is wanted. Trim would also eat an escaped quote at the end of the
		// value, leaving a dangling backslash.
		escaped[k] = strings.TrimSuffix(strings.TrimPrefix(string(encoded), `"`), `"`)
	}
	out, err := substitute(string(raw), escaped)
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(out)) {
		return nil, errors.New("substitution produced invalid JSON")
	}
	return json.RawMessage(out), nil
}

// validateSetup checks the setup block without executing it.
func validateSetup(tc model.AuthorizationTestCase) error {
	ids := make(map[string]struct{}, len(tc.Identities))
	for _, id := range tc.Identities {
		ids[id.ID] = struct{}{}
	}
	names := map[string]struct{}{}
	for i, step := range tc.Setup {
		if step.Request.Method == "" || step.Request.URL == "" {
			return fmt.Errorf("setup[%d] must have a request method and url", i)
		}
		if step.As != "" {
			if _, ok := ids[step.As]; !ok {
				return fmt.Errorf("setup[%d] runs as unknown identity %q", i, step.As)
			}
		}
		if step.Name != "" {
			if _, dup := names[step.Name]; dup {
				return fmt.Errorf("setup[%d] has duplicate name %q", i, step.Name)
			}
			names[step.Name] = struct{}{}
		}
		for name, path := range step.Capture {
			if name == "" || path == "" {
				return fmt.Errorf("setup[%d] capture entries need both a variable name and a response path", i)
			}
		}
		if model.IsUnsafeMethod(step.Request.Method) && !tc.Mutating {
			return fmt.Errorf(
				"setup[%d] uses %s, which changes server state; set mutating: true on the policy, or pass --allow-mutating, to confirm that is intended",
				i, strings.ToUpper(step.Request.Method))
		}
	}
	return nil
}
