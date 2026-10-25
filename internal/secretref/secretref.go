// Package secretref resolves ${VAR} references in credential values against
// the process environment.
//
// Authorization tests are only meaningful with real credentials, and the files
// that describe them — policy bindings, generated case suites — are meant to be
// committed next to the code they test. A reference keeps the file honest about
// which secret it needs without containing it.
package secretref

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

// Expand replaces every ${VAR} in s with that variable's value.
//
// An unset or empty variable is an error rather than a silent empty string: a
// blank token turns an authenticated identity into an anonymous one, which
// inverts the meaning of the test while still reporting a clean run.
func Expand(s string) (string, error) {
	var b strings.Builder
	for {
		open := strings.Index(s, "${")
		if open == -1 {
			b.WriteString(s)
			return b.String(), nil
		}
		end := strings.Index(s[open:], "}")
		if end == -1 {
			return "", fmt.Errorf("unterminated ${ in credential value")
		}
		end += open
		name := s[open+2 : end]
		if name == "" {
			return "", fmt.Errorf("empty ${} reference in credential value")
		}
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("environment variable %q referenced by the credential is unset or empty", name)
		}
		b.WriteString(s[:open])
		b.WriteString(val)
		s = s[end+1:]
	}
}

// ExpandVerification resolves references in a write verifier's credential and
// in the string values of its JSON request body, such as a victim's password
// for a login oracle. Values are JSON-escaped by re-encoding the body.
func ExpandVerification(wv *model.WriteVerification) error {
	if wv == nil {
		return nil
	}
	ids := []model.Identity{wv.Identity}
	if err := ExpandIdentities(ids); err != nil {
		return fmt.Errorf("write_verification: %w", err)
	}
	wv.Identity = ids[0]
	if err := ExpandRequest(&wv.Request); err != nil {
		return fmt.Errorf("write_verification: %w", err)
	}
	if wv.Reset != nil {
		if err := ExpandRequest(&wv.Reset.Request); err != nil {
			return fmt.Errorf("write_verification reset: %w", err)
		}
	}
	return nil
}

// ExpandRequest resolves environment references without interpolating raw JSON.
func ExpandRequest(req *model.RequestTemplate) error {
	var err error
	if req.URL, err = Expand(req.URL); err != nil {
		return err
	}
	for key, value := range req.Headers {
		if req.Headers[key], err = Expand(value); err != nil {
			return err
		}
	}
	for key, value := range req.QueryParams {
		if req.QueryParams[key], err = Expand(value); err != nil {
			return err
		}
	}
	if len(req.Body) == 0 || !strings.Contains(string(req.Body), "${") {
		return nil
	}
	var body any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return fmt.Errorf("write_verification: request body is not valid JSON")
	}
	expanded, err := expandStrings(body)
	if err != nil {
		return fmt.Errorf("write_verification: request body: %w", err)
	}
	out, err := json.Marshal(expanded)
	if err != nil {
		return fmt.Errorf("write_verification: request body: %w", err)
	}
	req.Body = out
	return nil
}

// ExpandCase binds a saved regression template once, before engine validation.
// Runtime setup captures use {{name}} and remain untouched by this pass.
func ExpandCase(tc *model.AuthorizationTestCase) error {
	if err := ExpandIdentities(tc.Identities); err != nil {
		return err
	}
	if err := ExpandVerification(tc.WriteVerification); err != nil {
		return err
	}
	if err := ExpandRequest(&tc.Request); err != nil {
		return err
	}
	for i := range tc.Setup {
		if err := ExpandRequest(&tc.Setup[i].Request); err != nil {
			return err
		}
	}
	for i := range tc.ExpectedAccess {
		for j := range tc.ExpectedAccess[i].ResponseAssertions {
			rule := &tc.ExpectedAccess[i].ResponseAssertions[j]
			req := model.RequestTemplate{Body: rule.Equals}
			if err := ExpandRequest(&req); err != nil {
				return err
			}
			rule.Equals = req.Body
		}
	}
	if tc.WriteVerification != nil && len(tc.WriteVerification.ChangedTo) > 0 {
		req := model.RequestTemplate{Body: tc.WriteVerification.ChangedTo}
		if err := ExpandRequest(&req); err != nil {
			return err
		}
		tc.WriteVerification.ChangedTo = req.Body
	}
	return nil
}

func expandStrings(v any) (any, error) {
	switch t := v.(type) {
	case string:
		return Expand(t)
	case []any:
		for i := range t {
			e, err := expandStrings(t[i])
			if err != nil {
				return nil, err
			}
			t[i] = e
		}
	case map[string]any:
		for k := range t {
			e, err := expandStrings(t[k])
			if err != nil {
				return nil, err
			}
			t[k] = e
		}
	}
	return v, nil
}

// ExpandIdentities resolves references in every identity's credential in place.
func ExpandIdentities(identities []model.Identity) error {
	for i := range identities {
		expanded, err := Expand(identities[i].Credential.Value)
		if err != nil {
			return fmt.Errorf("identity %q: %w", identities[i].ID, err)
		}
		identities[i].Credential.Value = expanded
		if p := identities[i].Preflight; p != nil {
			copy := *p
			var err error
			if copy.URL, err = Expand(p.URL); err != nil {
				return err
			}
			copy.JSONFields = make(map[string]string, len(p.JSONFields))
			for key, value := range p.JSONFields {
				copy.JSONFields[key], err = Expand(value)
				if err != nil {
					return err
				}
			}
			identities[i].Preflight = &copy
		}
	}
	return nil
}
