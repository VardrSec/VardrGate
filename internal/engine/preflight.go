package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

func validatePreflight(tc model.AuthorizationTestCase) error {
	if tc.RequireIdentityPreflight {
		assessed := 0
		for _, id := range tc.Identities {
			ea, ok := expectedFor(tc, id.ID)
			if ok && ea.Decision != model.AccessDecisionSkip {
				assessed++
			}
			if ok && ea.Decision != model.AccessDecisionSkip && !id.Credential.SendsNoAuth() && id.Preflight == nil {
				return fmt.Errorf("identity %q requires a declared principal preflight in strict mode", id.ID)
			}
		}
		if assessed == 0 {
			return errors.New("strict identity assurance requires at least one allow or deny expectation")
		}
	}
	for _, identity := range tc.Identities {
		p := identity.Preflight
		if p == nil {
			continue
		}
		if len(identity.ID) > 200 {
			return errors.New("identity preflight id must be at most 200 bytes")
		}
		if identity.Credential.SendsNoAuth() || identity.Credential.Value == "" {
			return errors.New("identity preflight requires an authenticated credential")
		}
		origin, err := preflightOrigin(p.URL)
		if err != nil {
			return err
		}
		target, err := preflightOrigin(tc.Request.URL)
		if err != nil || origin != target {
			return errors.New("identity preflight must use the request's HTTP origin")
		}
		if strings.Contains(p.URL, "{{") || strings.Contains(p.URL, "${") {
			return errors.New("identity preflight URL cannot contain variable references")
		}
		if p.ExpectedStatus < 200 || p.ExpectedStatus > 299 {
			return errors.New("identity preflight expected_status must be a 2xx status")
		}
		if len(p.JSONFields) == 0 || len(p.JSONFields) > 8 {
			return errors.New("identity preflight requires 1 to 8 JSON field matches")
		}
		for path, value := range p.JSONFields {
			if len(path) > 200 || len(value) > 200 || strings.TrimSpace(value) == "" {
				return errors.New("identity preflight field matches must be nonempty and at most 200 bytes")
			}
			for _, part := range strings.Split(path, ".") {
				if strings.TrimSpace(part) == "" {
					return errors.New("identity preflight JSON paths need nonempty segments")
				}
			}
		}
	}
	return nil
}

func preflightOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2000 || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("identity preflight requires an absolute HTTP URL without userinfo or fragment")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("identity preflight URL port is invalid")
		}
	}
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port, nil
}

// All configured checks run once before the request under test; one failure aborts
// the entire case. No target response value, header or raw error crosses this boundary.
func (e *Engine) runPreflight(ctx context.Context, tc model.AuthorizationTestCase) ([]model.PreflightResult, bool) {
	var results []model.PreflightResult
	ready := true
	for _, identity := range tc.Identities {
		p := identity.Preflight
		if p == nil {
			continue
		}
		ex := e.exec.Execute(ctx, identity, model.RequestTemplate{Method: "GET", URL: p.URL})
		r := model.PreflightResult{IdentityID: identity.ID, Status: "failed", Reason: "unexpected_status", StatusCode: ex.StatusCode}
		switch {
		case ex.Error != "" || ex.ErrorKind != "":
			r.Reason = "execution_error"
		case ex.StatusCode == 401 || ex.StatusCode == 403:
			r.Reason = "credential_rejected"
		case ex.StatusCode == p.ExpectedStatus:
			r.Reason = "identity_mismatch"
			if matchesPrincipal(ex.Body, p.JSONFields) {
				r.Status, r.Reason = "passed", "identity_verified"
			}
		}
		ready = ready && r.Status == "passed"
		results = append(results, r)
	}
	return results, ready
}

// Match exact case-sensitive dotted paths to scalars; do not coerce null/arrays,
// collapse keys differing in case, or round large numeric subject identifiers.
func matchesPrincipal(body []byte, fields map[string]string) bool {
	var data any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if d.Decode(&data) != nil {
		return false
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return false
	}
	for path, want := range fields {
		v := data
		for _, part := range strings.Split(path, ".") {
			obj, ok := v.(map[string]any)
			if !ok {
				return false
			}
			v, ok = obj[part]
			if !ok {
				return false
			}
		}
		var got string
		switch scalar := v.(type) {
		case string:
			got = scalar
		case json.Number:
			got = scalar.String()
		case bool:
			got = fmt.Sprint(scalar)
		default:
			return false
		}
		if got != want {
			return false
		}
	}
	return true
}
