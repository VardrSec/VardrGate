package discover

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/VardrSec/vardrgate/internal/compare"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/openapi"
)

// Hypothesis is authoring guidance, never an executable permission or finding.
// Capture numbers refer to one-based HAR entries; observed values stay in memory.
type Hypothesis struct {
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Field    string `json:"field,omitempty"`
	Captures []int  `json:"captures,omitempty"`
	Reason   string `json:"reason"`
}

type Candidate struct {
	Endpoint   string       `json:"endpoint"`
	Hypotheses []Hypothesis `json:"hypotheses"`
}

type capture struct {
	Request struct {
		Method  string `json:"method"`
		URL     string `json:"url"`
		Headers []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

// Candidates correlates a spec with optional HAR traffic, offline. Only entries
// matching a method, path template and declared server origin contribute facts.
// No URLs, cookies, tokens, object IDs or response values are copied from traffic.
func Candidates(spec openapi.Spec, base string, har []byte) ([]Candidate, error) {
	var entries []capture
	if len(har) > 0 {
		var doc struct {
			Log *struct {
				Entries []capture `json:"entries"`
			} `json:"log"`
		}
		if err := json.Unmarshal(har, &doc); err != nil || doc.Log == nil {
			return nil, fmt.Errorf("parse HAR: expected log.entries")
		}
		entries = doc.Log.Entries
	}
	if base == "" && len(spec.Servers) > 0 {
		base = spec.Servers[0].URL
	}
	origin, _ := url.Parse(base)
	if len(har) > 0 && (origin == nil || origin.Host == "" || (origin.Scheme != "http" && origin.Scheme != "https")) {
		return nil, fmt.Errorf("HAR correlation requires --base or an HTTP(S) spec server")
	}
	result := make([]Candidate, 0)
	for _, op := range spec.Operations() {
		c := Candidate{Endpoint: op.Method + " " + op.Path, Hypotheses: []Hypothesis{}}
		add := func(kind, field, reason string, captures ...int) {
			c.Hypotheses = append(c.Hypotheses, Hypothesis{Kind: kind, State: "unconfirmed", Field: field, Captures: captures, Reason: reason})
		}
		for _, param := range pathParams(op.Path) {
			if idParamPattern.MatchString(normalize(param)) {
				add("object_identifier", param, "ID-shaped path parameter; confirm which resource it selects")
			}
		}
		add("permission", "", "confirm owner, peer, cross-tenant and anonymous expectations; observed success does not establish permission")
		var previousAuth [32]byte
		var previousTenant string
		previous := 0
		for i, entry := range entries {
			u, err := url.Parse(entry.Request.URL)
			if err != nil || u.User != nil || !strings.EqualFold(u.Scheme, origin.Scheme) || !strings.EqualFold(u.Host, origin.Host) || !strings.EqualFold(entry.Request.Method, op.Method) {
				continue
			}
			prefix := strings.TrimRight(origin.Path, "/")
			if !matchesPath(prefix+op.Path, u.EscapedPath()) {
				continue
			}
			if entry.Response.Status < 200 || entry.Response.Status >= 300 {
				continue
			}
			body := []byte(entry.Response.Content.Text)
			if entry.Response.Content.Encoding == "base64" {
				body, err = base64.StdEncoding.DecodeString(string(body))
				if err != nil {
					continue
				}
			} else if entry.Response.Content.Encoding != "" {
				continue
			}
			var auth strings.Builder
			for _, h := range entry.Request.Headers {
				if strings.EqualFold(h.Name, "authorization") || strings.EqualFold(h.Name, "cookie") {
					fmt.Fprintf(&auth, "%s:%s\n", strings.ToLower(h.Name), h.Value)
				}
			}
			if auth.Len() == 0 {
				continue
			}
			fingerprint := sha256.Sum256([]byte(auth.String()))
			add("candidate_owner", "", "credentialed successful capture; confirm its principal and ownership independently", i+1)
			for _, field := range []string{"owner_id", "user_id", "created_by"} {
				if _, _, ok := compare.FindField(body, field); ok {
					add("owner_field", field, "owner-shaped response field; confirm its meaning", i+1)
				}
			}
			tenant := ""
			for _, field := range []string{"tenant_id", "org_id", "organization_id", "workspace_id"} {
				if _, value, ok := compare.FindField(body, field); ok {
					tenant = value
					add("tenant_field", field, "tenant-shaped response field; confirm isolation boundaries", i+1)
					break
				}
			}
			if previous != 0 && fingerprint != previousAuth {
				add("identity_relationship", "", "different credential material; confirm distinct principals before peer testing", previous, i+1)
				if tenant != "" && previousTenant != "" && tenant != previousTenant {
					add("cross_tenant", "", "different credentials and tenant values; confirm principals and replay against a reviewed common resource", previous, i+1)
				}
			}
			previous, previousAuth, previousTenant = i+1, fingerprint, tenant
		}
		result = append(result, c)
	}
	return result, nil
}

func matchesPath(template, path string) bool {
	a, b := strings.Split(template, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}") {
			if b[i] == "" {
				return false
			}
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ReviewCases removes importers' historical permission defaults. It affects
// gen only; existing reviewed policies and library callers retain their behavior.
func ReviewCases(cases []model.AuthorizationTestCase) {
	for i := range cases {
		c := &cases[i]
		c.Identities = append(c.Identities, model.Identity{ID: "other_user", Role: "peer", Credential: model.Credential{Type: model.CredentialTypeBearer}}, model.Identity{ID: "other_tenant", Role: "cross_tenant", Credential: model.Credential{Type: model.CredentialTypeBearer}})
		c.ExpectedAccess = nil
		for _, id := range c.Identities {
			c.ExpectedAccess = append(c.ExpectedAccess, model.ExpectedAccess{IdentityID: id.ID, Decision: model.AccessDecision("TODO")})
		}
	}
}
