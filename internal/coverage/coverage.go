// Package coverage reports which endpoints in an OpenAPI spec are exercised by a
// set of authorization test cases, and which are not — the "tested / untested"
// view called for in the API-inventory work.
package coverage

import (
	"sort"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/openapi"
)

// Endpoint identifies one operation by method and path template.
type Endpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Report summarizes coverage of a spec by a set of test cases.
type Report struct {
	Total         int        `json:"total"`
	TestedCount   int        `json:"tested_count"`
	UntestedCount int        `json:"untested_count"`
	PercentTested float64    `json:"percent_tested"`
	Tested        []Endpoint `json:"tested"`
	Untested      []Endpoint `json:"untested"`
}

// Analyze matches each spec operation against the test cases. An operation is
// covered when a case shares its HTTP method and its request path matches the
// operation's path template (with `{param}` segments treated as wildcards, and
// matched against the tail of the request path so server base paths are ignored).
func Analyze(spec openapi.Spec, cases []model.AuthorizationTestCase) Report {
	// Pre-split each case into (method, path segments).
	type caseReq struct {
		method string
		segs   []string
	}
	reqs := make([]caseReq, 0, len(cases))
	for _, c := range cases {
		reqs = append(reqs, caseReq{
			method: strings.ToUpper(c.Request.Method),
			segs:   pathSegments(requestPath(c.Request.URL)),
		})
	}

	var tested, untested []Endpoint
	for _, ep := range endpoints(spec) {
		tmpl := pathSegments(ep.Path)
		covered := false
		for _, r := range reqs {
			if r.method == ep.Method && matchSuffix(tmpl, r.segs) {
				covered = true
				break
			}
		}
		if covered {
			tested = append(tested, ep)
		} else {
			untested = append(untested, ep)
		}
	}

	total := len(tested) + len(untested)
	pct := 0.0
	if total > 0 {
		pct = float64(len(tested)) / float64(total) * 100
	}
	return Report{
		Total:         total,
		TestedCount:   len(tested),
		UntestedCount: len(untested),
		PercentTested: pct,
		Tested:        tested,
		Untested:      untested,
	}
}

// endpoints returns every operation in the spec, sorted by path then method.
func endpoints(spec openapi.Spec) []Endpoint {
	paths := make([]string, 0, len(spec.Paths))
	for p := range spec.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	order := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	var out []Endpoint
	for _, p := range paths {
		item := spec.Paths[p]
		has := map[string]bool{}
		for _, mo := range operationsOf(item) {
			has[mo] = true
		}
		for _, m := range order {
			if has[m] {
				out = append(out, Endpoint{Method: m, Path: p})
			}
		}
	}
	return out
}

// operationsOf lists the HTTP methods defined on a path item.
func operationsOf(item openapi.PathItem) []string {
	var out []string
	for m, op := range map[string]*openapi.Operation{
		"GET": item.Get, "POST": item.Post, "PUT": item.Put, "PATCH": item.Patch,
		"DELETE": item.Delete, "HEAD": item.Head, "OPTIONS": item.Options,
	} {
		if op != nil {
			out = append(out, m)
		}
	}
	return out
}

// requestPath extracts the path portion of a URL, tolerating a bare path.
func requestPath(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
		if j := strings.IndexByte(s, '/'); j != -1 {
			s = s[j:]
		} else {
			s = "/"
		}
	}
	if q := strings.IndexByte(s, '?'); q != -1 {
		s = s[:q]
	}
	return s
}

func pathSegments(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// matchSuffix reports whether tmpl matches the trailing len(tmpl) segments of
// path. A `{param}` template segment matches any single segment.
func matchSuffix(tmpl, path []string) bool {
	if len(tmpl) == 0 || len(path) < len(tmpl) {
		return false
	}
	offset := len(path) - len(tmpl)
	for i, t := range tmpl {
		if isParam(t) {
			continue
		}
		if t != path[offset+i] {
			return false
		}
	}
	return true
}

func isParam(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}
