package coverage

import (
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/openapi"
)

const spec = `{
  "openapi": "3.0.0",
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/users/{id}": {"get": {"operationId": "getUser"}, "delete": {}},
    "/admin": {"get": {}}
  }
}`

func mustSpec(t *testing.T) openapi.Spec {
	t.Helper()
	s, err := openapi.Parse([]byte(spec))
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return s
}

func caseFor(method, url string) model.AuthorizationTestCase {
	return model.AuthorizationTestCase{Request: model.RequestTemplate{Method: method, URL: url}}
}

func TestAnalyze_MatchesTemplateAndMethod(t *testing.T) {
	s := mustSpec(t)
	cases := []model.AuthorizationTestCase{
		caseFor("GET", "https://api.example.com/v1/users/42"), // covers GET /users/{id}
	}
	r := Analyze(s, cases)
	if r.Total != 3 {
		t.Fatalf("expected 3 endpoints, got %d", r.Total)
	}
	if r.TestedCount != 1 || r.UntestedCount != 2 {
		t.Fatalf("expected 1 tested / 2 untested, got %d / %d", r.TestedCount, r.UntestedCount)
	}
	if r.Tested[0].Method != "GET" || r.Tested[0].Path != "/users/{id}" {
		t.Errorf("wrong tested endpoint: %+v", r.Tested[0])
	}
}

func TestAnalyze_MethodMustMatch(t *testing.T) {
	s := mustSpec(t)
	// POST to a path that only defines GET/DELETE — no coverage.
	r := Analyze(s, []model.AuthorizationTestCase{caseFor("POST", "https://api.example.com/v1/users/42")})
	if r.TestedCount != 0 {
		t.Errorf("expected 0 tested, got %d", r.TestedCount)
	}
}

func TestAnalyze_FullCoveragePercent(t *testing.T) {
	s := mustSpec(t)
	cases := []model.AuthorizationTestCase{
		caseFor("GET", "https://api.example.com/v1/users/42"),
		caseFor("DELETE", "https://api.example.com/v1/users/7"),
		caseFor("GET", "https://api.example.com/v1/admin"),
	}
	r := Analyze(s, cases)
	if r.TestedCount != 3 || r.PercentTested != 100 {
		t.Fatalf("expected full coverage, got %d tested, %.1f%%", r.TestedCount, r.PercentTested)
	}
}

func TestAnalyze_ToleratesBarePathAndQuery(t *testing.T) {
	s := mustSpec(t)
	// Bare path (no scheme/host) and a query string still match.
	r := Analyze(s, []model.AuthorizationTestCase{caseFor("GET", "/v1/users/99?expand=1")})
	if r.TestedCount != 1 {
		t.Errorf("expected 1 tested for bare path, got %d", r.TestedCount)
	}
}

func TestAnalyze_NoCasesZeroPercent(t *testing.T) {
	s := mustSpec(t)
	r := Analyze(s, nil)
	if r.TestedCount != 0 || r.PercentTested != 0 || r.UntestedCount != 3 {
		t.Errorf("expected 0%% coverage over 3 endpoints, got %+v", r)
	}
}

func TestMatchSuffix(t *testing.T) {
	cases := []struct {
		tmpl, path []string
		want       bool
	}{
		{[]string{"users", "{id}"}, []string{"v1", "users", "42"}, true},
		{[]string{"users", "{id}"}, []string{"users", "42", "orders"}, false}, // trailing extra
		{[]string{"admin"}, []string{"v1", "admin"}, true},
		{[]string{"users", "{id}"}, []string{"users"}, false}, // too short
	}
	for _, c := range cases {
		if got := matchSuffix(c.tmpl, c.path); got != c.want {
			t.Errorf("matchSuffix(%v, %v)=%v, want %v", c.tmpl, c.path, got, c.want)
		}
	}
}
