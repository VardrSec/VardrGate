package openapi

import (
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

const sampleSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Demo", "version": "1.0"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/users/{id}": {
      "get": {"operationId": "getUser", "summary": "Read a user"},
      "delete": {"summary": "Delete a user"}
    },
    "/health": {
      "get": {"operationId": "health"}
    }
  }
}`

func TestParse_Valid(t *testing.T) {
	s, err := Parse([]byte(sampleSpec))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.Paths) != 2 {
		t.Errorf("expected 2 paths, got %d", len(s.Paths))
	}
	if s.Servers[0].URL != "https://api.example.com/v1" {
		t.Errorf("server not parsed: %+v", s.Servers)
	}
}

func TestParse_NoPaths(t *testing.T) {
	_, err := Parse([]byte(`{"openapi":"3.0.0","paths":{}}`))
	if err == nil {
		t.Fatal("expected error for spec with no paths")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("nope")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGenerate_OneCasePerOperationSorted(t *testing.T) {
	s, _ := Parse([]byte(sampleSpec))
	cases := s.GenerateTestCases("")

	// 3 operations: GET+DELETE /users/{id}, GET /health. Sorted by path then method.
	if len(cases) != 3 {
		t.Fatalf("expected 3 cases, got %d", len(cases))
	}
	// /health sorts before /users.
	if cases[0].Request.URL != "https://api.example.com/v1/health" || cases[0].Request.Method != "GET" {
		t.Errorf("first case wrong: %+v", cases[0].Request)
	}
	if cases[1].Request.Method != "GET" || cases[2].Request.Method != "DELETE" {
		t.Errorf("methods not in stable order: %s, %s", cases[1].Request.Method, cases[2].Request.Method)
	}
	if cases[1].Request.URL != "https://api.example.com/v1/users/{id}" {
		t.Errorf("url template not preserved: %q", cases[1].Request.URL)
	}
}

func TestGenerate_UsesOperationIDOrSlug(t *testing.T) {
	s, _ := Parse([]byte(sampleSpec))
	cases := s.GenerateTestCases("")
	ids := map[string]bool{}
	for _, c := range cases {
		ids[c.ID] = true
	}
	if !ids["getUser"] {
		t.Error("expected operationId getUser to be used")
	}
	if !ids["delete-users-id"] {
		t.Errorf("expected slug id delete-users-id, got %v", ids)
	}
}

func TestGenerate_BaseURLOverride(t *testing.T) {
	s, _ := Parse([]byte(sampleSpec))
	cases := s.GenerateTestCases("https://staging.example.com/")
	if cases[0].Request.URL != "https://staging.example.com/health" {
		t.Errorf("base override not applied: %q", cases[0].Request.URL)
	}
}

// A generated case, once a token is filled in, is a valid runnable test case.
func TestGenerate_ScaffoldShapeIsRunnable(t *testing.T) {
	s, _ := Parse([]byte(sampleSpec))
	c := s.GenerateTestCases("")[0]
	if len(c.Identities) != 2 || len(c.ExpectedAccess) != 2 {
		t.Fatalf("expected 2 identities and 2 expectations, got %d/%d", len(c.Identities), len(c.ExpectedAccess))
	}
	var hasAnon, hasAuth bool
	for _, ea := range c.ExpectedAccess {
		if ea.IdentityID == "anonymous" && ea.Decision == model.AccessDecisionDeny {
			hasAnon = true
		}
		if ea.IdentityID == "authenticated" && ea.Decision == model.AccessDecisionAllow {
			hasAuth = true
		}
	}
	if !hasAnon || !hasAuth {
		t.Errorf("scaffold expectations wrong: %+v", c.ExpectedAccess)
	}
}
