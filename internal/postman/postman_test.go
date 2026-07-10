package postman

import (
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

const sample = `{
  "info": {"name": "Demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item": [
    {"name": "Get user", "request": {"method": "GET", "url": {"raw": "https://api.example.com/users/42"}}},
    {"name": "Users", "item": [
      {"name": "List orders", "request": {"method": "GET", "url": "https://api.example.com/users/42/orders"}}
    ]}
  ]
}`

func TestParse_Valid(t *testing.T) {
	c, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Info.Name != "Demo" || len(c.Items) != 2 {
		t.Errorf("unexpected parse: %+v", c)
	}
}

func TestParse_NoItems(t *testing.T) {
	if _, err := Parse([]byte(`{"info":{"name":"x"},"item":[]}`)); err == nil {
		t.Fatal("expected error for empty collection")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("nope")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGenerate_FlattensFoldersAndBothURLForms(t *testing.T) {
	c, _ := Parse([]byte(sample))
	cases := c.GenerateTestCases("")
	if len(cases) != 2 {
		t.Fatalf("expected 2 cases (folder flattened), got %d", len(cases))
	}
	// Object-form URL.
	if cases[0].Request.URL != "https://api.example.com/users/42" || cases[0].Request.Method != "GET" {
		t.Errorf("case 0 wrong: %+v", cases[0].Request)
	}
	// String-form URL from nested folder.
	if cases[1].Request.URL != "https://api.example.com/users/42/orders" {
		t.Errorf("nested string URL not handled: %q", cases[1].Request.URL)
	}
	if cases[0].ID != "get-user" {
		t.Errorf("id from name expected get-user, got %q", cases[0].ID)
	}
}

func TestGenerate_BaseOverrideReplacesOrigin(t *testing.T) {
	c, _ := Parse([]byte(sample))
	cases := c.GenerateTestCases("https://staging.example.com")
	if cases[0].Request.URL != "https://staging.example.com/users/42" {
		t.Errorf("base override not applied: %q", cases[0].Request.URL)
	}
}

func TestGenerate_ScaffoldRunnableShape(t *testing.T) {
	c, _ := Parse([]byte(sample))
	got := c.GenerateTestCases("")[0]
	if len(got.Identities) != 2 || len(got.ExpectedAccess) != 2 {
		t.Fatalf("unexpected scaffold shape: %+v", got)
	}
	var anonDeny bool
	for _, ea := range got.ExpectedAccess {
		if ea.IdentityID == "anonymous" && ea.Decision == model.AccessDecisionDeny {
			anonDeny = true
		}
	}
	if !anonDeny {
		t.Error("expected anonymous→deny in scaffold")
	}
}
