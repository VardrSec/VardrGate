package scaffold

import (
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func TestStarterCase(t *testing.T) {
	c := StarterCase("get-users", "List users", "get", "https://api.example.com/users")
	if c.ID != "get-users" || c.Description != "List users" {
		t.Errorf("metadata wrong: %+v", c)
	}
	if c.Request.Method != "GET" { // method upper-cased
		t.Errorf("method not upper-cased: %q", c.Request.Method)
	}
	if c.Request.URL != "https://api.example.com/users" {
		t.Errorf("url wrong: %q", c.Request.URL)
	}
	if len(c.Identities) != 2 || len(c.ExpectedAccess) != 2 {
		t.Fatalf("unexpected shape: %+v", c)
	}
	want := map[string]model.AccessDecision{"authenticated": model.AccessDecisionAllow, "anonymous": model.AccessDecisionDeny}
	for _, ea := range c.ExpectedAccess {
		if want[ea.IdentityID] != ea.Decision {
			t.Errorf("%s: got %s, want %s", ea.IdentityID, ea.Decision, want[ea.IdentityID])
		}
	}
}

func TestSlug(t *testing.T) {
	if got := Slug("/users/{id}/profile"); got != "-users-id-profile" {
		t.Errorf("Slug: got %q", got)
	}
}
