package compare

import (
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func result(id string, status int, body []byte) model.ExecutionResult {
	return model.ExecutionResult{IdentityID: id, StatusCode: status, Body: body}
}

func TestResults_StatusCodeMatch(t *testing.T) {
	a := result("admin", 200, nil)
	b := result("user", 200, nil)
	cr := Results(a, b)
	if !cr.StatusCodeMatch {
		t.Fatal("expected status code match")
	}
}

func TestResults_StatusCodeMismatch(t *testing.T) {
	a := result("admin", 200, nil)
	b := result("user", 403, nil)
	cr := Results(a, b)
	if cr.StatusCodeMatch {
		t.Fatal("expected status code mismatch")
	}
	if !containsNote(cr, "status code mismatch") {
		t.Errorf("expected status code mismatch note, got %v", cr.Notes)
	}
}

func TestResults_BodyMatch_Identical(t *testing.T) {
	body := []byte(`{"id":1}`)
	a := result("a", 200, body)
	b := result("b", 200, body)
	cr := Results(a, b)
	if !cr.BodyMatch {
		t.Fatal("expected body match for identical bodies")
	}
}

func TestResults_BodyMatch_JSONWhitespace(t *testing.T) {
	a := result("a", 200, []byte(`{"id":1,"name":"alice"}`))
	b := result("b", 200, []byte(`{ "name": "alice", "id": 1 }`))
	cr := Results(a, b)
	if !cr.BodyMatch {
		t.Fatal("expected body match after JSON normalisation")
	}
	if !containsNote(cr, "whitespace/key order") {
		t.Errorf("expected whitespace note, got %v", cr.Notes)
	}
}

func TestResults_BodyMismatch_DifferentJSON(t *testing.T) {
	a := result("admin", 200, []byte(`{"id":1,"role":"admin"}`))
	b := result("user", 200, []byte(`{"id":2,"role":"user"}`))
	cr := Results(a, b)
	if cr.BodyMatch {
		t.Fatal("expected body mismatch for different JSON content")
	}
	if !containsNote(cr, "json body mismatch") {
		t.Errorf("expected json body mismatch note, got %v", cr.Notes)
	}
}

func TestResults_BodyMismatch_SizeDiff(t *testing.T) {
	a := result("a", 200, []byte("hello"))
	b := result("b", 200, []byte("hello world"))
	cr := Results(a, b)
	if cr.BodyMatch {
		t.Fatal("expected body mismatch")
	}
	if cr.SizeDiff != 6 {
		t.Fatalf("expected SizeDiff 6, got %d", cr.SizeDiff)
	}
}

func TestResults_SensitiveFieldPresentOnlyInOne(t *testing.T) {
	a := result("admin", 200, []byte(`{"id":1,"token":"abc"}`))
	b := result("user", 200, []byte(`{"id":2}`))
	cr := Results(a, b)
	if !containsNote(cr, "sensitive field") {
		t.Errorf("expected sensitive field note, got %v", cr.Notes)
	}
}

func TestResults_SensitiveFieldPresentInBoth_NoNote(t *testing.T) {
	a := result("a", 200, []byte(`{"token":"x"}`))
	b := result("b", 200, []byte(`{"token":"y"}`))
	cr := Results(a, b)
	for _, n := range cr.Notes {
		if strings.Contains(n, "sensitive field") {
			t.Errorf("unexpected sensitive field note when present in both: %q", n)
		}
	}
}

func TestResults_NilBodies(t *testing.T) {
	a := result("a", 204, nil)
	b := result("b", 204, nil)
	cr := Results(a, b)
	if !cr.BodyMatch {
		t.Fatal("expected body match for two nil bodies")
	}
}

func TestEvidence_PopulatesFromComparison(t *testing.T) {
	a := result("admin", 200, []byte(`{"id":1}`))
	b := result("user", 403, []byte(`{"error":"forbidden"}`))
	cr := Results(a, b)
	ev := Evidence(a, b, cr)
	if len(ev) == 0 {
		t.Fatal("expected at least one evidence string")
	}
	var hasStatus bool
	for _, e := range ev {
		if strings.Contains(e, "status_codes") {
			hasStatus = true
		}
	}
	if !hasStatus {
		t.Errorf("expected status_codes in evidence, got %v", ev)
	}
}

func TestLooksLikeJSON(t *testing.T) {
	cases := []struct {
		input []byte
		want  bool
	}{
		{[]byte(`{"a":1}`), true},
		{[]byte(`[1,2]`), true},
		{[]byte(`   {"a":1}`), true},
		{[]byte(`plain text`), false},
		{nil, false},
		{[]byte(`  `), false},
	}
	for _, c := range cases {
		got := looksLikeJSON(c.input)
		if got != c.want {
			t.Errorf("looksLikeJSON(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func containsNote(cr model.ComparisonResult, substr string) bool {
	for _, n := range cr.Notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}
