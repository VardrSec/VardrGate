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
	cr := Results(a, b, nil)
	if !cr.StatusCodeMatch {
		t.Fatal("expected status code match")
	}
}

func TestResults_StatusCodeMismatch(t *testing.T) {
	a := result("admin", 200, nil)
	b := result("user", 403, nil)
	cr := Results(a, b, nil)
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
	cr := Results(a, b, nil)
	if !cr.BodyMatch {
		t.Fatal("expected body match for identical bodies")
	}
}

func TestResults_BodyMatch_JSONWhitespace(t *testing.T) {
	a := result("a", 200, []byte(`{"id":1,"name":"alice"}`))
	b := result("b", 200, []byte(`{ "name": "alice", "id": 1 }`))
	cr := Results(a, b, nil)
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
	cr := Results(a, b, nil)
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
	cr := Results(a, b, nil)
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
	cr := Results(a, b, nil)
	if !containsNote(cr, "sensitive field") {
		t.Errorf("expected sensitive field note, got %v", cr.Notes)
	}
}

func TestResults_SensitiveFieldPresentInBoth_NoNote(t *testing.T) {
	a := result("a", 200, []byte(`{"token":"x"}`))
	b := result("b", 200, []byte(`{"token":"y"}`))
	cr := Results(a, b, nil)
	for _, n := range cr.Notes {
		if strings.Contains(n, "sensitive field") {
			t.Errorf("unexpected sensitive field note when present in both: %q", n)
		}
	}
}

func TestResults_NilBodies(t *testing.T) {
	a := result("a", 204, nil)
	b := result("b", 204, nil)
	cr := Results(a, b, nil)
	if !cr.BodyMatch {
		t.Fatal("expected body match for two nil bodies")
	}
}

func TestEvidence_PopulatesFromComparison(t *testing.T) {
	a := result("admin", 200, []byte(`{"id":1}`))
	b := result("user", 403, []byte(`{"error":"forbidden"}`))
	cr := Results(a, b, nil)
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

func TestSensitiveFieldsPresent(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string // sorted
	}{
		{"top level", `{"id":1,"ssn":"x","name":"a"}`, []string{"ssn"}},
		{"nested", `{"user":{"profile":{"password":"x"}},"ok":true}`, []string{"password"}},
		{"in array", `{"items":[{"api_key":"x"},{"id":2}]}`, []string{"api_key"}},
		{"case insensitive", `{"SSN":"x","Token":"y"}`, []string{"ssn", "token"}},
		{"none", `{"id":1,"name":"a"}`, nil},
		{"multiple", `{"ssn":"1","password":"2"}`, []string{"password", "ssn"}},
		{"not json", `not json`, nil},
		{"empty", ``, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SensitiveFieldsPresent([]byte(c.body), DefaultSensitiveFields)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestSensitiveFieldsPresent_NamesNotValues(t *testing.T) {
	// The returned evidence must never contain the sensitive value itself.
	got := SensitiveFieldsPresent([]byte(`{"ssn":"123-45-6789"}`), DefaultSensitiveFields)
	if len(got) != 1 || got[0] != "ssn" {
		t.Fatalf("expected [ssn], got %v", got)
	}
	for _, f := range got {
		if f == "123-45-6789" {
			t.Error("value leaked into result")
		}
	}
}

func TestSensitiveFieldsPresent_CustomFields(t *testing.T) {
	got := SensitiveFieldsPresent([]byte(`{"dob":"2000-01-01","id":1}`), []string{"dob"})
	if len(got) != 1 || got[0] != "dob" {
		t.Fatalf("expected [dob], got %v", got)
	}
}

func TestFieldValue(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		field string
		want  string
		ok    bool
	}{
		{"top level string", `{"tenant_id":"tenant-a"}`, "tenant_id", "tenant-a", true},
		{"case insensitive", `{"Tenant_ID":"tenant-a"}`, "tenant_id", "tenant-a", true},
		{"nested", `{"data":{"meta":{"tenant_id":"tenant-b"}}}`, "tenant_id", "tenant-b", true},
		{"inside array", `{"items":[{"tenant_id":"tenant-c"}]}`, "tenant_id", "tenant-c", true},
		{"integral number keeps no decimal point", `{"tenant_id":42}`, "tenant_id", "42", true},
		{"boolean", `{"active":true}`, "active", "true", true},
		{"absent", `{"other":"x"}`, "tenant_id", "", false},
		{"object value is not a scalar", `{"tenant_id":{"a":1}}`, "tenant_id", "", false},
		{"not json", `plain text`, "tenant_id", "", false},
		{"empty body", ``, "tenant_id", "", false},
		{"empty field name", `{"tenant_id":"a"}`, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FieldValue([]byte(tt.body), tt.field)
			if got != tt.want || ok != tt.ok {
				t.Errorf("FieldValue() = %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestResults_HonorsCustomSensitiveFields(t *testing.T) {
	a := model.ExecutionResult{IdentityID: "owner", StatusCode: 200, Body: []byte(`{"internal_note":"x"}`)}
	b := model.ExecutionResult{IdentityID: "other", StatusCode: 200, Body: []byte(`{"other":"y"}`)}

	// "internal_note" is not in the default set, so only an explicit field list
	// should surface it — this is the divergence the engine used to have.
	cr := Results(a, b, nil)
	if joined := strings.Join(cr.Notes, " "); strings.Contains(joined, "internal_note") {
		t.Errorf("default field set reported a custom field: %v", cr.Notes)
	}

	cr = Results(a, b, []string{"internal_note"})
	if joined := strings.Join(cr.Notes, " "); !strings.Contains(joined, "internal_note") {
		t.Errorf("custom field set did not report internal_note: %v", cr.Notes)
	}
}

func TestResults_NilFieldsUsesDefaultSet(t *testing.T) {
	a := model.ExecutionResult{IdentityID: "owner", StatusCode: 200, Body: []byte(`{"api_key":"sk_live"}`)}
	b := model.ExecutionResult{IdentityID: "other", StatusCode: 200, Body: []byte(`{"ok":true}`)}
	cr := Results(a, b, nil)
	if joined := strings.Join(cr.Notes, " "); !strings.Contains(joined, "api_key") {
		t.Errorf("default set did not report api_key: %v", cr.Notes)
	}
}
