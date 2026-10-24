package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredential_UnmarshalJSON_ReadsValue(t *testing.T) {
	data := []byte(`{"type":"bearer","header":"","value":"tok-secret"}`)
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Value != "tok-secret" {
		t.Fatalf("expected value tok-secret, got %q", c.Value)
	}
	if c.Type != CredentialTypeBearer {
		t.Fatalf("expected type bearer, got %q", c.Type)
	}
}

func TestCredential_UnmarshalJSON_HeaderPreserved(t *testing.T) {
	data := []byte(`{"type":"api_key_header","header":"X-Custom","value":"k"}`)
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Header != "X-Custom" {
		t.Fatalf("expected header X-Custom, got %q", c.Header)
	}
}

func TestCredential_MarshalJSON_OmitsValue(t *testing.T) {
	c := Credential{Type: CredentialTypeBearer, Header: "Authorization", Value: "tok-secret"}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	if _, ok := m["value"]; ok {
		t.Fatal("credential value must not appear in JSON output")
	}
	if _, ok := m["Value"]; ok {
		t.Fatal("credential Value (capitalized) must not appear in JSON output")
	}
}

func TestCredential_RoundTrip_ValueNeverLeaks(t *testing.T) {
	original := Credential{Type: CredentialTypeAPIKeyHeader, Header: "X-Key", Value: "super-secret"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify raw JSON contains no trace of the secret.
	raw := string(data)
	if strings.Contains(raw, "super-secret") {
		t.Fatalf("secret leaked into JSON: %s", raw)
	}

	// Unmarshal back and verify Value is empty (was never serialized).
	var decoded Credential
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Value != "" {
		t.Fatalf("round-trip must produce empty Value, got %q", decoded.Value)
	}
}

func TestClassifyOutcome(t *testing.T) {
	cases := []struct {
		code     int
		hasError bool
		want     ObservedOutcome
	}{
		{200, false, OutcomeAllow},
		{201, false, OutcomeAllow},
		{204, false, OutcomeAllow},
		{299, false, OutcomeAllow},
		{301, false, OutcomeRedirect},
		{302, false, OutcomeRedirect},
		{401, false, OutcomeDeny},
		{403, false, OutcomeDeny},
		{404, false, OutcomeNotFound},
		{400, false, OutcomeClientError},
		{422, false, OutcomeClientError},
		{429, false, OutcomeClientError},
		{500, false, OutcomeServerError},
		{503, false, OutcomeServerError},
		{0, true, OutcomeError},
		{200, true, OutcomeError},
	}
	for _, c := range cases {
		got := ClassifyOutcome(c.code, c.hasError)
		if got != c.want {
			t.Errorf("ClassifyOutcome(%d, %v) = %q, want %q", c.code, c.hasError, got, c.want)
		}
	}
}

func TestCredential_SendsNoAuth(t *testing.T) {
	cases := []struct {
		cred Credential
		want bool
	}{
		{Credential{Type: CredentialTypeStaticHeader}, true},
		{Credential{Type: CredentialTypeStaticHeader, Header: "X-Api", Value: "k"}, false},
		{Credential{Type: CredentialTypeBearer, Value: "t"}, false},
		{Credential{Type: CredentialTypeAPIKeyHeader, Value: "k"}, false},
	}
	for _, c := range cases {
		if got := c.cred.SendsNoAuth(); got != c.want {
			t.Errorf("SendsNoAuth(%+v)=%v, want %v", c.cred, got, c.want)
		}
	}
}

func TestClassifyOutcomeWith_DenyStatusesOverride(t *testing.T) {
	deny := []int{401, 403, 404}
	tests := []struct {
		name   string
		status int
		want   ObservedOutcome
	}{
		{"declared 404 becomes deny", 404, OutcomeDeny},
		{"declared 401 stays deny", 401, OutcomeDeny},
		{"success is never overridden", 200, OutcomeAllow},
		{"undeclared code keeps default mapping", 500, OutcomeServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyOutcomeWith(tt.status, false, deny); got != tt.want {
				t.Errorf("ClassifyOutcomeWith(%d) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestClassifyOutcomeWith_NilDenyStatusesMatchesDefault(t *testing.T) {
	for _, code := range []int{200, 302, 401, 403, 404, 418, 500} {
		if got, want := ClassifyOutcomeWith(code, false, nil), ClassifyOutcome(code, false); got != want {
			t.Errorf("status %d: with-nil = %q, default = %q", code, got, want)
		}
	}
}

func TestClassifyOutcomeWith_ErrorWinsOverDenyStatuses(t *testing.T) {
	if got := ClassifyOutcomeWith(404, true, []int{404}); got != OutcomeError {
		t.Errorf("got %q, want %q", got, OutcomeError)
	}
}

func TestSeverityRank_Ordering(t *testing.T) {
	ordered := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Rank() >= ordered[i].Rank() {
			t.Errorf("%q does not rank below %q", ordered[i-1], ordered[i])
		}
	}
	// An unrecognized severity must never trip a threshold.
	if Severity("bogus").Rank() != 0 {
		t.Errorf("unknown severity ranked %d, want 0", Severity("bogus").Rank())
	}
}

func TestParseSeverity(t *testing.T) {
	if got, ok := ParseSeverity("  HIGH "); !ok || got != SeverityHigh {
		t.Errorf("ParseSeverity(\"  HIGH \") = %q, %v", got, ok)
	}
	if _, ok := ParseSeverity("catastrophic"); ok {
		t.Error("ParseSeverity accepted an unknown severity")
	}
}
