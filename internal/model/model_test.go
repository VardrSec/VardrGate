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
