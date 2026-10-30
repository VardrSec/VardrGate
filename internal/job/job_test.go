package job

import (
	"strings"
	"testing"
	"time"
)

const envelopeJSON = `{
  "id": "job_123",
  "type": "vardrgate_api_test",
  "program_id": 42,
  "config": {
    "policy_id": "pol_abc",
    "test_case": {
      "id": "users-profile-owner-check",
      "identities": [{"id":"owner","credential":{"type":"bearer","value":"t"}}],
      "request": {"method":"GET","url":"https://api.example.com/users/42/profile"},
      "expected_access": [{"identity_id":"owner","decision":"allow"}]
    },
    "execution": {
      "timeout_seconds": 15,
      "max_response_bytes": 1048576,
      "allow_private_targets": true
    }
  }
}`

func TestParse_Envelope(t *testing.T) {
	e, err := Parse([]byte(envelopeJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Type != "vardrgate_api_test" {
		t.Errorf("type: got %q", e.Type)
	}
	if e.TestCase().ID != "users-profile-owner-check" {
		t.Errorf("test case id: got %q", e.TestCase().ID)
	}
	if e.Config.TestCase.Identities[0].Credential.Value != "t" {
		t.Errorf("credential value not decoded from job")
	}
	cfg := e.ClientConfig()
	if cfg.Timeout != 15*time.Second {
		t.Errorf("timeout: got %v", cfg.Timeout)
	}
	if cfg.MaxBodyBytes != 1048576 {
		t.Errorf("max body: got %d", cfg.MaxBodyBytes)
	}
	if !cfg.AllowPrivateTargets {
		t.Errorf("allow_private_targets not carried through")
	}
}

func TestParse_BareTestCase(t *testing.T) {
	bare := `{
      "id": "bare",
      "identities": [{"id":"u","credential":{"type":"bearer","value":"t"}}],
      "request": {"method":"GET","url":"https://x/"},
      "expected_access": [{"identity_id":"u","decision":"allow"}]
    }`
	e, err := Parse([]byte(bare))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.TestCase().ID != "bare" {
		t.Errorf("bare test case id: got %q", e.TestCase().ID)
	}
}

func TestClientConfig_Defaults(t *testing.T) {
	e, _ := Parse([]byte(`{"config":{"test_case":{"id":"x"}}}`))
	cfg := e.ClientConfig()
	if cfg.Timeout != 0 || cfg.MaxBodyBytes != 0 {
		t.Errorf("unset execution fields must stay zero so client applies defaults, got %+v", cfg)
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("nope")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParse_ExpandsCredentialEnvReferences(t *testing.T) {
	// All three input paths (job envelope, policy binding, generated suite)
	// resolve ${VAR} the same way. Without this a job envelope would send the
	// literal characters as a bearer token and the 401s would read as findings.
	t.Setenv("VARDRGATE_TEST_JOB_TOKEN", "resolved-token")
	env, err := Parse([]byte(`{
	  "config": {
	    "test_case": {
	      "id": "tc",
	      "identities": [
	        {"id":"owner","credential":{"type":"bearer","value":"${VARDRGATE_TEST_JOB_TOKEN}"}}
	      ],
	      "request": {"method":"GET","url":"https://api.example.com/x"}
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := env.TestCase().Identities[0].Credential.Value; got != "resolved-token" {
		t.Errorf("credential value = %q, want %q", got, "resolved-token")
	}
}

func TestParse_UnsetEnvReferenceIsAnError(t *testing.T) {
	_, err := Parse([]byte(`{
	  "config": {
	    "test_case": {
	      "id": "tc",
	      "identities": [
	        {"id":"owner","credential":{"type":"bearer","value":"${VARDRGATE_DEFINITELY_UNSET}"}}
	      ],
	      "request": {"method":"GET","url":"https://api.example.com/x"}
	    }
	  }
	}`))
	if err == nil || !strings.Contains(err.Error(), "unset or empty") {
		t.Fatalf("expected an unset-variable error, got %v", err)
	}
}

func TestParse_LiteralCredentialsAreUntouched(t *testing.T) {
	env, err := Parse([]byte(`{
	  "id": "tc",
	  "identities": [{"id":"owner","credential":{"type":"bearer","value":"plain-token"}}],
	  "request": {"method":"GET","url":"https://api.example.com/x"}
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := env.TestCase().Identities[0].Credential.Value; got != "plain-token" {
		t.Errorf("credential value = %q, want %q", got, "plain-token")
	}
}

func TestParseLiteral_DoesNotExpandReferences(t *testing.T) {
	// A caller that resolved its own credentials needs them used as written: a
	// resolved value that happens to contain ${...} must not be read again, and
	// a job must not be able to pull variables from Gate's environment.
	t.Setenv("VARDRGATE_TEST_LITERAL", "from-gate-environment")
	env, err := ParseLiteral([]byte(`{
	  "config": {
	    "test_case": {
	      "id": "tc",
	      "identities": [
	        {"id":"owner","credential":{"type":"bearer","value":"tok-${VARDRGATE_TEST_LITERAL}"}}
	      ],
	      "request": {
	        "method":"GET",
	        "url":"https://api.example.com/x?k=${VARDRGATE_TEST_LITERAL}",
	        "headers":{"X-Probe":"${VARDRGATE_TEST_LITERAL}"}
	      }
	    }
	  }
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tc := env.TestCase()
	if got := tc.Identities[0].Credential.Value; got != "tok-${VARDRGATE_TEST_LITERAL}" {
		t.Errorf("credential value = %q, want it unchanged", got)
	}
	if strings.Contains(tc.Request.URL, "from-gate-environment") || strings.Contains(tc.Request.Headers["X-Probe"], "from-gate-environment") {
		t.Errorf("request was expanded from the environment: %+v", tc.Request)
	}
}

func TestParseLiteral_UnsetReferenceIsNotAnError(t *testing.T) {
	if _, err := ParseLiteral([]byte(`{
	  "id": "tc",
	  "identities": [{"id":"owner","credential":{"type":"bearer","value":"${VARDRGATE_DEFINITELY_UNSET}"}}],
	  "request": {"method":"GET","url":"https://api.example.com/x"}
	}`)); err != nil {
		t.Fatalf("literal parsing must not resolve references: %v", err)
	}
}
