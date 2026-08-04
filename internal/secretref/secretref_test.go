package secretref

import (
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

func TestExpand(t *testing.T) {
	t.Setenv("VARDRGATE_TEST_A", "alpha")
	t.Setenv("VARDRGATE_TEST_B", "beta")

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "no reference passes through", in: "literal-token", want: "literal-token"},
		{name: "empty string is fine", in: "", want: ""},
		{name: "single reference", in: "${VARDRGATE_TEST_A}", want: "alpha"},
		{name: "surrounding text", in: "Bearer ${VARDRGATE_TEST_A}!", want: "Bearer alpha!"},
		{name: "two references", in: "${VARDRGATE_TEST_A}-${VARDRGATE_TEST_B}", want: "alpha-beta"},
		{name: "unset variable", in: "${VARDRGATE_TEST_MISSING}", wantErr: "unset or empty"},
		{name: "unterminated", in: "${OPEN", wantErr: "unterminated"},
		{name: "empty name", in: "${}", wantErr: "empty ${}"},
		{name: "lone dollar is literal", in: "$NOT_A_REF", want: "$NOT_A_REF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Expand(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Expand(%q) error = %v, want containing %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Expand(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Expand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandIdentities(t *testing.T) {
	t.Setenv("VARDRGATE_TEST_TOKEN", "resolved")
	ids := []model.Identity{
		{ID: "a", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "${VARDRGATE_TEST_TOKEN}"}},
		{ID: "anon", Credential: model.Credential{Type: model.CredentialTypeStaticHeader}},
	}
	if err := ExpandIdentities(ids); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ids[0].Credential.Value != "resolved" {
		t.Errorf("value = %q, want %q", ids[0].Credential.Value, "resolved")
	}
	if ids[1].Credential.Value != "" {
		t.Errorf("anonymous credential was modified: %q", ids[1].Credential.Value)
	}
}

func TestExpandIdentities_NamesTheFailingIdentity(t *testing.T) {
	ids := []model.Identity{
		{ID: "other_user", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "${VARDRGATE_TEST_MISSING}"}},
	}
	err := ExpandIdentities(ids)
	if err == nil || !strings.Contains(err.Error(), "other_user") {
		t.Fatalf("error did not name the identity: %v", err)
	}
}
