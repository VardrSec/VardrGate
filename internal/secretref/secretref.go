// Package secretref resolves ${VAR} references in credential values against
// the process environment.
//
// Authorization tests are only meaningful with real credentials, and the files
// that describe them — policy bindings, generated case suites — are meant to be
// committed next to the code they test. A reference keeps the file honest about
// which secret it needs without containing it.
package secretref

import (
	"fmt"
	"os"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

// Expand replaces every ${VAR} in s with that variable's value.
//
// An unset or empty variable is an error rather than a silent empty string: a
// blank token turns an authenticated identity into an anonymous one, which
// inverts the meaning of the test while still reporting a clean run.
func Expand(s string) (string, error) {
	var b strings.Builder
	for {
		open := strings.Index(s, "${")
		if open == -1 {
			b.WriteString(s)
			return b.String(), nil
		}
		end := strings.Index(s[open:], "}")
		if end == -1 {
			return "", fmt.Errorf("unterminated ${ in credential value")
		}
		end += open
		name := s[open+2 : end]
		if name == "" {
			return "", fmt.Errorf("empty ${} reference in credential value")
		}
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("environment variable %q referenced by the credential is unset or empty", name)
		}
		b.WriteString(s[:open])
		b.WriteString(val)
		s = s[end+1:]
	}
}

// ExpandIdentities resolves references in every identity's credential in place.
func ExpandIdentities(identities []model.Identity) error {
	for i := range identities {
		expanded, err := Expand(identities[i].Credential.Value)
		if err != nil {
			return fmt.Errorf("identity %q: %w", identities[i].ID, err)
		}
		identities[i].Credential.Value = expanded
	}
	return nil
}
