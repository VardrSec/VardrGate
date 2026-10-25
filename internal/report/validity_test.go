package report

import (
	"bytes"
	"html"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

func TestReportsExplainEveryIdentity(t *testing.T) {
	cases := []Case{{Result: engine.Result{TestCaseID: "write", Assessments: []model.Assessment{{IdentityID: "peer", ExpectedAccess: "deny", Decision: "allowed", Source: "write_verification", Reason: "state_changed", CredentialStatus: "preflight_passed", WriteVerification: "verified_effect", Verification: &model.VerificationEvidence{ReaderIdentityID: "reader", ReaderCredentialStatus: "not_checked", BeforeStatuses: []int{200, 200}, AfterStatus: 200, Strategy: "changed", Environment: "synchronous_isolated"}}}}}}
	for _, render := range []func(*bytes.Buffer) error{func(b *bytes.Buffer) error { return Text(b, cases) }, func(b *bytes.Buffer) error { return Markdown(b, cases) }} {
		var b bytes.Buffer
		if err := render(&b); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"peer", "deny", "allowed", "preflight_passed", "verified_effect", "reader", "state_changed", "operator confirmation"} {
			if !strings.Contains(html.UnescapeString(b.String()), want) {
				t.Fatalf("report omitted %s: %s", want, b.String())
			}
		}
	}
}
