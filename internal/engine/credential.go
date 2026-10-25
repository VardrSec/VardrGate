package engine

import (
	"net/http"

	"github.com/VardrSec/vardrgate/internal/model"
)

const reasonCredentialRejected = "credential_rejected"

// A 401 to a caller that sent credentials says the credentials were not
// accepted, not that authorization refused the caller. A dead or expired token
// produces exactly this, so counting it as a denial lets a vulnerable endpoint
// read as protected. unauthorized_is_denial is the reviewed statement that this
// API answers authorization refusals with 401. See ADR 0019.
func rejectsCredential(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult) bool {
	return !tc.UnauthorizedIsDenial && !identity.Credential.SendsNoAuth() &&
		exec.Error == "" && exec.StatusCode == http.StatusUnauthorized
}

// demoteRejectedCredential turns a deny-expected denial into an inconclusive
// assessment when the denial cannot be attributed to authorization, whatever
// decided it: status, a matched assertion, or unchanged verified state.
func demoteRejectedCredential(tc model.AuthorizationTestCase, identity model.Identity, exec model.ExecutionResult, a model.Assessment) model.Assessment {
	if a.ExpectedAccess == model.AccessDecisionDeny && a.Decision == model.AssessmentDenied && rejectsCredential(tc, identity, exec) {
		a.Decision, a.Reason = model.AssessmentInconclusive, reasonCredentialRejected
	}
	return a
}
