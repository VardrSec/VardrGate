package engine

import "github.com/VardrSec/vardrgate/internal/model"

func credentialStatus(id model.Identity, probes []model.PreflightResult, ex model.ExecutionResult) string {
	if id.Credential.SendsNoAuth() {
		return "anonymous_identity"
	}
	status := "not_checked"
	for _, probe := range probes {
		if probe.IdentityID == id.ID {
			status = "preflight_failed"
			if probe.Status == "passed" {
				status = "preflight_passed"
			}
		}
	}
	if ex.StatusCode == 401 {
		if status == "preflight_passed" {
			return "preflight_passed_resource_401"
		}
		return "resource_401_unverified"
	}
	return status
}

func preflightIdentities(tc model.AuthorizationTestCase) []model.Identity {
	ids := append([]model.Identity{}, tc.Identities...)
	if tc.WriteVerification != nil && tc.WriteVerification.Identity.Preflight != nil {
		ids = append(ids, tc.WriteVerification.Identity)
	}
	return ids
}
