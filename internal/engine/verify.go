package engine

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

// A write's own response cannot prove whether the write happened: an API can
// return 204 after changing only the caller's own record, or 500 after
// committing the change. Write verification reads the target's state before
// and after each identity's request with a separate reader and judges access
// from the difference. See ADR 0017.

const (
	sourceWriteVerification = "write_verification"

	reasonStateChanged          = "state_changed"
	reasonStateUnchanged        = "state_unchanged"
	reasonVerifierReadFailed    = "verifier_read_failed"
	reasonVerifierDenied        = "verifier_denied"
	reasonVerifierValueMissing  = "verifier_value_unavailable"
	reasonBaselineMissing       = "verifier_baseline_missing"
	reasonConcurrentChange      = "state_changing_concurrently"
	reasonTargetAlreadyPresent  = "target_value_already_present"
	reasonChangedUnexpectedly   = "state_changed_unexpectedly"
	reasonVerifierStatus        = "verifier_unexpected_status"
	reasonWriteFailed           = "write_execution_error"
	reasonNoPositiveControl     = "no_positive_control"
	reasonPositiveControlFailed = "positive_control_failed"
	reasonWritePending          = "write_completion_unconfirmed"
	reasonWriteEnvironment      = "write_environment_unverified"
	reasonResetFailed           = "verifier_reset_failed"
)

func validateVerification(tc model.AuthorizationTestCase, ids map[string]struct{}) error {
	wv := tc.WriteVerification
	if wv == nil {
		return nil
	}
	switch wv.Strategy {
	case "":
	case "changed", "created", "deleted":
		if wv.Environment != "synchronous_isolated" {
			return fmt.Errorf("explicit verification strategy requires environment synchronous_isolated")
		}
	default:
		return fmt.Errorf("write_verification.strategy must be changed, created or deleted")
	}
	if len(wv.AfterStatus) > 0 && wv.Strategy != "changed" {
		return fmt.Errorf("after_status requires strategy changed")
	}
	for _, status := range wv.AfterStatus {
		if status < 400 || status > 499 {
			return fmt.Errorf("after_status supports only reviewed 4xx readback transitions")
		}
	}
	if (wv.Strategy == "created" || wv.Strategy == "deleted") && len(wv.ChangedTo) > 0 {
		return fmt.Errorf("existence strategies cannot use changed_to")
	}
	if wv.Strategy == "changed" && wv.JSONPointer == "" && len(wv.AfterStatus) == 0 {
		return fmt.Errorf("strategy changed requires a json_pointer or reviewed after_status")
	}
	if wv.Reset != nil {
		if wv.Strategy == "" || len(wv.Reset.Capture) > 0 || !sameOrigin(wv.Reset.Request.URL, tc.Request.URL) {
			return fmt.Errorf("verification reset requires an explicit strategy, same-origin request and no captures")
		}
		resetCase := tc
		resetCase.Setup = []model.SetupStep{*wv.Reset}
		if err := validateSetup(resetCase); err != nil {
			return fmt.Errorf("verification reset: %w", err)
		}
	}
	switch wv.Environment {
	case "", "unknown", "synchronous_isolated":
	default:
		return fmt.Errorf("write_verification.environment must be unknown or synchronous_isolated (or omitted for legacy behavior)")
	}
	if !tc.Mutating {
		return fmt.Errorf("write_verification applies to a request that changes state; set mutating: true")
	}
	if wv.Identity.ID == "" {
		return fmt.Errorf("write_verification.identity must have an id")
	}
	if _, ok := ids[wv.Identity.ID]; ok {
		return fmt.Errorf("write_verification.identity %q is also an identity under test; the verifier must be a separate reader", wv.Identity.ID)
	}
	if err := validateCredential(wv.Identity); err != nil {
		return fmt.Errorf("write_verification: %w", err)
	}
	if wv.Request.URL == "" {
		return fmt.Errorf("write_verification.request must have a url")
	}
	if !sameOrigin(wv.Request.URL, tc.Request.URL) {
		return fmt.Errorf("write_verification.request must be same-origin with the request under test")
	}
	if model.IsUnsafeMethod(verifierMethod(wv)) && !wv.AllowUnsafeMethod {
		return fmt.Errorf("write_verification.request uses %s; set allow_unsafe_method to confirm it changes no state", verifierMethod(wv))
	}
	if _, err := pointerTokens(wv.JSONPointer); err != nil || len(wv.JSONPointer) > 1024 {
		return fmt.Errorf("write_verification: invalid JSON pointer")
	}
	verified := 0
	for _, ea := range tc.ExpectedAccess {
		if ea.Decision != model.AccessDecisionSkip {
			verified++
		}
	}
	if verified > 1 && len(wv.ChangedTo) == 0 && wv.Strategy != "created" && wv.Strategy != "deleted" && !(wv.Strategy == "changed" && wv.Reset != nil) {
		// Gate does not reset state between identities: without the target
		// value, a second writer of the same value would read as unchanged.
		return fmt.Errorf("write_verification of more than one identity requires changed_to")
	}
	if len(wv.ChangedTo) > 0 {
		if len(wv.ChangedTo) > 8192 {
			return fmt.Errorf("write_verification: changed_to exceeds 8192 bytes")
		}
		if _, err := decodeAssertionJSON(wv.ChangedTo); err != nil {
			return fmt.Errorf("write_verification: changed_to must contain one supported JSON value")
		}
		if wv.JSONPointer == "" {
			return fmt.Errorf("write_verification: changed_to requires json_pointer")
		}
	}
	return nil
}

func verifierMethod(wv *model.WriteVerification) string {
	if m := strings.TrimSpace(wv.Request.Method); m != "" {
		return strings.ToUpper(m)
	}
	return "GET"
}

func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Host != "" &&
		strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// observedState is held in memory only; it is never serialized.
type observedState struct {
	status   int
	value    any
	hasValue bool
}

func (s observedState) equal(o observedState) bool {
	// A different successful status alone does not prove a state change.
	sameStatus := s.status == o.status || (s.status >= 200 && s.status < 300 && o.status >= 200 && o.status < 300)
	return sameStatus && s.hasValue == o.hasValue && reflect.DeepEqual(s.value, o.value)
}

// observe performs one verifier read. A failed or refused read returns a
// reason instead of a state.
func (e *Engine) observe(ctx context.Context, wv *model.WriteVerification, after bool) (observedState, string) {
	req := wv.Request
	req.Method = verifierMethod(wv)
	ex := e.exec.Execute(ctx, wv.Identity, req)
	statusOnly := observedState{status: ex.StatusCode}
	if after && ex.Error == "" && ex.ErrorKind == "" {
		for _, status := range wv.AfterStatus {
			if ex.StatusCode == status {
				return observedState{status: status}, ""
			}
		}
	}
	switch {
	case ex.Error != "" || ex.ErrorKind != "" || ex.StatusCode >= 500:
		return statusOnly, reasonVerifierReadFailed
	case ex.StatusCode == 401 || ex.StatusCode == 403:
		return statusOnly, reasonVerifierDenied
	case ex.StatusCode != 404 && (ex.StatusCode < 200 || ex.StatusCode >= 300):
		// Only 404 is supported as an absent-resource observation for deletes.
		// Redirects, rate limits and other client errors are unreadable state.
		return statusOnly, reasonVerifierStatus
	}
	if wv.Strategy == "changed" && ex.StatusCode == 404 {
		return statusOnly, reasonVerifierStatus
	}
	st := observedState{status: ex.StatusCode}
	if wv.JSONPointer == "" || ex.StatusCode < 200 || ex.StatusCode >= 300 {
		return st, ""
	}
	doc, err := decodeAssertionJSON(ex.Body)
	if err != nil {
		return statusOnly, reasonVerifierValueMissing
	}
	tokens, _ := pointerTokens(wv.JSONPointer) // Validated before any execution.
	v, ok := pointerValue(doc, tokens)
	if !ok {
		return statusOnly, reasonVerifierValueMissing
	}
	st.value, st.hasValue = v, true
	return st, ""
}

// verifiedExecute wraps one identity's request in verifier reads: two before
// (to detect concurrent change) and one after. It returns the identity's raw
// execution and the verification assessment.
func (e *Engine) verifiedExecute(ctx context.Context, tc model.AuthorizationTestCase, identity model.Identity, req model.RequestTemplate, ea model.ExpectedAccess) (model.ExecutionResult, model.Assessment) {
	wv := tc.WriteVerification
	a := model.Assessment{IdentityID: identity.ID, ExpectedAccess: ea.Decision,
		Decision: model.AssessmentInconclusive, Source: sourceWriteVerification}
	strategy, environment := wv.Strategy, wv.Environment
	if strategy == "" {
		strategy = "legacy_change"
	}
	if environment == "" {
		environment = "legacy"
	}
	a.Verification = &model.VerificationEvidence{Strategy: strategy, Environment: environment, ReaderIdentityID: wv.Identity.ID, BeforeStatuses: []int{}}

	if wv.Reset != nil {
		actor := model.Identity{ID: "verification-reset", Credential: model.Credential{Type: model.CredentialTypeStaticHeader}}
		for _, id := range tc.Identities {
			if id.ID == wv.Reset.As {
				actor = id
			}
		}
		reset := e.exec.Execute(ctx, actor, wv.Reset.Request)
		a.Verification.ResetStatus = reset.StatusCode
		if reset.Error != "" || reset.ErrorKind != "" || reset.StatusCode < 200 || reset.StatusCode >= 300 || reset.StatusCode == 202 {
			a.Reason = reasonResetFailed
			return model.ExecutionResult{IdentityID: identity.ID, Error: "write verification reset failed", ErrorKind: model.ErrorKindVerification}, a
		}
	}
	before, reason := e.observe(ctx, wv, false)
	a.Verification.BeforeStatuses = append(a.Verification.BeforeStatuses, before.status)
	if reason == reasonVerifierStatus {
		// Preserve the baseline diagnostic for an unusable first read; after
		// reads use the more specific unexpected-status reason.
		reason = reasonBaselineMissing
	}
	if reason == "" && ((wv.Strategy == "created" && before.status != 404) || (wv.Strategy != "created" && (before.status < 200 || before.status >= 300))) {
		// A missing resource is not a baseline: a mistyped verifier path would
		// read 404 before and after and look like a refused write.
		reason = reasonBaselineMissing
	}
	if reason == "" {
		var again observedState
		again, reason = e.observe(ctx, wv, false)
		a.Verification.BeforeStatuses = append(a.Verification.BeforeStatuses, again.status)
		if reason == "" && !again.equal(before) {
			reason = reasonConcurrentChange
		}
	}
	var target any
	hasTarget := len(wv.ChangedTo) > 0
	if reason == "" && hasTarget {
		target, _ = decodeAssertionJSON(wv.ChangedTo) // Validated before any execution.
		if before.hasValue && reflect.DeepEqual(before.value, target) {
			reason = reasonTargetAlreadyPresent
		}
	}
	if reason != "" {
		// The request is not sent: without a usable before-state its effect
		// could not be judged, and an unsafe request should not run blind.
		a.Reason = reason
		return model.ExecutionResult{IdentityID: identity.ID, Error: "write verification could not read the state before the request", ErrorKind: model.ErrorKindVerification}, a
	}

	exec := e.exec.Execute(ctx, identity, req)

	after, reason := e.observe(ctx, wv, true)
	a.Verification.AfterStatus = after.status
	switch {
	case reason != "":
		a.Reason = reason
	case after.equal(before) && (exec.Error != "" || exec.ErrorKind != ""):
		a.Reason = reasonWriteFailed
	case after.equal(before) && exec.StatusCode == 202:
		// Accepted does not establish completion, even when an owner control
		// succeeds or the environment was declared synchronous.
		a.Reason = reasonWritePending
	case !after.equal(before) && hasTarget && !(after.hasValue && reflect.DeepEqual(after.value, target)):
		a.Reason = reasonChangedUnexpectedly
	case wv.Environment == "unknown":
		// Two stable baseline reads cannot establish completion or exclude an
		// unrelated writer after the baseline. Do not attribute either outcome.
		a.Reason = reasonWriteEnvironment
	case wv.Strategy == "created" && after.status != 404 && (after.status < 200 || after.status >= 300):
		a.Reason = reasonVerifierStatus
	case wv.Strategy == "deleted" && after.status != 404 && !after.equal(before):
		a.Reason = reasonChangedUnexpectedly
	case after.equal(before):
		a.Decision, a.Reason = model.AssessmentDenied, reasonStateUnchanged
	default:
		a.Decision, a.Reason = model.AssessmentAllowed, reasonStateChanged
	}
	return exec, a
}

// A constant or wrong oracle must not make deny-only tests look protected.
// Wait until all identities have run so the positive control must actually
// demonstrate a write using this oracle, rather than merely being declared.
func guardVerifiedDenials(tc model.AuthorizationTestCase, verified map[string]model.Assessment) {
	declared, passed := false, false
	for _, ea := range tc.ExpectedAccess {
		if ea.Decision == model.AccessDecisionAllow {
			declared = true
			a, ok := verified[ea.IdentityID]
			passed = passed || (ok && a.Decision == model.AssessmentAllowed)
		}
	}
	if passed {
		return
	}
	reason := reasonNoPositiveControl
	if declared {
		reason = reasonPositiveControlFailed
	}
	for id, a := range verified {
		if a.ExpectedAccess == model.AccessDecisionDeny && a.Decision == model.AssessmentDenied {
			a.Decision, a.Reason = model.AssessmentInconclusive, reason
			verified[id] = a
		}
	}
}

// executionOrder runs deny-expected identities first when writes are verified,
// so an unauthorized write is observed against an untouched before-state
// rather than hidden behind a legitimate write of the same value. Results keep
// the declared order.
func executionOrder(tc model.AuthorizationTestCase) []model.Identity {
	if tc.WriteVerification == nil {
		return tc.Identities
	}
	var deny, rest []model.Identity
	for _, id := range tc.Identities {
		if ea, ok := expectedFor(tc, id.ID); ok && ea.Decision == model.AccessDecisionDeny {
			deny = append(deny, id)
		} else {
			rest = append(rest, id)
		}
	}
	return append(deny, rest...)
}
