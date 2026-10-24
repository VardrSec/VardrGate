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

	reasonStateChanged         = "state_changed"
	reasonStateUnchanged       = "state_unchanged"
	reasonVerifierReadFailed   = "verifier_read_failed"
	reasonVerifierDenied       = "verifier_denied"
	reasonVerifierValueMissing = "verifier_value_unavailable"
	reasonConcurrentChange     = "state_changing_concurrently"
	reasonTargetAlreadyPresent = "target_value_already_present"
	reasonChangedUnexpectedly  = "state_changed_unexpectedly"
)

func validateVerification(tc model.AuthorizationTestCase, ids map[string]struct{}) error {
	wv := tc.WriteVerification
	if wv == nil {
		return nil
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
	return s.status == o.status && s.hasValue == o.hasValue && reflect.DeepEqual(s.value, o.value)
}

// observe performs one verifier read. A failed or refused read returns a
// reason instead of a state.
func (e *Engine) observe(ctx context.Context, wv *model.WriteVerification) (observedState, string) {
	req := wv.Request
	req.Method = verifierMethod(wv)
	ex := e.exec.Execute(ctx, wv.Identity, req)
	switch {
	case ex.Error != "" || ex.ErrorKind != "" || ex.StatusCode >= 500:
		return observedState{}, reasonVerifierReadFailed
	case ex.StatusCode == 401 || ex.StatusCode == 403:
		return observedState{}, reasonVerifierDenied
	}
	st := observedState{status: ex.StatusCode}
	if wv.JSONPointer == "" || ex.StatusCode < 200 || ex.StatusCode >= 300 {
		return st, ""
	}
	doc, err := decodeAssertionJSON(ex.Body)
	if err != nil {
		return observedState{}, reasonVerifierValueMissing
	}
	tokens, _ := pointerTokens(wv.JSONPointer) // Validated before any execution.
	v, ok := pointerValue(doc, tokens)
	if !ok {
		return observedState{}, reasonVerifierValueMissing
	}
	st.value, st.hasValue = v, true
	return st, ""
}

// verifiedExecute wraps one identity's request in verifier reads: two before
// (to detect concurrent change) and one after. It returns the identity's raw
// execution and the verification assessment.
func (e *Engine) verifiedExecute(ctx context.Context, wv *model.WriteVerification, identity model.Identity, req model.RequestTemplate, ea model.ExpectedAccess) (model.ExecutionResult, model.Assessment) {
	a := model.Assessment{IdentityID: identity.ID, ExpectedAccess: ea.Decision,
		Decision: model.AssessmentInconclusive, Source: sourceWriteVerification}

	before, reason := e.observe(ctx, wv)
	if reason == "" {
		var again observedState
		if again, reason = e.observe(ctx, wv); reason == "" && !again.equal(before) {
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

	after, reason := e.observe(ctx, wv)
	switch {
	case reason != "":
		a.Reason = reason
	case after.equal(before):
		a.Decision, a.Reason = model.AssessmentDenied, reasonStateUnchanged
	case hasTarget && !(after.hasValue && reflect.DeepEqual(after.value, target)):
		a.Reason = reasonChangedUnexpectedly
	default:
		a.Decision, a.Reason = model.AssessmentAllowed, reasonStateChanged
	}
	return exec, a
}
