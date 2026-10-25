package engine

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/VardrSec/vardrgate/internal/model"
)

func validateAssertions(rules []model.ResponseAssertion) error {
	if len(rules) > 32 {
		return fmt.Errorf("at most 32 response assertions are supported")
	}
	for i, rule := range rules {
		for _, code := range rule.StatusCodes {
			if code < 100 || code > 599 {
				return fmt.Errorf("response_assertions[%d]: invalid status code", i)
			}
		}
		if len(rule.Equals) == 0 && rule.JSONPointer == "" && len(rule.StatusCodes) > 0 && rule.Decision == model.AccessDecisionDeny {
			for _, code := range rule.StatusCodes {
				if code < 400 || code > 499 {
					return fmt.Errorf("response_assertions[%d]: status-only denial requires reviewed 4xx codes", i)
				}
			}
			continue
		}
		if rule.Decision != model.AccessDecisionAllow && rule.Decision != model.AccessDecisionDeny {
			return fmt.Errorf("response_assertions[%d]: decision must be allow or deny", i)
		}
		if len(rule.JSONPointer) > 1024 {
			return fmt.Errorf("response_assertions[%d]: JSON pointer exceeds 1024 bytes", i)
		}
		if _, err := pointerTokens(rule.JSONPointer); err != nil {
			return fmt.Errorf("response_assertions[%d]: invalid JSON pointer", i)
		}
		if len(rule.Equals) > 8192 {
			return fmt.Errorf("response_assertions[%d]: equals exceeds 8192 bytes", i)
		}
		if _, err := decodeAssertionJSON(rule.Equals); err != nil {
			return fmt.Errorf("response_assertions[%d]: equals must contain one supported JSON value", i)
		}
	}
	return nil
}

func assess(id string, ex model.ExecutionResult, ea model.ExpectedAccess, hasExpected bool) model.Assessment {
	a := model.Assessment{IdentityID: id, ExpectedAccess: ea.Decision, Decision: model.AssessmentInconclusive, Source: "none"}
	if !hasExpected {
		a.Decision = model.AssessmentSkipped
		a.Reason = "no_expectation"
		return a
	}
	if ea.Decision == model.AccessDecisionSkip {
		a.Decision = model.AssessmentSkipped
		a.Reason = "explicit_skip"
		return a
	}
	if ex.Error != "" || ex.ErrorKind != "" {
		a.Reason = "execution_error"
		return a
	}
	if len(ea.ResponseAssertions) == 0 {
		a.Source = "http_status"
		outcome := ex.ObservedOutcome
		if outcome == "" {
			outcome = model.ClassifyOutcome(ex.StatusCode, false)
		}
		a.Reason = "status_only"
		switch outcome {
		case model.OutcomeAllow:
			a.Decision = model.AssessmentAllowed
		case model.OutcomeDeny:
			a.Decision = model.AssessmentDenied
		default:
			a.Reason = "ambiguous_http_outcome"
		}
		return a
	}
	a.Source = "response_assertion"
	doc, err := decodeAssertionJSON(ex.Body)
	allow, deny := false, false
	for i, rule := range ea.ResponseAssertions {
		if len(rule.StatusCodes) > 0 {
			matches := false
			for _, code := range rule.StatusCodes {
				matches = matches || ex.StatusCode == code
			}
			if !matches {
				continue
			}
		}
		if len(rule.Equals) > 0 {
			if err != nil {
				continue
			}
			tokens, _ := pointerTokens(rule.JSONPointer) // Validated before any execution.
			want, _ := decodeAssertionJSON(rule.Equals)
			got, exists := pointerValue(doc, tokens)
			if !exists || !reflect.DeepEqual(got, want) {
				continue
			}
		}
		a.MatchedAssertions = append(a.MatchedAssertions, i)
		allow = allow || rule.Decision == model.AccessDecisionAllow
		deny = deny || rule.Decision == model.AccessDecisionDeny
	}
	switch {
	case allow && deny:
		a.Reason = "conflicting_assertions"
	case allow:
		a.Decision = model.AssessmentAllowed
		a.Reason = "assertion_matched"
	case deny:
		a.Decision = model.AssessmentDenied
		a.Reason = "assertion_matched"
	default:
		a.Reason = "no_assertion_matched"
		if err != nil {
			a.Reason = "invalid_or_unsupported_json"
		}
	}
	return a
}

func pointerTokens(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("pointer must start with slash")
	}
	tokens := strings.Split(pointer[1:], "/")
	for i, token := range tokens {
		for j := 0; j < len(token); j++ {
			if token[j] != '~' {
				continue
			}
			j++
			if j >= len(token) || (token[j] != '0' && token[j] != '1') {
				return nil, fmt.Errorf("invalid escape")
			}
		}
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
	}
	return tokens, nil
}

func pointerValue(value any, tokens []string) (any, bool) {
	for _, token := range tokens {
		switch v := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = v[token]
			if !ok {
				return nil, false
			}
		case []any:
			if token == "" || (len(token) > 1 && token[0] == '0') {
				return nil, false
			}
			for _, c := range token {
				if c < '0' || c > '9' {
					return nil, false
				}
			}
			i, err := strconv.Atoi(token)
			if err != nil || i >= len(v) {
				return nil, false
			}
			value = v[i]
		default:
			return nil, false
		}
	}
	return value, true
}
