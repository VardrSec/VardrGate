package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VardrSec/vardrgate/internal/model"
)

type strategyTarget struct {
	strategy                    string
	exists, changed, vulnerable bool
	resets, writes              int
	resetStatus                 int
}

func (s *strategyTarget) Execute(_ context.Context, id model.Identity, req model.RequestTemplate) model.ExecutionResult {
	r := model.ExecutionResult{IdentityID: id.ID, StatusCode: 200, Body: []byte(`{"value":"original"}`)}
	switch {
	case strings.HasSuffix(req.URL, "/reset"):
		s.resets++
		s.changed = false
		if s.resetStatus != 0 {
			r.StatusCode = s.resetStatus
		}
	case strings.HasSuffix(req.URL, "/record"):
		if s.strategy == "changed" && s.changed {
			r.StatusCode = 401
			r.Body = nil
		}
		if s.strategy != "changed" && !s.exists {
			r.StatusCode = 404
			r.Body = nil
		}
	default:
		s.writes++
		r.StatusCode = 204
		r.Body = nil
		if id.ID == "owner" || s.vulnerable {
			switch s.strategy {
			case "changed":
				s.changed = true
			case "created":
				s.exists = true
			case "deleted":
				s.exists = false
			}
		}
	}
	return r
}

func TestExplicitWriteStrategies(t *testing.T) {
	for _, strategy := range []string{"changed", "created", "deleted"} {
		for _, vulnerable := range []bool{false, true} {
			t.Run(strategy+map[bool]string{false: " secure", true: " vulnerable"}[vulnerable], func(t *testing.T) {
				tc := verifiedCase(model.AccessDecisionDeny)
				tc.Identities = append(tc.Identities, model.Identity{ID: "owner", Role: "owner", Credential: model.Credential{Type: model.CredentialTypeBearer, Value: "owner-token"}})
				tc.ExpectedAccess = append(tc.ExpectedAccess, model.ExpectedAccess{IdentityID: "owner", Decision: model.AccessDecisionAllow})
				wv := tc.WriteVerification
				wv.JSONPointer = "/value"
				wv.Strategy = strategy
				wv.Environment = "synchronous_isolated"
				if strategy == "changed" {
					wv.AfterStatus = []int{401}
					wv.Reset = &model.SetupStep{As: "owner", Request: model.RequestTemplate{Method: "PUT", URL: "https://api.example.com/reset"}}
				}
				s := &strategyTarget{strategy: strategy, exists: strategy != "created", vulnerable: vulnerable}
				r, err := New(s).Run(context.Background(), tc)
				if err != nil {
					t.Fatal(err)
				}
				want := model.AssessmentDenied
				if vulnerable {
					want = model.AssessmentAllowed
				}
				if r.Assessments[0].Decision != want {
					t.Fatalf("peer: %+v", r)
				}
				if !vulnerable && r.Assessments[1].Decision != model.AssessmentAllowed {
					t.Fatalf("missing positive control: %+v", r)
				}
				if vulnerable && (len(r.Findings) == 0 || r.Findings[0].IdentityID != "peer") {
					t.Fatal("lost independent effect finding")
				}
				b, _ := json.Marshal(r)
				if strings.Contains(string(b), "original") || strings.Contains(string(b), "owner-token") {
					t.Fatal("values leaked")
				}
			})
		}
	}
}

func TestStrategyResetFailureWithholdsWrite(t *testing.T) {
	tc := verifiedCase(model.AccessDecisionDeny)
	wv := tc.WriteVerification
	wv.Strategy = "changed"
	wv.Environment = "synchronous_isolated"
	wv.AfterStatus = []int{401}
	wv.Reset = &model.SetupStep{Request: model.RequestTemplate{Method: "POST", URL: "https://api.example.com/reset"}}
	for _, status := range []int{202, 302, 401, 500} {
		s := &strategyTarget{strategy: "changed", resetStatus: status}
		r, err := New(s).Run(context.Background(), tc)
		if err != nil || s.writes != 0 || r.Assessments[0].Reason != reasonResetFailed {
			t.Fatalf("reset %d: %+v %v", status, r, err)
		}
	}
}

func TestExplicitStrategiesRejectUnsafeContracts(t *testing.T) {
	for _, change := range []func(*model.WriteVerification){
		func(w *model.WriteVerification) { w.Strategy = "invented" },
		func(w *model.WriteVerification) { w.Environment = "unknown" },
		func(w *model.WriteVerification) { w.AfterStatus = []int{500} },
		func(w *model.WriteVerification) {
			w.Reset = &model.SetupStep{Request: model.RequestTemplate{Method: "PUT", URL: "https://other.example/reset"}}
		},
	} {
		tc := verifiedCase(model.AccessDecisionDeny)
		tc.WriteVerification.Strategy = "changed"
		tc.WriteVerification.Environment = "synchronous_isolated"
		change(tc.WriteVerification)
		if err := Validate(tc); err == nil {
			t.Fatal("accepted unsafe verification contract")
		}
	}
}
