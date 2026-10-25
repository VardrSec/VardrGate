package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/scaffold"
)

// saveRegression retains the unresolved reviewed input, never scanner response
// values. Confirmation is an explicit operator action, not inferred verification.
func saveRegression(args []string) error {
	if len(args) == 0 || args[0] != "save" {
		return errors.New("usage: vardrgate regression save --cases input.json --result result.json --case ID --out NEW_DIRECTORY --confirmed")
	}
	fs := flag.NewFlagSet("regression save", flag.ContinueOnError)
	casesPath := fs.String("cases", "", "unresolved reviewed case template")
	resultPath := fs.String("result", "", "Gate result containing the finding")
	caseID := fs.String("case", "", "case ID to retain")
	outDir := fs.String("out", "", "new directory for the regression")
	confirmed := fs.Bool("confirmed", false, "operator confirms the finding and its binding to this reviewed template")
	allowUnbound := fs.Bool("allow-unbound-result", false, "explicit manual confirmation for legacy/job results without a CLI input digest")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if !*confirmed || *casesPath == "" || *resultPath == "" || *caseID == "" || *outDir == "" {
		return errors.New("--cases, --result, --case, --out and explicit --confirmed are required")
	}
	data, err := os.ReadFile(*casesPath)
	if err != nil {
		return fmt.Errorf("read cases: %w", err)
	}
	cases, digests, err := caseTemplates(data)
	if err != nil {
		return err
	}
	var selected *model.AuthorizationTestCase
	for i := range cases {
		if cases[i].ID == *caseID {
			if selected != nil {
				return errors.New("case ID is not unique")
			}
			selected = &cases[i]
		}
	}
	if selected == nil {
		return errors.New("case ID was not found")
	}
	if len(selected.ExpectedAccess) == 0 {
		return errors.New("regression requires reviewed access expectations")
	}
	for _, ea := range selected.ExpectedAccess {
		if ea.Decision != model.AccessDecisionAllow && ea.Decision != model.AccessDecisionDeny && ea.Decision != model.AccessDecisionSkip {
			return errors.New("regression contains an unreviewed access decision")
		}
	}
	if err := portableRegression(*selected); err != nil {
		return err
	}
	resultData, err := os.ReadFile(*resultPath)
	if err != nil {
		return fmt.Errorf("read result: %w", err)
	}
	var results []engine.Result
	if err := json.Unmarshal(resultData, &results); err != nil {
		var single engine.Result
		if err := json.Unmarshal(resultData, &single); err != nil {
			return errors.New("parse regression result: invalid JSON")
		}
		results = []engine.Result{single}
	}
	var matched *engine.Result
	for _, r := range results {
		if r.TestCaseID == *caseID {
			if matched != nil {
				return errors.New("selected result is not unique")
			}
			copy := r
			matched = &copy
		}
	}
	if matched == nil || matched.Error != "" || matched.PreflightFailed() {
		return errors.New("selected case has no usable execution result")
	}
	binding := "exact_input_digest"
	if matched.InputDigest == "" {
		if !*allowUnbound {
			return errors.New("result has no input digest; rerun the portable --cases template, or explicitly use --allow-unbound-result with manual confirmation")
		}
		binding = "operator_confirmed_unbound"
	} else if matched.InputDigest != digests[*caseID] {
		return errors.New("result input digest does not match the selected unresolved template; rerun the reviewed case")
	}
	found := false
	for _, f := range matched.Findings {
		found = found || relevantRegressionFinding(*selected, *matched, f)
	}
	if !found {
		return errors.New("selected result contains no finding relevant to a reviewed identity and expectation")
	}
	out, err := scaffold.MarshalCases([]model.AuthorizationTestCase{*selected})
	if err != nil {
		return err
	}
	hash := sha256.Sum256(out)
	manifest, err := json.MarshalIndent(struct {
		Version           int    `json:"schema_version"`
		CaseID            string `json:"case_id"`
		Confirmation      string `json:"confirmation"`
		SpecSHA256        string `json:"spec_sha256"`
		ResultBinding     string `json:"result_binding"`
		SourceInputDigest string `json:"source_input_digest"`
	}{1, *caseID, "operator_confirmed_template_binding", hex.EncodeToString(hash[:]), binding, digests[*caseID]}, "", "  ")
	if err != nil {
		return err
	}
	// Create only after all input checks; an existing regression is never overwritten.
	if err := os.Mkdir(*outDir, 0o700); err != nil {
		return fmt.Errorf("create new regression directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "cases.json"), out, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*outDir, "confirmation.json"), append(manifest, '\n'), 0o600)
}

func relevantRegressionFinding(tc model.AuthorizationTestCase, result engine.Result, finding model.Finding) bool {
	var identity *model.Identity
	for i := range tc.Identities {
		if tc.Identities[i].ID == finding.IdentityID {
			identity = &tc.Identities[i]
		}
	}
	if identity == nil {
		return false
	}
	executed := false
	for _, ex := range result.Executions {
		executed = executed || ex.IdentityID == finding.IdentityID
	}
	if !executed {
		return false
	}
	var expected *model.ExpectedAccess
	for i := range tc.ExpectedAccess {
		if tc.ExpectedAccess[i].IdentityID == finding.IdentityID {
			if expected != nil {
				return false
			}
			expected = &tc.ExpectedAccess[i]
		}
	}
	if expected == nil || expected.Decision == model.AccessDecisionSkip {
		return false
	}
	switch finding.Category {
	case model.CategoryAuthorizationMismatch:
		return expected.Decision == model.AccessDecisionAllow
	case model.CategoryUnexpectedAccess:
		return expected.Decision == model.AccessDecisionDeny
	case model.CategoryMissingAuthentication:
		return expected.Decision == model.AccessDecisionDeny && identity.Credential.SendsNoAuth()
	case model.CategoryPotentialBOLA:
		return expected.Decision == model.AccessDecisionDeny && tc.Resource != nil && tc.Resource.OwnerIdentity != "" && tc.Resource.OwnerIdentity != identity.ID
	case model.CategoryCrossTenantAccess:
		return expected.Decision == model.AccessDecisionDeny && tc.Resource != nil && (tc.Resource.TenantID != "" || tc.Resource.TenantField != "")
	case model.CategoryPrivilegeEscalation:
		return expected.Decision == model.AccessDecisionDeny && tc.Resource != nil && tc.Resource.RequiredRole != "" && len(tc.RoleHierarchy) > 0
	case model.CategorySensitiveDataExposure, model.CategoryObjectPropertyExposure:
		return expected.ForbidSensitiveData
	case model.CategoryCORSMisconfiguration:
		return tc.CORS != nil && tc.CORS.ProbeOrigin != ""
	}
	return false
}

var secretReference = regexp.MustCompile(`^(?:(?:Bearer|Basic) )?(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[A-Za-z_][A-Za-z0-9_]*\}\})$`)

func portableRegression(tc model.AuthorizationTestCase) error {
	ids := append([]model.Identity{}, tc.Identities...)
	requests := []model.RequestTemplate{tc.Request}
	for _, s := range tc.Setup {
		requests = append(requests, s.Request)
	}
	if w := tc.WriteVerification; w != nil {
		ids = append(ids, w.Identity)
		requests = append(requests, w.Request)
		if w.Reset != nil {
			requests = append(requests, w.Reset.Request)
		}
	}
	for _, id := range ids {
		if !id.Credential.SendsNoAuth() && !secretReference.MatchString(id.Credential.Value) {
			return errors.New("regression credentials must use environment references or setup captures; literal/empty credentials cannot be saved")
		}
	}
	var sensitive func(any) bool
	sensitive = func(value any) bool {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				if secretKey(key) {
					if s, ok := child.(string); !ok || !secretReference.MatchString(s) {
						return true
					}
				}
				if sensitive(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if sensitive(child) {
					return true
				}
			}
		}
		return false
	}
	for _, req := range requests {
		u, err := url.Parse(req.URL)
		if err != nil || u.User != nil {
			return errors.New("regression request URLs must not contain credentials")
		}
		for key, values := range u.Query() {
			if secretKey(key) {
				for _, v := range values {
					if !secretReference.MatchString(v) {
						return errors.New("replace literal request secrets with references before saving")
					}
				}
			}
		}
		for _, values := range []map[string]string{req.Headers, req.QueryParams} {
			for key, value := range values {
				if secretKey(key) && !secretReference.MatchString(value) {
					return errors.New("replace literal request secrets with references before saving")
				}
			}
		}
		if len(req.Body) > 0 {
			var body any
			if json.Unmarshal(req.Body, &body) != nil || sensitive(body) {
				return errors.New("request JSON must use references for secret fields before saving")
			}
		}
	}
	return nil
}

func secretKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	switch key {
	case "authorization", "cookie", "setcookie", "password", "passwd", "secret", "token", "accesstoken", "refreshtoken", "authtoken", "apikey", "xapikey", "clientsecret":
		return true
	}
	return false
}
