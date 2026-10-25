// authbench measures authorization accuracy, not execution performance.
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/VardrSec/vardrgate/internal/api"
	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/store"
)

//go:embed cases.json
var manifest []byte

//go:embed assertions.json
var assertionProfiles []byte

type scenario struct {
	ID        string               `json:"id"`
	Path      string               `json:"path"`
	Method    string               `json:"method,omitempty"`
	Actor     string               `json:"actor"`
	Decision  model.AccessDecision `json:"decision"`
	Violation bool                 `json:"violation"`
}

type assessment struct {
	Scenario     scenario        `json:"scenario"`
	Oracle       observation     `json:"oracle"`
	Verdict      string          `json:"verdict"`
	Inconclusive bool            `json:"inconclusive"`
	Gate         json.RawMessage `json:"gate_response"`
}

type metrics struct {
	Total                int     `json:"total"`
	KnownFailures        int     `json:"known_authorization_failures"`
	TP                   int     `json:"true_positives"`
	FP                   int     `json:"false_positives"`
	FN                   int     `json:"missed_authorization_failures"`
	TN                   int     `json:"true_negatives"`
	Inconclusive         int     `json:"inconclusive_assessments"`
	InconclusiveMisses   int     `json:"inconclusive_known_failures"`
	InconclusiveControls int     `json:"inconclusive_controls"`
	Precision            float64 `json:"precision"`
	Recall               float64 `json:"recall"`
}

type report struct {
	SchemaVersion       int                `json:"schema_version"`
	GeneratedAt         time.Time          `json:"generated_at"`
	GoVersion           string             `json:"go_version"`
	Platform            string             `json:"platform"`
	Revision            string             `json:"git_revision"`
	WorkingTree         string             `json:"working_tree_status"`
	SourceSHA256        string             `json:"source_sha256"`
	RepeatCount         int                `json:"repeat_count"`
	Stable              bool               `json:"stable_classifications"`
	Metrics             metrics            `json:"metrics"`
	AssertionsEnabled   bool               `json:"assertions_enabled"`
	VerificationEnabled bool               `json:"verification_enabled"`
	ByExpectation       map[string]metrics `json:"by_expectation"`
	Assessments         []assessment       `json:"assessments"`
}

func main() {
	out := flag.String("out", "benchmarks/authz-latest.json", "JSON report path (run from repository root)")
	repeat := flag.Int("repeat", 3, "fresh lab runs; fail if classifications or oracle observations differ")
	assertions := flag.Bool("assertions", false, "apply the versioned response assertion profiles")
	verify := flag.Bool("verify", false, "verify write effects through the owner's view of the document")
	flag.Parse()
	if err := execute(*out, *repeat, *assertions, *verify); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(out string, repeat int, assertions, verify bool) error {
	if repeat < 1 {
		return fmt.Errorf("repeat must be positive")
	}
	hash, err := sourceHash()
	if err != nil {
		return err
	}
	r := report{SchemaVersion: 2, GeneratedAt: time.Now().UTC(), GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, Revision: git("rev-parse", "HEAD"), WorkingTree: git("status", "--short"), SourceSHA256: hash, RepeatCount: repeat, Stable: true, AssertionsEnabled: assertions, VerificationEnabled: verify}
	for i := 0; i < repeat; i++ {
		rows, err := runSuiteWith(assertions, verify)
		if err != nil {
			return fmt.Errorf("run %d: %w", i+1, err)
		}
		if i == 0 {
			r.Assessments = rows
			r.Metrics = summarize(rows)
			r.ByExpectation = summarizeGroups(rows)
		} else if !reflect.DeepEqual(signature(r.Assessments), signature(rows)) {
			return fmt.Errorf("run %d produced different classifications or oracle observations", i+1)
		}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(out, append(data, '\n'), 0644); err != nil {
		return err
	}
	m := r.Metrics
	fmt.Printf("%d assessments x %d stable runs: TP=%d FP=%d missed=%d TN=%d inconclusive=%d (including %d misses)\nPrecision=%.1f%% Recall=%.1f%%\nReport: %s\n", m.Total, repeat, m.TP, m.FP, m.FN, m.TN, m.Inconclusive, m.InconclusiveMisses, m.Precision*100, m.Recall*100, out)
	return nil
}

func runSuite() ([]assessment, error) {
	return runSuiteWithAssertions(false)
}

func runSuiteWithAssertions(enabled bool) ([]assessment, error) {
	return runSuiteWith(enabled, false)
}

// verifiedWrites are the write scenarios that receive write verification when
// it is enabled. The verifier reads the owner's view of the document and is
// never one of the identities under test.
var verifiedWrites = map[string]bool{"write-bypass": true, "write-protected": true, "write-before-500": true}

func runSuiteWith(enabled, verify bool) ([]assessment, error) {
	var cases []scenario
	if err := json.Unmarshal(manifest, &cases); err != nil {
		return nil, err
	}
	var profiles map[string][]model.ResponseAssertion
	if enabled {
		if err := json.Unmarshal(assertionProfiles, &profiles); err != nil {
			return nil, err
		}
	}
	l := &lab{audit: make(map[string][]observation)}
	target := httptest.NewServer(l)
	defer target.Close()
	// Production client, engine, and API handler: real HTTP on both hops.
	eng := engine.New(client.NewWithConfig(nil, client.Config{AllowPrivateTargets: true, Timeout: 2 * time.Second}))
	gate := httptest.NewServer(api.New(slog.New(slog.NewTextHandler(io.Discard, nil)), eng, store.NewMemory(), nil))
	defer gate.Close()
	httpClient := &http.Client{Timeout: 5 * time.Second}
	defer httpClient.CloseIdleConnections()
	var rows []assessment
	seen := make(map[string]bool)
	for _, s := range cases {
		if s.ID == "" || seen[s.ID] {
			return nil, fmt.Errorf("empty or duplicate case id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Decision != model.AccessDecisionAllow && s.Decision != model.AccessDecisionDeny {
			return nil, fmt.Errorf("%s: invalid decision", s.ID)
		}
		if s.Method == "" {
			s.Method = http.MethodGet
		}
		cred := map[string]string{"type": "static_header"}
		if s.Actor != "anonymous" {
			cred = map[string]string{"type": "bearer", "value": "lab-" + s.Actor}
		}
		// Credential.Value is write-only on domain models; explicitly encode API input.
		payload := map[string]any{
			"id":              s.ID,
			"identities":      []any{map[string]any{"id": s.Actor, "credential": cred}},
			"request":         map[string]any{"method": s.Method, "url": target.URL + s.Path, "headers": map[string]string{"X-Benchmark-Case": s.ID}},
			"expected_access": []any{map[string]any{"identity_id": s.Actor, "decision": s.Decision}},
			// Each case sends one identity once, against fresh fixture state.
			"mutating": model.IsUnsafeMethod(s.Method),
		}
		if verify && verifiedWrites[s.ID] {
			payload["write_verification"] = map[string]any{
				"identity":     map[string]any{"id": "verifier", "credential": map[string]string{"type": "bearer", "value": "lab-alice"}},
				"request":      map[string]any{"method": http.MethodGet, "url": target.URL + "/secure/documents/1/content"},
				"json_pointer": "/content",
			}
		}
		if rules := profiles[s.Path]; len(rules) > 0 {
			payload["expected_access"] = []model.ExpectedAccess{{IdentityID: s.Actor, Decision: s.Decision, ResponseAssertions: rules}}
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		resp, err := httpClient.Post(gate.URL+"/tests/execute", "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s: Gate returned %d: %s", s.ID, resp.StatusCode, raw)
		}
		var result engine.Result
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
		if result.TestCaseID != s.ID || len(result.Executions) != 1 || result.Executions[0].IdentityID != s.Actor {
			return nil, fmt.Errorf("%s: invalid Gate execution", s.ID)
		}
		if len(result.Assessments) != 1 || result.Assessments[0].IdentityID != s.Actor {
			return nil, fmt.Errorf("%s: missing or invalid assessment", s.ID)
		}
		observations := l.observations(s.ID)
		if len(observations) != 1 || observations[0].Actor != s.Actor {
			return nil, fmt.Errorf("%s: expected exactly one lab request with correct identity, got %v", s.ID, observations)
		}
		o := observations[0]
		// Verify declared ground truth using app read/write effects, not HTTP status.
		violation := o.Accessed != (s.Decision == model.AccessDecisionAllow)
		if violation != s.Violation {
			return nil, fmt.Errorf("%s: fixture disagrees with ground truth", s.ID)
		}
		verdict, inconclusive := classify(s, result)
		rows = append(rows, assessment{Scenario: s, Oracle: o, Verdict: verdict, Inconclusive: inconclusive, Gate: json.RawMessage(raw)})
	}
	return rows, nil
}

// unauthorizedAccessCategories are the findings the engine emits for an expected
// denial that was assessed as allowed. The engine refines unexpected_access into
// a more specific category when the context supports it (ADR 0002), so any of
// them is the corresponding finding for a broken deny.
var unauthorizedAccessCategories = map[model.FindingCategory]bool{
	model.CategoryUnexpectedAccess:      true,
	model.CategoryMissingAuthentication: true,
	model.CategoryCrossTenantAccess:     true,
	model.CategoryPotentialBOLA:         true,
	model.CategoryPrivilegeEscalation:   true,
}

func classify(s scenario, result engine.Result) (string, bool) {
	ex := result.Executions[0]
	inconclusive := ex.Error != "" || (ex.ObservedOutcome != model.OutcomeAllow && ex.ObservedOutcome != model.OutcomeDeny)
	for _, a := range result.Assessments {
		if a.IdentityID == s.Actor {
			inconclusive = a.Decision == model.AssessmentInconclusive || a.Decision == model.AssessmentSkipped
		}
	}
	want := unauthorizedAccessCategories
	if s.Decision == model.AccessDecisionAllow {
		want = map[model.FindingCategory]bool{model.CategoryAuthorizationMismatch: true}
	}
	detected := false
	for _, f := range result.Findings {
		if f.IdentityID == s.Actor && want[f.Category] {
			detected = true
		}
	}
	switch {
	case detected && s.Violation:
		return "true_positive", inconclusive
	case detected:
		return "false_positive", inconclusive
	case s.Violation:
		return "false_negative", inconclusive
	case inconclusive:
		return "inconclusive", true
	default:
		return "true_negative", false
	}
}

func summarize(rows []assessment) metrics {
	m := metrics{Total: len(rows)}
	for _, row := range rows {
		if row.Scenario.Violation {
			m.KnownFailures++
		}
		if row.Inconclusive {
			m.Inconclusive++
			if row.Scenario.Violation {
				m.InconclusiveMisses++
			} else {
				m.InconclusiveControls++
			}
		}
		switch row.Verdict {
		case "true_positive":
			m.TP++
		case "false_positive":
			m.FP++
		case "false_negative":
			m.FN++
		case "true_negative":
			m.TN++
		}
	}
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.KnownFailures > 0 {
		m.Recall = float64(m.TP) / float64(m.KnownFailures)
	}
	return m
}

func summarizeGroups(rows []assessment) map[string]metrics {
	groups := make(map[string][]assessment)
	for _, row := range rows {
		key := "unauthorized_reads"
		if row.Scenario.Decision == model.AccessDecisionAllow {
			key = "legitimate_access"
		} else if row.Scenario.Method == http.MethodPost {
			key = "unauthorized_writes"
		}
		groups[key] = append(groups[key], row)
	}
	result := make(map[string]metrics)
	for key, group := range groups {
		result[key] = summarize(group)
	}
	return result
}

// Exclude timestamps, timing, ephemeral ports and OS-specific network error text.
// Retain outcomes, finding categories, error kinds and independently observed effects.
func signature(rows []assessment) []string {
	var out []string
	for _, row := range rows {
		var result engine.Result
		_ = json.Unmarshal(row.Gate, &result) // Already validated by runSuite.
		ex := result.Executions[0]
		var categories []string
		for _, f := range result.Findings {
			categories = append(categories, string(f.Category)+":"+f.IdentityID)
		}
		sort.Strings(categories)
		semantic, _ := json.Marshal(result.Assessments) // Compare values, never pointer addresses.
		out = append(out, fmt.Sprintf("%s|%s|%t|%d|%s|%s|%v|%v|%s", row.Scenario.ID, row.Verdict, row.Inconclusive, ex.StatusCode, ex.ObservedOutcome, ex.ErrorKind, categories, row.Oracle, semantic))
	}
	return out
}

func git(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(out))
}

func sourceHash() (string, error) {
	if _, err := os.Stat("go.mod"); err != nil {
		return "", fmt.Errorf("run authbench from the VardrGate repository root: %w", err)
	}
	paths := []string{"go.mod", "cmd/authbench/cases.json", "cmd/authbench/assertions.json"}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") {
				paths = append(paths, filepath.ToSlash(path))
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		// Normalize checkout line endings for comparison across Windows and Unix.
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		fmt.Fprintf(h, "%s\x00%d\x00", path, len(data))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
