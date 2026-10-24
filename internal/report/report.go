// Package report renders engine results for people and for other tools: plain
// text for a terminal or CI log, Markdown for a pull request or job summary,
// and SARIF 2.1.0 for code-scanning dashboards. JSON stays the contract for
// VardrRunner and VardrMap and is written by the CLI directly. See ADR 0014.
//
// Every format states when a case tested nothing. Exit code 3 alone is not
// enough: a report that shows zero findings for an unreached target reads as a
// clean result to anyone who sees the report and not the exit code.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/VardrSec/vardrgate/internal/engine"
	"github.com/VardrSec/vardrgate/internal/model"
)

// Case is one result together with the file it came from: a policy file, a
// cases file, or a job envelope. Source may be empty.
type Case struct {
	Source string
	Result engine.Result
}

// notTested returns why a case tested nothing, or "" when it tested something.
func notTested(r engine.Result) string {
	switch {
	case r.Error != "":
		return "could not run: " + r.Error
	case r.PreflightFailed():
		return "identity preflight failed; no authorization request was sent"
	case r.Unreached():
		return "every identity failed to connect"
	default:
		return ""
	}
}

// summary counts what a set of cases produced.
type summary struct {
	cases, findings, untested, inconclusive int
	bySeverity                              map[model.Severity]int
}

func summarize(cases []Case) summary {
	s := summary{cases: len(cases), bySeverity: map[model.Severity]int{}}
	for _, c := range cases {
		if notTested(c.Result) != "" {
			s.untested++
		}
		s.inconclusive += len(c.Result.Inconclusive())
		for _, f := range c.Result.Findings {
			s.findings++
			s.bySeverity[f.Severity]++
		}
	}
	return s
}

// severityOrder lists severities most severe first, for stable output.
var severityOrder = []model.Severity{
	model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo,
}

// severityBreakdown renders "4 critical, 1 high", omitting zero counts.
func (s summary) severityBreakdown() string {
	var parts []string
	for _, sev := range severityOrder {
		if n := s.bySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	return strings.Join(parts, ", ")
}

func (s summary) headline() string {
	line := fmt.Sprintf("%s, %s", plural(s.cases, "case", "cases"), plural(s.findings, "finding", "findings"))
	if b := s.severityBreakdown(); b != "" {
		line += " (" + b + ")"
	}
	line += fmt.Sprintf(", %d not tested", s.untested)
	if s.inconclusive > 0 {
		line += fmt.Sprintf(", %s", plural(s.inconclusive, "inconclusive assessment", "inconclusive assessments"))
	}
	return line
}

// inconclusiveReasons explains each assessment reason in terms an operator can
// act on. Reasons are fixed codes from the engine, never response content.
var inconclusiveReasons = map[string]string{
	"no_assertion_matched":         "no response assertion matched; the assertion may be stale or the response format changed",
	"conflicting_assertions":       "both an allow and a deny assertion matched; the assertions contradict each other",
	"invalid_or_unsupported_json":  "response assertions are configured but the body is not usable JSON",
	"execution_error":              "the request failed before a usable response arrived",
	"ambiguous_http_outcome":       "the status is neither a success nor a declared denial; declare deny_status or add response assertions",
	"verifier_read_failed":         "the write verifier could not read the target state; the request was withheld if this happened before it",
	"verifier_denied":              "the write verifier was refused; check its credential",
	"verifier_value_unavailable":   "the write verifier's response has no value at its json_pointer; the pointer may be stale",
	"state_changing_concurrently":  "the target state changed between two reads before the request; something else is writing to it",
	"target_value_already_present": "the target already holds the value the write would set, so a change cannot be observed; reset the fixture",
	"state_changed_unexpectedly":   "the target state changed, but not to the value this write attempts",
}

// Explain renders an inconclusive assessment as one line of operator guidance.
func Explain(a model.Assessment) string {
	why, ok := inconclusiveReasons[a.Reason]
	if !ok {
		why = a.Reason
	}
	return fmt.Sprintf("%s expected %s: inconclusive — %s", a.IdentityID, a.ExpectedAccess, why)
}

// Text writes every case followed by a one-line summary.
func Text(w io.Writer, cases []Case) error {
	var b strings.Builder
	for i, c := range cases {
		if i > 0 {
			b.WriteString("\n")
		}
		header := "Case " + c.Result.TestCaseID
		if c.Source != "" {
			header += "  (" + c.Source + ")"
		}
		b.WriteString(header + "\n")
		TextCase(&b, c.Result)
	}
	fmt.Fprintf(&b, "\nSummary: %s\n", summarize(cases).headline())
	_, err := io.WriteString(w, b.String())
	return err
}

// TextCase writes one result's executions and findings. The demo uses it
// directly so its narrative and `--format text` cannot drift apart.
func TextCase(b *strings.Builder, res engine.Result) {
	if reason := notTested(res); reason != "" {
		fmt.Fprintf(b, "NOT TESTED: %s.\n", reason)
	}
	for _, p := range res.Preflight {
		if p.Status != "passed" {
			fmt.Fprintf(b, "  preflight %-12s %s %s\n", p.IdentityID, p.Status, p.Reason)
		}
	}
	if len(res.Executions) > 0 {
		b.WriteString("Executions:\n")
	}
	for _, ex := range res.Executions {
		if ex.Error != "" {
			fmt.Fprintf(b, "  %-12s error: %s\n", ex.IdentityID, ex.Error)
			continue
		}
		fmt.Fprintf(b, "  %-12s %d %s\n", ex.IdentityID, ex.StatusCode, ex.ObservedOutcome)
	}
	inc := res.Inconclusive()
	if len(inc) > 0 {
		fmt.Fprintf(b, "\n%s (not a pass):\n", plural(len(inc), "inconclusive assessment", "inconclusive assessments"))
		for _, a := range inc {
			fmt.Fprintf(b, "  %s\n", Explain(a))
		}
	}
	if len(res.Findings) == 0 {
		if notTested(res) == "" && len(inc) == 0 {
			b.WriteString("No findings.\n")
		}
		return
	}
	fmt.Fprintf(b, "\n%s:\n", plural(len(res.Findings), "finding", "findings"))
	for _, f := range SortedBySeverity(res.Findings) {
		fmt.Fprintf(b, "  [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.Category, f.Message)
		for _, ev := range f.Evidence {
			fmt.Fprintf(b, "      %s\n", ev)
		}
	}
}

// Markdown writes a summary table and a findings table, suitable for a GitHub
// job summary or a pull request comment.
func Markdown(w io.Writer, cases []Case) error {
	s := summarize(cases)
	var b strings.Builder
	b.WriteString("## VardrGate authorization results\n\n")
	fmt.Fprintf(&b, "**%s**\n\n", s.headline())

	b.WriteString("| Case | Source | Result |\n|---|---|---|\n")
	for _, c := range cases {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", md(c.Result.TestCaseID), md(c.Source), caseVerdict(c.Result))
	}

	if s.findings > 0 {
		b.WriteString("\n### Findings\n\n| Severity | Category | Case | Identity | Detail |\n|---|---|---|---|---|\n")
		for _, c := range cases {
			for _, f := range SortedBySeverity(c.Result.Findings) {
				detail := md(f.Message)
				if len(f.Evidence) > 0 {
					evidence := make([]string, len(f.Evidence))
					for i, ev := range f.Evidence {
						evidence[i] = md(ev)
					}
					detail += "<br>" + strings.Join(evidence, "<br>")
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
					strings.ToUpper(string(f.Severity)), md(string(f.Category)), md(c.Result.TestCaseID), md(f.IdentityID), detail)
			}
		}
	}
	if s.inconclusive > 0 {
		b.WriteString("\n### Inconclusive assessments\n\n| Case | Identity | Expected | Reason |\n|---|---|---|---|\n")
		for _, c := range cases {
			for _, a := range c.Result.Inconclusive() {
				why, ok := inconclusiveReasons[a.Reason]
				if !ok {
					why = a.Reason
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", md(c.Result.TestCaseID), md(a.IdentityID), md(string(a.ExpectedAccess)), md(why))
			}
		}
		b.WriteString("\n> [!WARNING]\n> Inconclusive assessments produced no finding and are not passes.\n")
	}
	if s.untested > 0 {
		b.WriteString("\n> [!WARNING]\n> Cases marked not tested sent no successful request. Zero findings for them is not a clean result.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func caseVerdict(res engine.Result) string {
	if reason := notTested(res); reason != "" {
		return "⚠️ Not tested: " + md(reason)
	}
	if len(res.Findings) == 0 {
		if n := len(res.Inconclusive()); n > 0 {
			return fmt.Sprintf("⚠️ No findings; %s", plural(n, "inconclusive assessment", "inconclusive assessments"))
		}
		return "✅ No findings"
	}
	worst := SortedBySeverity(res.Findings)[0].Severity
	return fmt.Sprintf("❌ %s (worst: %s)", plural(len(res.Findings), "finding", "findings"), worst)
}

// md escapes a value for a Markdown table cell. Evidence carries field names
// and paths taken from the target's own responses, so it is untrusted: a pipe
// would break the table and markup would render.
func md(s string) string {
	s = strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "&#124;", "`", "&#96;",
		"*", "&#42;", "_", "&#95;", "[", "&#91;", "]", "&#93;",
		"\r\n", " ", "\n", " ", "\r", " ",
	).Replace(s)
	if s == "" {
		return "—"
	}
	return s
}

// SortedBySeverity returns a copy of findings, most severe first. The sort is
// stable so findings of equal severity keep the engine's order.
func SortedBySeverity(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}

func plural(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}
