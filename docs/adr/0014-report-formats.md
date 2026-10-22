# ADR 0014 — Text, Markdown and SARIF reports

- Status: Accepted
- Date: 2026-10-22

## Context

ADR 0006 left findings as JSON only and explicitly deferred SARIF and JUnit.
JSON remains the right contract for VardrRunner and VardrMap. It is the wrong
output for the two places a CI gate is actually read:

- **The CI log.** `policy run` printed raw result JSON. The demo had a readable
  summary, but no command that ran against a real environment did, so the
  answer to "why did the build fail?" was a JSON document.
- **Code-scanning dashboards.** GitHub and other platforms ingest SARIF and show
  findings next to the code that defines them, with tracking across runs.
  Without SARIF, VardrGate findings live only in a job log.

A second problem sat underneath: exit code 3 means "nothing was tested", but a
report showing zero findings for an unreached target reads as a clean result to
anyone who sees the report and not the exit code. That matters more once a
report is uploaded to a dashboard that never sees the exit code.

## Decision

`policy run` and `run` accept:

| Flag | Effect |
|---|---|
| `--format json` (default) | stdout is the result JSON, exactly as before; empty when `--out` is set |
| `--format text` | stdout is a readable report: executions, findings by severity, a summary line |
| `--format markdown` | stdout is a summary table and findings table for a job summary or PR comment |
| `--out <file>` | always writes the result JSON |
| `--sarif <file>` | writes a SARIF 2.1.0 log |

- **JSON stays the default** so `run --job --out` (VardrRunner) and every
  existing pipeline see no change. The new formats change stdout only.
- **Outputs are written before the gate** decides the exit code, so the result
  file, SARIF and summary exist on exit 2 and exit 3, which is when a CI job
  needs them most.
- **"Not tested" is stated in every format**, using one definition
  (`engine.Result.PreflightFailed` and `Unreached`) shared with the exit-code
  gate. Text and Markdown name the case and the reason. SARIF sets
  `invocations[0].executionSuccessful` to false and adds an error notification.
  A clean run still emits a valid log with an empty `results` array.
- **SARIF details.** One rule per finding category, with a description and a
  `security-severity` taken from the category's worst severity, because code
  scanning ranks alerts by rule. Each result's level follows its own severity
  (critical and high are `error`, medium `warning`, lower `note`). Results are
  located at the policy file, cases file or job file that produced them, as a
  path relative to the working directory, or a `file://` URI when the file is
  outside it. `partialFingerprints` hash the case id, category and identity, and
  nothing else: never the timestamp, and never evidence, which can carry a
  loopback port that changes every run. A category unknown to the rule table is
  still reported under a generated rule. The output was validated against the
  OASIS SARIF 2.1.0 JSON schema.
- **Markdown escapes untrusted text.** Evidence carries field names and paths
  taken from the target's responses, so pipes, backticks, brackets and HTML are
  escaped and a hostile API cannot break the table or inject markup.
- **One text renderer.** `vardrgate demo` and `--format text` share
  `report.TextCase`, so the two cannot drift.

Rendering lives in a new `internal/report` package built on `encoding/json`. No
SARIF library is added.

## Consequences

- Findings can appear in GitHub code scanning, located at the policy that
  defines the violated control, and are tracked across runs.
- CI logs and job summaries are readable without a JSON viewer.
- Credential values cannot reach any report: reports render only
  `engine.Result`, and `model.Credential.Value` is never part of it.
- JUnit output is still not provided. SARIF covers the dashboard case and
  Markdown the summary case; JUnit can be added under this ADR if a CI system
  needs it.
- SARIF locations point at line 1 of the policy file. Pointing at the `expect`
  line would need YAML position tracking for little gain.
