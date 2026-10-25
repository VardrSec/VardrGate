# ADR 0016 — Response assertions and explicit assessments

- Status: Accepted
- Date: 2026-10-24

## Context

The engine judged access from the status line, with reviewed `deny_status` and
`deny_when` conventions (ADRs 0007, 0008). Two failure modes remained on a
synthetic benchmark of 22 cases:

- **Missed leaks.** Protected data returned with 403 or 404 was read as a
  denial or as ambiguous.
- **False positives.** A refusal returned with 200 and no declared `deny_when`
  produced an access finding, as did an empty filtered list.

A third problem was structural. Ambiguous outcomes emitted no finding, and
every report rendered "no findings" as a pass. A stale rule or a dead token
therefore looked clean.

## Decision

1. `ExpectedAccess.ResponseAssertions` (policy `response.assertions`) declares
   JSON values, located by JSON Pointer, that prove an allow or a deny. An
   assertion is input from the operator and is never inferred. That keeps the
   ADR 0009 invariant that inference may inform authoring but never produce an
   assertion.
2. Every result carries `assessments`, with one entry per identity:
   `allowed`, `denied`, `inconclusive` or `skipped`, plus a source and a fixed
   reason code. Raw executions are unchanged.
3. When an identity has assertions, they are authoritative: there is no status
   fallback, and they outrank `deny_status`/`deny_when`. An unmatched or
   conflicting set is inconclusive. Falling back to status would let an
   unexpected format pass silently.
4. Without assertions, findings come from the existing evaluator unchanged.
   The assessment is recorded alongside.
5. Assertion-derived findings reuse the existing categorization (ADR 0002),
   so ownership, tenant and role context still refine the category.
6. `Result.Inconclusive()` is the single definition shared by every report and
   the exit-code gate. Text, Markdown and SARIF list inconclusive assessments
   with an operator-facing explanation and never render them as a pass.
   `--fail-on-inconclusive` exits 4. It is opt-in so the documented 0–3
   contract and existing Runner and Map pipelines are unaffected.
7. Evidence and assessments carry assertion indices only. Values, pointers and
   bodies are never emitted.

## Consequences

- Status-only policies now show ambiguous outcomes (for example, an
  undeclared 404 on an expected denial) as inconclusive in reports. Findings
  and exit codes do not change.
- Adding `assessments` to the result JSON is additive. `findings` stays `[]`
  when empty, and `assessments` also serializes as `[]`.
- Assertion correctness is the author's responsibility. High confidence means
  confidence in the configured match, not in the rule.
- A write's effect cannot be proven from the write's own response. Verifying
  state changes is separate work.
