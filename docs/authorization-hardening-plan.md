# Authorization hardening plan

Addresses the gaps found while validating response assertions (ADR 0016) and
write verification (ADR 0017) against VAmPI, OWASP Juice Shop and crAPI. The
full gap list and evidence live in the validation lab's `GAPS.md`. Items are
ordered by risk to correctness, then by value. Effort is rough: S ≤ a day,
M a few days, L a week or more.

## P0 — close the measured silent passes

These are cases where Gate reports clean while a real failure exists. They are
the most important because they undermine trust in a green result.

### P0.1 Dead or expired credential reads as a clean denial — S/M, ADR
A credential that is invalid yields a denial (401, or a 200 soft-denial on some
apps), so a vulnerable endpoint looks protected. Today the only guard is
identity preflight, which is opt-in.
- Make preflight run by default whenever an identity carries a credential, with
  an explicit opt-out, and keep `--require-identity-preflight` as the strict
  form. A missing/!=expected principal makes the case "not tested", not a pass.
- Needs an ADR: default-on preflight changes behavior and adds one request per
  credentialed identity. Decide the default principal check (same-origin GET,
  one declared field) and how it interacts with setup.
- Tests: a live-token case passes preflight; a garbage-token case is not tested.

### P0.2 Broken verifier oracle passes when every identity is deny-expected — S
If a write verifier reads the wrong field or uses a wrong secret, it reads
"unchanged" and every deny-expected identity passes. An allow-expected positive
control exposes it, but nothing requires one.
- When `write_verification` is set and no expected-access entry is `allow`,
  emit an inconclusive (new reason `no_positive_control`) or refuse at
  validation, so the operator must include an allow identity whose own write is
  observed to take effect.
- Tests: deny-only verified case → flagged; owner+peer case → unaffected.

## P1 — reporting integrity and feature coverage

### P1.1 Inconclusive is green by default in the exit code — S, ADR
The report never shows inconclusive as a pass, but the exit code ignores it
unless `--fail-on-inconclusive` is set. Decide whether suites/CI templates
should default to failing on inconclusive, or add `fail_on_inconclusive` to the
suite file so a team sets it once. Backward compatibility is the constraint;
record the decision.

### P1.2 Inconclusive can flood and be ignored — S
On a real API, many ambiguous responses produce many inconclusives. Group them
by reason in every report with counts, so the signal stays legible and does not
become a de-facto silent pass.

### P1.3 Exercise the YAML `verify:` and assertion API against a live app — S
`verify:` (policy YAML) and assertions over `/tests/execute` have unit and
authbench coverage but were never run against VAmPI/Juice Shop/crAPI end to
end. Add a lab scenario that runs `vardrgate policy run` with a `verify:` block
against VAmPI's password endpoint. Lab-only (CI does not run Docker).

### P1.4 Run CI and -race — S
`go test -race` and CI have never run on this work (local gcc is 32-bit). Push
so CI exercises `-race` on Linux before any release. This is the immediate
follow-through on the merge.

## P2 — feature depth (each needs an ADR)

### P2.1 Verify creates, not only updates/deletes — M, ADR
Write verification requires a 2xx baseline, so a create (absent → present)
cannot be verified. Add a mode that expects an absent baseline and treats
appearance as the change. Keep the default (2xx baseline) unchanged.

### P2.2 Verify more than one observable — M, ADR
Verification observes a single oracle, so a write with side effects beyond that
field reads as unchanged. Allow a small list of verifier reads, any change
counting. Bounds and redaction as today.

### P2.3 Non-exact and non-JSON assertions — M, ADR
Assertions match exact JSON values, so dynamic bodies and non-JSON responses
(HTML/XML/CSV) have no usable marker. Add `contains` / regex matchers and a
header-based assertion, with the same value-free evidence rule.

### P2.4 Field-level authorization — M
"B may see the resource but not field Z" is only partly covered by the
sensitive-fields check. Extend assertions to assert a field's absence for an
identity.

## P3 — out of current scope, recorded

- **Multi-step and chained authorization, sequence/TOCTOU** (L). The
  single-request model cannot express these; a workflow language was
  deliberately declined (ADR 0010). Revisit only with a concrete need.
- **Discovery of what to test** (L). Gate tests what it is given; it does not
  infer the authorization model. Coverage remains the operator's.

## P4 — validation method

- Build a larger, independently labeled corpus, and have someone without source
  access configure the assertions/verifiers, to answer the question these runs
  did not: can a developer configure this correctly? (M)
- Keep the pinned-target lab (VAmPI, Juice Shop, crAPI) as regression evidence;
  add a target with status-misleading authorization if one surfaces. (S each)

## Suggested sequence

1. P1.4 (push, CI, -race) — gates everything else.
2. P0.2, then P0.1 — the silent passes.
3. P1.1, P1.2, P1.3 — reporting and coverage.
4. P2 items by demand, each behind an ADR.
