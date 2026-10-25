# ADR 0017 — Write verification

- Status: Accepted
- Date: 2026-10-24

## Context

A write's own response does not show whether the write happened. Two
benchmarks showed both failure directions:

- **Missed write.** On authbench, a write committed before an HTTP 500 was
  missed and inconclusive, even with response assertions.
- **False writes.** On VAmPI (pinned `f16052d`), the protected password and
  email endpoints return 204 while changing only the caller's own record.
  Status classification reported an unauthorized write in all three cases.
  The response has no body, so assertions cannot help.

## Decision

1. `AuthorizationTestCase.WriteVerification` (policy `verify`) names a
   separate reader identity and a request that reads the target's state. The
   verifier is never one of the identities under test, so it cannot perform
   the write. Its request must be same-origin and goes through the same
   client, so SSRF and private-target rules apply.
2. For each identity with an allow or deny expectation, the engine reads the
   state twice before the request and once after. The observed state is the
   status plus, for a 2xx, the value at an optional JSON Pointer. A 404 after
   a delete is therefore a change.
3. Outcomes are explicit:

   | Observation | Assessment / reason |
   |---|---|
   | Unchanged | `denied` / `state_unchanged` |
   | Changed (to `changed_to`, when declared) | `allowed` / `state_changed` |
   | Changed to another value | `inconclusive` / `state_changed_unexpectedly` |
   | First before-read not 2xx | `inconclusive` / `verifier_baseline_missing` |
   | Read failed or 5xx | `inconclusive` / `verifier_read_failed` |
   | Verifier got 401/403 | `inconclusive` / `verifier_denied` |
   | No value at the pointer | `inconclusive` / `verifier_value_unavailable` |
   | The two before-reads differ | `inconclusive` / `state_changing_concurrently` |
   | Before-state already holds `changed_to` | `inconclusive` / `target_value_already_present` |

   When the before-state cannot be established, the identity's request is
   **not sent**: its effect could not be judged, and a write should not run
   blind.
4. Verification outranks response assertions and declared deny conventions.
   Findings use the ADR 0002 categorization with `source=write_verification`
   evidence.
5. GET is the default. An unsafe verifier method, such as logging in as the
   victim, requires `allow_unsafe_method`, which asserts that the request
   changes no state. Verification requires `mutating: true`.
6. Observed values stay in memory. Results, evidence and reports carry only
   the reason code. `${VAR}` in the verifier credential and in string values
   of its JSON body is resolved from the environment and JSON-escaped.

7. The before-state must be a 2xx. A 404 baseline is rejected, so a mistyped
   verifier path cannot read 404 twice and pass as a refused write.
8. Gate does not reset fixtures between identities, so a later identity's
   before-state includes earlier identities' writes. Verifying more than one
   identity therefore requires `changed_to`. A second writer of the same
   value is then `target_value_already_present` (inconclusive) rather than a
   false "unchanged". Deny-expected identities run first, so an unauthorized
   write is judged against an untouched state. Results keep the declared
   identity order.

## Consequences

- With several identities, only the first writer of the target value is
  conclusive. When a peer's unauthorized write succeeds, the owner's later
  legitimate write is inconclusive. Use one identity per case, or a target
  that can be reset, for fully conclusive results.
- Creating a resource (404 before, 2xx after) cannot be verified.
- With only deny-expected identities, a verifier that reads the wrong field
  or uses a wrong password reads "unchanged" and passes. Include an
  allow-expected identity as a positive control: its own legitimate write
  must read as changed, or Gate reports `authorization_mismatch`.
- Each verified identity costs three extra requests.
- The verifier must be able to read the state. A refused verifier is
  inconclusive, never a pass.
- A verifier that is itself unsafe, or that reads the wrong thing, produces
  wrong answers. Like assertions, the oracle is the author's responsibility.
