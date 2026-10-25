# ADR 0018: Require usable observations and a demonstrated write control

Status: Accepted

## Context

Review of local main a5c5fab reproduced three errors outside the original
benchmark: a redirected verifier generated a false unauthorized-write finding;
an errored write with unchanged state was labeled denied; and a wrong oracle
with only deny-expected identities hid a real unauthorized write. A declared
control alone also cannot establish that an oracle observes the intended effect.

## Decision

- Verifier observations accept successful responses and an absent-resource 404.
  Other non-success outcomes are inconclusive. A successful status changing
  between 200 and 201, without the selected value changing, is not a mutation.
- If the write reports an execution error and no state change is observed,
  assess it inconclusive (`write_execution_error`). An independently observed
  effect can still prove access after a transport error or HTTP error status.
- After all identities execute, a deny-expected unchanged-state assessment
  requires an allow-expected identity whose verified write actually changed the
  selected state. Without one, report `no_positive_control`; if declared but
  unsuccessful, report `positive_control_failed`. This applies only to denials:
  directly observed unauthorized mutations retain their findings.
- Keep inputs and JSON shapes compatible. No extra requests, external
  dependencies, fixture resets, or raw observed values are introduced.

## Consequences and limits

The original 22 cases retain their labels. One deny-only protected-write case
becomes inconclusive, increasing that benchmark's inconclusive count from five
to six. It is not credited as verified protection. The nine known failures
remain detected, with zero false positives. Callers can supply a working owner
control in the same case; shared target values still follow ADR 0017's ordering
and already-present handling. A broken owner control keeps its mismatch finding
and also prevents peers from being labeled conclusively protected.

This does not make an author-supplied oracle independently trustworthy or provide
transactional isolation. Concurrent changes after the baseline, asynchronous
writes, incomplete observables, and dead credentials still need the documented
operator controls and identity preflight. A 404 after a successful baseline is
the existing deletion observation; arbitrary errors are not deletion evidence.

## Validation

The same four review regression probes fail on a5c5fab and pass with this
decision. Further tests cover unusable verifier statuses, success-code-only
changes, a passing/failing owner control, and a write that commits before a
transport error. The full suite includes Linux race tests. The comparison
driver freezes identical request profiles and labels across 17cf541, 3de1d0c,
a5c5fab, and the fixed build; its source and binary hashes accompany results.
