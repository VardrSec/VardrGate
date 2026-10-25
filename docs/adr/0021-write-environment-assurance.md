# ADR 0021: Declare the write-verification environment

Status: Accepted

## Context

At e86b8cd, deterministic delayed-write fixtures demonstrate that a peer's
unchanged after-read plus a successful synchronous owner control can produce
`denied`, even when the peer's write commits later. HTTP 202 also becomes a
verified denial. An unrelated writer changing the selected value after the
baseline can produce an unauthorized-write finding. Stable baseline reads and
positive controls cannot establish remote timing or isolation.

## Decision

Add `write_verification.environment` (policy `verify.environment`):

- `unknown`: retain observations, but do not infer allowed or denied access
  from their difference. Return `write_environment_unverified`. Existing
  specific failure diagnostics take precedence. Findings from other independent
  detectors remain unaffected.
- `synchronous_isolated`: the author declares a reviewed contract that the
  attempted write completes before its response, the verifier observes that
  completion immediately, and no other actor writes the fixture during the
  case. Existing verification rules and positive-control requirements apply.
- Omitted: retain compatibility behavior. This is not strict assurance.
  Invalid values fail validation before setup or network requests.

In every mode, HTTP 202 with unchanged state is inconclusive
(`write_completion_unconfirmed`). A successful owner control cannot promote it
to denied. If a change is already observed in a reviewed synchronous/isolated
environment, retain its finding even after 202, 500, or an execution error.
An errored write with unchanged state keeps `write_execution_error`.

This adds no requests, polling, sleeps, mutation retries, dependencies, or
automatic fixture reset. The protocol remains two before-reads, one mutation,
and one after-read per assessed identity, with existing early aborts.

## Consequences and limits

Recommended CI policies explicitly use `unknown` unless a fixture contract and
exclusive access have been reviewed, and enable `fail_on_inconclusive`. Unknown
environments can contain real violations: inconclusive violations remain missed
failures in accuracy reports. This change prevents unsupported conclusions; it
does not improve recall for asynchronous APIs.

The environment is an author assertion, not a guarantee Gate independently
enforces. Process-local sequencing is not remote isolation. A false declaration
can still misattribute concurrent changes or miss delayed writes returning a
synchronous-looking status. Prefer resettable dedicated resources and fresh,
unique `changed_to` markers. A selected value is not a resource-version check;
version-aware concurrency detection and asynchronous completion protocols remain
future work requiring an actual API contract and measured use case.

Existing jobs and policies remain compatible when the field is absent, except
that the unsupported 202 denial now becomes inconclusive. JSON result shapes and
value-free assessment evidence remain unchanged. Policy compilation, generated
JSON, API and jobs share the same model/engine setting. Identity preflight does
not implicitly attest write timing or isolation.

## Validation

`TestWriteEnvironmentSchedules` freezes nine deterministic schedules: accepted
and delayed commits, timeout before commit, interference, protected writes,
compatibility, and a commit before an execution error. Its fixture records
whether the peer actually commits; no wall-clock sleeps or timing races are
used. Additional tests cover invalid settings before traffic, specific oracle
diagnostics, policy propagation and generated-case round trips. Existing tests
retain failed/successful controls, no-op writes, verifier failure and redaction.
