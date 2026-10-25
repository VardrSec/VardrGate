# ADR 0020: Explicit complete identity assurance and suite uncertainty gates

Status: Accepted

## Context

ADR 0019 demotes credentialed 401 denials but cannot identify a wrong-user token
or a soft authentication failure returned as 200. The existing Runner guard
requires only one declared preflight per case. A probe on the owner alone does
not assure the peer's identity. Incomplete assessments are also green unless
the caller opts into exit-code gating.

## Decision

- Add `require_identity_preflight` to test-case JSON and suites. Add
  `--strict-identity-preflight` to `run` and `policy run`. Every credentialed
  identity participating in an allow/deny judgment must declare the existing
  reviewed same-origin principal preflight. Missing configuration fails engine
  validation before setup or target traffic. Strict cases need at least one
  allow/deny expectation; skipped-only cases cannot claim strict assurance.
- Anonymous and skipped/record-only identities are exempt from authenticated
  preflight. Their established execution semantics remain unchanged.
- Existing preflight validation, ordering, value exclusion and runtime failure
  behavior are reused: setup first, all configured preflights second, resource
  requests last. A runtime failure retains diagnostics, withholds resource
  requests for the entire case and exits 3 on the CLI. Setup may already have
  run; missing configuration is caught earlier and sends nothing.
- Do not infer a session endpoint or expected user from credentials. No refresh,
  retry, principal guessing or cross-case assurance cache is introduced.
- Add suite `fail_on_inconclusive`. Explicit CLI booleans override suite values,
  including explicit false. Absence of a flag preserves suite configuration.
  Defaults remain false for compatibility. New CI guidance recommends both
  suite settings. The existing `--require-identity-preflight` retains its
  Runner compatibility semantics and is not silently strengthened.
- Preserve exit precedence and output contracts: not-tested exit 3 and finding
  thresholds exit 2 outrank opted-in inconclusive exit 4. Reports are emitted
  before runtime exit selection. Configuration errors retain normal validation
  errors; they are not mislabeled as completed tests.

## Consequences

Strict mode establishes declared principal matches at a point in time, not that
policy is correct or that a token cannot expire during the test. ADR 0019 still
handles resource-time credential rejection. Wrong reviewed principal fields can
still be misleading. Anonymous login oracles are not forced to declare bearer
preflight; reader/oracle correctness remains governed by write verification.

The strict field survives scaffold, job and API serialization. Direct policy
runs set it through the CLI binding, while suites persist it in their reviewed
environment configuration. No new dependencies or result-shape changes.

## Validation

Test missing peer coverage before any requests, anonymous/skip exemptions,
skipped-only strict cases, live valid/invalid/expired/wrong-user/soft-denial
responses, suite propagation, explicit true/false override precedence, retained
diagnostics, strict CLI behavior and scaffold round trips. Existing preflight
tests continue to cover redirects, bad bodies, principal/tenant mismatches,
secrets exclusion, setup credentials and transport rules.
