# ADR 0011 — Reviewed identity/session preflight

- Status: Accepted
- Date: 2026-10-12

## Context

A 401/403 on a resource can mean an invalid session instead of an authorization
defect. A different user's valid token can silently test the wrong permissions.
Existing setup can obtain credentials, but does not establish which principal
those credentials represent. A completed command with zero findings is insufficient.

## Decision

An authenticated identity may declare `preflight` with exactly `url`,
`expected_status` and `json_fields`. Gate issues one GET to a reviewed session
endpoint, requiring the declared 2xx status and all 1–8 public principal field
matches. Paths are exact, case-sensitive dotted paths; strings, number text and
boolean text compare exactly. Nulls/arrays/objects and missing/malformed bodies fail.
Paths/values are nonempty and at most 200 UTF-8 bytes; ids are at most 200 bytes.
Unknown preflight fields are rejected, so an option typo cannot weaken the check.

The endpoint must use the same HTTP origin as the request under test (normalized
default port). URL userinfo, fragments, variable references, invalid ports and
URLs over 2000 bytes are refused. It receives the identity credential alone,
without resource-test headers/body/query/CORS. The normal HTTP client retains
timeouts, body limits, private-target opt-in, DNS/IP checks and no redirect following.
These are credential/transport correctness rules, not engagement scope enforcement.

All existing setup steps run first, followed by every configured preflight once.
If any check fails, resource requests do not execute and findings stay empty.
The result retains only identity, passed/failed status, reason and HTTP status.
Response bodies, header/cookie values, matched fields and raw errors are excluded.
CLI commands write the result before returning exit 3; the synchronous API returns
the result with explicit failed diagnostics. Configured probes add bounded traffic;
setup may already have mutated state before a check fails.

Runner uses `run --require-identity-preflight`. An older binary rejects the unknown
flag before target traffic. On the new binary the flag requires at least one
declared check. Runner inspects exit 3 only with a consistent failed diagnostic
report, uploads that evidence, and keeps the job failed. Cases without preflight
preserve their existing behavior. Older Runner builds lack this guard and must be
upgraded before using the feature.

## Consequences

Session metadata can be checked separately for owner, peer, cross-tenant and
privileged callers. Anonymous identities have no authenticated preflight. A passed
check is a point-in-time match against human-reviewed principal metadata; it is
neither a resource allow baseline nor independent proof of authorization/security.
Tokens may expire afterwards. Rejection is not labeled expiry/revocation without
evidence. Automatic refresh, retries, conditional setup, background keepers and
browser login recording remain separate work. No dependency or persistence change
is required. Real loopback tests enforce ordering, failure traffic, credential
application, value exclusion, scalar precision and setup-token compatibility.
