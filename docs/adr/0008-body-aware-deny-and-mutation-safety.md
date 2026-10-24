# ADR 0008 — Body-aware deny classification and mutation safety

- Status: Accepted
- Date: 2026-08-04
- Completes: ADR 0007

## Context

### A false critical, not a missing feature

ADR 0007 established that a policy declares what a denial looks like, but it
only handled the status line. Classification remained: 2xx means `allow`.

A great many APIs refuse a caller by answering `200 OK` with an error body —
`{"error": "forbidden"}` — because the framework serializes a result object
rather than mapping failures onto HTTP status codes. Against such an API,
VardrGate produced a **false finding at critical severity**: an anonymous
identity that the server correctly refused was classified as an allow, an
expected-deny/observed-allow mismatch was raised, and `SendsNoAuth()` escalated
it to `missing_authentication`.

That is the exact outcome the conservative classification of ADR 0002 exists to
prevent, reached through the status-code path rather than the escalation path.
A tool whose entire proposition is trustworthy, evidence-backed findings cannot
manufacture criticals against correctly-behaving software.

### Replaying a mutation once per identity

A test case executes one request as every identity. For `GET` that is
harmless. For `DELETE /users/{id}` it deletes the same object three times; for
`POST /orders` it creates three orders. Nothing in the engine noticed, warned,
or asked. Every other default in VardrGate fails safe — private targets
blocked, redirects unfollowed, credentials write-only — and this one silently
did damage.

## Decision

### `response.deny_when`

A policy may declare a refusal expressed in the body:

```yaml
response:
  deny_status: [401, 403, 404]
  deny_when:
    body_contains: ["forbidden"]
    json_field: { path: error.code, equals: FORBIDDEN }
```

A body satisfying any populated field is a denial. The condition **outranks the
status line**, since the whole reason it exists is APIs that answer 200 while
refusing. It is authored, never inferred: the engine still never guesses what a
denial looks like, it only answers a question the policy asked.

As with `deny_status`, the engine reclassifies the execution record alongside
the finding, so a single result document cannot contradict itself, and attaches
`deny_when_matched:` evidence so a reader can see why a 200 was read as a
refusal.

Matching lives in `compare.MatchesDeny`, supported by `compare.ValueAtPath`, a
dotted-path resolver that navigates exactly rather than searching at any depth
— a caller that knows the response shape gets a deterministic answer.

### `mutating`

The engine refuses `POST`, `PUT`, `PATCH`, and `DELETE` unless the policy sets
`api.mutating: true` or the caller passes `--allow-mutating`. The error names
the method and how many times it would have been replayed. Setup steps are held
to the same rule.

Refusing rather than warning is deliberate: a warning on stderr in CI is a
warning nobody reads, and the failure mode is destroyed data.

## Consequences

- An API that refuses via a success status can be tested at all, and stops
  generating false criticals. This is a correctness fix, not a feature.
- **Breaking:** a test case using an unsafe method now fails validation until
  `mutating` is set. Any existing case doing so was performing its mutation once
  per identity, which was almost certainly not intended.
- `deny_when` is opt-in and absent by default; a policy that declares neither it
  nor `deny_status` behaves exactly as before.
- `vardrgate discover` writes `mutating: false` into drafts for unsafe methods,
  so a proposed policy for a `DELETE` refuses to run until reviewed.
- Not addressed: an API that signals denial only through a header, or one whose
  refusal is indistinguishable from success without domain knowledge. Both would
  need a richer predicate language, and neither has shown up as a real case yet.
