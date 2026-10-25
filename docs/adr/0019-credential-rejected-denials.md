# ADR 0019: A 401 to a credentialed caller is not a verified denial

Status: Accepted

## Context

A dead or expired token is refused with 401, and Gate counted that 401 as the
deny-expected identity being correctly denied. A vulnerable endpoint therefore
read as protected whenever a peer's credential had lapsed. The VAmPI lab
recorded this as two silent passes: `dead-token-status` (status-only) and
`dead-token-generic-deny` (a deny assertion that matches any failure body).

Identity preflight (ADR 0011) catches a dead credential, but it is opt-in and
cannot be switched on by default: it needs a reviewed session endpoint and the
principal fields to match, which Gate cannot infer. The hardening plan's P0.1
proposed default-on preflight; that is not implementable without new
configuration on every identity.

An earlier lab pass rejected a status rule because VAmPI answers a non-admin
user delete with 401 for a live token, a correct refusal the rule would turn
inconclusive.

## Decision

- When an identity that sends credentials is expected to be denied and the
  request under test returns 401, its assessment is `inconclusive` with reason
  `credential_rejected`, never `denied`. A 401 says the credentials were not
  accepted; it does not show that authorization refused the caller.
- This applies whatever decided the denial: the status, a matched deny
  assertion, or unchanged state under write verification. For verified writes
  it runs before the positive-control guard (ADR 0018), so the reason names the
  token rather than the verifier.
- A case opts out with `response.unauthorized_is_denial: true` (JSON
  `unauthorized_is_denial`), the reviewed statement that this API refuses
  authenticated callers with 401. It defaults to false.
- Listing 401 in `deny_status` does **not** opt out. 401 was already a denial,
  so listing it was always redundant, and the bundled examples, the demo policy
  and `discover` drafts all write `[401, 403, …]`. Reusing it would leave the
  protection off for exactly the policies copied from the documentation,
  including existing Runner and Map policies. `deny_status` keeps its ADR 0007
  meaning and ADR 0016 precedence.
- Anonymous identities, other statuses, allow-expected identities and findings
  are unchanged. An allow-expected 401 keeps its `authorization_mismatch`
  finding. No request is added and no response value is retained.

## Consequences and limits

Measured on the pinned VAmPI lab against PR #8's build (`5eb6cc6`):

- Both recorded dead-token silent passes become `inconclusive:credential_rejected`;
  all nine configuration-mistake experiments are now acceptable (were seven).
- Without write verification, one correct control per mode, `delete-peer`, moves
  from true negative to inconclusive (TN 8→7 status/vulnerable). True positives,
  false positives and misses are unchanged in every mode. With write
  verification that case was already inconclusive (`no_positive_control`); only
  its reason changes.
- OWASP Juice Shop v20.2.0: no change across all 40 case-runs. crAPI was not
  re-run; its recorded deny controls are a 404 and an anonymous call, which this
  rule does not touch. authbench is unchanged (its only 401 is anonymous).

Trade-offs accepted:

- A false inconclusive is noise an operator resolves once with
  `unauthorized_is_denial`; a silent pass hides a vulnerability. Inconclusive
  never reads as a pass.
- A resource-specific deny assertion on a 401 body is real evidence, yet it is
  still demoted unless `unauthorized_is_denial` is set. Gate cannot tell a
  specific assertion from a generic one.
- Setting `unauthorized_is_denial` restores the dead-token blind spot for that
  case; preflight is then the control. The same holds for APIs that answer an invalid token with
  200: only preflight or resource-specific assertions catch those.
- The plan asked for "not tested" (exit 3). This produces a per-identity
  inconclusive instead, because exit 3 means nothing was reached and the other
  identities may have been. The default exit code stays 0 until the
  inconclusive gating decision (plan P1.1); `--fail-on-inconclusive` fails it
  now.

## Validation

Engine tests cover a credentialed 401, an anonymous 401, a credentialed 403,
`unauthorized_is_denial` with and without a matching deny assertion, the copied
`deny_status: [401, 403, 404]` convention (still demoted), a deny assertion
matching a 401 body, an allow-expected 401, the unchanged findings, and a
verified write whose peer gets 401 while the owner control passes. Policy and
scaffold tests cover compiling and round-tripping the field. A report test fails if any inconclusive reason lacks an
operator explanation.
