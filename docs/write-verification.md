# Write verification

A write endpoint's response does not show whether it wrote. An API can return
204 after changing only the caller's own record, or 500 after committing the
change. Write verification reads the target's state before and after each
identity's request, using a separate reader, and judges access from the
difference. See [ADR 0017](adr/0017-write-verification.md).

## In a policy

```yaml
api:
  endpoint: PUT /users/v1/{username}/email
  mutating: true
  body: '{"email": "bobtook@gate.io"}'
expect:
  owner: allow
  peer: deny
verify:
  environment: synchronous_isolated # reviewed completion, visibility and exclusive fixture access
  as: auditor                     # a role NOT in expect; bind exactly one identity to it
  request:
    method: GET
    path: /users/v1/{username}
  json_pointer: /email
  changed_to: bobtook@gate.io     # optional: the value this write would set
```

The `auditor` identity reads state and is never sent the write. Path
parameters are substituted the same way as in `api.endpoint`.

To check a password change, read through a login as the victim:

```yaml
verify:
  as: auditor
  request:
    method: POST
    path: /users/v1/login
    body: '{"username": "alice", "password": "${ALICE_PASSWORD}"}'
  allow_unsafe_method: true       # asserts this request changes no state
  json_pointer: /status
```

`${VAR}` references in the body are read from the environment. The victim's
password never appears in results.

## In the HTTP API

```json
"write_verification": {
  "environment": "synchronous_isolated",
  "identity": {"id": "auditor", "credential": {"type": "static_header"}},
  "request": {"method": "GET", "url": "https://api.example.com/users/v1/alice"},
  "json_pointer": "/email",
  "changed_to": "bobtook@gate.io"
}
```

## Outcomes

| Observation | `decision` / `reason` |
|---|---|
| Timing or isolation declared `unknown` | `inconclusive` / `write_environment_unverified` |
| HTTP 202 with no observed effect, even with a working owner control | `inconclusive` / `write_completion_unconfirmed` |
| State unchanged, with a demonstrated allow-expected write control | `denied` / `state_unchanged` |
| State unchanged with no allow-expected control | `inconclusive` / `no_positive_control` |
| State unchanged but the allow-expected control did not demonstrate a write | `inconclusive` / `positive_control_failed` |
| Write execution failed and no effect was observed | `inconclusive` / `write_execution_error` |
| Verifier redirected or returned an unsupported client error | `inconclusive` / `verifier_unexpected_status` |
| State changed, to `changed_to` when declared | `allowed` / `state_changed` |
| Changed to some other value | `inconclusive` / `state_changed_unexpectedly` |
| First read before the request was not 2xx | `inconclusive` / `verifier_baseline_missing` |
| Verifier read failed, or the target returned 5xx | `inconclusive` / `verifier_read_failed` |
| Verifier refused (401/403) | `inconclusive` / `verifier_denied` |
| No value at `json_pointer` | `inconclusive` / `verifier_value_unavailable` |
| State changed between the two before-reads | `inconclusive` / `state_changing_concurrently` |
| State already holds `changed_to` | `inconclusive` / `target_value_already_present` |
| State unchanged, but the deny-expected identity sent credentials and got 401 | `inconclusive` / `credential_rejected` |

If the before-state cannot be read, the identity's request is not sent.
Verification decides the result ahead of response assertions, `deny_status`
and `deny_when`.

## Choosing the oracle

Declare `environment: unknown` unless the API's write completes before its
response, the reader immediately observes the committed state, and the fixture
is exclusive to this test for the entire case. Only after reviewing those
conditions use `environment: synchronous_isolated`. Gate does not establish
these guarantees; two stable reads and a working control do not establish them.
With `unknown`, even an observed change cannot be attributed to the tested
identity. More specific verifier/error diagnostics still take precedence.
Use `--fail-on-inconclusive` in CI so uncertainty cannot produce a passing gate.

Omitting `environment` retains the old behavior for compatibility. It does not
establish timing or isolation. HTTP 202 with unchanged state is inconclusive
even in compatibility mode. These settings do not poll for asynchronous jobs;
a timeout or an observation deadline cannot prove that a write was denied.
Use a resettable dedicated resource and a fresh, unique attempted value when
possible. Gate does not provide resource-version checks or remote locking.
See [ADR 0021](adr/0021-write-environment-assurance.md).

- Read the victim's record, not the caller's own.
- Prefer a GET that any reviewed reader can make. Avoid oracles that depend
  on a vulnerability, such as a debug endpoint that exposes passwords.
- Gate does not reset state between identities. Verifying more than one
  identity requires `changed_to`. Deny-expected identities run first, so an
  unauthorized write is observed against the untouched state. A later
  identity that would write the same value is then inconclusive. For fully
  conclusive results, run one identity per case against a resettable
  fixture.
- **Add an allow-expected identity as a positive control.** The owner's own
  verified write must actually change state. If no control is supplied or it
  fails, unchanged deny-expected assessments are inconclusive. A control whose
  write is conclusively denied retains its `authorization_mismatch` finding.
  Observed unauthorized mutations retain their findings even without a control.
- The baseline read must succeed (2xx). Verifying a create, where the
  resource is absent beforehand, is not supported.
- Only reason codes are reported. Observed values never leave memory.

Successful HTTP statuses with the same selected value are equivalent; a 200
becoming 201 alone does not prove a write. After a successful baseline, 404
continues to represent absent state for deletion checks. Other 3xx/4xx verifier
responses do not establish state. See [ADR 0018](adr/0018-verifier-confidence.md).
