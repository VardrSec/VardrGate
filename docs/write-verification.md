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
  "identity": {"id": "auditor", "credential": {"type": "static_header"}},
  "request": {"method": "GET", "url": "https://api.example.com/users/v1/alice"},
  "json_pointer": "/email",
  "changed_to": "bobtook@gate.io"
}
```

## Outcomes

| Observation | `decision` / `reason` |
|---|---|
| State unchanged | `denied` / `state_unchanged` |
| State changed, to `changed_to` when declared | `allowed` / `state_changed` |
| Changed to some other value | `inconclusive` / `state_changed_unexpectedly` |
| Verifier read failed, or the target returned 5xx | `inconclusive` / `verifier_read_failed` |
| Verifier refused (401/403) | `inconclusive` / `verifier_denied` |
| No value at `json_pointer` | `inconclusive` / `verifier_value_unavailable` |
| State changed between the two before-reads | `inconclusive` / `state_changing_concurrently` |
| State already holds `changed_to` | `inconclusive` / `target_value_already_present` |

If the before-state cannot be read, the identity's request is not sent.
Verification decides the result ahead of response assertions, `deny_status`
and `deny_when`.

## Choosing the oracle

- Read the victim's record, not the caller's own.
- Prefer a GET that any reviewed reader can make. Avoid oracles that depend
  on a vulnerability, such as a debug endpoint that exposes passwords.
- Gate does not reset state between identities. With several identities in
  one case, an earlier identity's write becomes the next one's before-state.
  Declare `changed_to`, or run one identity per case against a resettable
  fixture.
- Only reason codes are reported. Observed values never leave memory.
