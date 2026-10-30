# VardrGate MVP

Historical MVP baseline, with implemented extensions listed below. The original
workflow and checklist describe that baseline, not the full current feature set.
See the [current README](../README.md) for installation and CLI usage.

## Goal

Give a security engineer or developer a single API call that answers the question:

> "Does this endpoint respect its authorization boundary?"

No agents, no UI, no persistence. One HTTP call in, one structured answer out.

## The MVP workflow

```
1. Engineer writes a test case JSON file
2. POST /tests/execute
3. Read findings in the response
```

That is the entire workflow. VardrGate does not store results, manage projects, or orchestrate test suites. Those concerns belong upstream of this service.

## Supported test scenario at MVP

**Horizontal access control check (unauthorized object access)**

An engineer has two or more identities with different permissions on the same resource. They want to confirm that lower-privileged or unrelated identities cannot access it.

### Concrete example

- `owner` — user who created the resource; expected to receive 200
- `other_user` — authenticated user who does not own the resource; expected to receive 403
- `anonymous` — unauthenticated caller; expected to receive 401 or 403

If `other_user` or `anonymous` receives a 2xx, VardrGate emits an `unexpected_access` finding.

## Beyond the MVP (now shipped — Phase 1)

The following were originally out of scope and are now implemented. See
[`CHANGELOG.md`](../CHANGELOG.md) and the ADRs.

| Capability | Notes |
|---|---|
| `potential_bola`, `cross_tenant_access`, `privilege_escalation` | Emitted when the test case supplies resource-ownership / tenant / role context |
| Response-body comparison in findings | Offending response compared against a legitimate baseline; exact body and value-free JSON schema matches distinguished, with field overlap and one-sided paths |
| Vertical privilege escalation | Via `resource.required_role` + `role_hierarchy` |
| Declarative policies | `internal/policy` compiles a YAML control into a test case, run by `vardrgate policy run` (ADR 0006) |
| Offline execution | `vardrgate run --job job.json --out result.json`, or `--cases` for a suite |
| CI gating | `--fail-on <severity>`: exit 2 on findings, exit 3 when a case reached nothing (ADR 0006) |
| API inventory / spec import | `vardrgate gen --spec` / `--postman`, plus `vardrgate coverage` |
| Persisted results | Runner job queue with a durable SQLite store (ADR 0003, 0004) |
| Result formats | JSON, text, Markdown and SARIF; see [ADR 0014](adr/0014-report-formats.md) |

## Still not covered

| Concern | Reason |
|---|---|
| Concurrent execution | Sequential per-identity execution is correct and sufficient at this scale |
| JUnit output | Not implemented; use supported result formats and CI exit codes |
| PostgreSQL store | The `Store` interface is ready for it; SQLite covers current needs |

## Inputs at MVP

| Field | Required | Notes |
|---|---|---|
| `id` | Yes | Caller-supplied test identifier |
| `identities[].id` | Yes | Unique within the test case |
| `identities[].credential` | Yes | `bearer`, `api_key_header`, or `static_header`; `value` is write-only |
| `identities[].name` | No | Human label for findings and logs |
| `identities[].role` | No | Ranked against `resource.required_role` via `role_hierarchy` for `privilege_escalation` |
| `identities[].tenant_id` | No | Compared against the resource's tenant for `cross_tenant_access` |
| `request.method` | Yes | Any valid HTTP method |
| `request.url` | Yes | `https://` target; `http://` allowed; private IPs blocked by default |
| `request.headers` | No | Applied to every identity's request |
| `request.query_params` | No | Merged with URL query string |
| `request.body` | No | JSON body forwarded as-is |
| `expected_access[].identity_id` | Yes | Must match an identity in the same test case |
| `expected_access[].decision` | Yes | `allow`, `deny`, or `skip` |

## Outputs at MVP

- `executions` — one entry per identity: status code, observed outcome, response headers, duration, error
- `findings` — zero or more: category, severity, confidence, identity, message, evidence, timestamp

## Observed outcome values

| Value | HTTP status |
|---|---|
| `allow` | 2xx |
| `deny` | 401, 403 |
| `not_found` | 404 |
| `redirect` | 3xx |
| `server_error` | 5xx |
| `client_error` | 4xx (other than 401, 403, 404) |
| `error` | Network failure, timeout, URL validation error, body too large |

## Finding conditions at MVP

| Category | Trigger |
|---|---|
| `unexpected_access` | expected `deny`, observed `allow` |
| `authorization_mismatch` | expected `allow`, observed `deny` |

No finding is emitted for: execution errors, `skip` decisions, or ambiguous outcomes (404, 5xx, 3xx, client_error) when the expected decision is `deny`.

## Security constraints on targets

- Only `http` and `https` schemes accepted
- Loopback and RFC-1918 private ranges blocked by default
- Link-local, multicast, and unspecified addresses always blocked
- DNS rebinding prevented via custom `DialContext` (resolve → validate → dial in one step)
- Set `ALLOW_PRIVATE_TARGETS=true` only for local lab use

## Definition of done for MVP

- [ ] `POST /tests/execute` returns correct findings for allow/deny mismatches
- [ ] Credential values never appear in responses, findings, or logs
- [ ] Private and loopback targets blocked by default
- [ ] Tests green, vet clean, gofmt clean
- [ ] `examples/ownership_check.json` demonstrates the primary workflow
