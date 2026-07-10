# VardrGate

Continuous API authorization assurance. Describe how an endpoint *should* treat
different callers, run the request as each of them, and get structured,
evidence-backed findings when the real behaviour disagrees.

VardrGate is the first execution primitive of a larger API security control
plane (see [`enterprise-platform.md`](enterprise-platform.md) for the North
Star). Today it proves authorization controls; it is designed to be driven
locally, in CI, from the HTTP API, or by [VardrRunner](../VardrRunner).

## What it does

Given a test case — a request, a set of identities with credentials, optional
resource-ownership context, and the expected authorization decision per identity
— VardrGate executes the request once per identity, classifies each observed
response, and returns findings for every mismatch.

### Finding categories

| Category | Severity | Meaning |
|---|---|---|
| `missing_authentication` | critical | An unauthenticated (anonymous) caller reached a resource it should be denied |
| `cross_tenant_access` | critical | An identity from a different tenant reached the resource |
| `potential_bola` | high | A non-owner identity reached an identified object |
| `privilege_escalation` | high | An identity below the required role reached the resource |
| `unexpected_access` | high | Denied identity received a 2xx (no ownership context to refine further) |
| `sensitive_data_exposure` | high | Identity received response fields it must not see (evidence names the fields, never the values) |
| `authorization_mismatch` | low | Allowed identity received a 401/403 |

The engine only elevates beyond `unexpected_access` when the test case supplies
explicit ownership/tenant/role context. It never guesses a high-severity
category from a weak signal. See [`docs/adr/0002-ownership-aware-classification.md`](docs/adr/0002-ownership-aware-classification.md).

## Quickstart

**Requirements:** Go 1.24 or newer.

```sh
git clone https://github.com/VardrSec/VardrGate
cd VardrGate
go build ./cmd/vardrgate
./vardrgate            # serve mode: listens on :8080
```

### Run a single job offline (CI / VardrRunner contract)

```sh
./vardrgate run --job examples/job_profile_check.json --out result.json
```

`run` reads a job envelope, executes the embedded test case, and writes the
sanitized result JSON. The binary defaults to `serve`; `run` is the offline path
VardrRunner and CI use. See [`docs/adr/0001-policy-input-and-run-cli.md`](docs/adr/0001-policy-input-and-run-cli.md).

Environment variables (serve mode):

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Listening port (1–65535) |
| `ALLOW_PRIVATE_TARGETS` | `false` | Permit loopback and RFC-1918 targets. Enable only for local lab testing. |
| `VARDRGATE_API_KEY` | _(unset)_ | Single bearer token for the runner endpoints (`/jobs`, `/runner`, `/audit`); maps to the `default` tenant. Unset disables auth for local dev. |
| `VARDRGATE_API_KEYS` | _(unset)_ | Per-tenant keys `"tenant-a:key1,tenant-b:key2"` for tenant isolation; takes precedence over `VARDRGATE_API_KEY`. |
| `VARDRGATE_DB` | _(unset)_ | Path to a SQLite database for a durable job queue (jobs survive restart). Unset uses an in-memory store. |

## Declarative policies

A policy expresses an authorization control once, independent of environment.
Bind it to a base URL, path parameters, and concrete identities (each identity's
`role` matching a key under `expect`) to compile a runnable test case. See
[`examples/profile_ownership.policy.yaml`](examples/profile_ownership.policy.yaml).

```yaml
api:
  endpoint: GET /users/{user_id}/profile
  owner: identity:owner
  resource:
    type: user_profile
    id_param: user_id
    tenant_field: tenant_id
expect:
  owner: allow
  other_user: deny
  anonymous: deny
```

## HTTP API

### `GET /health`

Returns `{"status":"ok"}` with HTTP 200.

### `POST /tests/execute`

Execute an authorization test case.

**Request body** (`application/json`, max 1 MB, exactly one JSON value):

```json
{
  "id": "string",
  "description": "optional",
  "identities": [
    {
      "id": "string",
      "name": "optional",
      "role": "optional",
      "tenant_id": "optional",
      "credential": {
        "type": "bearer | api_key_header | static_header",
        "header": "optional — header name for api_key_header and static_header",
        "value": "secret — write-only, never returned in any response"
      }
    }
  ],
  "request": {
    "method": "GET",
    "url": "https://api.example.com/resource/42",
    "headers": {},
    "query_params": {},
    "body": null
  },
  "resource": {
    "type": "user_profile",
    "object_id": "42",
    "owner_identity": "identity-id-of-legitimate-owner",
    "tenant_id": "optional-tenant-of-the-object",
    "required_role": "optional-least-privileged-role"
  },
  "role_hierarchy": ["viewer", "editor", "admin"],
  "expected_access": [
    { "identity_id": "string", "decision": "allow | deny | skip", "note": "optional" }
  ]
}
```

`resource` and `role_hierarchy` are optional; without them findings stay at
`unexpected_access` / `authorization_mismatch`.

**Response** (`application/json`): `test_case_id`, `executions[]` (status code,
observed outcome, selected headers, duration, error), and `findings[]` (category,
severity, confidence, identity, message, evidence, timestamp).

**Error responses** carry a stable `code` for client branching:

| Status | `code` | Condition |
|---|---|---|
| 400 | `invalid_json` | Malformed JSON |
| 400 | `trailing_content` | More than one JSON value in the body |
| 413 | `body_too_large` | Request body exceeds 1 MB |
| 422 | `validation_failed` | Test case fails validation |
| 405 | `method_not_allowed` | Wrong HTTP method |

## Runner job queue

For continuous, distributed execution, VardrGate exposes a job queue that
[VardrRunner](../VardrRunner) drives: it polls for pending jobs, claims them,
streams events, uploads results, and marks them done or failed. The endpoint
shapes match VardrRunner's existing client, so VardrGate is a drop-in backend.
See [`docs/adr/0003-runner-job-queue.md`](docs/adr/0003-runner-job-queue.md).

| Endpoint | Purpose |
|---|---|
| `POST /jobs` | Enqueue a job |
| `GET /jobs/pending` | Poll queued jobs |
| `GET /jobs/{id}` | Fetch a job and its result |
| `POST /jobs/{id}/claim` | Atomically claim (409 if already claimed) |
| `PATCH /jobs/{id}` · `POST /jobs/{id}/done` · `/failed` | Completion |
| `POST /jobs/{id}/events` | Stream a lifecycle event |
| `POST /jobs/{id}/upload` | Upload the sanitized result JSON |
| `POST /runner/heartbeat` | Report runner status and capabilities |
| `GET /audit` | Append-only audit trail of queue actions (`?limit=N`) |

All of these require a bearer token when keys are configured. With
`VARDRGATE_API_KEYS` each token maps to a tenant, and every operation is scoped to
that tenant — a caller can only see and act on its own jobs and audit entries;
cross-tenant access returns 404. Set `VARDRGATE_DB` to a file path for a durable
queue (SQLite) whose jobs survive a restart; unset uses an in-memory store.
PostgreSQL is the intended production driver and implements the same `Store`
interface.

## Security defaults

- Only `http` and `https` targets are accepted.
- Loopback, link-local, private (RFC-1918/4193), unspecified, and multicast
  addresses are blocked by default.
- DNS rebinding is prevented: hostnames are resolved once inside a custom
  `DialContext`, every returned address is validated, and the connection is made
  to the pre-validated IP directly.
- Credential `value` fields are accepted as input but never appear in any
  response, finding, or log; URL userinfo and sensitive query params are redacted
  from evidence.
- Redirects are not followed; response bodies are capped (5 MB default).

## Project layout

```
cmd/vardrgate/       — serve + run subcommands, dependency wiring
internal/
  api/               — HTTP handlers (GET /health, POST /tests/execute)
  client/            — HTTP execution, credential application, SSRF protection
  compare/           — response body / status-code comparison utilities
  engine/            — validation, execution, ownership-aware finding evaluation
  job/               — offline job envelope (vardrgate run)
  model/             — domain types and constants
  policy/            — declarative YAML policy parsing and compilation
  store/             — runner job queue + registry (in-memory Store)
  urlcheck/          — URL and IP validation
docs/
  mvp.md             — first supported workflow
  adr/               — architecture decision records
examples/            — test case, policy, and job examples
```

## Development

```sh
go test -race ./...
go vet ./...
gofmt -l .
```

CI runs formatting, vet, race tests, and build on every push. See
[`CHANGELOG.md`](CHANGELOG.md) for release notes.
