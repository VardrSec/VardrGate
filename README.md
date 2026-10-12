# VardrGate

Continuous API authorization assurance. Describe how an endpoint *should* treat
different callers, run the request as each of them, and get structured,
evidence-backed findings when the real behaviour disagrees.

VardrGate is the first execution primitive of a larger API security control
plane. It evaluates reviewed authorization expectations and is designed to be driven
locally, in CI, from the HTTP API, or by [VardrRunner](https://github.com/VardrSec/VardrRunner).

## What it does

Given a test case — a request, a set of identities with credentials, optional
resource-ownership context, and the expected authorization decision per identity
— VardrGate executes the request once per identity, classifies each observed
response, and returns candidate findings for definite mismatches. Errors and ambiguous
responses do not establish a clean assessment; verify candidates before reporting them.

### Finding categories

| Category | Severity | Meaning |
|---|---|---|
| `missing_authentication` | critical | An unauthenticated (anonymous) caller reached a resource it should be denied |
| `cross_tenant_access` | critical | An identity from a different tenant reached the resource |
| `potential_bola` | high | A non-owner identity reached an identified object |
| `privilege_escalation` | high | An identity below the required role reached the resource |
| `unexpected_access` | high | Denied identity received a 2xx (no ownership context to refine further) |
| `sensitive_data_exposure` | critical/high/medium | Identity received response fields it must not see. Severity follows the field's tier — a leaked API key is not a leaked `created_by`. Evidence gives the *path* to each field, never the value |
| `object_property_exposure` | high | OWASP API3:2023 (BOPLA) — identity received properties that govern authorization or value: `role`, `is_admin`, `permissions`, `balance` |
| `cors_misconfiguration` | high/low | Endpoint reflects an arbitrary `Origin` (high when credentials are also allowed); requires `cors.probe_origin` |
| `authorization_mismatch` | low | Allowed identity received a 401/403 |

The engine only elevates beyond `unexpected_access` when the test case supplies
explicit ownership/tenant/role context. It never guesses a high-severity
category from a weak signal. See [`docs/adr/0002-ownership-aware-classification.md`](docs/adr/0002-ownership-aware-classification.md).

## Quickstart

**Requirements:** Go 1.25 or newer, matching `go.mod`.

```sh
git clone https://github.com/VardrSec/VardrGate
cd VardrGate
go build ./cmd/vardrgate
./vardrgate demo
```

`demo` starts a deliberately broken profile API on loopback, runs the bundled
policy against it, and prints the findings. No setup, no credentials, nothing
leaves the machine. It is the fastest way to see what a finding looks like:

```
Executions:
  owner        200 allow
  other_user   200 allow
  anonymous    200 allow

4 findings:
  [CRITICAL] cross_tenant_access — identity "other_user" received access that should have been denied
  [CRITICAL] sensitive_data_exposure — identity "other_user" received sensitive fields it must not see
  [CRITICAL] missing_authentication — identity "anonymous" received access that should have been denied
  [CRITICAL] sensitive_data_exposure — identity "anonymous" received sensitive fields it must not see
```

The data-exposure findings are critical rather than high because the leaked
field is an API key. Severity follows the field's tier, so a leaked `created_by`
does not read the same as a leaked credential.

### Run a policy against a real environment

```sh
export VARDRGATE_OWNER_TOKEN=... VARDRGATE_OTHER_USER_TOKEN=...

./vardrgate policy run \
  --policy examples/profile_ownership.policy.yaml \
  --base https://api.example.com \
  --param user_id=42 \
  --identities examples/identities.json \
  --fail-on high
```

This is the same policy the demo runs, bound to a real environment. Credential
values in the identities file may reference environment variables as `${VAR}`,
so the file is committed next to the policy without containing a secret. An
unset variable is an error, not an empty token.

### Gate a pipeline on the result

`--fail-on` is what makes VardrGate usable as a CI check:

| Exit code | Meaning |
|---|---|
| `0` | Ran; nothing at or above the threshold |
| `1` | Usage or input error |
| `2` | Findings at or above `--fail-on` |
| `3` | A case reached nothing — every identity failed to connect |

Exit 3 is deliberate and separate: a run where nothing connected reports zero
findings, and treating that as a pass is worse than having no check at all. It
is evaluated per case, so a target that dies partway through a suite still fails
the build. Without `--fail-on` (the default, `none`), findings never affect the
exit code — but exit 3 still applies.

### Run a job envelope offline (VardrRunner contract)

```sh
./vardrgate run --job job.json --out result.json
```

`run` reads a job envelope, executes the embedded test case, and writes the
sanitized result JSON. `examples/job_profile_check.json` is a **template** — its
tokens and its `localhost:8081` URL are placeholders to replace, not a target
that exists. Use `./vardrgate demo` for something that runs as shipped. See
[`docs/adr/0001-policy-input-and-run-cli.md`](docs/adr/0001-policy-input-and-run-cli.md).

### Generate starter tests from an OpenAPI spec

```sh
./vardrgate gen --spec openapi.json --base https://api.example.com --out cases.json
```

Emits one starter test case per path+method (request pre-filled, plus an
authenticated and an anonymous template identity). Each credential carries a
`${VARDRGATE_<IDENTITY>_TOKEN}` placeholder showing where the token belongs; set
those variables and run the file directly:

```sh
VARDRGATE_AUTHENTICATED_TOKEN=... ./vardrgate run --cases cases.json --fail-on high
```

A Postman v2.1 collection works too:

```sh
./vardrgate gen --postman collection.json --base https://api.example.com
```

### Report coverage of a spec

```sh
./vardrgate coverage --spec openapi.json --cases cases.json
```

Maps case definitions to spec operations, using the output labels tested/untested
and a percentage. This shows authoring gaps; it does not execute cases or measure
verified controls, successful assessments or overall API security coverage.

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
`role` matching a key under `expect`) and run it with `vardrgate policy run`. See
[`examples/profile_ownership.policy.yaml`](examples/profile_ownership.policy.yaml)
and [`examples/identities.json`](examples/identities.json).

```yaml
api:
  endpoint: GET /users/{user_id}/profile
  owner: identity:owner
  resource:
    type: user_profile
    id_param: user_id      # path parameter naming the object
    tenant_field: tenant_id # response field carrying the object's tenant

expect:
  owner: allow
  other_user: deny
  anonymous: deny

response:
  deny_status: [401, 403, 404]  # this API hides existence behind 404
  sensitive_fields:
    forbidden_for: [other_user, anonymous]
```

`response.deny_status` states how this API refuses a caller. Without it, deny
means 401 or 403 and a 404 is ambiguous — correct as a default, but it means
every 404 from an API that hides existence goes unevaluated. `tenant_field` lets
the engine read the object's tenant out of the response body, so
`cross_tenant_access` does not require knowing the target's tenant in advance.
See [`docs/adr/0007-policy-driven-deny-classification.md`](docs/adr/0007-policy-driven-deny-classification.md).

### When the API refuses with a success status

Plenty of APIs answer `200 OK` with an error body instead of a 4xx. Left
undeclared, VardrGate reads that as a successful access and reports a critical
finding against an endpoint that behaved correctly. Say so:

```yaml
response:
  deny_when:
    body_contains: ["forbidden"]
    json_field: { path: error.code, equals: FORBIDDEN }
```

A body matching any populated field is a denial, and the condition outranks the
status line. Findings carry `deny_when_matched:` evidence so it is clear why a
200 was read as a refusal. See [`docs/adr/0008-body-aware-deny-and-mutation-safety.md`](docs/adr/0008-body-aware-deny-and-mutation-safety.md).

### Endpoints that change state

A test case replays one request as *every* identity, so a policy on
`DELETE /users/{id}` would delete the same object once per caller. VardrGate
refuses unsafe methods until you say you meant it:

```yaml
api:
  endpoint: DELETE /users/{user_id}
  mutating: true
```

or pass `--allow-mutating`. Setup steps are held to the same rule.

### Logging in, and creating the object under test

Some authorization tests need a request to run first — to exchange credentials
for a token, or to create the object another identity will try to reach. A
`setup` block does both:

```yaml
setup:
  - name: login
    request:
      method: POST
      path: /auth/login
      body: '{"user":"owner","pass":"${OWNER_PASSWORD}"}'
    capture:
      token: data.access_token

  - name: create
    as: owner            # a logical role from the expect map
    request: { method: POST, path: /objects }
    capture:
      object_id: id
```

Captured values are referenced as `{{token}}` and `{{object_id}}` in the request
URL, headers, query parameters, body, and in an identity's credential value —
which is how a login step supplies the token an identity presents. `${VAR}`
still means an environment variable; the two syntaxes are distinct so they
cannot be confused.

Create-as-one-identity-then-read-as-another is the sharpest object-level
authorization test there is, and it needs this. A failed setup step aborts the
run with exit 3: the precondition was not met, so nothing was tested. See
[`docs/adr/0010-setup-steps.md`](docs/adr/0010-setup-steps.md).

## Drafting policies for an API you have not covered yet

The honest limitation of a declarative tool is that it says nothing about
endpoints nobody wrote a policy for. `discover` removes the blank page:

```sh
./vardrgate discover --spec openapi.json --sample response.json --out policies/
```

It proposes one policy per operation that addresses an object, inferring the
object identifier, the resource type, and — from a captured response body — the
tenant field and any sensitive properties, printing its reasoning for each.

**Every expectation is written as `TODO`, and the policy parser rejects `TODO`.**
A draft cannot run until you replace them. That is deliberate and enforced
rather than advised: discovery can infer the *shape* of a control, but who
should be allowed to call an endpoint is a decision recorded nowhere a machine
can read, and a plausible-looking guess is exactly what VardrGate must never put
behind a finding. Inference informs authoring; it never becomes an assertion.
See [`docs/adr/0009-policy-discovery.md`](docs/adr/0009-policy-discovery.md).

## HTTP API

### Check sessions before authorization requests

An authenticated identity may declare an optional reviewed preflight:

```json
"preflight": {
  "url": "https://api.example.com/session",
  "expected_status": 200,
  "json_fields": {"user.id": "known-owner-id", "tenant": "known-tenant"}
}
```

Gate sends one same-origin GET with that identity's credential after setup and
before resource testing. Every declared public principal field must match. Any
failed check stops the case with no resource executions/findings; the safe
`preflight` diagnostic array is written and the CLI exits 3. Bodies, cookies and
matched values are not retained. Never put secrets in field matches or URLs.
Unconfigured cases retain their behavior. This does not refresh tokens or replace
a legitimate allow baseline on the resource. Runner uses
`run --require-identity-preflight` so older Gate builds fail before traffic.
See [ADR 0011](docs/adr/0011-identity-preflight.md).

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
observed outcome, selected headers, duration, error, and a value-free
`response_profile`), and `findings[]` (category, severity, confidence, identity,
message, evidence, timestamp). A JSON response profile contains a deterministic
schema hash and structural field paths; response values and body hashes are
never exposed. Non-JSON responses report only `kind: "text"`.

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
[VardrRunner](https://github.com/VardrSec/VardrRunner) drives: it polls for pending jobs, claims them,
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
PostgreSQL remains a planned driver behind the same `Store` interface; it is not
implemented in Gate. VardrMap's separate backend uses PostgreSQL.

### Using Map as the control plane

[VardrMap](https://github.com/VardrSec/VardrMap) stores reviewed cases and queues jobs;
Runner invokes the local Gate binary and uploads its result. This workflow uses Map's
queue rather than requiring the standalone Gate HTTP server. Runner retains a hash of
the unresolved case, which Map checks against its claim-time snapshot. Gate's own
result contract remains `test_case_id`, `executions` and `findings` (an empty array
when clean).

Map's separate assessment is conclusive, partial or inconclusive; an exit-0 command
or zero candidates alone does not prove a secure API. The shared API playbooks are
operator guidance, not executable Gate policies or evidence of coverage. The matching
Map/Runner additions are currently Unreleased; deploy the backend migration/endpoints
before publishing that Runner release.

The [combined acceptance harness](https://github.com/VardrSec/VardrMap/blob/main/scripts/integration/README.md)
tests this workflow against bounded loopback fixtures with disposable SQLite or
PostgreSQL for Map. It does not verify hosted GitHub OAuth or production deployment.

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
- Standalone `/tests/execute` is unauthenticated even when queue bearer keys are
  configured. Restrict access to that server appropriately; keys protect the queue,
  runner and audit routes, not the synchronous executor.

## Project layout

```
cmd/vardrgate/       — subcommand dispatch, exit codes
  main.go            — dispatch, usage, version
  execute.go         — run, policy run, demo; --fail-on gating
  discover.go        — discover
  importers.go       — gen, coverage
  serve.go           — HTTP API and its environment config
internal/
  api/               — HTTP handlers (GET /health, POST /tests/execute, job queue)
  client/            — HTTP execution, credential application, SSRF protection
  compare/           — body/status comparison, sensitivity tiers, deny predicates
  coverage/          — OpenAPI-vs-test-case coverage reporting
  demo/              — vulnerable loopback fixture for `vardrgate demo`
  discover/          — draft policies proposed from a spec (never executable)
  engine/            — validation, execution, ownership-aware finding evaluation
                       + setup.go: pre-request steps and variable capture
  job/               — offline job envelope (vardrgate run --job)
  model/             — domain types and constants
  openapi/           — OpenAPI 3 parsing + starter test-case generation
  postman/           — Postman v2.1 collection import
  policy/            — declarative YAML policy parsing, compilation, bindings
  scaffold/          — starter test-case builder and its on-disk format
  secretref/         — ${VAR} credential references
  store/             — runner job queue + registry (in-memory + SQLite Store)
  urlcheck/          — URL and IP validation
docs/
  mvp.md             — first supported workflow
  adr/               — architecture decision records
examples/            — policy, identities, test case, and job examples
```

## Development

```sh
go test -race ./...
go vet ./...
gofmt -l .
```

CI runs formatting, vet, race tests, and build on every push. See
[`CHANGELOG.md`](CHANGELOG.md) for release notes.
