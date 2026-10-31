# VardrGate

For CI that requires complete principal checks and fails incomplete assessments,
see [strict identity assurance](docs/strict-ci.md), including its pinned source
build. These controls postdate the packaged v0.1.0 release. Existing configurations
keep their compatibility defaults unless strict settings are supplied.

Scanners cannot find broken access control, because the rules an API is meant
to enforce are not written down anywhere a tool can read. VardrGate has you write
them down: a short policy per endpoint stating which callers should be allowed.
It replays the request as each caller and reports every place the API disagrees,
with request and response evidence. It runs locally or in CI and exits non-zero
when it finds something.

```yaml
api:
  endpoint: GET /users/{user_id}/profile
  owner: identity:owner
expect:
  owner: allow
  other_user: deny
  anonymous: deny
```

Findings are candidates for review, not verdicts. VardrGate reports a
high-severity category only when the policy supplies the context to justify it,
and a run that reached nothing fails instead of passing.

## See it work

Download a checksummed archive from [GitHub Releases](https://github.com/VardrSec/VardrGate/releases)
for Linux or macOS (amd64, arm64) or Windows (amd64), extract `vardrgate`
(Windows: `vardrgate.exe`) and put it on your `PATH`. No Go installation is
needed. See [v0.2.0 installation and upgrade notes](docs/releases/v0.2.0.md).
Version v0.2.0 includes `--literal-job`, `--strict-identity-preflight` and
`--fail-on-inconclusive`. The older v0.1.0 archives lack these controls.
The [strict-CI guide](docs/strict-ci.md) also provides an exact source build.

```sh
vardrgate demo
```

`demo` starts a deliberately broken profile API on loopback, runs the bundled
policy against it, and prints the findings. Nothing leaves the machine.

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
field is an API key. Severity follows the field's tier.

To build from source instead, use Go 1.25 or newer, matching `go.mod`:

```sh
git clone https://github.com/VardrSec/VardrGate
cd VardrGate
go build ./cmd/vardrgate
```

## Test one endpoint

Bind a policy to an environment and a set of identities:

```sh
export VARDRGATE_OWNER_TOKEN=... VARDRGATE_OTHER_USER_TOKEN=...

vardrgate policy run \
  --policy examples/profile_ownership.policy.yaml \
  --base https://api.example.com \
  --param user_id=42 \
  --identities examples/identities.json \
  --format text --fail-on high
```

Each identity's `role` matches a key under the policy's `expect`. Credential
values may reference environment variables as `${VAR}`, so the identities file is
committed next to the policy without containing a secret. An unset variable is an
error, not an empty token.

Supported credential types are `bearer`, `api_key_header` and `static_header`. A
session cookie is a `static_header` whose `header` is `Cookie`. An anonymous
caller is a `static_header` with no header.

## Test a whole API

A suite runs many policies against one environment as one command with one exit
code. Identities are shared: each policy binds only the roles it names, and fails
if a role it names has no identity.

```yaml
# examples/suite.yaml
base: ${VARDRGATE_BASE_URL}
identities: identities.json
policies:
  - policy: profile_ownership.policy.yaml
    params: {user_id: "${VARDRGATE_OWNER_USER_ID}"}
  - policy: user_orders.policy.yaml
    params: {user_id: "${VARDRGATE_OWNER_USER_ID}"}
```

```sh
vardrgate policy run --suite examples/suite.yaml --fail-on high --format text
```

Paths are relative to the suite file, `--base` overrides `base`, and every entry
is compiled and validated before any request is sent, so all authoring errors
are reported at once. If one entry fails at run time, such as a failed setup
step, it is reported as not run and the rest of the suite still runs. An entry
may also set `tenant`, `id` and its own `identities` file. See
[ADR 0013](docs/adr/0013-policy-suites.md).

## Run it in CI

`--fail-on` is what makes VardrGate a CI check:

| Exit code | Meaning |
|---|---|
| `0` | Ran; nothing at or above the threshold |
| `1` | Usage or input error |
| `2` | Findings at or above `--fail-on` |
| `3` | A case tested nothing: every identity failed to connect, or an identity preflight failed |
| `4` | With `--fail-on-inconclusive`: an identity with an allow or deny expectation could not be judged |

Exit 3 is separate on purpose: a run where nothing connected reports zero
findings, and treating that as a pass is worse than having no check. It is
evaluated per case, so a target that dies partway through a suite still fails the
build. Without `--fail-on` (default `none`), findings never affect the exit code,
but exit 3 still applies.

An inconclusive assessment, such as an assertion that no longer matches or an
undeclared 404, produces no finding. Every report format lists it and never shows
it as a pass. Add `--fail-on-inconclusive` to fail the build on it.

### GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
  - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
    with:
      go-version: "1.27.3"
  - name: Build vardrgate at the reviewed revision
    shell: bash
    run: |
      git clone --quiet https://github.com/VardrSec/VardrGate.git "$RUNNER_TEMP/vardrgate-src"
      git -C "$RUNNER_TEMP/vardrgate-src" checkout --quiet --detach c5682506ea1151eec98de6c957e59584e3e5a8fb
      (cd "$RUNNER_TEMP/vardrgate-src" && go build -trimpath -o "$RUNNER_TEMP/bin/vardrgate" ./cmd/vardrgate)
      echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"
  - uses: VardrSec/VardrGate@c5682506ea1151eec98de6c957e59584e3e5a8fb
    env:
      VARDRGATE_BASE_URL: ${{ vars.STAGING_API }}
      VARDRGATE_OWNER_USER_ID: "42"
      VARDRGATE_OWNER_TOKEN: ${{ secrets.OWNER_TOKEN }}
      VARDRGATE_OTHER_USER_TOKEN: ${{ secrets.OTHER_USER_TOKEN }}
    with:
      install: "false"
      args: policy run --suite vardrgate/suite.yaml --fail-on high --format markdown --sarif vardrgate.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: vardrgate.sarif
```

Policy suites, the text/Markdown/SARIF formats and this action are not in the
packaged v0.1.0 binary, so the example builds the same reviewed revision it
references the action by and sets `install: "false"`. With a release that
includes them, reference the action by that release tag and drop the build step:
the action then installs the release named by its tag (or its `version` input),
verifies the archive against that release's `SHA256SUMS`, runs `vardrgate` with
`args`, writes stdout to the job summary, and exposes the exit code as
`steps.<id>.outputs.exit-code`. Set
`verify-attestation: true` to also check build provenance with
`gh attestation verify`. There is no implicit "latest": pin a release. See
[ADR 0015](docs/adr/0015-github-action.md).

### Output formats

`policy run` and `run` share these flags:

| Flag | Writes |
|---|---|
| `--format json` (default) | Result JSON on stdout; nothing on stdout when `--out` is set |
| `--format text` | A readable report on stdout: executions, findings by severity, a summary line |
| `--format markdown` | Summary and findings tables on stdout, for a job summary or PR comment |
| `--out <file>` | Result JSON, always |
| `--sarif <file>` | SARIF 2.1.0 for GitHub code scanning and other dashboards |

All outputs are written before the exit code is decided, so they exist on exit 2
and 3. Every format states when a case tested nothing, and SARIF marks the
invocation unsuccessful rather than showing an empty, clean-looking scan. Run
from the repository root so SARIF locations resolve to the policy files. See
[ADR 0014](docs/adr/0014-report-formats.md).

## Finding categories

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

## Writing policies

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

A 401 to an identity that sent credentials is reported inconclusive
(`credential_rejected`), not as a correct denial: a dead or expired token gets
the same answer. If this API refuses authenticated callers with 401, set
`response.unauthorized_is_denial: true`. Listing 401 in `deny_status` does not
change this. See [ADR 0019](docs/adr/0019-credential-rejected-denials.md).

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

### Judging access by response content

The status line can be wrong in both directions: an API can leak a private record
in a 403 or 404, or refuse with a 200. Response assertions name JSON values that
prove access was granted or refused:

```yaml
response:
  assertions:
    - json_pointer: /secret
      equals: seeded-secret-for-this-book
      decision: allow
    - json_pointer: /status
      equals: fail
      decision: deny
```

When assertions are configured, they decide the result. If none match, the
identity is reported as inconclusive rather than falling back to status. Every
result also has an `assessments` array (`allowed`, `denied`, `inconclusive` or
`skipped`, with a reason). See [`docs/response-assertions.md`](docs/response-assertions.md).

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

A 204 does not prove a write happened, and a 500 does not prove it failed.
`verify` names a separate reader that checks the target's state before and after
each identity's request, so the result reflects what changed. See
[`docs/write-verification.md`](docs/write-verification.md).

A write endpoint usually needs a JSON body. `api.body` is sent by every identity,
with `Content-Type: application/json` unless `api.headers` sets one:

```yaml
api:
  endpoint: PUT /users/{username}/email
  mutating: true
  body: '{"email": "changed@example.com"}'
```

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

## Drafting policies for an API you have not covered yet

The honest limitation of a declarative tool is that it says nothing about
endpoints nobody wrote a policy for. `discover` removes the blank page:

```sh
vardrgate discover --spec openapi.json --sample response.json --out policies/
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

## Starting from a spec

```sh
vardrgate gen --spec openapi.json --base https://api.example.com --out cases.json
```

Emits one review-only test case per path+method (request pre-filled, plus
authenticated, peer, cross-tenant and anonymous identity templates). Every
permission is `TODO`: confirm identities, ownership and expected permissions
before execution. Each credential carries a
`${VARDRGATE_<IDENTITY>_TOKEN}` placeholder showing where the token belongs; set
those variables after reviewing the cases:

```sh
VARDRGATE_AUTHENTICATED_TOKEN=... vardrgate run --cases cases.json --fail-on high
```

A Postman v2.1 collection works too:

```sh
vardrgate gen --postman collection.json --base https://api.example.com
```

Add `--har capture.har --hypotheses hypotheses.json` with `--spec` for offline,
origin-scoped suggestions. Hypotheses never become executable permissions.
See [policy-assisted discovery](docs/policy-assisted-discovery.md).

### Report coverage of a spec

```sh
vardrgate coverage --spec openapi.json --cases cases.json
```

Maps case definitions to spec operations, using the output labels tested/untested
and a percentage. This shows authoring gaps; it does not execute cases or measure
verified controls, successful assessments or overall API security coverage.

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

### Serve-mode environment variables

Environment variables (serve mode):

| Variable | Default | Description |
|---|---|---|
| `VARDRGATE_HOST` | `127.0.0.1` | Listening address (an IP or `localhost`). Set `0.0.0.0` or `::` to listen on every interface, with API keys configured. |
| `PORT` | `8080` | Listening port (1–65535) |
| `ALLOW_PRIVATE_TARGETS` | `false` | Permit loopback and RFC-1918 targets. Enable only for local lab testing. |
| `VARDRGATE_API_KEY` | _(unset)_ | Single bearer token for `/tests/execute` and the runner endpoints (`/jobs`, `/runner`, `/audit`); maps to the `default` tenant. Unset disables auth for local dev. |
| `VARDRGATE_API_KEYS` | _(unset)_ | Per-tenant keys `"tenant-a:key1,tenant-b:key2"` for tenant isolation; takes precedence over `VARDRGATE_API_KEY`. |
| `VARDRGATE_DB` | _(unset)_ | Path to a SQLite database for a durable job queue (jobs survive restart). Unset uses an in-memory store. |

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
Runner 0.47.0 adds the matching assessment and preflight contract. Deploy the
matching Map backend and upgrade Runner plus Gate before authoring preflight cases.

The [combined acceptance harness](https://github.com/VardrSec/VardrMap/blob/main/scripts/integration/README.md)
tests this workflow against bounded loopback fixtures with disposable SQLite or
PostgreSQL for Map. It does not verify hosted GitHub OAuth or production deployment.

### Run a job envelope offline (VardrRunner contract)

```sh
vardrgate run --job job.json --out result.json
```

`run` reads a job envelope, executes the embedded test case, and writes the
sanitized result JSON. `examples/job_profile_check.json` is a **template** — its
tokens and its `localhost:8081` URL are placeholders to replace, not a target
that exists. Use `vardrgate demo` for something that runs as shipped. See
[`docs/adr/0001-policy-input-and-run-cli.md`](docs/adr/0001-policy-input-and-run-cli.md).

`${VAR}` references in a job are expanded from Gate's environment. Add
`--literal-job` when the caller has already resolved every credential: the
envelope is then used exactly as written. VardrRunner passes it on every job.
See [ADR 0028](docs/adr/0028-literal-job-input.md).

## Security defaults

- Only `http` and `https` targets are accepted.
- Loopback, private (RFC-1918/4193), shared (100.64.0.0/10) and benchmarking
  (198.18.0.0/15) addresses are blocked unless private targets are explicitly
  allowed. Unspecified and 0.0.0.0/8, link-local, cloud metadata and multicast
  addresses are always blocked. NAT64 and 6to4 addresses are judged by the IPv4
  address they carry.
- DNS rebinding is prevented: hostnames are resolved once inside a custom
  `DialContext`, every returned address is validated, and the connection is made
  to the pre-validated IP directly.
- Credential `value` fields are accepted as input but never appear in any
  response, finding, or log; URL userinfo and sensitive query params are redacted
  from evidence.
- Redirects are not followed; response bodies are capped (5 MB default).
- `vardrgate serve` (and a bare `vardrgate`) listens on loopback unless
  `VARDRGATE_HOST` says otherwise. When API keys are configured they protect
  `/tests/execute` as well as the queue, runner and audit routes; only `/health`
  stays open. Without keys every route is open, which is meant for local
  development only.

## Project layout

```
action.yml           — GitHub Action: verified install + run
cmd/vardrgate/       — subcommand dispatch, exit codes
  main.go            — dispatch, usage, version
  execute.go         — run, policy run (--policy, --suite), demo; output flags, --fail-on gating
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
  report/            — text, Markdown and SARIF renderers
  scaffold/          — starter test-case builder and its on-disk format
  secretref/         — ${VAR} credential references
  store/             — runner job queue + registry (in-memory + SQLite Store)
  suite/             — suite files: many policies bound to one environment
  urlcheck/          — URL and IP validation
docs/
  mvp.md             — first supported workflow
  adr/               — architecture decision records
examples/            — policies, a suite, identities, test case, and job examples
```

## Development

```sh
go test -race ./...
go vet ./...
gofmt -l .
```

CI runs formatting, vet, race tests, and build on every push. Releases use the
version in `VERSION`; a matching `vX.Y.Z` tag verifies source, builds all five
platform archives, attests their provenance and publishes them with checksums.
See [ADR 0012](docs/adr/0012-binary-releases.md) and
[`CHANGELOG.md`](CHANGELOG.md) for release notes.
