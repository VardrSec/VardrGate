# Changelog

All notable changes to VardrGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`vardrgate policy run`**: compile a declarative policy against one
  environment and execute it — `--policy p.yaml --base https://api.example.com
  --param user_id=42 --identities identities.json`. Until now `internal/policy`
  compiled test cases that no command could run, so the policy format was
  unreachable from the CLI. Identities come from a JSON array whose `role`
  matches a key in the policy's `expect` map; see `examples/identities.json`.
  See ADR 0006.
- **`--fail-on <severity>`** on `run`, `policy run`, and `demo`, with distinct
  exit codes: `0` clean, `1` usage or input error, `2` findings at or above the
  threshold, `3` a case reached nothing. Defaults to `none`, so gating is opt-in.
  Exit 3 is not gated on the threshold and outranks findings — a finding count of
  zero means nothing when no request succeeded. It is evaluated per case, so a
  target that dies partway through a suite cannot leave the run green.
- **`vardrgate run --cases <file>`**: execute a JSON array of test cases and emit
  an array of results, closing the loop with `vardrgate gen`. The whole suite is
  validated before any of it runs, so every authoring error is reported at once.
- **`vardrgate demo`**: run the bundled policy against a deliberately broken
  loopback fixture. No setup, no credentials, no network egress — the quickstart
  now proves the tool works on a first run.
- **`${VAR}` credential references** (`internal/secretref`): credential values in
  policy bindings, generated suites, and job envelopes resolve against the
  process environment, so a file committed next to the code it tests can name a
  secret without containing one. An unset or empty variable is an error, not an
  empty string — a blank token turns an authenticated identity into an anonymous
  one and would invert the meaning of the test while still reporting a clean run.
- **`vardrgate help` and `vardrgate version`**, and `engine.Validate` for
  checking a test case without executing it.

### Changed

- **Policy `response.deny_status` is now enforced.** It was parsed and dropped;
  it now compiles to the test case, and any listed status code is classified as
  an explicit deny. An API that returns 404 to avoid confirming an object exists
  can finally be tested. A 2xx in the list is rejected — a success code cannot
  mean denied. See ADR 0007.
- **Policy `api.resource.tenant_field` is now enforced.** When no tenant is
  bound, the engine reads that field from the offending identity's own response
  body, so `cross_tenant_access` no longer requires knowing the target object's
  tenant in advance. A bound `resource.tenant_id` still wins. See ADR 0007.
- Findings from a policy with a declared deny convention carry
  `deny_status_declared=` evidence, and the execution record is reclassified
  alongside the finding so a single result document cannot contradict itself.
- `cors_misconfiguration` findings now populate `identity_id` and record
  `observed_on_identity=` in evidence. The policy is endpoint-level, but the
  field was left empty while every other category filled it.
- `compare.Results` takes the sensitive-field set as a parameter. It previously
  always used the package default, so a test case that overrode
  `sensitive_fields` had its override honoured by the sensitive-data check and
  ignored by the comparison evidence.

### Fixed

- **`vardrgate --help` started a web server.** Subcommand dispatch fell through
  to `serve` for any unrecognised argument. Unknown commands now exit 1 with
  usage; a bare `vardrgate` still serves, as documented.
- Dead link to `enterprise-platform.md` in the README and CLAUDE.md — the file
  has never existed in this repository.

### Breaking

- `vardrgate run` against an unreachable target now exits **3** where it
  previously exited **0**. A pipeline relying on the old behaviour was reporting
  success without testing anything.
- `vardrgate gen` output now contains a `"value"` key holding a
  `${VARDRGATE_<IDENTITY>_TOKEN}` placeholder. Previously the key was absent
  entirely, leaving no indication of where a credential belonged. Files generated
  before this change still parse; they validate as missing a credential, which is
  what they always were.
- `compare.Results` gained a third parameter (internal API).

- **CORS misconfiguration detection**: set `cors.probe_origin` on a test case and
  the engine sends that `Origin` and inspects the response. A reflected arbitrary
  origin combined with `Access-Control-Allow-Credentials: true` is a high finding
  (`cors_misconfiguration`); a reflected or wildcard origin without credentials is
  reported at low severity. Off unless `cors` is set. The client now captures the
  `Access-Control-Allow-Origin`/`-Credentials` response headers.
- **Postman collection import** (`internal/postman`): `vardrgate gen --postman
  collection.json` generates starter test cases from a Postman v2.1 collection
  (folders flattened; both string and object URL forms; `--base` retargets the
  origin). The shared scaffold builder now lives in `internal/scaffold` and is
  used by both the OpenAPI and Postman importers.
- **Coverage reporting** (`internal/coverage`, `vardrgate coverage`): match a set
  of test cases against an OpenAPI spec and report which operations are tested vs
  untested, with a percentage. Path templates match on the request path suffix so
  server base paths are ignored and `{param}` segments are wildcards.
  `vardrgate coverage --spec spec.json --cases cases.json [--out file]`.
- **OpenAPI import + starter test generation** (`internal/openapi`, `vardrgate gen`):
  parse an OpenAPI 3 spec and generate one starter authorization test case per
  path+method — request pre-filled, plus an authenticated (allow) and anonymous
  (deny) template identity so a generated case exercises the missing-auth check
  once a real token is added. `vardrgate gen --spec spec.json [--base URL] [--out file]`.
- **Missing-authentication detection**: when an anonymous identity (a
  `static_header` credential with no header — i.e. no credentials sent) reaches a
  resource it should be denied, the finding is now the more precise
  `missing_authentication` (critical) rather than generic `unexpected_access`. It
  is the highest-precedence refinement of a deny→allow result.
- **Sensitive-data-exposure detection**: an identity marked `forbid_sensitive_data`
  (or a policy `response.sensitive_fields.forbidden_for` role) that receives a
  response containing sensitive fields now yields a `sensitive_data_exposure`
  finding. Detection is recursive and case-insensitive; evidence lists only the
  leaked field *names*, never their values. Uses a default sensitive-field set,
  overridable per test case via `sensitive_fields`. Wires the previously-inert
  policy `sensitive_fields` block into the engine.
- **Tenant isolation**: per-tenant API keys
  (`VARDRGATE_API_KEYS="tenant-a:key1,tenant-b:key2"`) scope every queue
  operation to the caller's tenant. Jobs and audit entries are tagged with the
  owning tenant; cross-tenant access to a job returns 404 (existence is never
  revealed); pending and audit lists are tenant-filtered. A single
  `VARDRGATE_API_KEY` still works and maps to the `default` tenant. See ADR 0005.
- **Audit log**: an append-only trail of queue actions (`job_created`,
  `job_claimed`, `job_result_uploaded`, `job_completed`, `runner_heartbeat`)
  recorded by both stores and exposed at `GET /audit` (`?limit=N`, bearer-protected).
  Persists with the durable store.
- **Durable job store** (`store.SQLite`, `modernc.org/sqlite`): set `VARDRGATE_DB`
  to a file path and jobs survive a restart. Same `Store` interface as the
  in-memory store, selected at startup; unset keeps the in-memory store. The
  conformance suite runs against both, and a test verifies survival across
  reopen. PostgreSQL remains the intended production driver behind the same
  interface. See ADR 0004.
- **Runner job queue** (`internal/store` + HTTP endpoints): VardrGate can now be
  driven by VardrRunner. A `Store` interface with an in-memory implementation
  backs `POST /jobs`, `GET /jobs/pending`, `GET /jobs/{id}`,
  `POST /jobs/{id}/claim` (atomic; 409 on double-claim),
  `PATCH /jobs/{id}` + `POST /jobs/{id}/done|failed` (completion),
  `POST /jobs/{id}/events`, `POST /jobs/{id}/upload`, and
  `POST /runner/heartbeat`. Shapes match VardrRunner's existing client exactly.
  See ADR 0003.
- **Bearer auth** on the runner endpoints via `VARDRGATE_API_KEY`. `/health` and
  `/tests/execute` remain open; an unset key disables auth for local dev (warned
  at startup).

### Added (Phase 1)

- **Resource-ownership model** (`model.Resource`): optional owner identity,
  object id, tenant, and required-role context on a test case, plus a
  `role_hierarchy` for privilege ranking.
- **Ownership-aware finding classification**: `cross_tenant_access` (critical),
  `potential_bola` (high), and `privilege_escalation` (high) are now emitted
  when — and only when — the resource context supports them. See ADR 0002.
- **Response-comparison evidence in findings**: an offending response is compared
  against a legitimate baseline (owner or any allowed identity); a matching body
  is flagged as strong evidence the same data was exposed. Wires the existing
  `compare` package into the engine.
- **Declarative YAML policies** (`internal/policy`): parse an `api`/`expect`/
  `response` control file and compile it into a runnable test case given base
  URL, path params, and identities. See ADR 0001.
- **`vardrgate run --job job.json --out result.json`**: offline execution
  subcommand and job envelope (`internal/job`), the CLI contract used by
  VardrRunner and CI. The binary still defaults to `serve`.
- **GitHub Actions CI**: gofmt, `go vet`, `go test -race`, and build on every
  push and pull request.
- Stable machine-readable error codes on the HTTP API (`code` field): 
  `method_not_allowed`, `body_too_large`, `invalid_json`, `trailing_content`,
  `validation_failed`.

### Changed

- **Stricter test-case validation**: duplicate identity ids, expected-access
  references to unknown identities, invalid credential type/header/value
  combinations, and dangling resource references are now rejected up front.
- Evidence redaction now strips URL userinfo (`user:pass@host`) in addition to
  sensitive query parameters.

### Dependencies

- Added `gopkg.in/yaml.v3` for policy parsing (see ADR 0001).
