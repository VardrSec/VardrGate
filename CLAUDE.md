# VardrGate — Engineering Reference

## What this project is

VardrGate is an API authorization assurance engine. It accepts a test case (or a declarative policy compiled into one), executes a single HTTP request as multiple identities, classifies each observed outcome against the expected access decision with optional ownership/tenant/role context, and returns structured, evidence-backed findings. It can be driven four ways: the HTTP API (`POST /tests/execute`), a declarative policy or suite of policies (`vardrgate policy run`, also packaged as the GitHub Action in `action.yml`), the offline CLI (`vardrgate run --job` / `--cases`), or as a library. It is the first execution primitive of a larger API security control plane. No frontend; the job queue optionally persists to SQLite.

## Technology

- Go 1.25 or newer, matching `go.mod`
- Standard library plus two direct dependencies: `gopkg.in/yaml.v3` for policy parsing (ADR 0001) and `modernc.org/sqlite` for durable queue storage (ADR 0004), with their indirect dependencies recorded in `go.mod`
- Do not add further dependencies without an ADR.
- `net/http` for HTTP clients and server
- `http.ServeMux` for routing
- `log/slog` for structured logging
- Code changes require `go test -race ./...`, `go vet ./...` and formatting checks before review. Docs-only changes require a diff and Markdown-link check rather than rerunning the Go suite.

Do not add PostgreSQL, Redis, Docker, Kubernetes, message queues, background workers, or cloud deployment unless explicitly requested.

## Repository layout

```
cmd/vardrgate/
├── main.go                  subcommand dispatch, usage, version, exit codes
├── execute.go               run / policy run (--policy, --suite) / demo, output flags, --fail-on gating
├── discover.go              discover
├── importers.go             gen, coverage
└── serve.go                 HTTP server, env config, wiring, shutdown

internal/
├── api/                     handler.go (health, tests/execute) + jobs.go (queue)
├── client/                  HTTP execution, credential application, SSRF protection
├── compare/                 status-code, body, JSON, sensitive-field, FieldValue
├── coverage/                OpenAPI-vs-test-case coverage reporting
├── demo/                    vulnerable loopback fixture + bundled policy
├── discover/                draft policies proposed from a spec (never executable)
├── engine/                  engine.go: validation, execution, findings
│                         setup.go: pre-request steps, capture, substitution
│                         preflight.go: same-origin session principal checks
├── job/                     offline job envelope for `vardrgate run --job`
├── model/                   domain types, constants, Resource, ClassifyOutcomeWith
├── openapi/                 OpenAPI 3 parse + starter case generation
├── policy/                  policy.go (parse/compile) + identities.go (bindings)
├── postman/                 Postman v2.1 collection import
├── report/                  text, Markdown and SARIF renderers
├── scaffold/                starter case builder + MarshalCases on-disk format
├── secretref/               ${VAR} credential references
├── store/                   runner job queue + registry (Memory + SQLite)
├── suite/                   suite files: many policies bound to one environment
└── urlcheck/                URL scheme validation, CheckIP, DialContext-ready exports

Every package above has a _test.go alongside it.

docs/
├── mvp.md                   first supported workflow
└── adr/                     0001 policy+CLI · 0002 classification · 0003 queue
                             0004 persistence · 0005 tenancy · 0006 policy CLI
                             0007 policy-driven deny · 0008 body-aware deny +
                             mutation safety · 0009 discovery · 0010 setup steps
                             0011 identity preflight · 0012 binary releases
                             0013 policy suites · 0014 report formats
                             0015 GitHub Action

examples/
├── bola_check.json              three-identity unauthorized-access scenario
├── ownership_check.json         local demo against an httptest-style target
├── job_profile_check.json       `vardrgate run --job` envelope (a template — its
│                                tokens and localhost URL are placeholders)
├── identities.json              policy bindings with ${VAR} credential references
├── petstore.openapi.json        import fixture
├── store.postman_collection.json import fixture
├── profile_ownership.policy.yaml declarative policy example (run by `vardrgate demo`)
├── user_orders.policy.yaml       second policy for the suite example
└── suite.yaml                    suite binding both policies (compiled by a test)

action.yml                   composite GitHub Action: verified release install + run
.github/workflows/ci.yml     gofmt + vet + race tests + build; Action on Ubuntu/macOS/Windows
CHANGELOG.md                 Keep a Changelog / SemVer
SECURITY.md                  private vulnerability reporting and scope
```

## Package responsibilities

### `internal/model`

Owns all domain types. `ClassifyOutcome` maps default HTTP statuses and `ClassifyOutcomeWith` adds reviewed denial statuses; the engine applies body-aware denial conditions. All types that cross the API boundary carry JSON tags. `Credential.Value` has `json:"-"` and a custom `UnmarshalJSON` so callers can supply the secret in request JSON but it is never written to any response, finding, or log.

Current types: `Identity`, `Credential`, `RequestTemplate`, `ExpectedAccess`, `ExecutionResult`, `ComparisonResult`, `Finding`, `AuthorizationTestCase`.

Current custom string types: `CredentialType`, `AccessDecision`, `ObservedOutcome`, `ExecutionErrorKind`, `Confidence`, `Severity`, `FindingCategory`.

### `internal/urlcheck`

Validates URLs and IP addresses before any network request is made.

- `Check` validates scheme (`http`/`https` only), host presence, and literal IP addresses.
- `CheckIP` is exported so the transport `DialContext` can reuse the same policy at connect time.
- Hostname targets are **not** resolved in `Check`; DNS resolution and IP validation happen inside `buildHTTPClient`'s `DialContext` to prevent DNS rebinding.

Always blocked (even with `AllowPrivateTargets=true`): unspecified, link-local, multicast.
Blocked by default, opt-in via `AllowPrivateTargets`: loopback, RFC-1918/4193 private ranges.

### `internal/client`

Executes a single HTTP request for one identity. Owns credential application, URL pre-flight validation, and SSRF protection.

Key behaviors:
- `New(nil)` produces a safe default client: private targets blocked, 30 s timeout, 5 MB body limit.
- `NewWithConfig` accepts a `Config` for non-default settings.
- The default `http.Client` is built by `buildHTTPClient`, which installs a custom `DialContext`. The dialer resolves the hostname, validates every returned IP with `CheckIP`, and dials the first pre-validated address directly — no second DNS resolution between check and connect.
- `context.WithTimeout` cancel is always deferred in `Execute`.
- Redirects are not followed.
- TLS verification is on by default.
- Credentials are never logged.
- `Redact(cred)` returns a safe copy for use in error messages.

### `internal/engine`

Coordinates execution. Validates the test case, iterates identities, calls the `Executor` interface, and evaluates findings.

Finding rules for a deny→allow result, most to least specific (see ADR 0002):
- `missing_authentication` (critical): the caller sent no credentials (`Credential.SendsNoAuth()` — a `static_header` with no header). Highest precedence.
- `cross_tenant_access` (critical): identity's tenant differs from `resource.tenant_id`.
- `potential_bola` (high): non-owner identity reached an identified object (`resource.owner_identity` set and `resource.type`/`object_id` present).
- `privilege_escalation` (high): identity's role ranks below `resource.required_role` in `role_hierarchy`.
- `unexpected_access` (high): no ownership context — conservative fallback.

Other rules:
- `sensitive_data_exposure` (high): an identity whose expected access has `ForbidSensitiveData` receives a response body containing sensitive fields. Independent of the allow/deny decision. Detection (in `compare.SensitiveFieldsPresent`) is recursive and case-insensitive; evidence records field *names* only, never values. Field set defaults to `compare.DefaultSensitiveFields`, overridable via `tc.SensitiveFields`. Policy `response.sensitive_fields.forbidden_for` roles compile to `ForbidSensitiveData`.
- `authorization_mismatch` (low): expected `allow`, observed `deny` (401/403).
- `cors_misconfiguration`: opt-in via `tc.CORS.ProbeOrigin`. The engine injects that `Origin` header (once, endpoint-level) and inspects `Access-Control-Allow-Origin`/`-Credentials` (captured by the client). Reflected arbitrary origin + credentials → high; reflected/wildcard without credentials → low; otherwise none.
- `deny_when`: `tc.DenyWhen` (from `response.deny_when`) recognises a refusal in the response *body* — `body_contains` or a dotted-path `json_field` match — and **outranks the status line**. This is a correctness fix, not a convenience: an API answering `200 {"error":"forbidden"}` previously produced a false `missing_authentication` at critical severity against correctly-behaving software. Classification is centralised in `engine.classify`, which every path uses, so the execution record and the findings drawn from it cannot disagree. See ADR 0008.
- `mutating`: unsafe methods (POST/PUT/PATCH/DELETE) fail validation unless `tc.Mutating` is set via `api.mutating` or `--allow-mutating`. A test case replays one request per identity, so an unsafe method mutates once per caller. Setup steps obey the same rule. Refusing rather than warning is deliberate — the failure mode is destroyed data. See ADR 0008.
- `object_property_exposure` (OWASP API3, BOPLA): an `elevated`-tier field (`role`, `is_admin`, `permissions`, `balance`) reaching a caller marked `ForbidSensitiveData`. Split from `sensitive_data_exposure` by tier in `sensitiveDataFindings`; severity is the highest tier in each group.
- `deny_status`: `tc.DenyStatuses` (from a policy's `response.deny_status`) makes the listed status codes explicit denials, so an API that hides existence behind 404 can be evaluated. The engine reclassifies the *execution record* as well as the finding, so a result document cannot contradict itself, and adds `deny_status_declared=` evidence. A 2xx in the list is rejected by validation. See ADR 0007.
- `tenant_field`: when `Resource.TenantID` is empty and `Resource.TenantField` is set, the resource's tenant is read from the offending identity's own response body via `compare.FieldValue` — the caller's own response proves the isolation break. A bound `TenantID` wins. See ADR 0007.
- Every elevated category requires explicit context in the test case; `TenantID` alone still yields `unexpected_access`. The engine never guesses from a weak signal.
- Findings include response-comparison evidence: the offending response is compared against a baseline (the owner, or any allowed identity); exact body matches and value-free JSON schema matches are distinguished. Every JSON execution exposes a bounded `ResponseProfile` (schema hash plus structural paths, no values) for control-plane visualization. JSON and non-JSON size deltas are accurate, and sensitive-field differences are recursive.
- Execution errors suppress findings for that identity.
- `decision: skip` records execution but emits no finding.
- Ambiguous outcomes (undeclared 404, 5xx, 3xx) when expected `deny` produce no authorization finding. A reviewed `deny_status` can explicitly classify 404 as denial.

Validation rejects: duplicate identity ids, expected-access references to unknown identities, invalid credential type/header/value combinations, and resource references to unknown owner identities or roles absent from `role_hierarchy`.

The `Executor` interface is defined in the engine package and satisfied by `*client.Client`. Tests use a `stubExecutor`. `Run` executes all identities first, then evaluates findings so it can compare against a baseline.

`engine.Result` has JSON tags (`test_case_id`, `executions`, `findings`). A clean run serializes `findings` as `[]`, not `null`, for Map's import contract. `engine.Validate` is exported so a caller holding a suite can check every case before running any of them.

`Result.PreflightFailed()` and `Result.Unreached()` are the single definition of "this case tested nothing", shared by the CLI's exit-code gate and every report format. `Result.Error` (`omitempty`) is set only by the CLI, for a suite entry that failed at run time; `Run` never sets it, so `run --job` output is unchanged.

### `internal/suite`

Loads a suite file (`base`, `identities`, `policies[]` with `policy`, `params`, `tenant`, `id`, per-entry `identities`) and `Compile`s every entry into a test case. Unknown fields are rejected. Paths resolve relative to the suite file; `${VAR}` resolves in `base`, `params` and `tenant` through `secretref`; `Options.BaseOverride` (from `--base`) wins over `base`. Each entry binds only the identities whose role its policy names, and a role in `expect` with no identity is an error. All problems are reported together, and duplicate test case ids are rejected. See ADR 0013.

### `internal/report`

Renders `[]report.Case` (a source path plus an `engine.Result`) as text, Markdown or SARIF 2.1.0. JSON is not here: the CLI writes it directly, because it is the Runner/Map contract. Every format states when a case tested nothing; SARIF sets `executionSuccessful: false` with an error notification. Markdown escapes untrusted evidence. SARIF fingerprints hash only case id, category and identity — never timestamps or evidence. `TextCase` is shared with `vardrgate demo`. Built on `encoding/json`, no SARIF library. See ADR 0014.

### `internal/coverage`

`Analyze(spec, cases)` maps case definitions to spec operations (output labels tested/untested + percent). It does not run cases or measure verified security coverage. Matches a case to an operation on HTTP method and a path-template suffix match (`{param}` wildcards; server base path ignored). Exposed via `vardrgate coverage`.

### `internal/scaffold`

Shared starter-test-case builder used by the importers. `StarterCase(id, description, method, url)` returns a scaffold with the request pre-filled plus an `authenticated` (allow) and `anonymous` (deny) template identity; `Slug` normalises a path into an id fragment.

### `internal/openapi` / `internal/postman`

Spec importers. `openapi.Parse` + `Spec.GenerateTestCases` handle OpenAPI 3 (one case per path+method, sorted). `postman.Parse` + `Collection.GenerateTestCases` handle Postman v2.1 (folders flattened; string or object URL forms). Both build cases through `scaffold` and are exposed via `vardrgate gen` (`--spec` / `--postman`, with optional `--base`). Unknown fields are ignored so real documents parse.

### `internal/policy`

Parses a declarative YAML policy (`api`/`expect`/`response`) and `Compile`s it into a `model.AuthorizationTestCase` given `Bindings` (base URL, path params, identities whose `role` matches an `expect` key, optional resource tenant). Unknown YAML fields are rejected. This is what makes a control reusable across environments.

`Compile` carries `response.deny_status` to `tc.DenyStatuses` and `api.resource.tenant_field` to `Resource.TenantField`; both were parsed and dropped before ADR 0007.

`Compile` also carries `response.deny_when` to `tc.DenyWhen`, `api.mutating` (or `Bindings.AllowMutating`) to `tc.Mutating`, and the `setup` block to `tc.Setup`, resolving each step's logical role to a concrete identity id and joining its path to the base URL. `substitutePath` steps over `{{var}}` runtime references so they survive compilation.

`DraftMarker` (`TODO`) is rejected by `toDecision` — this is what makes a `discover` draft inert. See ADR 0009.

`LoadIdentities`/`ParseIdentities` (in `identities.go`) read the JSON identity array that binds a policy, requiring an id and a role on each and resolving `${VAR}` credential references through `secretref`. Exposed via `vardrgate policy run --identities`.

### `internal/discover`

Proposes draft policies from an OpenAPI spec (`FromSpec`), inferring the object identifier, resource type, and — given a captured response body via `--sample` — the tenant field and sensitive properties. Every inference is explained in `Draft.Notes`.

**The invariant:** every expectation is emitted as `policy.DraftMarker` (`TODO`), which `policy.toDecision` rejects. A draft therefore *cannot execute* until a human has typed a decision — enforced by the compiler, not promised in docs, and asserted by `discover_test.go`. Identifier matching is on whole normalised names, never substrings. Inference may inform **authoring**; it must never produce an **assertion**. Any future heuristic obeys the same rule. See ADR 0009.

### `internal/secretref`

Resolves `${VAR}` references in credential values against the process environment. Used by `policy.ParseIdentities`, `job.Parse`, and the CLI's `loadCases`, so all three input paths behave identically. An unset or empty variable is an **error**, never an empty string: a blank token turns an authenticated identity into an anonymous one, which inverts the meaning of the test while still reporting a clean run. See ADR 0006.

### `internal/demo`

A deliberately broken profile API on loopback plus the policy and identities to run against it, behind `demo.Run(ctx)`. It exists because the README's first command used to point at a service the reader does not have running: every identity failed and the command still exited 0. `Policy` is inlined so the binary is self-contained; a test compares it against `examples/profile_ownership.policy.yaml` (parsed, so the file keeps its comments) and fails on drift.

### `internal/job`

Parses the offline job envelope (`type`, `program_id`, `config.test_case`, `config.execution`) used by `vardrgate run --job`. Also accepts a bare test case. `ClientConfig()` derives `client.Config` from the execution block. Credential values resolve `${VAR}` references through `secretref`, the same as every other input path. No coupling to VardrRunner beyond this JSON shape.

### `internal/compare`

Compares two `ExecutionResult` values. Wired into the engine: `comparisonEvidence` compares an offending response against a legitimate baseline and attaches the result to the finding.

Comparisons: status-code equality, raw body equality, normalised JSON equality (key-order independent), value-free JSON schema equality and field overlap, response-size difference, recursive presence/absence of sensitive fields (`token`, `secret`, `api_key`, etc.).

`Profile(body)` emits a bounded structural description: at most 2,048 distinct
paths and 64 levels, with a truncation flag. Its SHA-256 schema hash covers only
sorted path/type tokens, never scalar values. Non-JSON bodies expose only their
kind and deliberately receive no body hash.

`Results(a, b, fields)` takes the sensitive-field set as a parameter — `nil` means `DefaultSensitiveFields`. It is passed `tc.SensitiveFields` so a case that overrides the set gets the same answer here as from the engine's sensitive-data check.

`Evidence(a, b, cr)` extracts comparison output into evidence strings ready to attach to a `Finding`.

`FieldValue(body, field)` is a recursive, case-insensitive scalar lookup used to read a resource's tenant out of a response body (see ADR 0007). `ValueAtPath(body, "error.code")` navigates a dotted path exactly rather than searching, for callers that know the response shape.

`SensitiveTiers` groups field names into `critical`/`elevated`/`pii`/`internal`; `ScanSensitive(body, declared)` returns `SensitiveHit{Path, Field, Tier}` so evidence locates a leak (`user.profile.ssn`) instead of merely naming it, and arrays collapse to one representative path. Matching is on whole normalised names — **never substrings**, which would classify `username` as `user`. A non-empty `declared` list replaces the tiers entirely and reports at `TierDeclared`. `MatchesDeny(body, cond)` evaluates a declared deny condition and describes what matched.

### `internal/store`

Runner job queue and runner registry behind a `Store` interface. Two implementations: `Memory` (default) and `SQLite` (durable, `modernc.org/sqlite`, selected via `VARDRGATE_DB`; jobs survive restart). Job lifecycle: `pending → claimed → running → done|failed`; `Claim` is atomic (`ErrAlreadyClaimed` on double-claim). Both pass the same conformance suite in `store_test.go`. PostgreSQL is the intended production driver behind the same interface. See ADR 0003 (queue) and 0004 (persistence).

### `internal/api`

Exposes the HTTP API. No business logic.

- `New(log, eng, store, keys)` registers routes on a `ServeMux` and returns a `Handler`; `keys` maps bearer tokens to tenants.
- `GET /health` — 200 `{"status":"ok"}`.
- `POST /tests/execute` — synchronous execution; 1 MB `MaxBytesReader`, single-decoder, second `Decode` must return `io.EOF`, stable error codes.
- Runner job queue (in `jobs.go`), matching VardrRunner's client shapes: `POST /jobs`, `GET /jobs/pending`, `GET /jobs/{id}`, `POST /jobs/{id}/claim` (409 on double-claim), `PATCH /jobs/{id}`, `POST /jobs/{id}/done|failed|events|upload`, `POST /runner/heartbeat`. Uses Go 1.22 method+path routing.
- `protected`/`resolveTenant` enforce per-tenant bearer keys (token→tenant map, constant-time compare) on `/jobs`, `/runner`, `/audit`; the resolved tenant is carried on the request context. Every job records its owning tenant; `requireOwned` returns 404 for cross-tenant access (existence never revealed), and pending/audit lists are tenant-filtered. `/health` and `/tests/execute` stay open. Empty key map = dev mode (`default` tenant). See ADR 0005.
- `writeJSON` and `writeError` (stable `code` envelope) are shared helpers; all responses carry `Content-Type: application/json`.

### `cmd/vardrgate`

Subcommand dispatch (`main.go`). A bare invocation serves, which is the documented default; **any unrecognised argument is an error**, not a fallthrough to `serve` — that fallthrough is why `vardrgate --help` used to start a web server.

Exit codes are shared by every command that executes a test case: `0` ran clean, `1` usage or input error, `2` findings at or above `--fail-on`, `3` a case reached nothing. `exitError` carries the code out of a subcommand; `gate` decides it. Exit 3 is not gated on the threshold and outranks findings — zero findings means nothing when no request succeeded — and it is evaluated **per case**, so a target that dies partway through a suite still fails the run.

| Command | Purpose |
|---|---|
| `serve` (default) | HTTP API. Reads `PORT` (1–65535, default 8080), `ALLOW_PRIVATE_TARGETS`, `VARDRGATE_API_KEY(S)`, `VARDRGATE_DB`; wires `client → engine → handler` with a store (`ReadHeaderTimeout` 5 s, `ReadTimeout` 30 s, `WriteTimeout` 60 s, `IdleTimeout` 120 s; 10 s graceful shutdown on `SIGINT`/`SIGTERM`) |
| `policy run` | Compile a policy against one environment and run it: `--policy --base --param name=value (repeatable) --identities [--tenant --id --fail-on --allow-private-targets --timeout]`. Or `--suite <file> [--base]` to run a suite; per-policy flags are rejected with `--suite`. Every compiled case is validated before any request; in suite mode a run-time failure (e.g. setup) is recorded in `Result.Error`, the rest continue, and the run exits 3 |
| `run` | `--job <file>` (one envelope) or `--cases <file>` (a JSON array). A suite is fully validated via `engine.Validate` before any of it runs, so every authoring error is reported together |

`policy run` and `run` share output flags: `--format json|text|markdown` (stdout; default `json`), `--out` (always JSON) and `--sarif`. With the default format and `--out` set, stdout stays empty — Runner's `run --job --out` contract. Outputs are written before `gate` decides the exit code.
| `demo` | Bundled policy against the `internal/demo` loopback fixture; prints a human summary rather than JSON |
| `discover` | `--spec` [`--sample`] [`--out` dir] [`--roles`] — draft policies whose expectations are `TODO` and therefore unrunnable |
| `gen` | `--spec` / `--postman` [`--base`] [`--out`] — starter cases through `scaffold.MarshalCases` |
| `coverage` | `--spec --cases` [`--out`] — tested/untested operations |
| `help`, `version` | Usage; version from `-ldflags -X main.version` or the build info |

`--fail-on` defaults to `none`, so adding gating to an existing pipeline is deliberate.

## Development rules

Use focused tests while editing, then run the relevant full checks for code changes.
For docs-only changes, inspect the diff and local Markdown links; steps 3–6 below
apply when runtime code or tests change.

Before starting:
- `git fetch && git status -sb` — is local `main` behind?
- `gh run list --limit 1` — is CI red already? This repo's `main` did not compile for a month because `.gitignore` silently excluded `internal/coverage/coverage.go`; every local check passed the whole time.

Before committing:
1. Read the files you plan to change.
2. Make the smallest coherent change.
3. Add or update tests for every behavioral change.
4. Run `gofmt -w` on changed files.
5. Run `go test ./...` — suite must be green.
6. Run `go vet ./...` — must be clean.
7. Do not rewrite unrelated files.
8. Do not introduce speculative interfaces or abstractions.
9. Do not add external dependencies without a written justification.
10. Stop when the task is complete.

## Map and Runner integration

- Map is the engagement control plane; Runner drives this binary over JSON. Gate's
  standalone queue is separate from Map's job queue and assessment storage.
- Runner adds a `case_hash` of the unresolved reviewed spec to the retained artifact;
  Map verifies it against the claim-time snapshot. Gate does not compute this hash
  or know Map's evidence foreign keys. Preserve the result fields and empty arrays.
- Gate's exit 0 means nothing reached the configured finding threshold, not that
  every identity was evaluated or the API is secure. Map separately reports
  conclusive, partial or inconclusive assessment completeness using a bound case
  and legitimate baseline. Findings remain candidates for operator verification.
- Map/Runner share original versioned playbook guidance; those guides are not
  Gate policies and do not execute, mark coverage or replace reviewed expectations.
- Map's disposable three-repository acceptance harness runs this real binary and
  Runner against loopback fixtures with SQLite or migrated PostgreSQL for Map.
  It does not add a PostgreSQL Store to Gate or establish hosted OAuth success.
- Preserve local private-target opt-in, declared deny conventions, mutation safety
  and setup failure behavior. Automatic login refresh and a general workflow
  language remain future work.
- Optional `Identity.Preflight` is a reviewed same-origin GET plus explicit public
  principal field matches. It runs after setup and before resource testing;
  any failure returns safe diagnostics, no executions/findings and CLI exit 3.
  Never retain response values, headers or raw errors, infer expiry, or treat a
  probe as an authorization baseline. `--require-identity-preflight` is Runner's
  compatibility guard. See ADR 0011; automatic refresh remains future work.

## Binary releases

`VERSION` is the packaged version. Prepare matching changelog and
`docs/releases/vX.Y.Z.md` notes in a PR, merge after CI/cross-builds pass, then
push the matching tag. `release.yml` verifies source, builds Linux/macOS amd64
and arm64 plus Windows amd64, adds SHA256SUMS and provenance, and publishes the
archives. Release actions are commit-pinned; verify checksums and repository
attestations before installing. See ADR 0012. Tagging requires explicit release
authorization; merging a feature PR alone is not permission to publish.

## Communication

Report major results, blockers and required decisions; omit routine command-by-command
updates to conserve tokens. Use dated, inspected evidence when comparing the platform
with ars0n after platform changes; no weekly polling is requested.

## Code quality standards

Use:
- Small packages with clear single ownership
- Explicit constructors when initialization matters
- Context propagation for all network operations
- Sentinel or typed errors when callers need to distinguish failures
- Table-driven tests
- `httptest.Server` or `roundTripFunc` for HTTP tests
- Dependency injection for `http.Client`, clocks, executors

Avoid:
- Global mutable state
- `panic` for recoverable errors
- Empty interfaces unless genuinely required
- Premature generics
- Large multipurpose packages
- Hidden goroutine lifecycles
- Unbounded concurrency
- Logging credentials or secrets
- Ignoring returned errors

## What not to build yet

Phases 1–3 and the Phase 2 importers are complete: resource ownership, ownership-aware findings, compare wiring, YAML policies, the policy/run/gen/coverage/demo CLI, the runner job queue with a durable SQLite store, tenant isolation, and an audit log. Do **not** build later work unless asked:

- PostgreSQL `Store` — the interface is ready for it; SQLite covers current needs
- Multi-tenant control plane beyond per-key tenancy: orgs/projects/environments, secret providers (Phase 3)
- Frontend or dashboard (Phase 4)
- Further vulnerability packs: rate-limit, JWT, GraphQL (Phase 5). CORS and BOPLA are done
- Live crawling in `discover` — it is spec-driven and offline by design
- Teardown, retries, or conditional `setup` steps: that turns setup into a workflow language (ADR 0010)
- JUnit output — text, Markdown and SARIF cover the CI log, summary and dashboard cases (ADR 0014)
- Concurrency, ordering or shared setup across suite entries — each entry is an independent policy run (ADR 0013)
- User accounts, organizations, SSO, billing
- Concurrency in the execution loop — sequential is a stated decision (`docs/mvp.md`)
- Additional HTTP API endpoints
