# VardrGate architecture

How the packages divide the work, what each one guarantees, and the CLI surface.
The directory layout is in the [README](../README.md#project-layout); design
decisions are in [`docs/adr/`](adr/). The rules an agent or contributor must not
break are summarised in [`AGENTS.md`](../AGENTS.md); this document explains them.

Beyond the README layout, `cmd/authbench/` holds the authorization benchmark (a
vulnerable loopback lab, versioned corpus, scorer and regression budgets) and
`benchmarks/` holds recorded benchmark reports and their methodology.

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

Always blocked (even with `AllowPrivateTargets=true`): unspecified and 0.0.0.0/8, link-local, cloud metadata addresses outside link-local (100.100.100.200), multicast.
Blocked by default, opt-in via `AllowPrivateTargets`: loopback, RFC-1918/4193 private ranges, shared address space 100.64.0.0/10, benchmarking 198.18.0.0/15.
NAT64 (64:ff9b::/96) and 6to4 (2002::/16) addresses are also judged by the IPv4 address they carry.

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
- `deny_when`: `tc.DenyWhen` (from `response.deny_when`) recognizes a refusal in the response *body* — `body_contains` or a dotted-path `json_field` match — and **outranks the status line**. This is a correctness fix, not a convenience: an API answering `200 {"error":"forbidden"}` previously produced a false `missing_authentication` at critical severity against correctly-behaving software. Classification is centralized in `engine.classify`, which every path uses, so the execution record and the findings drawn from it cannot disagree. See ADR 0008.
- `mutating`: unsafe methods (POST/PUT/PATCH/DELETE) fail validation unless `tc.Mutating` is set via `api.mutating` or `--allow-mutating`. A test case replays one request per identity, so an unsafe method mutates once per caller. Setup steps obey the same rule. Refusing rather than warning is deliberate — the failure mode is destroyed data. See ADR 0008.
- `object_property_exposure` (OWASP API3, BOPLA): an `elevated`-tier field (`role`, `is_admin`, `permissions`, `balance`) reaching a caller marked `ForbidSensitiveData`. Split from `sensitive_data_exposure` by tier in `sensitiveDataFindings`; severity is the highest tier in each group.
- `deny_status`: `tc.DenyStatuses` (from a policy's `response.deny_status`) makes the listed status codes explicit denials, so an API that hides existence behind 404 can be evaluated. The engine reclassifies the *execution record* as well as the finding, so a result document cannot contradict itself, and adds `deny_status_declared=` evidence. A 2xx in the list is rejected by validation. See ADR 0007.
- `tenant_field`: when `Resource.TenantID` is empty and `Resource.TenantField` is set, the resource's tenant is read from the offending identity's own response body via `compare.FieldValue` — the caller's own response proves the isolation break. A bound `TenantID` wins. See ADR 0007.
- Every elevated category requires explicit context in the test case; `TenantID` alone still yields `unexpected_access`. The engine never guesses from a weak signal.
- Findings include response-comparison evidence: the offending response is compared against a baseline (the owner, or any allowed identity); exact body matches and value-free JSON schema matches are distinguished. Every JSON execution exposes a bounded `ResponseProfile` (schema hash plus structural paths, no values) for control-plane visualization. JSON and non-JSON size deltas are accurate, and sensitive-field differences are recursive.
- Execution errors suppress findings for that identity.
- `decision: skip` records execution but emits no finding.
- Ambiguous outcomes (undeclared 404, 5xx, 3xx) when expected `deny` produce no authorization finding. A reviewed `deny_status` can explicitly classify 404 as denial.
- `response_assertions` (`ExpectedAccess.ResponseAssertions`, policy `response.assertions`): JSON Pointer + exact JSON `equals` + the decision a match proves. When an identity has assertions they are authoritative — no status fallback, and they outrank `deny_status`/`deny_when`; unmatched or conflicting evidence is inconclusive. Findings still go through the ADR 0002 categorization (`assertionFinding`). Evidence carries assertion indices only. Evaluator in `engine/assertions.go`; exact, duplicate-key-rejecting JSON decoding in `engine/assertion_json.go`. See ADR 0016 and `docs/response-assertions.md`.
- `write_verification` (`tc.WriteVerification`, policy `verify` with a role not in `expect`): a separate reader identity, same-origin request (GET unless `allow_unsafe_method`), optional JSON Pointer and `changed_to`. `verifiedExecute` reads twice before and once after each identity's request; unchanged → denied, changed → allowed, every failure or ambiguity → inconclusive with a fixed reason; the request is withheld when the before-state is unreadable. Outranks assertions and status. Observed values never leave memory. Requires `mutating`. In `engine/verify.go`; see ADR 0017.
- Write-verification denials require a demonstrated allow-expected positive control; missing/failed controls are inconclusive. Unsupported verifier errors and errored writes without observed effects are inconclusive. Successful status changes alone are not mutations. See ADR 0018.
- `credential_rejected` (`engine/credential.go`): a deny-expected identity that sends credentials and gets 401 is inconclusive, never denied, whatever decided it (status, assertion, verified state) — a dead token looks identical. Applied before the positive-control guard. Opt-out is `tc.UnauthorizedIsDenial` (policy `response.unauthorized_is_denial`), deliberately not `deny_status: [401]`, which is copied everywhere and was always redundant. Findings are unchanged. See ADR 0019.
- Every identity gets an `Assessment` (`allowed`/`denied`/`inconclusive`/`skipped`, source, fixed reason code). Without assertions, findings come from `evaluate` unchanged and the assessment is recorded alongside.

Validation rejects: duplicate identity ids, expected-access references to unknown identities, invalid credential type/header/value combinations, and resource references to unknown owner identities or roles absent from `role_hierarchy`.

The `Executor` interface is defined in the engine package and satisfied by `*client.Client`. Tests use a `stubExecutor`. `Run` executes all identities first, then evaluates findings so it can compare against a baseline.

`engine.Result` has JSON tags (`test_case_id`, `executions`, `findings`, `assessments`). A clean run serializes `findings` and `assessments` as `[]`, not `null`, for Map's import contract. `engine.Validate` is exported so a caller holding a suite can check every case before running any of them.

`Result.PreflightFailed()` and `Result.Unreached()` are the single definition of "this case tested nothing", shared by the CLI's exit-code gate and every report format. `Result.Inconclusive()` is likewise the single definition of "an expectation could not be judged": every report lists those assessments (never as a pass) and `--fail-on-inconclusive` gates on them. `Result.Error` (`omitempty`) is set only by the CLI, for a suite entry that failed at run time; `Run` never sets it, so `run --job` output is unchanged.

### `internal/suite`

Loads a suite file (`base`, `identities`, `policies[]` with `policy`, `params`, `tenant`, `id`, per-entry `identities`) and `Compile`s every entry into a test case. Unknown fields are rejected. Paths resolve relative to the suite file; `${VAR}` resolves in `base`, `params` and `tenant` through `secretref`; `Options.BaseOverride` (from `--base`) wins over `base`. Each entry binds only the identities whose role its policy names, and a role in `expect` with no identity is an error. All problems are reported together, and duplicate test case ids are rejected. See ADR 0013.

### `internal/report`

Renders `[]report.Case` (a source path plus an `engine.Result`) as text, Markdown or SARIF 2.1.0. JSON is not here: the CLI writes it directly, because it is the Runner/Map contract. Every format states when a case tested nothing; SARIF sets `executionSuccessful: false` with an error notification. Markdown escapes untrusted evidence. SARIF fingerprints hash only case id, category and identity — never timestamps or evidence. `TextCase` is shared with `vardrgate demo`. Built on `encoding/json`, no SARIF library. See ADR 0014.

### `internal/coverage`

`Analyze(spec, cases)` maps case definitions to spec operations (output labels tested/untested + percent). It does not run cases or measure verified security coverage. Matches a case to an operation on HTTP method and a path-template suffix match (`{param}` wildcards; server base path ignored). Exposed via `vardrgate coverage`.

### `internal/scaffold`

Shared starter-test-case builder used by the importers. `StarterCase(id, description, method, url)` returns a scaffold with the request pre-filled plus `authenticated` and `anonymous` template identities. The in-memory starter still carries allow/deny, but `gen` emits review-only cases: every decision is `TODO` and cannot run until a human sets it (ADR 0022); `Slug` normalizes a path into an id fragment.

### `internal/openapi` / `internal/postman`

Spec importers. `openapi.Parse` + `Spec.GenerateTestCases` handle OpenAPI 3 (one case per path+method, sorted). `postman.Parse` + `Collection.GenerateTestCases` handle Postman v2.1 (folders flattened; string or object URL forms). Both build cases through `scaffold` and are exposed via `vardrgate gen` (`--spec` / `--postman`, with optional `--base`). Unknown fields are ignored so real documents parse.

### `internal/policy`

Parses a declarative YAML policy (`api`/`expect`/`response`) and `Compile`s it into a `model.AuthorizationTestCase` given `Bindings` (base URL, path params, identities whose `role` matches an `expect` key, optional resource tenant). Unknown YAML fields are rejected. This is what makes a control reusable across environments.

`Compile` carries `response.deny_status` to `tc.DenyStatuses` and `api.resource.tenant_field` to `Resource.TenantField`; both were parsed and dropped before ADR 0007.

`Compile` carries `api.body` (validated JSON) and `api.headers` to the request under test, defaulting `Content-Type: application/json` when a body is set; error messages never echo the body. `Compile` also carries `response.deny_when` to `tc.DenyWhen`, `api.mutating` (or `Bindings.AllowMutating`) to `tc.Mutating`, and the `setup` block to `tc.Setup`, resolving each step's logical role to a concrete identity id and joining its path to the base URL. `substitutePath` steps over `{{var}}` runtime references so they survive compilation.

`DraftMarker` (`TODO`) is rejected by `toDecision` — this is what makes a `discover` draft inert. See ADR 0009.

`LoadIdentities`/`ParseIdentities` (in `identities.go`) read the JSON identity array that binds a policy, requiring an id and a role on each and resolving `${VAR}` credential references through `secretref`. Exposed via `vardrgate policy run --identities`.

### `internal/discover`

Proposes draft policies from an OpenAPI spec (`FromSpec`), inferring the object identifier, resource type, and — given a captured response body via `--sample` — the tenant field and sensitive properties. Every inference is explained in `Draft.Notes`.

**The invariant:** every expectation is emitted as `policy.DraftMarker` (`TODO`), which `policy.toDecision` rejects. A draft therefore *cannot execute* until a human has typed a decision — enforced by the compiler, not promised in docs, and asserted by `discover_test.go`. Identifier matching is on whole normalized names, never substrings. Inference may inform **authoring**; it must never produce an **assertion**. Any future heuristic obeys the same rule. See ADR 0009.

### `internal/secretref`

Resolves `${VAR}` references in credential values against the process environment. Used by `policy.ParseIdentities`, `job.Parse`, and the CLI's `loadCases`, so all three input paths behave identically. An unset or empty variable is an **error**, never an empty string: a blank token turns an authenticated identity into an anonymous one, which inverts the meaning of the test while still reporting a clean run. See ADR 0006.

### `internal/demo`

A deliberately broken profile API on loopback plus the policy and identities to run against it, behind `demo.Run(ctx)`. It exists because the README's first command used to point at a service the reader does not have running: every identity failed and the command still exited 0. `Policy` is inlined so the binary is self-contained; a test compares it against `examples/profile_ownership.policy.yaml` (parsed, so the file keeps its comments) and fails on drift.

### `internal/job`

Parses the offline job envelope (`type`, `program_id`, `config.test_case`, `config.execution`) used by `vardrgate run --job`. Also accepts a bare test case. `ClientConfig()` derives `client.Config` from the execution block. Credential values resolve `${VAR}` references through `secretref`, the same as every other input path. No coupling to VardrRunner beyond this JSON shape.

### `internal/compare`

Compares two `ExecutionResult` values. Wired into the engine: `comparisonEvidence` compares an offending response against a legitimate baseline and attaches the result to the finding.

Comparisons: status-code equality, raw body equality, normalized JSON equality (key-order independent), value-free JSON schema equality and field overlap, response-size difference, recursive presence/absence of sensitive fields (`token`, `secret`, `api_key`, etc.).

`Profile(body)` emits a bounded structural description: at most 2,048 distinct
paths and 64 levels, with a truncation flag. Its SHA-256 schema hash covers only
sorted path/type tokens, never scalar values. Non-JSON bodies expose only their
kind and deliberately receive no body hash.

`Results(a, b, fields)` takes the sensitive-field set as a parameter — `nil` means `DefaultSensitiveFields`. It is passed `tc.SensitiveFields` so a case that overrides the set gets the same answer here as from the engine's sensitive-data check.

`Evidence(a, b, cr)` extracts comparison output into evidence strings ready to attach to a `Finding`.

`FieldValue(body, field)` (built on `FindField`, which also returns the key as spelled) is a recursive scalar lookup, case- and separator-insensitive like `ScanSensitive`, with deterministic resolution: own keys before children, exact spelling before normalized, disagreeing siblings resolve to nothing. It is used to read a resource's tenant out of a response body (see ADR 0007). `ValueAtPath(body, "error.code")` navigates a dotted path exactly rather than searching, for callers that know the response shape.

`SensitiveTiers` groups field names into `critical`/`elevated`/`pii`/`internal`; `ScanSensitive(body, declared)` returns `SensitiveHit{Path, Field, Tier}` so evidence locates a leak (`user.profile.ssn`) instead of merely naming it, and arrays collapse to one representative path. Matching is on whole normalized names — **never substrings**, which would classify `username` as `user`. A non-empty `declared` list replaces the tiers entirely and reports at `TierDeclared`. `MatchesDeny(body, cond)` evaluates a declared deny condition and describes what matched.

### `internal/store`

Runner job queue and runner registry behind a `Store` interface. Two implementations: `Memory` (default) and `SQLite` (durable, `modernc.org/sqlite`, selected via `VARDRGATE_DB`; jobs survive restart). Job lifecycle: `pending → claimed → running → done|failed`; `Claim` is atomic (`ErrAlreadyClaimed` on double-claim). Both pass the same conformance suite in `store_test.go`. PostgreSQL is the intended production driver behind the same interface. See ADR 0003 (queue) and 0004 (persistence).

### `internal/api`

Exposes the HTTP API. No business logic.

- `New(log, eng, store, keys)` registers routes on a `ServeMux` and returns a `Handler`; `keys` maps bearer tokens to tenants.
- `GET /health` — 200 `{"status":"ok"}`.
- `POST /tests/execute` — synchronous execution; 1 MB `MaxBytesReader`, single-decoder, second `Decode` must return `io.EOF`, stable error codes.
- Runner job queue (in `jobs.go`), matching VardrRunner's client shapes: `POST /jobs`, `GET /jobs/pending`, `GET /jobs/{id}`, `POST /jobs/{id}/claim` (409 on double-claim), `PATCH /jobs/{id}`, `POST /jobs/{id}/done|failed|events|upload`, `POST /runner/heartbeat`. Uses Go 1.22 method+path routing.
- `protected`/`resolveTenant` enforce per-tenant bearer keys (token→tenant map, constant-time compare) on `/tests/execute`, `/jobs`, `/runner`, `/audit`; the resolved tenant is carried on the request context. Every job records its owning tenant; `requireOwned` returns 404 for cross-tenant access (existence never revealed), and pending/audit lists are tenant-filtered. `/health` stays open. Empty key map = dev mode (`default` tenant). See ADR 0005.
- `writeJSON` and `writeError` (stable `code` envelope) are shared helpers; all responses carry `Content-Type: application/json`.

### `cmd/vardrgate`

Subcommand dispatch (`main.go`). A bare invocation serves, which is the documented default; **any unrecognized argument is an error**, not a fallthrough to `serve` — that fallthrough is why `vardrgate --help` used to start a web server.

Exit codes are shared by every command that executes a test case: `0` ran clean, `1` usage or input error, `2` findings at or above `--fail-on`, `3` a case reached nothing, `4` (only with `--fail-on-inconclusive`) an expectation could not be judged. `gateInconclusive` runs after `gate`, so 3 and 2 keep precedence. `exitError` carries the code out of a subcommand; `gate` decides it. Exit 3 is not gated on the threshold and outranks findings — zero findings means nothing when no request succeeded — and it is evaluated **per case**, so a target that dies partway through a suite still fails the run.

| Command | Purpose |
|---|---|
| `serve` (default) | HTTP API. Reads `VARDRGATE_HOST` (IP or `localhost`, default `127.0.0.1`), `PORT` (1–65535, default 8080), `ALLOW_PRIVATE_TARGETS`, `VARDRGATE_API_KEY(S)`, `VARDRGATE_DB`; wires `client → engine → handler` with a store (`ReadHeaderTimeout` 5 s, `ReadTimeout` 30 s, `WriteTimeout` 60 s, `IdleTimeout` 120 s; 10 s graceful shutdown on `SIGINT`/`SIGTERM`) |
| `policy run` | Compile a policy against one environment and run it: `--policy --base --param name=value (repeatable) --identities [--tenant --id --fail-on --allow-private-targets --timeout]`. Or `--suite <file> [--base]` to run a suite; per-policy flags are rejected with `--suite`. Every compiled case is validated before any request; in suite mode a run-time failure (e.g. setup) is recorded in `Result.Error`, the rest continue, and the run exits 3 |
| `run` | `--job <file>` (one envelope) or `--cases <file>` (a JSON array). A suite is fully validated via `engine.Validate` before any of it runs, so every authoring error is reported together. `--literal-job` (with `--job` only) skips `${VAR}` expansion for callers that resolve credentials themselves (ADR 0028) |
| `regression save` | `--cases --result --case --out NEW_DIRECTORY --confirmed` — retain one operator-confirmed finding as a new portable regression for the existing engine (ADR 0025/0027). Never overwrites; `--allow-unbound-result` is the explicit manual path for results lacking an input digest |
| `demo` | Bundled policy against the `internal/demo` loopback fixture; prints a human summary rather than JSON |
| `discover` | `--spec` [`--sample`] [`--out` dir] [`--roles`] — draft policies whose expectations are `TODO` and therefore unrunnable |
| `gen` | `--spec` / `--postman` [`--base`] [`--out`] — starter cases through `scaffold.MarshalCases` |
| `coverage` | `--spec --cases` [`--out`] — tested/untested operations |
| `help`, `version` | Usage; version from `-ldflags -X main.version` or the build info |

`policy run` and `run` share output flags: `--format json|text|markdown` (stdout; default `json`), `--out` (always JSON) and `--sarif`. With the default format and `--out` set, stdout stays empty — Runner's `run --job --out` contract. Outputs are written before `gate` decides the exit code.

`--fail-on` defaults to `none`, so adding gating to an existing pipeline is deliberate.
