# VardrGate — Engineering Reference

## What this project is

VardrGate is an API authorization assurance engine. It accepts a test case (or a declarative policy compiled into one), executes a single HTTP request as multiple identities, classifies each observed outcome against the expected access decision with optional ownership/tenant/role context, and returns structured, evidence-backed findings. It can be driven three ways: the HTTP API (`POST /tests/execute`), the offline CLI (`vardrgate run --job`), or as a library. It is the first execution primitive of the larger platform in `enterprise-platform.md`. No frontend, no database.

## Technology

- Go 1.24 or newer
- Standard library for everything except policy parsing
- `gopkg.in/yaml.v3` — the **only** external dependency, for YAML policy files (see ADR 0001). Do not add further dependencies without an ADR.
- `net/http` for HTTP clients and server
- `http.ServeMux` for routing
- `log/slog` for structured logging
- `go test -race`, `go vet`, `gofmt` before every commit

Do not add PostgreSQL, Redis, Docker, Kubernetes, message queues, background workers, OpenAPI importers, or cloud deployment unless explicitly requested.

## Repository layout

```
cmd/vardrgate/
└── main.go                  serve + run subcommands, env config, wiring, shutdown

internal/
├── api/
│   ├── handler.go           GET /health, POST /tests/execute, stable error codes
│   └── handler_test.go
├── client/
│   ├── client.go            HTTP execution, credential application, SSRF protection
│   └── client_test.go
├── compare/
│   ├── compare.go           status-code, body, JSON, and sensitive-field comparison
│   └── compare_test.go
├── engine/
│   ├── engine.go            validation, execution loop, ownership-aware findings
│   └── engine_test.go
├── job/
│   ├── job.go               offline job envelope for `vardrgate run`
│   └── job_test.go
├── model/
│   ├── model.go             domain types, constants, Resource, ClassifyOutcome
│   └── model_test.go
├── policy/
│   ├── policy.go            YAML policy parse + compile to test case
│   └── policy_test.go
├── store/
│   ├── store.go             runner job queue + registry, Store interface (in-memory)
│   └── store_test.go
└── urlcheck/
    ├── urlcheck.go          URL scheme validation, CheckIP, DialContext-ready exports
    └── urlcheck_test.go

docs/
├── mvp.md                   first supported workflow
└── adr/                     architecture decision records (0001 policy+CLI, 0002 classification)

examples/
├── bola_check.json              three-identity unauthorized-access scenario
├── ownership_check.json         local demo against an httptest-style target
├── job_profile_check.json       `vardrgate run` job envelope
└── profile_ownership.policy.yaml declarative policy example

.github/workflows/ci.yml     gofmt + vet + race tests + build
CHANGELOG.md                 Keep a Changelog / SemVer
```

## Package responsibilities

### `internal/model`

Owns all domain types. No business logic except `ClassifyOutcome`, which converts an HTTP status code to an `ObservedOutcome` constant. All types that cross the API boundary carry JSON tags. `Credential.Value` has `json:"-"` and a custom `UnmarshalJSON` so callers can supply the secret in request JSON but it is never written to any response, finding, or log.

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
- `cross_tenant_access` (critical): identity's tenant differs from `resource.tenant_id`.
- `potential_bola` (high): non-owner identity reached an identified object (`resource.owner_identity` set and `resource.type`/`object_id` present).
- `privilege_escalation` (high): identity's role ranks below `resource.required_role` in `role_hierarchy`.
- `unexpected_access` (high): no ownership context — conservative fallback.

Other rules:
- `authorization_mismatch` (low): expected `allow`, observed `deny` (401/403).
- Every elevated category requires explicit context in the test case; `TenantID` alone still yields `unexpected_access`. The engine never guesses from a weak signal.
- Findings include response-comparison evidence: the offending response is compared against a baseline (the owner, or any allowed identity); a matching body is flagged.
- Execution errors suppress findings for that identity.
- `decision: skip` records execution but emits no finding.
- Ambiguous outcomes (404, 5xx, 3xx) when expected `deny` produce no finding.

Validation rejects: duplicate identity ids, expected-access references to unknown identities, invalid credential type/header/value combinations, and resource references to unknown owner identities or roles absent from `role_hierarchy`.

The `Executor` interface is defined in the engine package and satisfied by `*client.Client`. Tests use a `stubExecutor`. `Run` executes all identities first, then evaluates findings so it can compare against a baseline.

`engine.Result` has JSON tags (`test_case_id`, `executions`, `findings`).

### `internal/policy`

Parses a declarative YAML policy (`api`/`expect`/`response`) and `Compile`s it into a `model.AuthorizationTestCase` given `Bindings` (base URL, path params, identities whose `role` matches an `expect` key, optional resource tenant). Unknown YAML fields are rejected. This is what makes a control reusable across environments.

### `internal/job`

Parses the offline job envelope (`type`, `program_id`, `config.test_case`, `config.execution`) used by `vardrgate run`. Also accepts a bare test case. `ClientConfig()` derives `client.Config` from the execution block. No coupling to VardrRunner beyond this JSON shape.

### `internal/compare`

Compares two `ExecutionResult` values. Standalone utilities — not yet wired into the engine's finding evaluation.

Comparisons: status-code equality, raw body equality, normalised JSON equality (key-order independent), response-size difference, presence/absence of sensitive fields (`token`, `secret`, `api_key`, etc.).

`Evidence(a, b, cr)` extracts comparison output into evidence strings ready to attach to a `Finding`.

### `internal/store`

Runner job queue and runner registry behind a `Store` interface. Two implementations: `Memory` (default) and `SQLite` (durable, `modernc.org/sqlite`, selected via `VARDRGATE_DB`; jobs survive restart). Job lifecycle: `pending → claimed → running → done|failed`; `Claim` is atomic (`ErrAlreadyClaimed` on double-claim). Both pass the same conformance suite in `store_test.go`. PostgreSQL is the intended production driver behind the same interface. See ADR 0003 (queue) and 0004 (persistence).

### `internal/api`

Exposes the HTTP API. No business logic.

- `New(log, eng, store, apiKey)` registers routes on a `ServeMux` and returns a `Handler`.
- `GET /health` — 200 `{"status":"ok"}`.
- `POST /tests/execute` — synchronous execution; 1 MB `MaxBytesReader`, single-decoder, second `Decode` must return `io.EOF`, stable error codes.
- Runner job queue (in `jobs.go`), matching VardrRunner's client shapes: `POST /jobs`, `GET /jobs/pending`, `GET /jobs/{id}`, `POST /jobs/{id}/claim` (409 on double-claim), `PATCH /jobs/{id}`, `POST /jobs/{id}/done|failed|events|upload`, `POST /runner/heartbeat`. Uses Go 1.22 method+path routing.
- `protected`/`authOK` enforce a bearer `apiKey` on `/jobs` and `/runner` (constant-time compare); `/health` and `/tests/execute` stay open. Empty key = dev mode.
- `writeJSON` and `writeError` (stable `code` envelope) are shared helpers; all responses carry `Content-Type: application/json`.

### `cmd/vardrgate`

Two subcommands. Default (`serve`) reads `PORT` (1–65535, default 8080) and `ALLOW_PRIVATE_TARGETS` (bool, default false), wires `client → engine → handler`, and runs the HTTP server (`ReadHeaderTimeout` 5 s, `ReadTimeout` 30 s, `WriteTimeout` 60 s, `IdleTimeout` 120 s; 10 s graceful shutdown on `SIGINT`/`SIGTERM`). `run --job <file> --out <file>` executes one job envelope offline and writes the result JSON (stdout if `--out` omitted); exits non-zero on error for CI/VardrRunner gating.

## Development rules

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

Phase 1 is complete (resource ownership, ownership-aware findings, compare wiring, YAML policies, the `run` CLI). The first Phase 3 slice — the runner job queue endpoints + in-memory store — is also in place. Do **not** yet build later work unless asked:

- Persistent `Store` (PostgreSQL) — the next Phase 3 step; the interface is ready for it
- Multi-tenant control plane: orgs/projects/environments, tenant isolation, secret providers, audit logs (Phase 3)
- Frontend or dashboard (Phase 4)
- OpenAPI / Postman import and test generation (Phase 2)
- Additional vulnerability packs (rate-limit, CORS, JWT, GraphQL) (Phase 5)
- User accounts, organizations, SSO, billing
- Concurrency in the execution loop
- Additional HTTP API endpoints
