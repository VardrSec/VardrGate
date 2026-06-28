# VardrGate — Engineering Reference

## What this project is

VardrGate is an API authorization test runner. It accepts a test case, executes a single HTTP request as multiple identities, classifies each observed outcome against the expected access decision, and returns structured findings. It is a backend service with no frontend, no database, and no external dependencies.

## Technology

- Go 1.24 or newer
- Go standard library only — no third-party frameworks
- `net/http` for HTTP clients and server
- `http.ServeMux` for routing
- `log/slog` for structured logging
- `go test`, `go vet`, `gofmt` before every commit

Do not add PostgreSQL, Redis, Docker, Kubernetes, message queues, background workers, OpenAPI importers, or cloud deployment unless explicitly requested.

## Repository layout

```
cmd/vardrgate/
└── main.go                  startup, env config, dependency wiring, graceful shutdown

internal/
├── api/
│   ├── handler.go           GET /health, POST /tests/execute
│   └── handler_test.go
├── client/
│   ├── client.go            HTTP execution, credential application, SSRF protection
│   └── client_test.go
├── compare/
│   ├── compare.go           status-code, body, JSON, and sensitive-field comparison
│   └── compare_test.go
├── engine/
│   ├── engine.go            test-case validation, execution loop, finding evaluation
│   └── engine_test.go
├── model/
│   ├── model.go             all domain types, constants, ClassifyOutcome
│   └── model_test.go        credential marshal/unmarshal, ClassifyOutcome table
└── urlcheck/
    ├── urlcheck.go          URL scheme validation, CheckIP, DialContext-ready exports
    └── urlcheck_test.go

docs/
└── mvp.md                   MVP workflow definition

examples/
├── bola_check.json          three-identity unauthorized-access scenario
└── ownership_check.json     local demo against an httptest-style target
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

Finding rules:
- `unexpected_access` (severity: high): expected `deny`, observed `allow` (2xx).
- `authorization_mismatch` (severity: low): expected `allow`, observed `deny` (401/403).
- `potential_bola` is **not emitted yet** — it requires resource-ownership context (owner identity, target tenant, object ID) that is not yet modelled. `TenantID` alone is insufficient.
- Execution errors suppress findings for that identity (single weak signal).
- `decision: skip` records execution but emits no finding.
- Ambiguous outcomes (404, 5xx, 3xx) when expected `deny` produce no finding.

The `Executor` interface is defined in the engine package and satisfied by `*client.Client`. Tests use a `stubExecutor`.

`engine.Result` has JSON tags (`test_case_id`, `executions`, `findings`).

### `internal/compare`

Compares two `ExecutionResult` values. Standalone utilities — not yet wired into the engine's finding evaluation.

Comparisons: status-code equality, raw body equality, normalised JSON equality (key-order independent), response-size difference, presence/absence of sensitive fields (`token`, `secret`, `api_key`, etc.).

`Evidence(a, b, cr)` extracts comparison output into evidence strings ready to attach to a `Finding`.

### `internal/api`

Exposes the HTTP API. No business logic.

- `New(log, eng)` registers routes on a `ServeMux` and returns a `Handler`.
- `GET /health` — 200 `{"status":"ok"}`.
- `POST /tests/execute` — 1 MB `MaxBytesReader`, single-decoder, second `Decode` must return `io.EOF` (rejects trailing content), 400/413/422/405 on error.
- `writeJSON` and `writeError` are shared helpers; all responses carry `Content-Type: application/json`.

### `cmd/vardrgate`

Startup only. Reads `PORT` (1–65535, default 8080) and `ALLOW_PRIVATE_TARGETS` (bool, default false) from the environment. Wires `client → engine → handler`. HTTP server has `ReadHeaderTimeout` 5 s, `ReadTimeout` 30 s, `WriteTimeout` 60 s, `IdleTimeout` 120 s. Graceful shutdown waits up to 10 s on `SIGINT`/`SIGTERM`.

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

- Frontend or dashboard
- Database or persistence layer
- OpenAPI / Swagger import
- AI-agent features
- User accounts, organizations, billing
- `potential_bola` findings (needs resource-ownership model first)
- Concurrency in the execution loop
- Additional API endpoints
