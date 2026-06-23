Technology

Use:

Go 1.24 or newer
Go standard library wherever practical
net/http for HTTP clients and server functionality
http.ServeMux for the initial API router
log/slog for structured logging
Go's built-in testing package
httptest for HTTP tests
go vet and go test
golangci-lint only after the initial project structure is working

Do not add a frontend yet.

Do not add PostgreSQL, Redis, Docker, background workers, Kubernetes, message queues, or cloud deployment unless explicitly requested.

Do not add a third-party framework when the Go standard library is sufficient.

Architecture

Keep the initial codebase small and modular.

Expected structure:

cmd/vardrgate/
└── main.go

internal/
├── api/
│   ├── handler.go
│   └── handler_test.go
├── model/
│   └── model.go
├── client/
│   ├── client.go
│   └── client_test.go
├── compare/
│   ├── compare.go
│   └── compare_test.go
└── engine/
    ├── engine.go
    └── engine_test.go

Responsibilities:

internal/model

Define typed structs and constants for:

Identity
Credential
RequestTemplate
ExpectedAccess
ExecutionResult
ComparisonResult
Finding
AuthorizationTestCase

Avoid untyped maps where a concrete struct is appropriate.

Use custom string types and constants for values such as:

credential type
expected access decision
confidence
severity
finding category

Add JSON tags to structures that will be exposed through the API.

Do not expose credential values in response models.

internal/client

Responsible only for HTTP request execution.

Requirements:

Use net/http.
Accept an injected http.Client.
Support common HTTP methods.
Support headers, query parameters, and JSON bodies.
Apply identity credentials without modifying unrelated request data.
Capture status code, selected headers, response body, duration, and errors.
Use request contexts and configurable timeouts.
Do not follow redirects unless explicitly configured.
Do not disable TLS verification by default.
Do not log raw credentials.
internal/compare

Compare execution results across identities.

Initial comparisons should include:

Status-code differences
Response-body equality
Normalized JSON equality
Response-size differences
Presence or absence of configured sensitive fields

Do not claim a vulnerability based only on one weak signal.

internal/engine

Coordinate authorization test execution.

The engine should:

Validate the test case.
Execute the request for each configured identity.
Record evidence.
Compare expected and observed access.
Return findings and raw execution results.

Keep request execution separate from finding evaluation.

internal/api

Expose a minimal HTTP API.

Initial endpoints:

GET /health
POST /tests/execute

Use http.ServeMux initially.

Do not add user accounts, dashboards, projects, organizations, or billing.

cmd/vardrgate

Contains only application startup and dependency wiring.

Do not place business logic in main.go.

Go Development Rules

When making changes:

Inspect the existing code before editing.
Preserve working behavior.
Make the smallest coherent change.
Do not rewrite unrelated files.
Do not introduce speculative interfaces.
Define interfaces where substitution is needed, not automatically for every struct.
Do not add dependencies without explaining why.
Add or update tests for behavioral changes.
Run gofmt on changed Go files.
Run go test ./....
Run go vet ./....
Report exactly what changed and what remains.
Stop when the requested task is complete.

Do not implement future roadmap features unless explicitly requested.

Go Code Quality

Use:

Small packages with clear ownership
Explicit constructors when initialization matters
Context propagation for network operations
Sentinel errors or typed errors when callers need to distinguish failures
Table-driven tests
httptest.Server or custom RoundTripper implementations for HTTP tests
Dependency injection for HTTP clients, clocks, and other nondeterministic behavior where necessary
Defensive copying of sensitive maps where mutation could cause security problems

Avoid:

Global mutable state
panic for recoverable errors
Empty interfaces unless genuinely necessary
Premature generic abstractions
Interfaces defined far away from their consumers
Large multipurpose packages
Generic utils packages
Hidden goroutine lifecycles
Unbounded concurrency
Logging secrets
Ignoring returned errors
Initial Development Sequence

Implement only one stage at a time.

Stage 1
Initialize the Go module
Create the application entry point
Create the HTTP server
Add GET /health
Define core domain models
Add basic tests
Add a graceful shutdown path
Stage 2
Build the safe HTTP execution client
Apply credentials
Add credential redaction
Add mocked HTTP tests
Stage 3
Build the authorization execution engine
Evaluate expected versus observed access
Add engine tests
Stage 4
Implement response comparison
Generate initial potential-BOLA findings
Add evidence references
Stage 5
Add POST /tests/execute
Add end-to-end HTTP API tests
Add an example test definition

Do not begin a later stage until the current stage passes its tests.
