# ADR 0001 — YAML policy input and the `vardrgate run` CLI contract

- Status: Accepted
- Date: 2026-07-08

## Context

VardrGate began as an HTTP service that runs a single authorization test case
(`POST /tests/execute`). The enterprise direction (see `enterprise-platform.md`)
requires two things the service alone does not provide:

1. **Declarative, reusable controls.** A test case bound to concrete tokens and
   URLs is not reusable across environments. Enterprises need to express an
   authorization control once ("only the owner may read this profile") and prove
   it repeatedly in dev, staging, and prod.
2. **An execution contract for VardrRunner.** Customers will not point a cloud
   service at their internal APIs. VardrRunner already polls a backend, claims
   jobs, runs local tools, and uploads results. VardrGate should be *invoked by*
   VardrRunner, not reimplement a second agent.

## Decision

### Policy files (YAML)

Add an `internal/policy` package that parses a declarative policy and compiles
it, given bindings (base URL, path params, concrete identities), into a
`model.AuthorizationTestCase`. The policy format is the one in
`enterprise-platform.md` (`api`/`expect`/`response`).

We accept a single new dependency, `gopkg.in/yaml.v3`, to parse it. This is a
deliberate exception to the "standard library only" rule in the charter,
justified because:

- The documented policy format is YAML; hand-authored security controls are far
  more readable in YAML than JSON.
- `yaml.v3` is the de-facto standard, widely audited, and has no transitive
  dependencies.

Unknown fields are rejected (`KnownFields(true)`) so typos in a control file
fail loudly rather than silently disabling a check.

### `vardrgate run --job job.json --out result.json`

Add a `run` subcommand (the binary still defaults to `serve`). It reads a job
envelope (`internal/job`), executes the embedded test case with the job's
execution settings, and writes the sanitized `engine.Result` as JSON. The
envelope matches the shape VardrRunner sends (`type`, `program_id`,
`config.test_case`, `config.execution`). A bare test case (no `config` key) is
also accepted for convenience in CI.

The boundary between VardrGate and VardrRunner is this file/CLI contract only —
no shared code, no imported internals.

## Consequences

- One external dependency is introduced; `go.mod`/`go.sum` now list `yaml.v3`.
- Policies and jobs are new input formats with their own validation and tests.
- The CLI makes VardrGate usable in CI and from VardrRunner without the HTTP
  server, which is the first concrete step toward the platform architecture.
- Credential values remain write-only: they are read from job/policy input but
  never serialized into results, matching the existing model guarantees.
