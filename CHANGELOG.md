# Changelog

All notable changes to VardrGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
