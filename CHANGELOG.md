# Changelog

All notable changes to VardrGate are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
