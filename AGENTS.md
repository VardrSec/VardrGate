# VardrGate — agent instructions

Shared rules for every coding agent (Claude Code imports this file from `CLAUDE.md`;
Codex reads it directly). They must hold even when this repository is cloned on its own.

VardrGate is an API authorization assurance engine: it replays one HTTP request as
several identities, classifies each observed outcome against the expected access
decision, and returns evidence-backed findings. It runs as an HTTP API
(`POST /tests/execute`), a policy/suite CLI and GitHub Action, an offline job CLI
(`run --job`/`--cases`) or a library. It is one component of the VardrSec platform:
VardrMap is the engagement control plane and VardrRunner drives this binary.

Where to look: [README](README.md) (usage, security defaults, layout),
[`docs/architecture.md`](docs/architecture.md) (package responsibilities, finding
rules, CLI surface), [`docs/adr/`](docs/adr/) (decisions 0001–0028), and the guides
in `docs/` (`write-verification.md`, `authorization-regressions.md`,
`policy-assisted-discovery.md`, `denial-profiles.md`, `identity-evidence.md`,
`strict-ci.md`, `response-assertions.md`).

## Safety floor
- Execute only what the operator explicitly asked for, against authorized or local
  targets. No background workers or unattended execution.
- Never log, print, commit or report credentials, tokens or response values.
- No force-push, history rewrite, release tag, image publication or deployment
  without explicit authorization. Merging a feature PR is not release permission.
- `git fetch && git status -sb` and `gh run list --limit 1` before starting work.
- No AI attribution: no `Co-Authored-By` trailers or "Generated with" lines.

## Technology and dependencies
- Go version as in `go.mod`; standard library plus `gopkg.in/yaml.v3` (ADR 0001)
  and `modernc.org/sqlite` (ADR 0004). **No further dependency without an ADR.**
- `net/http`, `http.ServeMux`, `log/slog`.
- Do not add PostgreSQL, Redis, Docker, Kubernetes, message queues, background
  workers or cloud deployment unless explicitly requested.

## Network and credential invariants
- **SSRF:** `urlcheck.Check` accepts only `http`/`https`. Hostnames are resolved once
  inside `buildHTTPClient`'s `DialContext`; every returned IP passes `CheckIP` and the
  connection goes to the pre-validated address — never a second DNS resolution.
  Always blocked (even with `AllowPrivateTargets`): unspecified and 0.0.0.0/8,
  link-local, cloud metadata (incl. 100.100.100.200), multicast. Blocked unless
  private targets are opted in: loopback, RFC-1918/4193, 100.64.0.0/10,
  198.18.0.0/15. NAT64/6to4 are judged by their embedded IPv4.
- Redirects are not followed; TLS verification on; default client 30 s timeout and
  5 MB body cap; `context.WithTimeout` cancel always deferred.
- `Credential.Value` is `json:"-"` with a custom `UnmarshalJSON`: accepted as input,
  never written to any response, finding or log. Use `client.Redact` in errors.
- **`${VAR}` references** (`secretref`): an unset or empty variable is an **error**,
  never an empty string — a blank token silently turns an authenticated identity
  into an anonymous one. All input paths (policy identities, job, `--cases`) behave
  identically, except `run --job --literal-job`, which uses the envelope exactly as
  written for callers (Runner) that resolve credentials themselves (ADR 0028).
- Observed values stay in memory; evidence records field names, hashes and fixed
  reason codes, never secrets or response values. Sensitive-field matching is on
  whole normalized names, never substrings. HAR parsing is bounded; only field
  names and capture indices leave memory. Markdown reports escape untrusted
  evidence; SARIF fingerprints hash only case id, category and identity.
- HTTP API: 1 MB `MaxBytesReader`, single decoder with trailing-data rejection,
  stable error codes. Per-tenant bearer keys (constant-time compare) protect
  `/tests/execute`, `/jobs`, `/runner`, `/audit`; cross-tenant access returns 404
  (ADR 0005). Only `/health` is open. Serve binds loopback by default.

## Authorization-assessment invariants
- **Outcome vocabulary:** every identity is `allowed`, `denied`, `inconclusive` or
  `skipped`. A 401 for a deny-expected caller that sent credentials is
  inconclusive, never a verified denial (ADR 0019; opt-out only via
  `unauthorized_is_denial`). Unavailable resources, ambiguous outcomes (undeclared
  404, 5xx, 3xx) and failed preflight are inconclusive. Failed authentication is
  never evidence that authorization is correct. Exit 0 does not mean secure.
- **Elevated finding categories** (`missing_authentication`, `cross_tenant_access`,
  `potential_bola`, `privilege_escalation`) require explicit context in the case
  (ADR 0002). The engine never guesses from a weak signal; the fallback is
  `unexpected_access`. Execution errors suppress findings for that identity.
- **Classification is centralized** in `engine.classify`; `deny_when` outranks the
  status line, reviewed `deny_status` reclassifies the execution record too, and
  response assertions are authoritative when present (ADR 0007/0008/0016).
- **Mutation safety:** unsafe methods (POST/PUT/PATCH/DELETE), including setup
  steps, fail validation unless `mutating` / `--allow-mutating` is set. Refuse,
  don't warn — the failure mode is destroyed data (ADR 0008).
- **Generated cases are candidates.** `gen`, `discover` and HAR hypotheses emit
  review-only cases whose decisions are `TODO`, which `policy.toDecision` rejects,
  so a draft cannot execute until a human types a decision (ADR 0009/0022). Never
  infer an executable allow/deny expectation from traffic, an OpenAPI document or
  a successful response. Inference may inform authoring, never produce an assertion.
- **Write-effect verification** (`changed`/`created`/`deleted`; ADR
  0017/0018/0021/0024/0027): independent readback by a separate reader identity;
  a demonstrated allow-expected positive control before any denial; a declared
  reviewed, synchronous, isolated environment; creation starts absent, deletion
  starts present; repeated attempts need a reviewed fixture reset reproducing the
  first stable baseline. A write response alone proves nothing; if causality cannot
  be established (202, unreadable state, missing control) the result is inconclusive.
- **Identity preflight** (ADR 0011/0020): a reviewed same-origin GET with explicit
  public principal matches, after setup and before resource testing. Any failure
  returns safe diagnostics, no executions/findings and exit 3. Never retain response
  values, headers or raw errors, infer expiry, or treat a probe as a baseline.
- **Regressions** (`regression save`, ADR 0025/0027): only a reviewed, unresolved
  template, literal credentials refused, bound to a result by the
  `sha256-json-compact-v1:` digest; never overwrites. The digest correlates source
  and result; it is not cryptographic attestation and cannot detect tampering.

## Contracts with Runner and Map
- `engine.Result` JSON (`test_case_id`, `executions`, `findings`, `assessments`) is
  the Runner/Map contract: a clean run serializes `[]`, not `null`. Preserve fields.
- Exit codes: `0` clean, `1` usage/input error, `2` findings at or above
  `--fail-on` (default `none`), `3` a case reached nothing (per case; outranks
  findings), `4` inconclusive only with `--fail-on-inconclusive`. Any unrecognized
  argument is an error, never a fallthrough to `serve`. `Result.PreflightFailed`,
  `Unreached` and `Inconclusive` are the single definitions every report and gate
  uses; no format may present an inconclusive or unreached case as a pass.
- With the default format and `--out`, stdout stays empty (Runner's
  `run --job --out` contract); outputs are written before the exit code is decided.
- Runner adds `case_hash` and Map verifies it against the claim-time snapshot; Gate
  does not compute it or know Map's evidence keys. `--require-identity-preflight`
  is Runner's compatibility guard. Gate's standalone queue is separate from Map's.
- Map/Runner API playbooks are guidance, not Gate policies: they do not execute,
  mark coverage or replace reviewed expectations.
- Preserve the local private-target opt-in, declared deny conventions, mutation
  safety and setup-failure behavior. Automatic login refresh and a general
  workflow language remain future work.

## Development rules
- Read the files you change; make the smallest coherent change; don't rewrite
  unrelated files or add speculative interfaces.
- Every behavior change ships tests (table-driven; `httptest.Server` or
  `roundTripFunc`; inject `http.Client`, clocks and executors) and a `CHANGELOG.md`
  entry; non-trivial decisions get an ADR.
- Code changes: `gofmt -l .` clean, `go vet ./...`, `go test -race ./...`. Docs-only
  changes: review the diff, check Markdown links and `git diff --check`.
- Avoid global mutable state, `panic` for recoverable errors, hidden goroutine
  lifecycles, unbounded concurrency, ignored errors and logging secrets. The
  execution loop is sequential by decision (`docs/mvp.md`).
- Releases: `VERSION`, changelog and `docs/releases/vX.Y.Z.md` land in a PR; a tag
  is pushed only with explicit release authorization (ADR 0012).

## Not in scope unless asked
PostgreSQL `Store`; orgs/projects/environments or secret providers; a frontend;
new vulnerability packs (rate-limit, JWT, GraphQL); live crawling in `discover`;
teardown, retries or conditional `setup` steps (ADR 0010); JUnit output (ADR 0014);
concurrency or shared setup across suite entries (ADR 0013); user accounts, SSO,
billing; additional HTTP API endpoints.
