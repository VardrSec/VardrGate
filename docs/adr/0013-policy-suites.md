# ADR 0013 — Policy suites

- Status: Accepted
- Date: 2026-10-22

## Context

A policy describes one endpoint, and `vardrgate policy run` executes one policy
with one set of path parameters. Testing an API's authorization on every commit
means dozens of endpoints. The only way to do that was a shell loop around
`policy run`, which has three problems:

- **No combined exit code.** A loop either stops at the first failure, hiding
  every later result, or continues and has to aggregate exit codes by hand. The
  per-case exit 3 rule from ADR 0006 is the first thing a hand-written loop gets
  wrong.
- **No combined report.** Each invocation writes its own JSON, so a CI summary,
  a SARIF upload (ADR 0014) or a coverage view has to be stitched together.
- **Repeated bindings.** The identities file and base URL are passed again for
  every policy, and the identities file is rejected by `Compile` unless every
  identity's role appears in that policy's `expect` map. A shared file across
  policies with different roles therefore did not work at all.

`run --cases` already runs a suite of compiled test cases, but those are
generated scaffolds, not reviewed policies.

## Decision

`vardrgate policy run --suite <file>` runs a YAML suite:

```yaml
base: ${VARDRGATE_BASE_URL}
identities: identities.json
policies:
  - policy: policies/profile.policy.yaml
    params: {user_id: "42"}
  - policy: policies/orders.policy.yaml
    params: {user_id: "42"}
    tenant: tenant-a          # optional
    id: owner-orders          # optional
    identities: other.json    # optional per-entry override
```

- **Paths are relative to the suite file**, so a suite can be run from any
  working directory. Unknown fields are rejected, as in the policy parser.
- **`${VAR}` references** resolve in `base`, `params` and `tenant` through
  `internal/secretref`, so one committed suite runs against several
  environments. An unset variable is an error, for the reason ADR 0006 gives for
  credentials: an empty path segment silently tests a different endpoint.
- **`--base` overrides the suite's base.** Per-policy flags (`--policy`,
  `--identities`, `--param`, `--tenant`, `--id`) are rejected with `--suite`
  rather than ignored, so it is never unclear which value won.
- **Role binding.** Each entry binds only the identities whose role its policy
  names, which is what makes a shared identities file possible. A role in
  `expect` with no matching identity is an error: that control would otherwise
  go untested while the run reports clean.
- **Compile and validate everything first.** Every entry is loaded, compiled
  and passed through engine validation before any request is sent, and all
  problems are reported together, as `run --cases` already does. Compilation
  alone is not enough: an unconfirmed unsafe method compiles but fails
  validation, and finding that at entry five would mean entries one to four had
  already sent live traffic. Test case ids must be unique within a suite,
  because the unreached list and SARIF fingerprints are keyed by id.
- **One failed entry does not stop the suite.** If an entry fails at run time,
  for example a setup step returns an error status, it is recorded with an
  `error` field and reported as not run in every format, the remaining entries
  still run, all outputs are written, and the suite exits 3. A single
  `--policy` run keeps returning its error directly.
- **One run, one gate.** Entries execute sequentially (`docs/mvp.md`), results
  are emitted as a JSON array matching `run --cases`, and the existing `gate`
  decides a single exit code, still evaluating exit 3 per case.

The logic lives in a new `internal/suite` package. The command layer only loads,
compiles and runs.

## Consequences

- A whole API's authorization runs as one CI step with one exit code and one
  report. This is what the GitHub Action (ADR 0015) runs.
- `policy run --policy` is unchanged: same flags, same single-object JSON output,
  and identities whose role the policy does not name are still an error there.
- A suite with a role that no identity holds now fails at compile time. This is
  deliberate and stricter than single-policy mode, where every identity must be
  named but not every role must be bound.
- No dependency is added. The suite format is YAML, parsed with the existing
  `gopkg.in/yaml.v3`.
- Suites do not add concurrency, retries, ordering between entries, or shared
  setup steps. Each entry is an independent policy run. Shared state across
  entries would turn the suite into a workflow language (ADR 0010).
