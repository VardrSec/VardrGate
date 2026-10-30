# ADR 0028 — Literal job input for callers that resolve credentials

- Status: Accepted
- Date: 2026-10-30

## Context

`run --job` expands `${VAR}` references from Gate's process environment in
credential values, the request URL, headers, query, body, setup requests,
verification and assertion values (ADR 0006). That is the right behavior for a
job file an operator writes by hand.

VardrRunner is a different caller. It resolves each identity's credential
reference itself and writes the resolved value into a private job file. It
receives the rest of the case from VardrMap. Expanding that envelope again has
two consequences:

- A resolved secret that contains `${...}` is read as a reference, so the value
  Gate sends is not the value the operator supplied.
- A stored case can name any variable in the environment Gate inherits, such as
  the Runner's own API key, and have its value sent to the case's target.

## Decision

`run --job <file> --literal-job` decodes the envelope exactly as written. No
`${VAR}` reference is expanded anywhere in the case. `--literal-job` is accepted
only with `--job`.

Without the flag, every input path keeps its existing expansion: `policy run`,
`run --cases` and `run --job`.

Runner passes the flag on every Gate job. An older Gate binary rejects the
unknown flag before sending any request, the same compatibility guard as
`--require-identity-preflight` (ADR 0011).

A failed `{{name}}` substitution in an identity's credential value reports the
identity, not the value, matching the existing verifier message.

## Consequences

- A literal job sends `${...}` text as written. A caller using the flag must
  resolve every reference before writing the job.
- Setup captures (`{{name}}`) are unchanged: they are runtime values produced by
  the case's own setup steps, not environment variables.
- Deploy this Gate build before a Runner release that passes the flag.
- The flag does not restrict which credentials a caller resolves; that is the
  caller's responsibility.
