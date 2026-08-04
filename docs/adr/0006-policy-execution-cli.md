# ADR 0006 — Policy execution CLI, credential references, and exit-code gating

- Status: Accepted
- Date: 2026-08-04

## Context

Three claims were being made that the binary did not support.

**The policy format was unreachable.** `internal/policy` parsed a YAML control
and compiled it into a runnable test case, and nothing imported it outside its
own test. There was no CLI verb and no HTTP route that accepted a policy file.
The format was the headline idea — write the authorization rules down once, run
them against any environment — and the only way to exercise it was to import the
package into a Go program.

**`run` could not fail.** `runJob` never inspected `result.Findings`, so the
process exited 0 whatever came back. It also exited 0 when every identity failed
to connect: pointing the bundled example at a host that was not running produced
three network errors and a success exit. Wiring that into CI produced a green
check that had tested nothing, which is worse than no check, because it reads as
evidence.

**The importers produced files nothing accepted.** `gen` emits a JSON array of
test cases; `run` took a single job envelope. The generated file had no command
that would take it back, so `gen → edit → run` was not a workflow.

A fourth problem sat underneath all of them: a policy binding is meant to be
committed next to the policy it binds, but running a real authorization test
needs real credentials.

## Decision

**`vardrgate policy run`** compiles a policy against one environment and
executes it: `--policy`, `--base`, `--param name=value` (repeatable),
`--identities`, and optional `--tenant` and `--id`. Identities come from a JSON
array whose `role` matches a key in the policy's `expect` map — that binding is
what connects a concrete credential to a logical role in the control. The
subcommand form (`policy run` rather than a top-level `policy` verb) leaves room
for `policy validate` without another top-level word.

**`${VAR}` references in credential values** (`internal/secretref`) resolve
against the process environment on every input path — policy bindings, generated
suites, and job envelopes. A reference lets a committed file name the secret it
needs without containing it. An unset or empty variable is an error rather than
an empty string: a blank token silently turns an authenticated identity into an
anonymous one, which inverts the meaning of the test while still reporting a
clean run. `gen` writes these placeholders into the files it generates, because
`model.Credential` never marshals a value and a scaffold with no `value` key at
all gives the reader nowhere to put the token.

**`--fail-on <severity>`** with distinct exit codes:

| Code | Meaning |
|---|---|
| 0 | Ran; nothing at or above the threshold |
| 1 | Usage or input error |
| 2 | Findings at or above the threshold |
| 3 | A case reached nothing; every identity failed to connect |

The threshold defaults to `none`, so adding the flag to an existing pipeline is
deliberate. Exit 3 is not gated on the threshold and outranks findings: a
finding count of zero means nothing when no request succeeded. It is evaluated
per case rather than across the suite, because a target that dies after the
first case leaves the rest reaching nothing while the suite-wide failure ratio
still looks partial — the same green-but-tested-nothing result, one level up.

**`run --cases`** executes a JSON array of test cases and emits an array of
results, closing the loop with `gen`. The whole suite is validated
(`engine.Validate`) before any of it runs, so every authoring error is reported
together rather than one execution at a time.

**`vardrgate demo`** runs the bundled policy against a deliberately broken
loopback fixture (`internal/demo`). The quickstart now proves the tool works
with no setup, no credentials, and no network egress.

**Unknown arguments are errors.** Dispatch previously fell through to `serve`
for anything it did not recognise, so `vardrgate --help` started a web server on
:8080. `help`, `version`, and unknown commands are now handled explicitly; a
bare invocation still serves, which is the documented default.

## Consequences

- The policy format is reachable from the command line, and the example policy
  in `examples/` is now something a reader can run.
- **Breaking:** `vardrgate run` against an unreachable target exits 3 where it
  previously exited 0. Any pipeline that depended on the old behaviour was
  passing without testing anything.
- **Breaking:** `gen` output now contains a `value` key holding a `${VAR}`
  placeholder. Files generated before this change still run; they simply
  validate as missing a credential, which is what they always were.
- `internal/secretref` is a new package and `internal/demo` is a new package.
  Neither adds a dependency; both are standard library only.
- `engine.Validate` is exported so a caller holding a suite can check it without
  executing it.
- Findings are still not written to any format other than JSON. SARIF and JUnit
  output are not part of this decision.
