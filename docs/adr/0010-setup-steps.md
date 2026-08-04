# ADR 0010 — Setup steps and captured variables

- Status: Accepted
- Date: 2026-08-04

## Context

Two gaps looked separate and were the same gap.

**Authentication as a handshake.** Credentials were static strings supplied
ahead of time. An API where a caller logs in and receives a token could only be
tested by obtaining tokens out of band and pasting them in, where they expire
partway through a suite.

**Ownership that must be established first.** The sharpest BOLA test is: create
an object as user A, then attempt to read it as user B. VardrGate could only
target an object that already existed at a known identifier, so this class of
test was out of reach — and it is precisely the class a manual tester reaches
for first.

Both reduce to: *run a request before the one under test, and carry something
from its response into what follows.* Building them as separate mechanisms would
have produced two half-features with overlapping machinery.

## Decision

A policy may declare `setup`, a list of steps executed in order before the
request under test:

```yaml
setup:
  - name: login
    request:
      method: POST
      path: /auth/login
      body: '{"user":"owner","pass":"${OWNER_PASSWORD}"}'
    capture:
      token: data.access_token

  - name: create
    as: owner
    request:
      method: POST
      path: /objects
    capture:
      object_id: id
```

- `as` names the logical role to run the step as; empty sends no credentials,
  which is what a login request needs.
- `capture` binds a variable to a dotted path in the step's JSON response.
- `{{name}}` references a captured value, and is substituted into the request
  URL, headers, query parameters, body, the resource's object id, and each
  identity's credential value. That last target is what lets a login step supply
  the token an identity presents.

The syntax is deliberately `{{name}}` rather than `${name}`, which `secretref`
already uses for environment references (ADR 0006). Two sources of substitution
with two distinct syntaxes cannot be mistaken for each other.

**A failed step aborts the run** with `ErrSetupFailed`, which the CLI maps to
exit 3 — the same code as a target that could not be reached, because the
situation is the same: nothing was tested. A step counts as failed on a network
error, a 4xx/5xx response, or a capture path absent from the response. Degrading
gracefully was rejected: a test that proceeds without its precondition reports a
clean result for something it never checked, which is the failure mode the exit
codes exist to eliminate.

Values substituted into a JSON body are JSON-escaped and the result re-validated,
so a captured value containing a quote cannot silently corrupt the document.

## Consequences

- Create-then-read-as-another-identity is expressible, opening a class of
  object-level authorization test that a single stateless request cannot reach.
- APIs with token handshakes are testable without out-of-band credential
  wrangling.
- Steps run once each, in declared order — not once per identity. An API needing
  a separate login per caller declares one step per role. Verbose, but explicit,
  and it keeps the execution model something a reader can hold in their head.
- Setup steps are subject to the same mutation guard as the request under test
  (ADR 0008); a `POST` in setup needs the same acknowledgement.
- Not addressed: teardown, retries, and conditional steps. None has a
  demonstrated need, and each would expand setup from "a few requests first"
  into a workflow language, which is not what this tool is.
