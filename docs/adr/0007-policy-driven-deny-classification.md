# ADR 0007 — Policy-driven deny classification and tenant discovery

- Status: Accepted
- Date: 2026-08-04

## Context

The policy format declared two things the engine never received.

`response.deny_status` listed the status codes an API uses to refuse a caller.
It was parsed, validated as a known field, and dropped on the floor in
`Compile`. Meanwhile `model.ClassifyOutcome` hardcoded deny as 401 or 403 and
treated 404 as ambiguous — correct as a default, since a 404 usually means the
object is not there. But an API that returns 404 specifically to avoid
confirming that an object exists is following a deliberate and common
convention, and under the default mapping VardrGate silently declined to
evaluate every one of those responses. The example policy shipped with
`deny_status: [401, 403, 404]`, so the documented example was teaching a rule
the engine contradicted.

`api.resource.tenant_field` named the response field carrying an object's
tenant. It was parsed and never compiled. `cross_tenant_access` therefore
required the caller to already know which tenant the target object belonged to
and to pass it in as a binding — which is the thing you are usually trying to
find out.

## Decision

**`deny_status` compiles to `AuthorizationTestCase.DenyStatuses`** and
`ClassifyOutcomeWith` treats any listed code as an explicit deny. The declared
convention never overrides a 2xx, and validation rejects a 2xx in the list: a
success code cannot mean denied. Execution errors still win over everything.

The engine reclassifies the execution record itself, not just the finding, so a
single result document cannot contradict itself — `executions[].observed_outcome`
and the `observed_outcome=` evidence on a finding drawn from it always agree.
Findings carry `deny_status_declared=` evidence when a convention is in force,
so a reader can see why a 404 was read as a denial.

**`tenant_field` compiles to `Resource.TenantField`**, and when no tenant is
bound the engine reads that field from the *offending* identity's own response
body. A caller in tenant B that received an object stamped `tenant-a` is a
self-evidencing isolation break: the proof is in the response the caller got. A
bound `resource.tenant_id` still wins when present, since an explicit binding is
a stronger statement than an observation.

Both remain opt-in and both fail closed. A policy that declares neither behaves
exactly as before. A `tenant_field` naming a field absent from the response
yields no tenant and the classification falls back through the existing
precedence to `potential_bola` or `unexpected_access` — consistent with ADR 0002,
the engine never guesses a higher-severity category from a weak signal.

## Consequences

- `cross_tenant_access` is reachable without knowing the target object's tenant
  in advance, which is what makes it useful during discovery rather than only
  during regression.
- An API that hides existence behind 404 can now be tested. Declaring
  `deny_status: [404]` means an allowed identity receiving a 404 becomes an
  `authorization_mismatch` — previously silence.
- Two fields that a reader could reasonably assume were doing something now do
  it. The alternative considered was deleting both from the policy struct and
  the example; wiring them was preferred because the behaviors are ones the
  tool needs, not merely ones the format happened to name.
- `compare.FieldValue` is new: a recursive, case-insensitive scalar lookup in a
  JSON body. Field order is not preserved by decoding, so a field appearing at
  several depths has no defined winner; it is documented for identifiers that
  appear once.
