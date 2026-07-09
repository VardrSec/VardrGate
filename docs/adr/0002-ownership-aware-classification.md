# ADR 0002 — Ownership-aware finding classification

- Status: Accepted
- Date: 2026-07-08

## Context

Earlier the engine deliberately refused to emit `potential_bola`: a
deny→allow result with only a `TenantID` present is too weak a signal to claim a
broken-object-level-authorization vulnerability. That decision was correct given
the model at the time — there was no way to know *whose* object was reached.

Phase 1 of the enterprise plan adds a resource-ownership model, which supplies
exactly the missing context: the owning identity, the object identifier, the
resource tenant, and (optionally) the required role.

## Decision

Add an optional `model.Resource` to the test case and classify a
deny→allow result into the most specific category the available context
supports, in this precedence order:

1. `cross_tenant_access` (critical) — the identity's tenant differs from the
   resource's tenant. Strongest isolation break.
2. `potential_bola` (high) — a non-owner identity reached an identified object
   (owner identity known and object type/id present).
3. `privilege_escalation` (high) — the identity's role ranks below the
   resource's `required_role` within the declared `role_hierarchy`.
4. `unexpected_access` (high) — no ownership context; conservative fallback,
   unchanged behaviour.

The engine never guesses a higher-severity category from a weak signal: every
elevated category requires explicit context in the test case. `TenantID` alone
on an identity still yields `unexpected_access`.

## Consequences

- `potential_bola`, `cross_tenant_access`, and `privilege_escalation` are now
  emitted, but only with sufficient context — no false-precision findings.
- Findings gained response-comparison evidence: the offending response is
  compared against a legitimate baseline (the owner, or any allowed identity),
  and a matching body is recorded as strong evidence the same data was exposed.
- The classification is deterministic and unit-tested per category.
