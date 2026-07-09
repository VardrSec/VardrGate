# ADR 0005 — Per-tenant API keys and job-queue isolation

- Status: Accepted
- Date: 2026-07-09

## Context

Phase 3 of `enterprise-platform.md` calls for a "control plane API with tenant
isolation." The job queue (ADR 0003) launched with a single shared bearer token:
every authenticated caller could see and act on every job. For a multi-customer
backend that is unacceptable — one tenant must never observe or touch another's
jobs, nor see their existence.

The full control plane (organizations, projects, environments, RBAC, SSO/SCIM,
PostgreSQL) is a large body of work. The first isolation primitive that delivers
real value and is fully testable here is tenant-scoped authentication over the
existing queue.

## Decision

Authenticate with per-tenant API keys and scope every queue operation to the
caller's tenant.

- Keys are configured as `VARDRGATE_API_KEYS="tenant-a:key1,tenant-b:key2"`. A
  single `VARDRGATE_API_KEY` still works and maps to the `default` tenant. The
  handler holds a token→tenant map; `resolveTenant` compares the presented bearer
  token against every key in constant time and returns the matching tenant.
- Each job records the `Tenant` of the caller that created it. `GET /jobs/pending`
  and `GET /audit` return only the caller's tenant; `GET /jobs/{id}`, claim,
  complete, events, and upload go through `requireOwned`, which returns **404**
  for both a missing job and a cross-tenant job so existence is never revealed.
- Audit entries are tagged with the tenant and filtered on read.

## Consequences

- Tenants are isolated at the queue level: verified by tests where tenant B
  cannot list, read, claim, complete, event, or upload tenant A's job, and sees
  an empty audit log.
- Isolation is enforced in the API layer against the tenant stamped on each job;
  it holds for both the in-memory and SQLite stores without store changes.
- This is authentication-level isolation, not yet a full control plane. Orgs,
  projects, environments, per-tenant rate limits, RBAC, and SSO remain future
  Phase 3/4 work. Key management is env-based for now; a persistent key/identity
  store arrives with the control plane.
- 404-on-cross-tenant avoids leaking job existence, at the cost that a tenant
  cannot distinguish "never existed" from "not yours" — the correct trade-off for
  isolation.
