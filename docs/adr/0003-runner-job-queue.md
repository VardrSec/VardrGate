# ADR 0003 — Runner job queue and lifecycle endpoints

- Status: Accepted
- Date: 2026-07-08

## Context

Phase 3 of `enterprise-platform.md` connects VardrGate to VardrRunner: runners
poll for pending jobs, claim them atomically, stream events, upload results, and
mark them done or failed. VardrRunner already speaks a fixed HTTP contract to its
backend (`vardrrunner/api.py`): `GET /jobs/pending`, `POST /jobs/{id}/claim`,
`PATCH /jobs/{id}`, `POST /jobs/{id}/events`, `POST /runner/heartbeat`, all with
`Authorization: Bearer <key>`.

The full Phase 3 also lists PostgreSQL-backed orgs/projects/environments, tenant
isolation, secret providers, and audit logs. Building persistence and a
multi-tenant control plane before the queue's data model is settled would be
premature — the doc itself says "add storage only after the data model is clear
enough to survive enterprise use."

## Decision

Introduce the runner job queue as the first Phase 3 slice, in two parts:

1. **`internal/store`** — a `Store` interface (jobs + runner registry) with a
   thread-safe in-memory implementation (`Memory`). Job statuses are
   `pending → claimed → running → done|failed`. Claims are atomic: a second claim
   of the same job returns `ErrAlreadyClaimed`.

2. **HTTP endpoints** on the existing server, shaped to match VardrRunner's
   client exactly so it is a drop-in backend:
   - `POST /jobs` (enqueue), `GET /jobs/pending`, `GET /jobs/{id}`
   - `POST /jobs/{id}/claim` (200, or 409 if already claimed)
   - `PATCH /jobs/{id}` and `POST /jobs/{id}/done` / `/failed` (completion)
   - `POST /jobs/{id}/events`, `POST /jobs/{id}/upload`
   - `POST /runner/heartbeat`

   These use Go 1.22 method+path routing. A bearer token
   (`VARDRGATE_API_KEY`) is required on `/jobs` and `/runner`; `/health` and
   `/tests/execute` stay open. An unset key disables auth for local dev and logs
   a warning at startup.

Persistence (a PostgreSQL `Store`) is deferred; it now implements a settled
interface rather than driving the design.

## Consequences

- VardrRunner can drive VardrGate today via its existing client, pointed at the
  VardrGate URL — no VardrRunner changes are required for the backend to work.
- Jobs live in memory: they do not survive a restart. This is acceptable for the
  current prototype and CI; durability arrives with the PostgreSQL `Store`.
- Result uploads must be valid JSON and are size-capped (10 MB); credential
  values never appear in results by the existing model guarantees.
- Multi-tenancy, orgs/projects, secret providers, and audit logs remain future
  Phase 3 work and are intentionally not implemented here.
