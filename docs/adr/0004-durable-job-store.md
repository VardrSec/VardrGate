# ADR 0004 — Durable job store (SQLite), Postgres-ready

- Status: Accepted
- Date: 2026-07-09

## Context

The runner job queue (ADR 0003) launched with an in-memory `Store`: jobs are lost
on restart. That is fine for CI and local development but not for a backend that
schedules and tracks real work — a deploy or crash would silently drop the queue.

Phase 3 of `enterprise-platform.md` calls for PostgreSQL-backed persistence. A
real PostgreSQL integration cannot be exercised in this project's build/test
sandbox (no database to connect to), and committing an unverifiable database
implementation is not acceptable.

## Decision

Add a durable `Store` implementation backed by SQLite via `modernc.org/sqlite`
(a pure-Go driver — no cgo, so it builds and tests everywhere the rest of the
project does). It implements the exact same `Store` interface as `Memory`, so it
is a drop-in selected at startup:

- `VARDRGATE_DB=<path>` opens/creates a durable SQLite database at that path.
- Unset keeps the in-memory store (existing behaviour), with a startup warning.

Jobs and runners are stored as JSON documents keyed by id/hostname, with `status`
and `created_at` promoted to columns for filtering and ordering. A single mutex
plus `SetMaxOpenConns(1)` and WAL mode serializes access and avoids "database is
locked" races; the queue's throughput needs are modest. Claim atomicity is
preserved (load → check `pending` → update under the lock).

The same conformance test suite runs against both `Memory` and `SQLite`, and a
dedicated test verifies a job survives closing and reopening the database.

## Consequences

- Jobs now survive a restart when `VARDRGATE_DB` is set; verified end to end.
- One new dependency (`modernc.org/sqlite`) and its pure-Go transitive modules.
- PostgreSQL remains the intended production driver. Because callers depend only
  on the `Store` interface, a `pgstore` can be added later without touching the
  API, engine, or CLI — and can be tested wherever a Postgres instance is
  available. SQLite persistence closes the durability gap in the meantime.
- The document-per-row schema is intentionally simple; the richer relational
  model (orgs/projects/environments/findings) arrives with the control-plane work
  and may use its own tables.
