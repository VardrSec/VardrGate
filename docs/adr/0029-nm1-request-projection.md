# ADR 0029: Opt-in NM-1 fixed-request projection

Status: Accepted direction, 2026-11-01. No dependency additions.

Runner validates signed permission, approval, scope, plan, ownership, grants and
durable single use. Gate's optional `gate-fixed-http/1` projection constrains actual
HTTP dispatch; it does not issue permission or replace existing engine safeguards.
The existing CLI/API/library paths remain unchanged without a projection.

`run --job --literal-job --request-guard FILE` requires an unchanged literal job,
matching binary hash and exact effective options. Overrides cannot widen it.
The existing executor boundary labels setup, preflight, resource, verification and
reset. The HTTP client checks phase, actor, method, URL, application headers, query,
body and atomic dispatch count before DNS/TLS/target traffic. Existing private-target
opt-in, SSRF, TLS, mutation and evidence semantics remain mandatory.

Counts include skipped identities, reader preflight and repeated readback/reset.
They measure logical dispatches, not packets or transport retries. Setup may run
before failed preflight; report that accurately. CORS changes an approved header,
not the destination. Captures/substitutions are unsupported by Runner's initial
profile. Missing guard capability means no Strict request-enforcement claim.
Supplying a projection to standalone Gate is not cryptographic permission checking;
Runner remains that boundary.

Tests cover auxiliary traffic, request/phase/count mismatch, concurrent reservation,
malformed/duplicate/oversize input and binary binding. No worker, global budget,
managed lease/cancellation or workflow language is added. Rollback removes the
additive flag/projection. Existing hashes/results are unchanged; an older Gate
refuses a required unknown flag before target traffic.
