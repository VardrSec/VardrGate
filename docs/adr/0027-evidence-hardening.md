# 0027: Bind regression sources and bound verification work

Status: Accepted

## Decision

The CLI `--cases` path hashes each original individual case using SHA-256 over
`json.Compact` bytes, before environment/setup expansion, with the version prefix
`sha256-json-compact-v1:`. It emits the digest only for portable templates that
pass the existing known-secret/literal-credential guard. The execution and hash
use the same file read. Preserve source numeric spelling, escapes and ordering;
do not canonicalize through floating-point JSON decoding.

Regression saving requires a unique result, exact digest equality, no result or
preflight failure, and a recognized finding consistent with a reviewed identity
and expectation that has execution evidence. Legacy/resolved job results require
explicit `--allow-unbound-result` operator confirmation recorded in the manifest.
A present mismatch cannot be overridden. Keep Runner/Map's established `case_hash`
canonicalization and transport unchanged.

HAR discovery rejects oversized files, entries, response text, header counts,
operation/entry work and repeated decoded body analysis before writing outputs.
The limits and migration from immediately runnable generated scaffolds are
documented in the discovery guide.

Within one run, reset verification must reproduce the first stable selected
baseline before each identity's write. Failed/canceled reset or unreadable state
withholds the write; context cancellation starts no subsequent requests. A failed
write response does not negate a committed effect proved by independent readback.

## Limits and consequences

Digests correlate source, not authenticated execution or runtime flag/secret
values. They cannot detect result tampering. Retain explicit operator review and
the manual legacy path. The literal-secret guard is deliberately not universal.
No new dependencies, execution engine, cleanup retries, asynchronous polling,
rollback, remote locks or automatic finding promotion are introduced.

The initial reset baseline remains operator-reviewed; identical selected values
cannot prove complete fixture restoration. Exceeding HAR budgets requires split
inputs. Reordering source keys requires rerunning the case.
