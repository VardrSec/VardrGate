# ADR 0030: Bounded cooperative cancellation for guarded managed jobs

Status: Accepted direction, 2026-11-05. No dependency additions.

Runner already supervises its own Gate child and may request graceful stop before
its existing lease/hard cutoff. A guarded literal job now handles SIGINT/SIGTERM
by cancelling the same context used by the existing engine and HTTP client.
The request guard refuses remaining dispatch; verified writes retain their
existing cancellation/reset/readback rules. No work is retried or resumed.

The CLI retains completed observations and publishes the existing single-result
JSON shape with fixed `error: "execution_cancelled"`. Interrupted setup records
the case ID and empty arrays, not successful preconditions. Errored executions
use the same fixed diagnostic rather than raw transport URLs. Output is written
to a same-directory temporary file with mode 0600, closed, then renamed; ordinary
POSIX rename publishes a complete file. Windows relies on the owning run directory
ACL for privacy and offers its platform rename semantics. A forced exit may leave no artifact. Publication never extends a
lease, hard deadline or Runner grace period. No response values or credentials
are added to evidence.

Cancellation exits 3 if no resource response was reached and otherwise 4, even
without `--fail-on-inconclusive`. An ordinary unguarded CLI run is unchanged.
The marker is a diagnostic, not authority or proof of native child drainage.
Runner must independently confirm stop, validate and bind any retained artifact,
and select a non-success terminal lane; it must never infer healthy completion
or automatic reuse from this file. Remote partial-evidence delivery remains a
separate Runner integration. Existing stop/result receipt exclusivity remains.

Tests inject cancellation into ordinary local HTTP requests; they send no OS
signals and make no new containment claim. Rollback removes this guarded-only
handling; forced-stop and missing-artifact recovery remain Runner concerns.

Managed jobs with an explicit output file now synchronously checkpoint completed
preflight and resource observations before each resource identity. The existing
atomic writer publishes the existing result shape with local `execution_in_progress`
diagnostics and pending identities marked inconclusive. Findings wait for final
evaluation; incomplete write verification asserts no effect. Ordinary final output
replaces the checkpoint. A checkpoint failure refuses subsequent dispatch and
extends no timeout. Unguarded/API/library calls keep their existing behavior.

This local marker is not a Map result or proof of cancellation. Only Runner's
independent confirmed-stop lane may promote it into a cancelled private copy,
with the original reviewed case binding. Normal return must reject a stale
checkpoint. The original checkpoint bytes remain unchanged. No checkpoint is
promised before successful setup/preflight, after storage failure, or after an
unconfirmed exit. Ordinary HTTP tests observe the real file before dispatch;
they do not establish native termination or installed platform acceptance.
