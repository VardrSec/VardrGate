# Authorization research roadmap: staged implementation

Prepared 2026-10-25. These changes are review branches, not deployed releases.

| Stage | Implemented behavior | Guide |
|---|---|---|
| 1 | `gen` requires reviewed TODO permissions; offline HAR correlations remain unconfirmed hypotheses | [Discovery](policy-assisted-discovery.md) |
| 2 | Confirmed endpoint-scoped denial profiles compile into existing assertions | [Denial profiles](denial-profiles.md) |
| 3 | Explicit changed/created/deleted verification; optional fixture reset and declared readback transitions | [Write verification](write-verification.md) |
| 4 | Save an operator-confirmed unresolved case and rerun it with the existing runner/CI outputs | [Regressions](authorization-regressions.md) |
| 5 | Per-identity credential assurance and value-free readback provenance in Gate, Runner and Map | [Evidence](identity-evidence.md) |

The Gate branches are stacked in stage order. Map and Runner have separate
companion branches. Deploy the Map backend's semantic upload handling before
using the new Gate/Runner reader evidence together. No migration or automatic
promotion of findings to confirmed vulnerabilities is introduced.

## Measured results

- ZAP prerequisite completed first: all seven frozen VAmPI violations detected,
  seven false positives across the two modes, three stable repeats each. The
  benchmark isolates Sites Tree nodes and independently checks database effects.
- Shared AuthZLab denial profiles: 9 TP / 0 FP / 0 FN on vulnerable, 12 TN /
  2 inconclusive on protected. Four reusable profiles reproduce the individually
  authored assertions' result, preserving the two justified unknowns.
- Three formerly unsupported paired VAmPI writes execute in both modes across
  three repeats. Password checks agree with independent ground truth. Delete-peer
  retains the existing `credential_rejected` uncertainty; it is not a clean denial.
- A real VAmPI password regression exits 2 on the defect, 0 on protected mode,
  and 2 after reintroduction, with principal checks passing.
- Synthetic verified benchmark: 9 TP / 0 FP / 0 misses, stable across three runs.
- Gate tests, vet, build and Linux race checks pass. Map backend: 1,088 tests pass;
  frontend: 182 tests pass, lint/typecheck/build pass (21 existing lint warnings).
  Runner: 1,535 tests pass, 10 opt-in skips, 96.46% coverage; lint/format/mypy pass.
- Existing three-product loopback acceptance: 104 checks pass, no failures.

See [retained benchmark evidence](../benchmarks/roadmap-lab/README.md). The local
acceptance run also retains isolated source snapshots and `sources.json` hashes.
This does not establish hosted OAuth, production deployment or asynchronous write
completion. The full historical 19/19 research result is not newly reproduced
here. Human policy-authoring time remains unmeasured; the discovery guide records
the counterbalanced study protocol rather than inventing an improvement figure.
