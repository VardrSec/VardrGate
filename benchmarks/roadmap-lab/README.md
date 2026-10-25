# Roadmap validation, 2026-10-25

The frozen fixtures/plan and existing lab adapters were copied from the local
research lab; the corpus/permissions were not relabelled. Targets are disposable
VAmPI `f16052d` on loopback 5101/5102. ZAP image digest and add-on versions are
retained in the exports. No production system is involved.

## ZAP prerequisite

```sh
python -I competitors/zap_bench.py --mode vulnerable --repeat 3
python -I competitors/zap_bench.py --mode protected --repeat 3
python -I competitors/score_vampi.py
```

Requires the existing Docker VAmPI fixtures and `authzlab-network`, and Docker
Desktop's host.docker.internal. The harness starts/stops only `vgbench-zap`.
It uses ZAP's Access Control API, documented at
https://www.zaproxy.org/docs/api/ and
https://github.com/zaproxy/zaproxy/wiki/ApiGen_core.

Each case independently checks the actor's real database effect against its
frozen label before scanning. Reset again after unauthenticated seeding: seeding
can mutate VAmPI. A unique query parameter name isolates repeated operation
nodes, and whole-site deletion between cases removes prior nodes without
reusing cached Access Control context managers. An authenticated Alice control
is added for anonymous-only cases because the scan API requires one; only the
actor is scored. Replay status must match independent ground truth. Other-user
alarms are not counted as actor false positives.

Setup attempts before the final configuration stopped on node collisions,
missing authenticated users or node cleanup errors; none was scored. The final
two complete runs each have three identical classifications for all 14 cases.
Original HTML reports remain locally in ignored `competitors/results/zap/` and
can be regenerated. Committed sanitized exports retain their complete table
rows and replay statuses, without response bodies or credentials.

| Mode | TP | FP | FN | TN |
|---|---:|---:|---:|---:|
| Vulnerable | 5 | 3 | 0 | 6 |
| Protected | 2 | 4 | 0 | 8 |

Protected mode retains two labelled debug disclosures. These results concern
the frozen configured cases, not general discovery accuracy. ZAP detected all
seven labelled violations but gave seven false positives, including masked
writes with no unauthorized target effect. This supports retaining independent
write verification as a priority; it does not establish a universal comparison.

## Flexible writes

```sh
go build -o roadmap-gate.exe ./cmd/vardrgate
# From this directory:
python -I harness/strategies_bench.py --gate ../../roadmap-gate.exe
```

`reports/strategies-vampi.json` records all three formerly inexpressible paired
write cases, both modes, three repeats. Password-peer: verified allowed on the
vulnerable target, denied on protected. Password-anonymous: denied on both.
Delete-peer: inconclusive `credential_rejected` on both, preserving the existing
401 ambiguity; the admin positive control executes. No FP/FN is introduced in
these cases. These results do not claim the delete credential ambiguity is fixed.

## Scorecard limits

The final shared-profile replay uses the same frozen allow evidence and
deduplicates existing denial assertions into four scoped profiles, with real
policy/suite compilation (`harness/profiles_bench.py`). Independent ground truth
matches all 28 case/mode pairs. Results: vulnerable 9 TP / 0 FP / 0 FN; protected
12 TN / 2 inconclusive. It replaces repeated denial authoring while preserving
the two justified unknowns; it does not label generic validation errors denials.

The final synthetic verifier benchmark (`reports/authbench-final.json`) is stable
across three runs: 9 TP / 0 FP / 0 misses / 7 TN / 6 inconclusive. New provenance
pointers are compared as JSON values in its repeat signature, never addresses.

The supplied 19/19 recall and zero verified false positives across the larger
research corpus remain historical baselines, not newly reproduced claims here.
AuthZLab's retained baseline is 7 secure inconclusives with status-only and 2
with individual assertions. Reusable profiles preserve that distinction;
generic validation failures must not become authorization denials. Human policy
authoring time still needs a counterbalanced operator study.
