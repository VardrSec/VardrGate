# Write timing and isolation regression evidence

Baseline: merged Gate `e86b8cd`. Implementation: `e8269e9`.
These are source-informed checks, not an independent configuration study or a
production accuracy estimate. Inputs and violation labels stay fixed.

## Deterministic schedules

`schedules.json` compares nine executor schedules over three identical runs of
each engine. The same test file is injected into the baseline checkout, which
ignores the then-unsupported JSON `environment` field. The report retains the
fixture, source and executed test-binary hashes. No sleeps or polling are used;
delayed commits are released after Gate returns. Interference is an unrelated
writer acting at the first post-write read. The fixture's commit flag supplies
ground truth independently of Gate's assessment.

| Measure | Before | After |
|---|---:|---:|
| True positives | 1 | 1 |
| False positives | 1 | 0 |
| Missed authorization failures | 4 | 4 |
| Conclusive true negatives | 3 | 2 |
| Inconclusive assessments | 1 | 6 |
| Inconclusive known failures (included in misses) | 1 | 4 |
| Schedule contract assertions passing | 4/9 | 9/9 |

The five violations include two configurations of the same accepted-write
schedule; these are regression checks, not five independent applications.
Unknown environments stop producing unsupported protection or access claims.
This improves confidence and removes a false finding, **not delayed-write
recall**. Four delayed/accepted commits remain missed and are counted as such.
`synchronous_isolated` is a reviewed author declaration; Gate cannot detect a
false declaration or enforce remote isolation. Omitted settings retain legacy
assumptions except for unchanged state after HTTP 202, now inconclusive.

From a separate baseline checkout and this implementation checkout:

```sh
git worktree add --detach /tmp/gate-write-before e86b8cd
python scripts/benchmarks/compare_write_schedules.py --before /tmp/gate-write-before --after . --out /tmp/write-schedules.json
```

The driver temporarily copies the frozen test into the baseline and restores
any existing file afterward. It requires Go and Python's standard library.

## Existing authorization corpus

`compatibility.json`: the unchanged 22-case corpus, assertions plus verification,
three stable repetitions: **9 TP, 0 FP, 0 misses, 7 TN, 6 inconclusive**. None of
the known failures is inconclusive. This corpus does not establish accuracy for
asynchronous or concurrent production APIs.

```sh
go run ./cmd/authbench -assertions -verify -repeat 3 -out /tmp/write-compatibility.json
```

## Pinned application replay

`vampi-parity.json`: all 14 existing vulnerable/protected VAmPI checks pass with
the reviewed `synchronous_isolated` fixture contract declared through API and
YAML write-verification inputs. The disposable fixture is reset per case; a
separate database check establishes whether the peer can change the password.
The report retains executable, product and pinned lab metadata without secrets.
Only the test process writes these fixture resources during this replay.

With the existing loopback lab's two containers running:

```sh
go build -o /tmp/vardrgate ./cmd/vardrgate
python scripts/integration/strict_vampi.py --lab /path/to/vardrgate-lab --gate /tmp/vardrgate --write-environment synchronous_isolated --out /tmp/write-vampi.json
```

The driver does not manage container lifecycle. Both containers were stopped
again after this recorded run. Broader suite/Action/report parity and an
independently configured study remain separate roadmap work.
