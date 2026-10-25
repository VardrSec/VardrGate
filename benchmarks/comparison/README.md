# Original, pre-Claude, Claude, and corrected Gate

This comparison answers whether the changes actually fix measured behavior.
The same public HTTP API requests, optional assertion/verification configuration,
22 frozen labels, identity credentials, and seeded target are used for all four
builds. Every case starts with fresh target state. All four runs have three
identical repetitions; the labels and assertions are not tuned between versions.

| Build | Revision | Detected failures | False positives | Misses | True negatives | Inconclusive |
|---|---|---:|---:|---:|---:|---:|
| Original checkout first tested | 17cf541 | 6 | 2 | 3 | 6 | 7 |
| Main before Claude's additions | 3de1d0c | 6 | 2 | 3 | 6 | 7 |
| Claude's merged main | a5c5fab | 9 | 0 | 0 | 8 | 5 |
| Corrected code | 7eada03 | 9 | 0 | 0 | 7 | 6 |

Precision/recall changes from 75.0%/66.7% to 100%/100% on these known failures.
Inconclusive overlaps misses: two original misses are also inconclusive. It is
never counted as a true negative. The corrected version intentionally does not
credit the deny-only `write-protected` case as calibrated protection without an
allow-expected control that actually demonstrates a state change. The extra
inconclusive is visible, not removed from the corpus or reclassified as a pass.

**Conclusion:** Claude's additions fixed the three original misses and two
false positives on this corpus. They did not fix every verifier failure path.
The corrections preserve the detection gains and fix the additional review
cases while making one previously overconfident denial inconclusive.

## Added review cases: same tests before and after

The four `TestReview*` tests in
`internal/engine/verification_regression_test.go` were copied from the review
before changing product code. They all fail on a5c5fab and pass on the corrected
code. They are distinct from the 22-case benchmark and are not mixed into its
precision/recall percentages.

| Test | Claude | Corrected |
|---|---|---|
| Verifier redirects after a refused write | False high-confidence access finding | Inconclusive |
| Write cannot connect, observed state unchanged | Conclusive denial | Inconclusive |
| Failed peer request plus a successful owner control | No inconclusives or findings; incomplete case can look clean | Peer remains inconclusive |
| Wrong constant oracle, deny-only case, actual unauthorized mutation | No finding, conclusive denial | Inconclusive: no positive control |

Additional regression coverage tests unsupported 3xx/4xx statuses, before-read
diagnostic compatibility, successful status changes without value changes, a
declared but failed owner control, a successful owner control, and a write that
commits before a transport error. Independently observed unauthorized effects
still produce findings, even when the write returns an error or no owner control
can run afterward. See [ADR 0018](../../docs/adr/0018-verifier-confidence.md).

## Pinned real app: VAmPI

The existing separate lab's harness, labels, profiles, and independent database
ground-truth checks were reused unchanged. The local image is pinned to VAmPI
f16052d and both containers expose only 127.0.0.1 ports. Each of the three newer
builds is tested in vulnerable/protected modes with and without assertions,
with the supplied write verifier, three repetitions per configuration. All 28
case/mode ground-truth labels are checked before each build's benchmark.

The original 17cf541 binary has no `run --cases` CLI, so the third-party CLI
harness comparison starts at 3de1d0c. Its public HTTP path is included in the
four-version comparison above.

The assertion-plus-verification rows are:

| Build / app mode | TP | FP | FN | TN | Inconclusive |
|---|---:|---:|---:|---:|---:|
| Before Claude / vulnerable | 5 | 1 | 0 | 8 | 0 |
| Before Claude / protected | 2 | 2 | 0 | 10 | 0 |
| Claude / vulnerable | 5 | 0 | 0 | 8 | 1 |
| Claude / protected | 2 | 0 | 0 | 11 | 1 |
| Corrected / vulnerable | 5 | 0 | 0 | 5 | 4 |
| Corrected / protected | 2 | 0 | 0 | 7 | 5 |

The newly inconclusive write controls lack a demonstrated positive control in
the unchanged corpus. They are not additional missed vulnerabilities: all known
failures remain detected. Supply a functioning owner control to resolve those
unchanged-state assessments. The frozen misconfiguration cases separately check
that wrong passwords and wrong fields no longer look conclusively protected.

## What passed and what remains

- Each of the original, pre-Claude, Claude, and corrected builds passes its own
  existing test suite. The old suites alone therefore cannot establish that the
  added review cases work.
- The corrected code passes the full uncached Windows suite and vet, and the
  full Linux `go test -race -count=1 ./...`, vet and build. An official Go 1.25
  container supplies the 64-bit C toolchain missing on the Windows host.
- Git-blob formatting checks cover all 67 committed Go files; Windows checkout
  CRLF conversion is not treated as a source formatting defect.
- The four review regressions pass, and no new false positives or missed known
  vulnerabilities appear in the frozen synthetic or VAmPI corpus.
- **Known open limitation:** invalid/expired credentials still look like
  protection in the status-only and generic-denial experiments when identity
  preflight is omitted. This is recorded as unacceptable in the retained lab
  reports. Identity preflight mitigates it; default-on preflight remains the
  separate P0.1 change in the hardening plan.
- No production-accuracy claim is made. These are small source-informed corpora;
  a true blind configuration study and broader API coverage remain unmeasured.

## Evidence and reproduction

`four-versions.json` records source/binary hashes, exact commits, frozen input
hashes, repeat counts and per-case outcomes. `claude-before.json` and
`fixed-after.json` retain the native authbench results. `*-suite*.txt`, the two
`*-regressions-*.txt` files, and `linux-validation.txt` retain test results.
`vampi-*.json` retain all four profiles per build, independent ground truth,
misconfiguration results, image id, lab revision and input hashes.
`oracle-mistakes-*.json` retain the extra verifier-mistake experiments.

The same eight oracle-mistake cases pass 6/8 on Claude's version and 8/8 after
the corrections, using the lab's original acceptable-outcome rules. A wrong
victim password and an untouched field are the two corrected cases.
`SHA256.json` hashes the retained text evidence with CRLF normalized to LF, so
Windows checkout conversion does not invalidate the manifest.

From the repository root, with Go and Python available:

```sh
python benchmarks/comparison/compare.py
go test ./internal/engine -run '^TestReview' -count=1 -v
go test -race -count=1 ./...
go vet ./...
```

The comparison exports old Git revisions under ignored `.comparison-work/` and
builds each binary without overwriting a checkout. It stops its test servers on
completion. The target binds to loopback; each product server runs briefly with
the normal product server binding and private-target opt-in. To reuse the
separate pinned VAmPI lab, start its existing loopback containers and run:

```sh
python benchmarks/comparison/compare_vampi.py --lab /path/to/vardrgate-lab
```

Keep that lab at the revision recorded in the reports. The wrapper verifies
binary hashes and associates reports with their actual build provenance. It
does not modify labels, target code, or the lab's scoring rules.
