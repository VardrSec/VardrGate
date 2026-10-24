# Authorization effectiveness benchmark

Run from the VardrGate repository root with Go 1.24 or newer:

```sh
go run ./cmd/authbench -repeat 3 -out benchmarks/authz-status-only.json
go run ./cmd/authbench -assertions -repeat 3 -out benchmarks/authz-assertions.json
go test ./...
go vet ./...
```

The command starts a deliberately vulnerable synthetic API and the production
VardrGate HTTP handler on ephemeral **loopback-only** listeners. It posts real
JSON to `/tests/execute`; Gate uses its production engine and HTTP client to call
the target. Both servers close on completion. No Docker, external services,
downloads, credentials, or environment changes are required. The execution
environment must permit localhost connections.

Private targets are enabled only on the benchmark's client instance. Production
defaults are unchanged. This exercises the API/client/engine path, not the
`cmd/vardrgate` process startup or environment-variable parsing.

## Ground truth and scoring

The versioned corpus is [`cases.json`](../cmd/authbench/cases.json). Alice owns
document 1 in tenant A; Bob is a peer in tenant A; Mallory belongs to tenant B;
only Admin may export. Anonymous sends no credential. All data and tokens are
synthetic. Each row is one identity/request assessment with an explicit access
expectation and independently declared authorization-failure label. Each repeat
starts with fresh in-memory state.

The [lab API](../cmd/authbench/fixture.go) includes missing ownership, tenant,
authentication, and role checks; protected controls; misleading response codes;
and transport failures. Its audit records data disclosure and actual changes to
an in-memory document. The harness checks those effects against the corpus label
and verifies the request reached the intended endpoint with the intended actor.
The target's status code does not determine ground truth. Audit observations are
available to the benchmark scorer, not to Gate's decision logic.

| Measure | Definition |
|---|---|
| True positive | Known authorization failure with a finding for the correct identity and category |
| False positive | No authorization failure, but Gate emits the corresponding finding |
| Missed authorization failure | Known failure without the corresponding finding, including inconclusive responses |
| True negative | No failure and no finding, with a conclusive Gate response |
| Inconclusive | Gate's explicit assessment is inconclusive; historical responses without assessments use the raw HTTP outcome/error fallback |
| Precision | TP / (TP + FP) |
| Recall | TP / all known authorization failures, including inconclusive misses |

For expected denial, the corresponding finding is `unexpected_access`; for
expected allowance, it is `authorization_mismatch`. Thus the overall metrics
include one wrongly denied owner, as well as unauthorized-access failures.

Inconclusive is an **overlapping measure**, not another confusion-matrix bucket:
two known failures in this baseline are both missed and inconclusive. Safe
inconclusive controls are not credited as true negatives. Accounting is
`TP + FP + missed + TN + inconclusive_controls = total`. Precision and recall
are fractions in JSON; a zero denominator is reported as zero.

A mismatch between fixture behavior and declared ground truth, malformed Gate
output, unexpected request counts/identities, or unstable results aborts the run
with a nonzero exit. Poor detection rates do not abort: this is an honest
measurement, not a quality threshold. `-repeat` compares status, outcome, error
kind, finding categories/identities, verdict, and target effects. It excludes
timestamps, latency, ports, and OS-specific error messages. The disconnect case
uses POST to avoid Go's automatic retries of idempotent GET requests.

## Recorded baseline

[`authz-baseline.json`](authz-baseline.json) contains all 22 assessments, the raw
Gate responses from the first run, target audit evidence, metrics, repeat count,
Go/platform metadata, Git revision and working-tree status, and a SHA-256 source
fingerprint. The fingerprint covers `go.mod`, the manifest, and all Go files
under `cmd/` and `internal/`, with line endings normalized. The measured checkout
included pre-existing uncommitted edits; the Git revision alone does not identify
the measured source. Preserve this source snapshot with the report when sharing.

Three fresh runs (66 assessments) produced identical classifications:

| Measure | Count |
|---|---:|
| Assessments per run | 22 |
| Known authorization failures | 9 |
| True positives | 6 |
| False positives | 2 |
| Missed authorization failures | 3 |
| True negatives | 6 |
| Inconclusive assessments | 7 |
| Inconclusive known failures (also misses) | 2 |
| Inconclusive safe controls | 5 |
| Precision | 75.0% |
| Recall | 66.7% |

For unauthorized access alone (excluding the wrongly denied owner), Gate detects
5 of 8 failures: recall 62.5%, precision 71.4% (5 / 7 findings).

| Cases | Observed behavior |
|---|---|
| Peer, cross-tenant, and anonymous document access; admin-role bypass; unauthorized write | Five correct `unexpected_access` findings |
| Owner wrongly denied | One correct `authorization_mismatch` finding |
| JSON denial with HTTP 200; empty filtered data with HTTP 200 | Two false positives; no protected data or side effects |
| Secret in HTTP 403 | Missed; Gate considers the status a denial despite disclosed data |
| Secret in HTTP 404 | Missed and inconclusive |
| Write completed before HTTP 500 | Missed and inconclusive; before/after document evidence retained |
| Masked 404, login redirect, 429, 503, connection abort | Five inconclusive controls |
| Authorized owner/admin and protected reads/write | Six true negatives |

These are synthetic, deliberately selected cases, not a representative estimate
of production accuracy or an independent public-app benchmark. They establish a
reproducible baseline and expose the current status-only evaluator's limits.
They do not test endpoint discovery, credential acquisition, workflow chains,
or large real-world API coverage. Gate receives access expectations; it does not
infer them. A subsequent benchmark against a pinned third-party vulnerable app
should retain these scoring rules and add independently verified ground truth.

## Response assertion improvement

The original `authz-baseline.json` is preserved. Two new reports measure the
current source over the same 22 scenarios and labels, each repeated three times:

| Measure | [Status only](authz-status-only.json) | [With assertions](authz-assertions.json) |
|---|---:|---:|
| True positives | 6 | 8 |
| False positives | 2 | 0 |
| Missed failures | 3 | 1 |
| True negatives | 6 | 8 |
| Inconclusive (overlaps misses) | 7 | 6 |
| Precision | 75.0% | 100.0% |
| Recall | 66.7% | 88.9% |

The optional [assertion profiles](../cmd/authbench/assertions.json) are explicit
additional input, keyed by endpoint rather than ground-truth labels. They
recognize the lab's known private data and denial formats. The scorer never
passes audit observations or vulnerability labels to Gate. Source fingerprints
now also cover this profile; report schema version 2 records whether assertions
were enabled and separates unauthorized reads, unauthorized writes, and
legitimate-access expectations in `by_expectation`.

With assertions, unauthorized reads detect 6/6 failures, writes detect 1/2, and
legitimate-access tests detect their one wrong-denial failure. All three groups
have zero false positives. These numbers are corpus-specific and reflect
caller-supplied knowledge; they are not independently measured production rates.

The benchmark scorer uses Gate's assessment to distinguish semantic access from
raw status. The remaining write-before-500 miss remains in recall's denominator.
CI runs both modes; Go regression tests require unchanged legacy counts and,
with assertions, at least eight true positives, zero false positives, at most
one miss, and at most six inconclusive assessments. The command itself remains a
measurement tool and does not enforce these detection thresholds.

See [response assertion semantics](../docs/response-assertions.md) for configuration,
limits, and evidence handling. Write postconditions and independent third-party
app validation remain future work.
