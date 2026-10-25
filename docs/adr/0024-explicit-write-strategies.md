# ADR 0024: Explicit write effects and repeatable baselines

Accepted 2026-10-25 after the pinned ZAP-on-VAmPI comparison.

The comparison found all seven labelled violations but seven false positives
over the two modes (three stable repeats); response-only interpretation could
not independently distinguish masked writes. Independent verification remains
a useful priority. See the retained benchmark under `benchmarks/roadmap-lab`.

Add `changed`, `created` and `deleted` strategies, requiring an explicitly
reviewed synchronous/isolated environment. Creation starts absent (404), deletion
starts present (2xx), and each requires the corresponding transition. A changed
value uses JSON comparison; optional reviewed 4xx `after_status` supports an
independent login oracle whose old password stops working. Such a refusal is
only a readback transition, never a default authorization denial.

Multiple changed-value attempts without `changed_to` require an explicit fixed
fixture reset before every attempt. It is same-origin, uses a declared identity,
has no captures/branching, and must complete with 2xx (never 202). Baseline reads
still follow it. Creation/deletion refuse to execute when their required initial
existence state is unavailable, preventing consumed fixtures from passing.

Existing positive-control requirements, resource-time rejected credentials,
202 uncertainty and legacy verification behavior remain. Observed values stay
in memory. No automatic retries, asynchronous completion or remote isolation
guarantees are introduced.
