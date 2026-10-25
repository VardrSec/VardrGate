# ADR 0025: Save reviewed inputs for the existing runner

Accepted 2026-10-25.

`regression save` retains one unresolved test case after explicit operator
confirmation and requires a matching Gate result containing a finding. It never
derives expected permissions or copies response evidence into a new assertion.
The operator confirms the template/result binding because existing Gate results
do not carry a claim-time input hash. The confirmation records a hash of the
saved unresolved template; it does not replace Runner/Map provenance contracts.

Retain existing setup, preflight, assertions and verification. Reject literal
credentials and known secret request fields; resolve references only when the
existing runner loads the case. Do not overwrite saved regressions. Existing
exit codes, JSON, Markdown and SARIF remain the CI interface. A second execution
engine or workflow language would add no value to this task.
