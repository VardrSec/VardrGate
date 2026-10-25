# Read an identity's evidence

Every assessment states the expected and assessed access decision, its source and
fixed reason. `execution_index` refers to the raw result's executions array;
the raw HTTP status/outcome is preserved even when body assertions or independent
readback support a different authorization conclusion.

`credential_status` reports `anonymous_identity`, `not_checked`,
`preflight_passed`, `preflight_failed`, `resource_401_unverified`, or
`preflight_passed_resource_401`. A passed principal check describes a point in
time; a later resource 401 remains visible and cannot establish token validity.
The field does not infer expiry, revocation or intended identity from token text.
Configured verifier principal preflights are now honored alongside caller checks.

`write_verification` reports `not_configured`, `not_applied`, `inconclusive`,
`verified_effect` or `verified_no_effect`. `verification` records the reader id,
its credential-check status, strategy/environment, baseline HTTP statuses,
after-read status and optional reset status. No observed state or asserted value
is retained. Positive-control and rejected-credential guards still apply.

Failed preflight now returns per-caller inconclusive/skipped assessments with
`identity_preflight_failed`; no resource executions or findings are fabricated.
Text and Markdown show each identity's evidence, not only findings or failures.
JSON fields are additive for Runner/Map. Findings remain scanner candidates until
an operator confirms reproduction and impact. Map's companion reporting branch
retains these fields without replacing claim-time case hashes or receipts.
