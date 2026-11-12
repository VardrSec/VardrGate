# Review a compact authorization case set

The [six runnable cases](../examples/authorization-cases.json) exercise ownership,
tenant isolation, privileged functions, credential failure and state-dependent
publishing. A [separate unsupported input](../examples/authorization-unsupported.json)
demonstrates refusal of an unverified write contract. Both use the existing case
schema and CLI; no additional runner or result format is required.

Reproduce both deliberately vulnerable and fixed fixtures from a source checkout:

```sh
go test ./cmd/vardrgate -run '^TestCompactAuthorizationCases$' -count=1 -v
```

The existing CLI integration test starts disposable servers on loopback and
supplies synthetic `AUTHCASE_*` environment references. It runs each input
separately through `run --cases` with `--fail-on high` and
`--fail-on-inconclusive`, then checks the ordinary Gate result, CLI exit and
fixture traffic. The verbose test output records each identity's reviewed
expectation, observed semantic decision, reason and verification status. Standard
`go test -json` can retain these observations in CI. A Go test pass means these
declared behaviors were reproduced, including the intentional findings and
refusals. It does not turn the vulnerable fixture into a protection pass.

## Expected policy and observed behavior

Owner and peer belong to tenant A; outsider belongs to B. Admin alone has the
administrator role. Reader is a separate preflight-verified identity used only
for write readback. Credential possession establishes identity, not permission
to perform an assessment.

| Case | Reviewed expectation | Vulnerable fixture observation | Fixed fixture observation |
| --- | --- | --- | --- |
| `ownership` | Owner allowed; peer and anonymous denied | Peer and anonymous read the record; ownership/authentication candidates | Owner reads; peer/anonymous denied |
| `tenant` | Owner and peer allowed; outsider denied | Outsider reads tenant A's record; cross-tenant candidate | A members read; B member denied |
| `privileged-function` | Admin allowed; peer and anonymous denied | Peer/anonymous export; privilege/authentication candidates | Admin exports; other callers denied |
| `credential-failure` | Owner allowed; peer denied by policy | Expired peer credential fails preflight; entire case inconclusive, no resource request, exit 3 | Same refusal; no claim that authorization protected the record |
| `draft-publish` | Owner allowed; peer denied until approval | Peer changes draft to published despite HTTP 500; verified effect and unexpected-access candidate | Peer denied with unchanged state; owner's positive control changes state |
| `approved-publish` | Owner and peer allowed | Both change approved to published; peer's HTTP 500 still has a verified effect | Both publish with verified effects |
| `unverified-write-environment` (separate file) | Same draft policy; timing/isolation unknown | Unsupported explicit change/reset contract refused before all HTTP traffic; no result file | Same validation refusal |

`expected_access` records the reviewed rule. `assessments[].decision` records
`allowed`, `denied` or `inconclusive` from the evidence. The raw
`executions[].observed_outcome` can differ: the vulnerable publisher returns
`server_error`, while independent readback proves that it changed state.
Neither a 500 nor a failed credential establishes a successful denial.

The write cases declare `synchronous_isolated` because this fixture commits
before responding and has exclusive access during each sequential test. A
reviewed owner reset restores draft or approved state before **every** identity,
and a successful owner write calibrates the unchanged-state denial. Readback
values and resolved credentials are not included in the result.

## Support boundary

The unsupported input intentionally combines an explicit change/reset strategy
with `environment: unknown`. Gate's existing validator rejects this combination;
the test checks that no preflight, reset or resource request occurred. Here
“unsupported” describes that refused input, not a new assessment decision or a
fabricated successful result. Keep it separate from the runnable case file.

This set does not establish asynchronous completion, downstream effects,
cross-service workflows, concurrency safety or arbitrary business policies.
Changing an environment declaration cannot establish those guarantees. See
[write verification](write-verification.md) for existing inconclusive reasons.

To adapt a case, review the real policy, resource/tenant/role context, principal
checks, response assertions and authorization first. Use dedicated disposable
resources for reset/publish requests. The example fixture's synthetic credentials,
responses and timing guarantees are not evidence about another application.
Findings still require human confirmation; retain the original case and result
for a separately authorized [regression retest](authorization-regressions.md).
