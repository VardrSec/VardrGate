# Keep a confirmed defect as a regression

Keep the unresolved reviewed input and the Gate result from reproducing a
defect. Confirm the actual authorization violation and the result's binding to
that input; scanner findings alone do not establish that confirmation.

```sh
vardrgate regression save --cases reviewed.json --result result.json \
  --case password-peer --out regressions/password-peer --confirmed
vardrgate run --cases regressions/password-peer/cases.json \
  --fail-on high --fail-on-inconclusive --out results.json --sarif results.sarif
```

The new directory contains an unresolved case and an operator-confirmation
record with its SHA-256. An existing directory is never overwritten. The
confirmation is not a Runner `case_hash` or automatic finding verification.
No scanner response values, evidence strings or resolved credentials are copied.
Use environment references for credentials and password/token/secret request
fields. Review fixture values and any other application-specific secrets before
committing the template. This guard is not a universal secret detector.

The retained case uses the existing engine, setup captures, principal preflights,
resource declarations, response assertions and write verifier. `${VARIABLE}`
references resolve at execution in credentials, request URLs/headers/query/JSON
values, setup requests, assertion values and verifier/reset requests. `{{capture}}`
still denotes a runtime setup value. Missing environment variables fail before
traffic. JSON string escaping is preserved.

Configure login/resource creation through existing `setup` steps, and
`require_identity_preflight: true` with a declared principal check for every
credentialed caller. Use unique disposable resources and explicit mutation
opt-in for writes. A fixture reset supports repeated unknown-value write checks.

Run the saved case against the vulnerable app (exit 2), the fixed app (exit 0),
and a controlled reintroduction (exit 2). Invalid credentials or unreadable
evidence must fail as not tested/inconclusive, never a protection pass. The CLI
integration test exercises this full sequence with login, resource creation and
principal preflight. The retained VAmPI regression replay checks a real paired
password defect across vulnerable/protected/vulnerable modes.

CI can use the existing Action's `args` input with the same `run --cases`
command. Upload JSON/SARIF with an `always()` step so exits 2/3/4 keep evidence.
Use `${{ secrets.NAME }}` only in workflow environment bindings; never resolve
secrets into committed case files. No new test runner or CI result format exists.
