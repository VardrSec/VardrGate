# Strict identity assurance in CI

Use these reviewed suite settings:

```yaml
base: ${VARDRGATE_BASE_URL}
identities: identities.json
require_identity_preflight: true
fail_on_inconclusive: true
policies:
  - policy: profile.policy.yaml
```

Each credentialed identity judged allowed or denied must include its reviewed
`preflight` configuration in the identities file. It needs a same-origin
session URL, a required 2xx status, and public principal field matches:

```json
{
  "id":"peer", "role":"peer",
  "credential":{"type":"bearer","value":"${PEER_TOKEN}"},
  "preflight":{
    "url":"https://api.example.com/session",
    "expected_status":200,
    "json_fields":{"user.id":"reviewed-peer-id"}
  }
}
```

Replace the endpoint and fields with your API's actual contract. Gate will not
guess them or derive identity from a token. Anonymous tests remain supported;
skipped identities do not count as authorization assessments. A strict case
with no allow/deny expectations is rejected.

For standalone policies or JSON cases:

```sh
vardrgate policy run --suite suite.yaml --fail-on high
vardrgate policy run --policy profile.yaml --base https://api.example.com --identities identities.json --strict-identity-preflight --fail-on-inconclusive --fail-on high
vardrgate run --cases cases.json --strict-identity-preflight --fail-on-inconclusive --fail-on high
```

The HTTP API and job envelope use `require_identity_preflight: true` inside the
test case. The API retains its normal structured result/status contract; HTTP
200 does not mean an authorization test passed. Inspect preflight diagnostics,
assessments and findings. Direct engine users get the same validation.

Explicit CLI `--strict-identity-preflight=false` or
`--fail-on-inconclusive=false` overrides suite configuration. Omitted flags
preserve suite settings. Treat an override as a deliberate relaxation of the
reviewed CI policy. The old `--require-identity-preflight` means at least one
declared check for Runner compatibility; use the new strict mode for complete
coverage.

Missing required configuration fails before setup or target traffic. Runtime
preflight failure withholds resource requests and produces not-tested exit 3;
setup may already have executed. Finding thresholds exit 2. Otherwise unresolved
assessments exit 4 with inconclusive gating enabled. Outputs retain all findings
and uncertainty even when one exit code has precedence.

These controls verify principal identity and assessment completeness, not API
security. A token can expire after its preflight. Preserve resource-time
credential uncertainty, reviewed authorization expectations and positive write
controls. Existing jobs/cases/suites default to compatibility behavior unless
strict settings are supplied.
