# Response assertions and assessments

Status alone misjudges two common responses: protected data returned with 403,
404 or 500, and a refusal returned with HTTP 200. Response assertions let a
policy say which JSON values prove access was granted or refused. They are
optional. Without them, findings are exactly what the status-based evaluator
produced before. See [ADR 0016](adr/0016-response-assertions.md).

## In a policy

```yaml
api:
  endpoint: GET /books/v1/{title}
expect:
  owner: allow
  peer: deny
  anonymous: deny
response:
  assertions:
    - json_pointer: /secret
      equals: seeded-secret-for-this-book
      decision: allow          # a response containing this value proves access
    - json_pointer: /status
      equals: fail
      decision: deny           # the API's refusal shape
      roles: [peer]            # optional; default is every role in expect
```

`expect` states policy: the peer must be denied. Each assertion's `decision`
states what a matching response proves. An assertion describes the endpoint's
response format, so it applies to every role with an allow or deny expectation
unless `roles` narrows it. `equals` takes any YAML value and is compared as
JSON. Numbers keep their literal text, so large ids are compared exactly.

## In the HTTP API

Assertions belong to an `expected_access` entry:

```json
{"identity_id": "peer", "decision": "deny", "response_assertions": [
  {"json_pointer": "/secret", "equals": "seeded-secret-for-this-book", "decision": "allow"}
]}
```

## Choosing evidence

Use a value that only an authorized caller could receive, tied to the resource
under test, such as a seeded private field. A public id or a generic success
message is weak evidence. Check every rule against both an authorized and an
unauthorized response before relying on it. An empty or failed response does
not prove that a write was refused.

## Assessments

Every result has an `assessments` array with one entry per identity:

| Evidence | `decision` / `reason` |
|---|---|
| No expectation | `skipped` / `no_expectation` |
| `decision: skip` | `skipped` / `explicit_skip` |
| Request, body-read or body-limit error | `inconclusive` / `execution_error` |
| No assertions; 2xx | `allowed` / `status_only` |
| No assertions; 401, 403, or a declared `deny_status`/`deny_when` | `denied` / `status_only` |
| No assertions; any other status | `inconclusive` / `ambiguous_http_outcome` |
| Only allow assertions match | `allowed` / `assertion_matched` |
| Only deny assertions match | `denied` / `assertion_matched` |
| Allow and deny assertions both match | `inconclusive` / `conflicting_assertions` |
| Assertions configured, none match | `inconclusive` / `no_assertion_matched` |
| Body is not usable JSON | `inconclusive` / `invalid_or_unsupported_json` |

Any one matching assertion is enough unless an opposing one also matches. To
require several properties together, compare a whole object at a pointer.

**With assertions configured there is no status fallback.** If the response
format changes and no rule matches, the identity is inconclusive. It does not
become a status-based pass. Assertions also outrank `deny_status` and
`deny_when`, which apply to the status path only.

`source` is `http_status`, `response_assertion` or `none`. Execution
`status_code` and `observed_outcome` remain the raw HTTP classification.
Assertion-derived findings use the same categories as status findings
(`missing_authentication`, `cross_tenant_access`, `potential_bola`,
`privilege_escalation`, `unexpected_access`, `authorization_mismatch`), with
high confidence in the configured match. That confidence does not certify that
the rule correctly encodes the policy.

Assessments and finding evidence carry assertion indices only, never pointers,
asserted values or response bodies.

## Inconclusive is not a pass

An inconclusive assessment emits no finding. So that it cannot read as a clean
result:

- `--format text` lists each one with an explanation under "inconclusive
  assessments (not a pass)", and the summary line counts them.
- `--format markdown` shows ⚠️ instead of ✅ for the case and adds an
  "Inconclusive assessments" table.
- SARIF adds a `warning` notification per inconclusive assessment.
- `--fail-on-inconclusive` exits 4 when any expectation could not be judged.
  It is off by default, so existing pipelines keep their exit codes. Exit 3 (not
  tested) and exit 2 (findings) take precedence.

Status-only policies also report their ambiguous outcomes, such as an
undeclared 404, as inconclusive. To resolve one, declare `deny_status` or add
assertions.

## Matching rules and limits

- JSON Pointer (RFC 6901): object keys, array indices, `~0` for `~`, `~1` for
  `/`. An empty pointer selects the whole document. No wildcards, URI fragments,
  leading-zero or signed indices, or `-`.
- `equals` is required. JSON null is valid, but a missing key does not match
  null. Arrays are ordered, while object key order is ignored. `1`, `1.0` and
  `1e0` are equal.
- Response bodies with duplicate keys, trailing data, invalid UTF-8, nesting
  deeper than 64, or numbers longer than 128 characters are inconclusive.
- At most 32 assertions per identity, pointers up to 1024 bytes, and each
  `equals` up to 8192 bytes. Invalid configuration fails validation before any
  request is sent. Error messages never echo assertion contents.

## Measured effect

On the synthetic corpus in [`benchmarks/`](../benchmarks/README.md), adding the
endpoint assertion profile moves precision from 75.0% to 100% and recall from
66.7% to 88.9%: 8 of 9 known failures, versus 6. The remaining miss is a write
that completes before an HTTP 500. That corpus was designed alongside the
feature. It shows the value of explicit domain knowledge and is not an estimate
of real-world accuracy.
