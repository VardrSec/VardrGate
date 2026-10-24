# Response assertions and explicit assessments

VardrGate can now evaluate caller-defined JSON evidence instead of relying only
on HTTP status. Assertions are optional and belong to an identity's
`expected_access` entry. Existing requests keep their previous finding behavior;
the response gains an additive `assessments` array with one entry per identity.

## Request example

```json
{
  "id": "private-document-read",
  "identities": [
    {"id":"peer","credential":{"type":"bearer","value":"TEST_TOKEN"}}
  ],
  "request": {"method":"GET","url":"https://api.example.com/documents/42"},
  "expected_access": [{
    "identity_id":"peer",
    "decision":"deny",
    "response_assertions":[
      {"json_pointer":"/document/private_marker","equals":"seeded-private-value","decision":"allow"},
      {"json_pointer":"/error/code","equals":"FORBIDDEN","decision":"deny"}
    ]
  }]
}
```

The outer `decision` specifies policy: the peer must be denied. Each assertion's
`decision` describes what a matching response proves. An allow match can identify
disclosed data even with 403, 404, or 500. A deny match can recognize an API's soft
denial even with HTTP 200. Gate does not discover these rules automatically.

Use values known to be protected, tied to the resource under test. A public ID or
a generic success message alone may be insufficient evidence. A denial-shaped
response is conclusive only to the extent that the configured assertion proves
denial. Match rules against both authorized and unauthorized control responses.
Do not infer that a failed or empty response means a write did not happen.

## Assessment semantics

| Evidence | Decision / reason |
|---|---|
| No expectation | `skipped` / `no_expectation` |
| Explicit skip | `skipped` / `explicit_skip` |
| Execution, body-read, or body-limit error | `inconclusive` / `execution_error` |
| No assertions; 2xx | `allowed` / `status_only` |
| No assertions; 401 or 403 | `denied` / `status_only` |
| No assertions; other outcome | `inconclusive` / `ambiguous_http_outcome` |
| Only allow assertions match | `allowed` / `assertion_matched` |
| Only deny assertions match | `denied` / `assertion_matched` |
| Both allow and deny assertions match | `inconclusive` / `conflicting_assertions` |
| Assertions configured, none match | `inconclusive` / `no_assertion_matched` |
| Invalid, ambiguous, or unsupported JSON body | `inconclusive` / `invalid_or_unsupported_json` |

Assertions are alternative pieces of evidence, not an AND group: one matching
rule is sufficient unless an opposing rule also matches. To require several
properties together, compare an entire JSON object at a pointer; object equality
requires exactly the same keys and values. With assertions configured, there is
**no status fallback** when evidence is absent or conflicting. This prevents an
unexpected response format from silently appearing verified.

For example, a matched allow rule for an identity expected to be denied produces:

```json
{
  "identity_id":"peer",
  "expected_access":"deny",
  "decision":"allowed",
  "source":"response_assertion",
  "reason":"assertion_matched",
  "matched_assertions":[0]
}
```

`source` is `http_status`, `response_assertion`, or `none`. Assertion indices are
zero-based. Execution `status_code` and `observed_outcome` remain the raw HTTP
classification even when semantic assessment differs. Findings use the semantic
decision; assertion-derived findings have high confidence in the configured
match. This confidence does not certify that the caller's rules encode policy
correctly. Status-only finding severities and confidence remain unchanged.

Assessment output and finding evidence contain assertion indices, not JSON
pointers, asserted values, or response bodies. Existing credential redaction and
response-body limits remain in force.

## Supported matching

- JSON Pointer traversal supports object keys, array indices, `~0` for `~`, and
  `~1` for `/`. Empty pointer selects the whole document. URI fragments and
  wildcard expressions are not supported. Array indices cannot have leading
  zeros, a sign, or `-` append syntax.
- `equals` is required. JSON strings, numbers, booleans, null, arrays, and objects
  are supported. Missing keys do not match null. Arrays are ordered; object key
  order does not matter. Numbers compare exactly: `1`, `1.0`, and `1e0` are equal;
  large integer IDs are never rounded through floating point.
- Duplicate object keys, trailing JSON, invalid UTF-8, nesting beyond 64, and
  numeric literals over 128 characters are rejected. Unsupported response JSON
  is inconclusive. Invalid assertion configuration returns HTTP 422 before any
  target request. JSON syntax errors in the outer API request return HTTP 400.
- At most 32 assertions per identity; pointers up to 1024 bytes; each encoded
  `equals` value up to 8192 bytes. Limits bound evaluation work and error output
  does not echo assertion contents.

## Validation and remaining scope

The original 22 benchmark scenarios and ground-truth labels are unchanged. An
explicit endpoint assertion profile supplies the new input. Both modes run in
CI; regression tests preserve status-only behavior and require at least eight
detected failures, zero false positives, and no more than six inconclusive
assessments with assertions. Known inconclusive vulnerabilities still count as
misses. Read failures, write failures, and legitimate-access cases are reported
separately.

The recorded assertion run detects 8 of 9 failures, versus 6 before; false
positives fall from 2 to 0. All three repetitions agree. This measures the benefit
of explicit domain knowledge on the existing synthetic corpus, not automatic
detection or independent real-world accuracy. Nested formats and malformed input
have separate unit/API coverage, but are not a held-out third-party benchmark.

Write postconditions remain a separate change: the write-before-500 case is still
a known miss. A follow-up should define a read-only authorized verifier, compare
state before and after each identity's action, and handle verifier failures and
concurrent changes explicitly. A pinned third-party vulnerable app is also still
needed for independent validation.
