# VardrGate

API authorization test runner. Send a single HTTP request as multiple identities and detect when access decisions do not match expectations.

## What it does

VardrGate accepts a test case describing a request, a set of identities with credentials, and the expected authorization outcome for each identity. It executes the request once per identity, classifies the observed HTTP response, compares it against the expectation, and returns structured findings.

**Current finding categories**

| Category | Meaning |
|---|---|
| `unexpected_access` | Identity received a 2xx when it should have been denied |
| `authorization_mismatch` | Identity received a 401/403 when it should have been allowed |

## Quickstart

**Requirements:** Go 1.24 or newer.

```sh
git clone https://github.com/VardrSec/VardrGate
cd VardrGate
go build ./cmd/vardrgate
./vardrgate          # listens on :8080
```

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Listening port (1–65535) |
| `ALLOW_PRIVATE_TARGETS` | `false` | Permit loopback and RFC-1918 targets. Enable only for local lab testing. |

## API

### `GET /health`

Returns `{"status":"ok"}` with HTTP 200.

### `POST /tests/execute`

Execute an authorization test case.

**Request body** (`application/json`, max 1 MB, exactly one JSON value):

```json
{
  "id": "string",
  "description": "optional",
  "identities": [
    {
      "id": "string",
      "name": "optional",
      "role": "optional",
      "tenant_id": "optional",
      "credential": {
        "type": "bearer | api_key_header | static_header",
        "header": "optional — header name for api_key_header and static_header",
        "value": "secret — write-only, never returned in any response"
      }
    }
  ],
  "request": {
    "method": "GET",
    "url": "https://api.example.com/resource/42",
    "headers": {},
    "query_params": {},
    "body": null
  },
  "expected_access": [
    { "identity_id": "string", "decision": "allow | deny | skip", "note": "optional" }
  ]
}
```

**Response** (`application/json`):

```json
{
  "test_case_id": "string",
  "executions": [
    {
      "identity_id": "string",
      "status_code": 200,
      "observed_outcome": "allow | deny | not_found | redirect | server_error | client_error | error",
      "headers": {},
      "duration_ms": 142,
      "error": "",
      "error_kind": ""
    }
  ],
  "findings": [
    {
      "category": "unexpected_access",
      "severity": "high",
      "confidence": "medium",
      "identity_id": "string",
      "message": "identity \"viewer\" received access that should have been denied",
      "evidence": ["observed_outcome=allow", "status_code=200", "..."],
      "detected_at": "2026-06-28T00:00:00Z"
    }
  ]
}
```

**Error responses:**

| Status | Condition |
|---|---|
| 400 | Malformed JSON or trailing content after the JSON value |
| 413 | Request body exceeds 1 MB |
| 422 | Test case fails validation (missing id, no identities, bad decision value, etc.) |
| 405 | Wrong HTTP method |

## Security defaults

- Only `http` and `https` targets are accepted.
- Loopback (127.x, ::1), link-local (169.254.x, fe80::), private ranges (RFC-1918/4193), unspecified (0.0.0.0), and multicast addresses are blocked by default.
- DNS rebinding is prevented: hostnames are resolved once inside a custom `DialContext`, every returned address is validated, and the connection is made to the pre-validated IP directly.
- Credential `value` fields are accepted in request input but are never included in any response, finding, or log.
- Redirects are not followed; the raw authorization response is captured.
- Response bodies are capped at 5 MB per identity.

## Example

See [`examples/bola_check.json`](examples/bola_check.json) for a three-identity test case.

Run it against a local target (requires `ALLOW_PRIVATE_TARGETS=true`):

```sh
ALLOW_PRIVATE_TARGETS=true ./vardrgate &
curl -s -X POST http://localhost:8080/tests/execute \
  -H 'Content-Type: application/json' \
  -d @examples/ownership_check.json | jq .
```

## Project layout

```
cmd/vardrgate/       — startup and dependency wiring
internal/
  api/               — HTTP handlers (GET /health, POST /tests/execute)
  client/            — HTTP execution, credential application, SSRF protection
  compare/           — response body and status-code comparison utilities
  engine/            — test-case validation, execution coordination, finding evaluation
  model/             — domain types and constants
  urlcheck/          — URL and IP validation (scheme, blocked ranges, CheckIP)
docs/
  mvp.md             — MVP workflow definition
examples/            — example test case JSON files
```

## Development

```sh
go test ./...
go vet ./...
gofmt -w .
```

All stages pass before the next begins. No external dependencies.
