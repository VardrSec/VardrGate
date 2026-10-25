# Reviewed denial profiles

Define a profile once in a policy or suite and reference it explicitly in each
relevant policy. Endpoint scopes are exact method/path templates; no wildcard or
global error-code interpretation exists. Confirmation records operator review,
not an independent proof of correctness.

```yaml
denial_profiles:
  private_object:
    confirmed: true
    endpoints: ["GET /books/{id}", "GET /notes/{id}"]
    rules:
      - status_codes: [404, 409, 422]
        json_pointer: /error/code
        equals: PRIVATE_OBJECT
      - status_codes: [200]
        json_pointer: /error/code
        equals: ACCESS_REFUSED
```

Each policy opts in:

```yaml
response:
  denial_profiles: [private_object]
  assertions:
    - json_pointer: /secret
      equals: expected-private-value
      decision: allow
```

Status and body constraints in a rule are conjunctive. Rules are alternatives.
Status-only denial rules require explicit reviewed 4xx codes. A 200 refusal
needs an exact JSON value. Unmatched, malformed or conflicting evidence remains
inconclusive. Add an independent allow assertion to recognize real disclosure,
including disclosure in an error response. Existing write-verification priority,
credential-rejection demotion and sensitive-field checks remain in force.

Profiles compile into ordinary response assertions, including for suite/API/job
execution. Their output contains matched assertion indices, never matched values.
There is no learning from scanner responses or automatic confirmation.
