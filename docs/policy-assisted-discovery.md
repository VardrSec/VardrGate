# Policy-assisted discovery

`gen` now writes four identity templates with `TODO` decisions. Credentials alone
cannot make these cases executable: review every permission, bind the request's
resource and confirm which principals the credentials represent first.

```sh
vardrgate gen --spec api.json --base https://api.example.test \
  --har capture.har --hypotheses hypotheses.json --out cases.json
```

The optional HAR is read offline. Only successful credentialed entries matching
the declared origin, base path, method and OpenAPI path template contribute.
Headers, URLs, bodies, object IDs and tenant values from traffic are never
retained. Capture numbers identify one-based HAR entries for local review.
Authorization and Cookie headers distinguish credential material in memory;
token rotation and multiple sessions do **not** establish different principals.
Other authentication mechanisms need manual identity confirmation.

Every suggestion is `unconfirmed`: ID-shaped path parameters, possible owners,
owner/tenant fields, credential relationships and cross-tenant opportunities.
Success does not prove ownership or permission. Tenant field names alone do not
prove tenant boundaries. No hypothesis is copied into executable ownership or
tenant assertions. `discover` remains available for YAML draft policies.

Review the authenticated template as the legitimate control, `other_user` as a
peer, `other_tenant` as a principal in a different tenant, and `anonymous` as an
unauthenticated caller. Supply independent principal preflights where available.
Set each decision to `allow`, `deny` or `skip`; replace request path parameters;
declare resource ownership/tenancy only after confirmation. Unsafe operations
still require explicit mutation opt-in.

## Migrating existing scripts and bounded captures

Existing `gen` scripts must add a review step before `run`: providing credential
variables alone now leaves every generated permission at `TODO`, and execution
validation fails before sending requests. Keep the reviewed case separately;
regenerating the scaffold must not overwrite confirmed permissions. This applies
to both OpenAPI and Postman generation. There is no flag to infer permissions
from captured HTTP success.

HAR input is limited to 32 MiB and 5,000 entries. Each response may contain at
most 1 MiB decoded content (with a corresponding base64 text limit); stored
response text totals at most 8 MiB. Each request may declare at most 128 headers.
Correlation permits at most 2,000,000 operation/entry comparisons, 50,000 output
hypotheses and 64 MiB of matched decoded body/header analysis across operations. Split the spec/capture or trim
irrelevant bodies when a limit is reached. Invalid HAR structure and exceeded
budgets fail before cases or hypotheses are written; existing outputs remain.

## Measuring authoring effort

No human time baseline has yet been measured. Use the same frozen endpoints and
identity set for manual and assisted sessions, counterbalance their order, time
from initial artifacts to a validated reviewed suite, and record corrections,
unconfirmed hypotheses and errors as well as elapsed time. Keep false positives,
recall and inconclusives in the scorecard; fewer keystrokes are not correctness.
