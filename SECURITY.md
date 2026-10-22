# Security policy

VardrGate sends authenticated requests to the APIs it tests and handles the
credentials of every identity in a test case, so security reports are treated as
sensitive.

## Supported versions

Security fixes are provided for the latest released VardrGate version. Upgrade
before reporting an issue that may already be fixed.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting form:

https://github.com/VardrSec/VardrGate/security/advisories/new

If the form is unavailable, email contact@vardrsec.com with "VardrGate security"
in the subject.

Do not open a public issue for a suspected vulnerability. Include the affected
version, platform, reproduction steps, impact, and any suggested mitigation.
Remove real credentials, tokens, target hostnames, and response data from
evidence.

The maintainers will acknowledge a report within five business days, investigate
it, and coordinate disclosure and remediation with the reporter. Please allow a
reasonable period for a fix and supported-user migration before public
disclosure.

## Scope

In scope are vulnerabilities in VardrGate itself, including:

- credential handling, and any path by which a credential value reaches output,
  logs, results, SARIF or summaries;
- target validation: the SSRF, private-address and DNS-rebinding protections;
- policy, suite and identity file parsing;
- the HTTP API and job queue, including tenant isolation;
- the GitHub Action, release automation, and published archives.

A finding VardrGate reports about *your* API is not a vulnerability in VardrGate.
A false positive or false negative is a bug; report it as a public issue with
sanitized evidence. Vulnerabilities in VardrMap, VardrRunner or third-party
infrastructure should be reported to their respective maintainers.
