# ADR 0023: Scoped denial profiles reuse response assertions

Accepted 2026-10-25.

Operators may reuse confirmed denial patterns across an exact endpoint allowlist
in policy/suite YAML. Profiles compile to existing authoritative assertions;
there is no second classifier. Optional status constraints are conjunctive with
the exact body match. Status-only rules are limited to explicitly reviewed 4xx
denials; 2xx cannot become a blanket denial. Profile references outside scope,
missing definitions, and unconfirmed profiles fail before traffic.

Unmatched and conflicting evidence remains inconclusive. Disclosure assertions,
write-verification precedence, rejected-credential handling, and value redaction
remain intact. A shared profile reduces repeated authoring; it cannot justify
claiming that every unmatched success or error means authorization worked.
