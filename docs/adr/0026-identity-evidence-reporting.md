# ADR 0026: Make validity and provenance visible per identity

Accepted 2026-10-25.

Add credential-check state, write-readback state, raw execution index and bounded
readback status provenance to existing assessments. Retain no response values or
credential values. Reports show every identity and distinguish raw status,
semantic evidence, credential assurance and remaining uncertainty. A failed
principal check still withholds all resource traffic, now with per-caller
assessments instead of an empty summary. Honor optional verifier principal checks.

These are additive engine-result fields, not a claim that findings are operator
verified. Map may display bound reported conclusions but cannot promote missing,
contradictory or unbound metadata to assurance. Keep legacy receipts immutable
and preserve Runner's separate unresolved claim-time hash contract.
