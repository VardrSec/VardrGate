# ADR 0012 — Versioned binary releases

- Status: Accepted
- Date: 2026-10-14

## Decision

`VERSION` records the next packaged semantic version. Release preparation lands
through a PR with matching dated changelog and `docs/releases/vX.Y.Z.md` notes.
A `vX.Y.Z` tag on the merged commit must match `VERSION`; it triggers source
formatting, vet and race tests, then CGO-disabled cross-builds for Linux and
macOS amd64/arm64 and Windows amd64. The version is supplied through the existing
`main.version` linker field. No runtime dependency or engine behavior changes.

Each archive contains only the executable, README and license. The pipeline
collects five archives, generates SHA256SUMS, attests the archives/checksums with
GitHub OIDC build provenance and publishes a GitHub release. Build, attestation
and publishing jobs have separate permissions. Third-party actions use immutable
commit pins. Existing releases/tags are not overwritten.

Pull requests changing release configuration or VERSION also cross-build all
platforms, but cannot attest or publish. Operators verify the checksum and
repository-bound provenance before putting the binary on PATH. Releases contain
no credentials and add no installer, auto-update service or managed Runner pin.

## Consequences

Gate can be installed without a Go toolchain and upgraded before Runner cases
enable identity preflight. Source installation remains available through the
versioned Go module. Archives are not Windows/macOS code-signed; users remain
subject to their OS execution policy. CI race tests execute on Linux; cross-build
success is not a claim that every architecture was executed. Published Windows
binaries receive a separate local CLI/loopback acceptance smoke check.
