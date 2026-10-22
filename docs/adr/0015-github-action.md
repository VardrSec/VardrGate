# ADR 0015 — GitHub Action

- Status: Accepted
- Date: 2026-10-22

## Context

VardrGate is meant to run on every commit, and its README said so, but using it
in GitHub Actions meant downloading a release archive, checking its checksum,
unpacking it and adding it to `PATH` by hand in every workflow. Most users skip
the checksum. A one-line `uses:` is the expected interface for a CI check.

The project rules exclude Docker, and a container action would also exclude
macOS and Windows runners.

## Decision

A composite action, `action.yml` at the repository root, with two steps.

**Install.** Downloads the release archive for the runner's OS and architecture
and that release's `SHA256SUMS`, verifies the archive's checksum, unpacks it and
adds it to `PATH`.

- **Version.** It comes from the `version` input, or from the action reference
  when that is a release tag (`VardrSec/VardrGate@v0.2.0`). Anything else, such
  as `@main` with no `version`, is an error. There is no implicit "latest":
  a CI gate must not change behavior because a new release was published.
- **Optional provenance.** `verify-attestation: true` also runs
  `gh attestation verify --repo VardrSec/VardrGate`. A checksum from the same
  release only proves the download is intact. The provenance attestation
  (ADR 0012) proves the archive was built by this repository's release workflow.
- **Platforms.** Linux and macOS on x64 and arm64, and Windows x64, matching the
  published archives. Other combinations fail with a clear message.
- `install: false` uses a binary already on `PATH`.

**Run.** Executes `vardrgate` with the `args` input, appends stdout to the job
summary (`step-summary`, on by default; pair it with `--format markdown`),
exposes the exit code as the `exit-code` output, and exits with it.

- **No script injection.** Every input reaches the shell through `env:`, never
  through `${{ }}` interpolation inside `run:`. `args` is split on whitespace
  with `read -a`, and nothing from it is evaluated.
- Uploading SARIF stays the workflow's choice. It needs the
  `security-events: write` permission, and an action should not require
  permissions a user did not grant.

CI exercises the action on Ubuntu, macOS and Windows against a published
release. It checks a clean run, exit code 2 propagation, and that an unpinned
install is refused.

## Consequences

- Adding VardrGate to a workflow is one step, with a verified binary.
- The action installs published releases only. Features newer than the pinned
  release, such as suites before v0.2.0 is tagged, are unavailable through it
  until that release exists.
- The action adds no runtime dependency to the binary. It uses `curl`, `tar` or
  `unzip`/`7z`, and `sha256sum`/`shasum`, all present on GitHub-hosted runners.
- Marketplace listing is a separate, manual step. Publishing the action is not
  part of this decision.
