# Reproducible Gate release artifacts

The release build now exports the same committed Git tree twice into independent
source directories, uses separate Go module/build caches, verifies all downloaded
modules and refuses go.mod/go.sum changes. Compilation then runs with GOPROXY=off,
CGO_ENABLED=0, the pinned Go compiler, `-mod=readonly -trimpath -buildvcs=false`,
and the existing `-s -w -X main.version=<tag>` version flags.

Binary bytes and final archive bytes must match before an artifact is uploaded.
Both build paths are compared; a success message is not substituted for `cmp`.
The Linux binary's version subcommand remains checked. Matrix platforms retain
these same comparisons; each platform must pass its own job.

Ambient VCS discovery is disabled deliberately. Exported source should not change
behavior when a parent directory happens to contain a repository, or due to
checkout dirtiness. Every archive instead contains SOURCE.json binding the full
committed source identity and Git tree, exact compiler/environment/flags, source
input hashes, and binary SHA-256. BUILDINFO.txt and go.mod/go.sum are also retained.
This is integrity/build evidence, not a new provenance signature or permission.

The canonical packer uses sorted fixed member names, fixed regular-file modes,
zero tar ownership/timestamps, and an empty zero-timestamp gzip header. It uses
stored DEFLATE blocks and stored ZIP members to avoid compression heuristics;
archives are consequently larger than compressed releases. ZIP dates are fixed
to 1980-01-01. Test coverage verifies mtime independence, exact membership,
metadata, missing-input refusal, and refusal to overwrite an artifact.

Local Linux/amd64 qualification used the pinned Gate 0.3.0 source and Go 1.27.4.
Two separate module/build caches and source paths produced identical binaries.
Other platforms require their workflow result; this does not claim container
image reproducibility, independently rebuilt compiler provenance, or completion
of licensing/vulnerability gates. Existing release/attestation permissions and
tag-only publication conditions are unchanged. No release is published by a PR.
