"""Canonical release packaging. Input artifacts must already be verified."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def package(stage, output, binary):
    if binary not in ("vardrgate", "vardrgate.exe"):
        raise ValueError("Unexpected binary member")
    names = (binary, "README.md", "LICENSE", "BUILDINFO.txt", "SOURCE.json", "go.mod", "go.sum")
    files = {}
    for name in names:
        path = stage / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or unsafe release member: " + name)
        files[name] = path.read_bytes()
    with output.open("xb") as raw:
        if output.name.endswith(".zip"):
            with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, content in sorted(files.items()):
                    entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    entry.create_system = 3
                    entry.external_attr = ((0o100755 if name == binary else 0o100644) << 16)
                    archive.writestr(entry, content)
        else:
            # Stored DEFLATE blocks avoid compressor-version-dependent choices.
            with gzip.GzipFile(fileobj=raw, filename="", mtime=0, mode="wb", compresslevel=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for name, content in sorted(files.items()):
                        entry = tarfile.TarInfo(name)
                        entry.size = len(content)
                        entry.mode = 0o755 if name == binary else 0o644
                        archive.addfile(entry, io.BytesIO(content))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", required=True, choices=("vardrgate", "vardrgate.exe"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    import re
    if not all(re.fullmatch("[a-f0-9]{40}", v) for v in (args.commit, args.tree)):
        raise ValueError("Full source identities required")
    for name in ("README.md", "LICENSE", "go.mod", "go.sum"):
        source = args.source / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("Missing or unsafe source member: " + name)
        (args.stage / name).write_bytes(source.read_bytes())
    info = subprocess.check_output(["go", "version", "-m", str(args.stage / args.binary)], text=True)
    info = "binary: " + info.splitlines()[0].split(": ", 1)[1] + "\n" + "\n".join(info.splitlines()[1:]) + "\n"
    (args.stage / "BUILDINFO.txt").write_text(info, encoding="utf-8")
    environment = json.loads(subprocess.check_output(["go", "env", "-json", "GOOS", "GOARCH", "GOAMD64", "GOARM64", "CGO_ENABLED", "GOEXPERIMENT", "GOTOOLCHAIN"]))
    receipt = {"schema": "vardrgate.reproducible-source-binary/1", "commit": args.commit, "tree": args.tree,
               "version": args.version, "compiler": subprocess.check_output(["go", "version"], text=True).strip(),
               "environment": environment, "binary_sha256": digest((args.stage / args.binary).read_bytes()),
               "source_input_sha256": {n: digest((args.source / n).read_bytes()) for n in ("go.mod", "go.sum")},
               "build_flags": ["-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X main.version=" + args.version],
               "scope": "Same-input binary and canonical archive; no image reproducibility or independent provenance signature claim"}
    (args.stage / "SOURCE.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    package(args.stage, args.output, args.binary)


if __name__ == "__main__":
    main()
