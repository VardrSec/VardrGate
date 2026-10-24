"""Reuse the separately committed VAmPI lab, with identical inputs per build.

Run compare.py first. Supply --lab to the existing pinned validation repository.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab", required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--versions", nargs="+", choices=["before_claude", "claude", "fixed"], default=["before_claude", "claude", "fixed"])
    args = parser.parse_args()
    lab = Path(args.lab).resolve()
    harness = lab / "harness/vampi_bench.py"
    provenance = json.loads((ROOT / "benchmarks/comparison/four-versions.json").read_text())
    for version in args.versions:
        binary = ROOT / ".comparison-work" / (version + (".exe" if sys.platform == "win32" else ""))
        out = ROOT / "benchmarks/comparison" / ("vampi-" + version + ".json")
        subprocess.run([sys.executable, "-I", str(harness), "--gate", str(binary), "--gate-src", str(ROOT), "--repeat", str(args.repeat), "--verifier", "--out", str(out)], check=True)
        report = json.loads(out.read_text())
        # The source archives have no .git; bind provenance to the exact build
        # recorded by the common HTTP comparison, not the wrapper's worktree.
        build = provenance["versions"][version]
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != build["binary_sha256"]:
            raise AssertionError("Binary changed since common comparison")
        report.update(gate_revision=build["commit"], gate_tree_clean=not build["working_tree"], gate_source_sha256=build["source_sha256"], gate_binary_sha256=digest, gate_working_tree=build["working_tree"], harness_sha256=hashlib.sha256(harness.read_bytes()).hexdigest())
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("COMPLETED", version, flush=True)


if __name__ == "__main__":
    main()
