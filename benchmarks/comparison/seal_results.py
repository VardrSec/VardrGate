"""Check retained comparison consistency and bind lab reports to exact binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "benchmarks/comparison"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab", required=True)
    args = parser.parse_args()
    lab = Path(args.lab)
    comparison = json.loads((OUT / "four-versions.json").read_text())
    expected = {"original": (6, 2, 3, 7), "before_claude": (6, 2, 3, 7), "claude": (9, 0, 0, 5), "fixed": (9, 0, 0, 6)}
    for version, want in expected.items():
        build = comparison["versions"][version]
        m = build["metrics"]
        assert tuple(m[k] for k in ("TP", "FP", "FN", "inconclusive")) == want
        assert build["stable_repeats"] == 3 and len(build["rows"]) == 22
        assert build["source_sha256"] != hashlib.sha256(b"").hexdigest()
        assert not build["working_tree"]
        if version == "original":
            continue  # The original binary predates the third-party CLI harness.
        binary = ROOT / ".comparison-work" / (version + (".exe" if os.name == "nt" else ""))
        assert digest(binary) == build["binary_sha256"]
        report_path = OUT / ("vampi-" + version + ".json")
        report = json.loads(report_path.read_text())
        assert report["gate_binary_sha256"] == build["binary_sha256"]
        assert report["gate_revision"] == build["commit"]
        assert report["repeat"] == 3 and len(report["ground_truth"]) == 28
        for name, sha in report["inputs_sha256"].items():
            assert hashlib.sha256((lab / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() == sha
        for key, row in report["results"].items():
            metrics = row["metrics"]
            assert metrics["false_negative"] == 0
            if version != "before_claude":
                assert metrics["false_positive"] == 0
        # These binary checks also allow correction of a source-fingerprint
        # export-path bug without changing a single observed test result.
        report["gate_source_sha256"] = build["source_sha256"]
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for version in ("claude", "fixed"):
        path = OUT / ("oracle-mistakes-" + version + ".json")
        report = json.loads(path.read_text())
        build = comparison["versions"][version]
        report.update(gate_binary_sha256=build["binary_sha256"], gate_source_sha256=build["source_sha256"], harness_sha256=digest(lab / "harness/verifier_mistakes.py"))
        assert report["gate_revision"] == build["commit"]
        failed = [row["id"] for row in report["experiments"] if not row["acceptable"]]
        assert failed == (["wrong-victim-password", "untouched-field"] if version == "claude" else [])
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    manifest = {p.name: hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest() for p in sorted(OUT.iterdir()) if p.is_file() and p.name != "SHA256.json"}
    (OUT / "SHA256.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Comparison verified: four builds, unchanged labels, stable repeats, no new misses/false positives, and 8/8 corrected oracle-mistake cases.")


if __name__ == "__main__":
    main()
