#!/usr/bin/env python3
"""Compare frozen executor schedules on two Gate checkouts; stdlib only.

Temporarily copies the current regression fixture into the baseline checkout,
restoring any existing file afterwards. Builds and executes both test binaries.
This is source-informed regression evidence, not independent application testing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


FIXTURE = Path("internal/engine/write_assurance_test.go")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(args, cwd):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True)


def evaluate(root, binary):
    built = command(["go", "test", "-c", "-o", str(binary), "./internal/engine"], root)
    if built.returncode:
        raise RuntimeError(built.stderr or built.stdout)
    run = command([str(binary), "-test.v", "-test.run=^TestWriteEnvironmentSchedules$", "-test.count=3"], root)
    rows = []
    for line in run.stdout.splitlines():
        if "schedule_observation=" in line:
            rows.append(json.loads(line.split("schedule_observation=", 1)[1]))
    if len(rows) != 27 or rows[:9] != rows[9:18] or rows[:9] != rows[18:]:
        raise RuntimeError("expected nine schedules with identical observations over three runs")
    metrics = dict(true_positives=0, false_positives=0, missed_authorization_failures=0,
                   true_negatives=0, inconclusive_assessments=0, inconclusive_known_failures=0)
    for row in rows[:9]:
        violation = row["peer_committed"]
        finding = row["findings"] > 0
        unknown = row["decision"] == "inconclusive"
        if violation:
            metrics["true_positives" if finding else "missed_authorization_failures"] += 1
        elif finding:
            metrics["false_positives"] += 1
        elif not unknown:
            metrics["true_negatives"] += 1
        metrics["inconclusive_assessments"] += int(unknown)
        metrics["inconclusive_known_failures"] += int(unknown and violation and not finding)
    sources = {str(p.relative_to(root)).replace("\\", "/"): sha(p.read_bytes())
               for p in sorted(root.rglob("*.go"))}
    return dict(revision=command(["git", "rev-parse", "HEAD"], root).stdout.strip(),
                source_sha256=sha(json.dumps(sources, sort_keys=True).encode()),
                test_binary_sha256=sha(binary.read_bytes()), test_exit=run.returncode,
                repeat_count=3, stable=True, metrics=metrics, schedules=rows[:9])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    before, after = args.before.resolve(), args.after.resolve()
    if before == after:
        parser.error("use separate baseline and current checkouts")
    fixture = (after / FIXTURE).read_bytes()
    destination = before / FIXTURE
    previous = destination.read_bytes() if destination.exists() else None
    try:
        destination.write_bytes(fixture)
        with tempfile.TemporaryDirectory(prefix="gate-write-schedules-") as directory:
            report = dict(schema_version=1, method="source-informed deterministic executor schedules",
                          fixture_sha256=sha(fixture), go_version=command(["go", "version"], after).stdout.strip(),
                          before=evaluate(before, Path(directory) / "before.test.exe"),
                          after=evaluate(after, Path(directory) / "after.test.exe"))
        if report["after"]["test_exit"] != 0:
            raise RuntimeError("current engine failed its frozen schedule assertions")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        for version in ("before", "after"):
            print(version, json.dumps(report[version]["metrics"], sort_keys=True))
    finally:
        if previous is None:
            destination.unlink(missing_ok=True)
        else:
            destination.write_bytes(previous)


if __name__ == "__main__":
    main()
