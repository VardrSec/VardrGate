"""Same public HTTP requests, seeded target and labels against four Gate builds.

Python stdlib only. Run from the product root. Old versions are exported from
Git (never checked out over the working tree); target state resets per case.
"""
import argparse
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
UNAUTHORIZED = {"unexpected_access", "missing_authentication", "cross_tenant_access", "potential_bola", "privilege_escalation"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def call(method, url, body=None):
    request = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Gate HTTP {error.code}: {error.read().decode()}") from error


class Target(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        actor = self.headers.get("Authorization", "").removeprefix("Bearer lab-") or "anonymous"
        path = self.path
        code, body, accessed = 403, {"error": "forbidden"}, False
        write = path in {"/vulnerable/documents/1/update", "/secure/documents/1/update", "/edge/write-500"}
        if path in {"/vulnerable/documents/1", "/vulnerable/admin/export", "/edge/leak-403", "/edge/leak-404"} or (path == "/secure/documents/1" and actor == "alice"):
            code, body, accessed = 200, {"document_id": 1, "secret": "synthetic-tenant-A-data"}, True
            if path.endswith("leak-403"):
                code = 403
            if path.endswith("leak-404"):
                code = 404
        elif path == "/secure/documents/1" and actor == "anonymous":
            code = 401
        elif write and self.command == "POST" and (path != "/secure/documents/1/update" or actor == "alice"):
            self.server.document += "|modified-by-" + actor
            code, body, accessed = 204, None, True
            if path == "/edge/write-500":
                code, body = 500, {"error": "failed after mutation"}
        elif path == "/secure/documents/1/content" and actor == "alice":
            code, body = 200, {"content": self.server.document}
        elif path == "/edge/soft-denial":
            code = 200
        elif path == "/edge/empty":
            code, body = 200, {"data": []}
        elif path == "/edge/masked":
            code = 404
        elif path == "/edge/redirect":
            code = 302
        elif path == "/edge/rate-limit":
            code = 429
        elif path == "/edge/unavailable":
            code = 503
        elif path == "/edge/disconnect":
            code = 0
        if path != "/secure/documents/1/content":
            self.server.audit.append({"actor": actor, "accessed": accessed, "status": code})
        if code == 0:
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if code == 302:
            self.send_header("Location", "/secure/documents/1")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())


def source_hash(root):
    h = hashlib.sha256()
    for path in sorted([*root.rglob("*.go"), root / "go.mod", root / "go.sum"]):
        if path.exists() and ".comparison-work" not in path.relative_to(root).parts:
            h.update(str(path.relative_to(root)).replace("\\", "/").encode() + b"\0")
            h.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def run(binary, cases, profiles, repeats):
    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
    target.document, target.audit = "", []
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith("VARDRGATE_")}
    env.update(PORT=str(port), ALLOW_PRIVATE_TARGETS="true")
    gate = subprocess.Popen([str(binary), "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gate_url, target_url = f"http://127.0.0.1:{port}", f"http://127.0.0.1:{target.server_port}"
    all_runs = []
    try:
        for _ in range(100):
            try:
                call("GET", gate_url + "/health")
                break
            except (OSError, RuntimeError):
                if gate.poll() is not None:
                    raise RuntimeError("Gate exited before readiness")
                time.sleep(.05)
        else:
            raise RuntimeError("Gate readiness timed out")
        for _ in range(repeats):
            rows = []
            for case in cases:
                target.document, target.audit = "", []
                actor = case["actor"]
                cred = {"type": "static_header"} if actor == "anonymous" else {"type": "bearer", "value": "lab-" + actor}
                expected = {"identity_id": actor, "decision": case["decision"]}
                if profiles.get(case["path"]):
                    expected["response_assertions"] = profiles[case["path"]]
                method = case.get("method", "GET")
                payload = {"id": case["id"], "identities": [{"id": actor, "credential": cred}], "request": {"method": method, "url": target_url + case["path"]}, "expected_access": [expected], "mutating": method != "GET"}
                if case["id"] in {"write-bypass", "write-protected", "write-before-500"}:
                    payload["write_verification"] = {"identity": {"id": "verifier", "credential": {"type": "bearer", "value": "lab-alice"}}, "request": {"method": "GET", "url": target_url + "/secure/documents/1/content"}, "json_pointer": "/content"}
                _, result = call("POST", gate_url + "/tests/execute", payload)
                if len(target.audit) != 1 or target.audit[0]["actor"] != actor:
                    raise AssertionError((case["id"], target.audit))
                oracle = target.audit[0]
                if (oracle["accessed"] != (case["decision"] == "allow")) != case["violation"]:
                    raise AssertionError("Frozen ground truth disagrees with target effects")
                executions = result["executions"]
                if len(executions) != 1 or executions[0]["identity_id"] != actor:
                    raise AssertionError("Invalid execution identity")
                ex = executions[0]
                inconclusive = bool(ex.get("error")) or ex.get("observed_outcome") not in {"allow", "deny"}
                assessments = result.get("assessments", [])
                if assessments:
                    inconclusive = assessments[0]["decision"] in {"inconclusive", "skipped"}
                findings = result.get("findings") or []
                categories = UNAUTHORIZED if case["decision"] == "deny" else {"authorization_mismatch"}
                detected = any(f["identity_id"] == actor and f["category"] in categories for f in findings)
                verdict = ("TP" if case["violation"] else "FP") if detected else "FN" if case["violation"] else "IC" if inconclusive else "TN"
                # Comparison rows exclude runtime timestamps, ports and network text.
                rows.append({"id": case["id"], "verdict": verdict, "inconclusive": inconclusive, "assessment": assessments[0] if assessments else None, "status": ex["status_code"], "categories": sorted(f["category"] for f in findings), "oracle": oracle})
            all_runs.append(rows)
        if any(rows != all_runs[0] for rows in all_runs[1:]):
            raise AssertionError("Classifications changed between repeats")
        rows = all_runs[0]
        counts = {key: sum(row["verdict"] == key for row in rows) for key in ("TP", "FP", "FN", "TN", "IC")}
        counts["inconclusive"] = sum(row["inconclusive"] for row in rows)
        counts["precision"] = counts["TP"] / max(1, counts["TP"] + counts["FP"])
        counts["recall"] = counts["TP"] / max(1, counts["TP"] + counts["FN"])
        return {"metrics": counts, "stable_repeats": repeats, "rows": rows}
    finally:
        gate.terminate()
        gate.wait(timeout=10)
        target.shutdown()
        target.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(ROOT))
    parser.add_argument("--out", default=str(ROOT / "benchmarks/comparison/four-versions.json"))
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("repeat must be positive")
    cases_raw = (ROOT / "cmd/authbench/cases.json").read_bytes()
    profiles_raw = (ROOT / "cmd/authbench/assertions.json").read_bytes()
    contract = {"cases_sha256": sha(cases_raw), "profiles_sha256": sha(profiles_raw), "driver_sha256": sha(Path(__file__).read_bytes())}
    work = ROOT / ".comparison-work"
    work.mkdir(exist_ok=True)
    versions = [("original", "17cf541"), ("before_claude", "3de1d0c"), ("claude", "a5c5fab"), ("fixed", None)]
    reports = {}
    for name, ref in versions:
        source = ROOT
        if ref:
            source = work / name
            source.mkdir(exist_ok=True)
            archive = subprocess.check_output(["git", "-C", args.repo, "-c", "core.autocrlf=false", "archive", "--format=zip", ref])
            with zipfile.ZipFile(io.BytesIO(archive)) as z:
                z.extractall(source)
        binary = work / (name + (".exe" if os.name == "nt" else ""))
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/vardrgate"], cwd=source, check=True)
        report = run(binary, json.loads(cases_raw), json.loads(profiles_raw), args.repeat)
        dirty = ref is None and bool(subprocess.check_output(["git", "-C", args.repo, "status", "--porcelain", "--", "cmd", "internal", "go.mod", "go.sum"]).strip())
        report.update(commit=subprocess.check_output(["git", "-C", args.repo, "rev-parse", ref or "HEAD"]).decode().strip(), source_sha256=source_hash(source), binary_sha256=sha(binary.read_bytes()), working_tree=dirty)
        reports[name] = report
        print(name, json.dumps(report["metrics"]), flush=True)
    Path(args.out).write_text(json.dumps({"contract": contract, "versions": reports}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
