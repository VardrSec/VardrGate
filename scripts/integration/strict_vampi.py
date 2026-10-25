"""Pinned VAmPI checks across strict API, JSON CLI and YAML verification.

Requires the existing separate vardrgate-lab repository and its two loopback
VAmPI containers. Secrets stay in temporary inputs, never in the result artifact.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", required=True)
    ap.add_argument("--gate", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--write-environment", choices=["synchronous_isolated"], help="declare the reviewed disposable fixture's synchronous, exclusive write contract")
    args = ap.parse_args()
    lab, gate = Path(args.lab).resolve(), str(Path(args.gate).resolve())
    spec = importlib.util.spec_from_file_location("vampi_bench", lab / "harness/vampi_bench.py")
    vb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vb)
    corpus = vb.load("corpus.json")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, PORT=str(port), ALLOW_PRIVATE_TARGETS="true")
    server = subprocess.Popen([gate, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rows = []
    try:
        for _ in range(100):
            try:
                if vb.http("GET", f"http://127.0.0.1:{port}/health")[0] == 200:
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError("Gate failed readiness")
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            for mode in vb.MODES:
                fx = vb.Fixture(corpus, mode)
                # Independent oracle: inspect the database after a direct peer
                # request, before Gate is involved, then reset before each run.
                fx.reset()
                alice = fx.ids["alice"]["username"]
                password = fx.ids["alice"]["password"]
                before = fx.state()["users"][alice]["password"]
                vb.http("PUT", fx.base + f"/users/v1/{alice}/password", fx.tokens["bob"], {"password": "strict-parity-marker"})
                peer_changed = fx.state()["users"][alice]["password"] != before
                assert peer_changed == (mode == "vulnerable")
                read_vectors = []
                for entry in ("api", "json-cli", "job-cli"):
                    fx.reset()
                    identity = {"id": "peer", "credential": vb.credential(fx, "bob"), "preflight": {"url": fx.base + "/me", "expected_status": 200, "json_fields": {"data.username": fx.ids["bob"]["username"]}}}
                    tc = {"id": "strict-private-read", "require_identity_preflight": True, "identities": [identity], "request": {"method": "GET", "url": fx.base + "/books/v1/" + fx.book["title"]}, "expected_access": [{"identity_id": "peer", "decision": "deny", "response_assertions": [{"json_pointer": "/secret", "equals": fx.book["secret"], "decision": "allow"}, {"json_pointer": "/message", "equals": "Book not found!", "decision": "deny"}]}]}
                    if entry == "api":
                        code, body = vb.http("POST", f"http://127.0.0.1:{port}/tests/execute", body=tc)
                        assert code == 200
                        result = json.loads(body)
                    else:
                        cases, out = temp / "cases.json", temp / "out.json"
                        cases.write_text(json.dumps({"config": {"test_case": tc, "execution": {"allow_private_targets": True}}} if entry == "job-cli" else [tc]))
                        process = subprocess.run([gate, "run", "--job" if entry == "job-cli" else "--cases", str(cases), "--strict-identity-preflight", "--fail-on-inconclusive", "--allow-private-targets", "--out", str(out)], capture_output=True)
                        assert process.returncode == 0
                        parsed = json.loads(out.read_text())
                        result = parsed if entry == "job-cli" else parsed[0]
                    assert result["preflight"][0]["status"] == "passed"
                    a = result["assessments"][0]
                    assert a["decision"] == ("allowed" if peer_changed else "denied")
                    vector = (a["decision"], a["reason"], sorted(f["category"] for f in result["findings"]))
                    read_vectors.append(vector)
                    rows.append({"mode": mode, "entry": entry, "case": "private-read", "assessment": a, "categories": vector[2]})
                assert all(v == read_vectors[0] for v in read_vectors)
                for bad in ("malformed", "wrong-user"):
                    fx.reset()
                    identity["credential"]["value"] = "not-a-valid-token" if bad == "malformed" else fx.tokens["alice"]
                    tc["identities"] = [identity]
                    code, response = vb.http("POST", f"http://127.0.0.1:{port}/tests/execute", body=tc)
                    assert code == 200
                    result = json.loads(response)
                    assert result["preflight"][0]["status"] == "failed" and not result["executions"] and not result["findings"]
                    rows.append({"mode": mode, "entry": "api", "case": bad, "preflight": result["preflight"]})
                write_vectors = []
                for entry in ("api", "yaml-cli"):
                    fx.reset()
                    ids = [{"id": role, "role": role, "credential": vb.credential(fx, actor), "preflight": {"url": fx.base + "/me", "expected_status": 200, "json_fields": {"data.username": fx.ids[actor]["username"]}}} for role, actor in (("owner", "alice"), ("peer", "bob"))]
                    body = {"password": "strict-parity-marker"}
                    read_body = {"username": alice, "password": password}
                    if entry == "api":
                        tc = {"id": "strict-write", "require_identity_preflight": True, "mutating": True, "identities": ids, "request": {"method": "PUT", "url": fx.base + f"/users/v1/{alice}/password", "body": body}, "expected_access": [{"identity_id": "owner", "decision": "allow"}, {"identity_id": "peer", "decision": "deny"}], "write_verification": {"identity": {"id": "auditor", "credential": {"type": "static_header"}}, "request": {"method": "POST", "url": fx.base + "/users/v1/login", "body": read_body}, "allow_unsafe_method": True, "json_pointer": "/status", "changed_to": "fail"}}
                        if args.write_environment:
                            tc["write_verification"]["environment"] = args.write_environment
                        code, response = vb.http("POST", f"http://127.0.0.1:{port}/tests/execute", body=tc)
                        assert code == 200
                        result = json.loads(response)
                    else:
                        ids.append({"id": "auditor", "role": "auditor", "credential": {"type": "static_header"}})
                        identities, policy, out = temp / "ids.json", temp / "policy.yaml", temp / "write.json"
                        identities.write_text(json.dumps(ids))
                        policy.write_text(f"api:\n  endpoint: PUT /users/v1/{alice}/password\n  mutating: true\n  body: '{json.dumps(body)}'\nexpect:\n  owner: allow\n  peer: deny\nverify:\n  as: auditor\n  request:\n    method: POST\n    path: /users/v1/login\n    body: '{json.dumps(read_body)}'\n  allow_unsafe_method: true\n  json_pointer: /status\n  changed_to: fail\n")
                        if args.write_environment:
                            policy.write_text(policy.read_text().replace("  as: auditor\n", "  as: auditor\n  environment: " + args.write_environment + "\n", 1))
                        process = subprocess.run([gate, "policy", "run", "--policy", str(policy), "--base", fx.base, "--identities", str(identities), "--strict-identity-preflight", "--allow-private-targets", "--out", str(out)], capture_output=True)
                        assert process.returncode == 0
                        result = json.loads(out.read_text())
                    assert all(p["status"] == "passed" for p in result["preflight"])
                    assessments = {a["identity_id"]: a for a in result["assessments"]}
                    assert assessments["peer"]["decision"] == ("allowed" if peer_changed else "denied")
                    vector = [(key, a["decision"], a["reason"]) for key, a in sorted(assessments.items())]
                    write_vectors.append(vector)
                    rows.append({"mode": mode, "entry": entry, "case": "verified-write", "assessments": assessments, "categories": sorted(f["category"] for f in result["findings"])})
                assert write_vectors[0] == write_vectors[1]
        report = {"gate_revision": vb.git(str(Path(__file__).resolve().parents[2]), "rev-parse", "HEAD"), "gate_binary_sha256": hashlib.sha256(Path(gate).read_bytes()).hexdigest(), "lab_revision": vb.git(str(lab), "rev-parse", "HEAD"), "target": corpus["target"], "results": rows}
        report["write_environment"] = args.write_environment or "legacy"
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS: {len(rows)} real-app checks; API/JSON/job/YAML parity; strict principal checks; independent peer-write ground truth.")
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    main()
