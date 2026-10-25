"""Score VardrGate against AuthZLab (third-party multi-tenant API) in both modes.

Each case creates fresh invoices through the API. Ground truth is checked
independently: the harness sends each request itself and reads the invoice row
from PostgreSQL inside the container. Gate then runs as a real binary, one case
per invocation. A credential experiment re-runs every deny case with a token
signed by the other app's key (a rejected credential) and requires that Gate
never reports it as a clean denial. Run with:
  python -I harness/authzlab_bench.py --gate bin/vardrgate.exe --gate-src ../VardrGate --out reports/<name>.json
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vampi_bench as vb  # noqa: E402

PASSWORD = "password123"
INVOICE_IDS = ("E", "C", "B", "D")


def http(base, method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class Fixture:
    def __init__(self, corpus, mode):
        m = corpus["target"]["modes"][mode]
        self.mode, self.base, self.db = mode, m["base_url"], m["database"]
        self.ids = corpus["fixtures"]["identities"]
        self.tokens = {}
        for name, ident in self.ids.items():
            if "email" not in ident:
                continue
            s, b = http(self.base, "POST", "/api/v1/auth/token", body={"email": ident["email"], "password": PASSWORD})
            tok = json.loads(b).get("access_token") if s == 200 else None
            if not tok:
                raise SystemExit(f"{mode} login {name}: {s}")
            self.tokens[name] = tok
        self.resolved = {}

    def _invoice(self, owner, desc, submit):
        s, b = http(self.base, "POST", "/api/v1/invoices", self.tokens[owner],
                    {"amount_cents": 1000, "currency": "USD", "description": desc})
        if s != 201:
            raise SystemExit(f"{self.mode} create invoice as {owner}: {s} {b}")
        inv = json.loads(b)
        if submit:
            s, b = http(self.base, "POST", f"/api/v1/invoices/{inv['id']}/submit", self.tokens[owner])
            if s != 200:
                raise SystemExit(f"{self.mode} submit as {owner}: {s} {b}")
        return inv

    def reset(self):
        e = self._invoice("eve", "gate-E", False)
        self.resolved = {"E": e["id"], "globex": e["tenant_id"],
                         "C": self._invoice("charlie", "gate-C", True)["id"],
                         "B": self._invoice("bob", "gate-B", True)["id"],
                         "D": self._invoice("charlie", "gate-D", False)["id"]}

    def resolve(self, text):
        for k, v in self.resolved.items():
            text = text.replace("{" + k + "}", v)
        return text

    def row(self, key):
        sql = ("select status, coalesce(description,''), coalesce(approved_by::text,'') "
               f"from invoices where id = '{self.resolved[key]}'")
        out = subprocess.run(["docker", "exec", "authzlab-postgres", "psql", "-U", "authzlab", "-d", self.db,
                              "-At", "-F", "|", "-c", sql], capture_output=True, text=True, check=True)
        status, desc, approver = out.stdout.strip().split("|")
        return {"status": status.lower(), "description": desc, "approved_by": approver}


def observed_violation(case, fx, status, body, before):
    kind, _, subject = case["oracle"].partition(":")
    deny = case["expect"] == "deny"
    if kind == "disclosure":
        got = 200 <= status < 300 and fx.resolved[subject] in body
    else:
        key, _, assign = subject.partition(".")
        field, _, value = assign.partition("=")
        after = fx.row(key)
        got = before[field] != after[field] and after[field] == value
    return got if deny else not got


def ground_truth(corpus):
    rows = []
    for mode in corpus["target"]["modes"]:
        fx = Fixture(corpus, mode)
        for case in corpus["cases"]:
            fx.reset()
            target = case["oracle"].partition(":")[2].partition(".")[0]
            before = fx.row(target)
            status, body = http(fx.base, case["method"], fx.resolve(case["path"]), fx.tokens.get(case["actor"]), case.get("body"))
            got = observed_violation(case, fx, status, body, before)
            want = case["violation"][mode]
            rows.append({"mode": mode, "case": case["id"], "status": status, "violation": got})
            if got != want:
                raise SystemExit(f"GROUND TRUTH MISMATCH {mode}/{case['id']}: label={want} observed={got} status={status}")
    return rows


def credential(token):
    return {"type": "static_header"} if token is None else {"type": "bearer", "value": token}


def resolve_rules(rules, fx):
    return [{**r, "equals": fx.resolve(r["equals"])} for r in rules]


def test_case(case, fx, assertions=None, oracle=None, token=None):
    actor = case["actor"]
    tok = token if token is not None else fx.tokens.get(actor)
    req = {"method": case["method"], "url": fx.base + fx.resolve(case["path"])}
    if "body" in case:
        req["body"] = case["body"]
        req["headers"] = {"Content-Type": "application/json"}
    ea = {"identity_id": actor, "decision": case["expect"]}
    if assertions:
        ea["response_assertions"] = resolve_rules(assertions, fx)
    tc = {"id": case["id"], "identities": [{"id": actor, "credential": credential(tok)}], "request": req,
          "expected_access": [ea], "mutating": case["method"] not in ("GET", "HEAD", "OPTIONS")}
    if oracle:
        tc["write_verification"] = {
            "identity": {"id": "verifier", "credential": credential(fx.tokens[oracle["identity"]])},
            "request": {"method": "GET", "url": fx.base + fx.resolve(oracle["path"])},
            "json_pointer": oracle["json_pointer"], "changed_to": oracle["changed_to"]}
    return tc


def benchmark(gate, corpus, profiles, oracles, repeat, use_assertions, use_verify):
    out = {}
    for mode in corpus["target"]["modes"]:
        fx = Fixture(corpus, mode)
        runs = []
        for _ in range(repeat):
            rows = []
            for case in corpus["cases"]:
                fx.reset()
                rules = profiles["assertions"].get(case["id"]) if use_assertions else None
                oracle = oracles.get(case["id"]) if use_verify else None
                t0 = time.perf_counter()
                code, res = vb.run_gate(gate, test_case(case, fx, rules, oracle))
                row = vb.score(case, mode, code, res)
                row.update(case=case["id"], exit_code=code, seconds=round(time.perf_counter() - t0, 3))
                rows.append(row)
            runs.append(rows)
        key = [[(r["case"], r["verdict"], r["inconclusive"]) for r in run] for run in runs]
        if any(k != key[0] for k in key):
            raise SystemExit(f"unstable results for {mode}")
        out[mode] = {"metrics": vb.metrics(runs[0]), "cases": runs[0]}
    return out


def rejected_credentials(gate, corpus, profiles):
    """Deny cases in vulnerable mode with a token the target cannot verify."""
    vuln, prot = Fixture(corpus, "vulnerable"), Fixture(corpus, "protected")
    rows = []
    for use_assertions in (False, True):
        for case in corpus["cases"]:
            if case["expect"] != "deny" or case["actor"] == "anonymous":
                continue
            vuln.reset()
            rules = profiles["assertions"].get(case["id"]) if use_assertions else None
            code, res = vb.run_gate(gate, test_case(case, vuln, rules, token=prot.tokens[case["actor"]]))
            a = vb.assessment_of(res, case["actor"])
            findings = [f["category"] for f in res.get("findings") or [] if f["identity_id"] == case["actor"]]
            outcome = ("finding:" + findings[0]) if findings else (
                f"{a['decision']}:{a.get('reason', '')}" if a else f"exit:{code}")
            rows.append({"profile": "assertions" if use_assertions else "status", "case": case["id"],
                         "outcome": outcome, "silent_pass": outcome.startswith("denied")})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", required=True)
    ap.add_argument("--gate-src", required=True)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    args.gate = os.path.abspath(args.gate)
    names = ("corpus-authzlab.json", "profiles-authzlab.json", "verification-authzlab.json")
    corpus, profiles, oracles = (vb.load(n) for n in names)
    oracles = {k: v for k, v in oracles.items() if isinstance(v, dict)}

    gt = ground_truth(corpus)
    print(f"ground truth verified: {len(gt)} case/mode pairs match the frozen labels")
    results = {}
    for profile, use_a in (("status", False), ("assertions", True)):
        for vf in (False, True):
            key = profile + ("+verify" if vf else "")
            for mode, r in benchmark(args.gate, corpus, profiles, oracles, args.repeat, use_a, vf).items():
                results[f"{key}/{mode}"] = r
    creds = rejected_credentials(args.gate, corpus, profiles)

    report = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gate_revision": vb.git(args.gate_src, "rev-parse", "HEAD"),
        "gate_tree_clean": vb.git(args.gate_src, "status", "--porcelain", "--", "cmd", "internal", "go.mod") == "",
        "lab_revision": vb.git(vb.LAB, "rev-parse", "HEAD"),
        "target": corpus["target"],
        "inputs_sha256": {n: vb.sha256(os.path.join(vb.LAB, n)) for n in names},
        "repeat": args.repeat,
        "ground_truth": gt,
        "results": results,
        "rejected_credentials": creds,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    for key, r in results.items():
        m = r["metrics"]
        print(f"{key:30s} TP={m['true_positive']} FP={m['false_positive']} FN={m['false_negative']} "
              f"TN={m['true_negative']} inconclusive={m['inconclusive_assessments']} "
              f"precision={m['precision']:.0%} recall={m['recall']:.0%}")
    for r in creds:
        print(f"rejected-credential {r['profile']:10s} {r['case']:22s} {r['outcome']:40s} {'SILENT PASS' if r['silent_pass'] else 'ok'}")


if __name__ == "__main__":
    sys.exit(main())
