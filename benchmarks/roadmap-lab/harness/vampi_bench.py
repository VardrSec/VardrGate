"""Score VardrGate against pinned VAmPI in vulnerable and protected modes.

Ground truth comes from the frozen corpus and is checked independently: the
harness sends each request itself and reads VAmPI's database inside the
container. Gate is then run as a real binary, one case per invocation, with a
fixture reset before every case. Run with: python -I harness/vampi_bench.py.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODES = {"vulnerable": ("vampi-vuln", "http://127.0.0.1:5101"),
         "protected": ("vampi-prot", "http://127.0.0.1:5102")}
UNAUTHORIZED = {"unexpected_access", "missing_authentication", "cross_tenant_access",
                "potential_bola", "privilege_escalation"}


def load(name):
    with open(os.path.join(LAB, name), encoding="utf-8") as f:
        return json.load(f)


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read().replace(b"\r\n", b"\n")).hexdigest()


def http(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class Fixture:
    def __init__(self, corpus, mode):
        self.ids = corpus["fixtures"]["identities"]
        self.book = corpus["fixtures"]["resources"]["alice_book"]
        self.container, self.base = MODES[mode]
        self.tokens = {}

    def reset(self):
        # createdb seeds books with random titles that can collide; retry.
        for _ in range(10):
            status, _ = http("GET", self.base + "/createdb")
            if status == 200:
                break
        else:
            raise SystemExit("createdb kept failing")
        for name in ("alice", "bob", "carol"):
            u = self.ids[name]
            s, b = http("POST", self.base + "/users/v1/register",
                        body={"username": u["username"], "password": u["password"], "email": u["email"]})
            if s != 200 or "Successfully registered" not in b:
                raise SystemExit(f"register {name}: {s} {b}")
        for name in ("alice", "bob", "carol", "admin"):
            u = self.ids[name]
            s, b = http("POST", self.base + "/users/v1/login",
                        body={"username": u["username"], "password": u["password"]})
            tok = json.loads(b).get("auth_token")
            if s != 200 or not tok:
                raise SystemExit(f"login {name}: {s} {b}")
            self.tokens[name] = tok
        s, b = http("POST", self.base + "/books/v1", self.tokens["alice"],
                    {"book_title": self.book["title"], "secret": self.book["secret"]})
        if s != 200:
            raise SystemExit(f"add book: {s} {b}")

    def state(self):
        script = ("import sqlite3,json;c=sqlite3.connect('/vampi/database/database.db');"
                  "print(json.dumps({'users':{r[0]:{'password':r[1],'email':r[2]} for r in "
                  "c.execute('select username,password,email from users')},"
                  "'books':{r[0]:r[1] for r in c.execute('select book_title,secret_content from books')}}))")
        out = subprocess.run(["docker", "exec", self.container, "python", "-c", script],
                             capture_output=True, text=True, check=True)
        return json.loads(out.stdout)


def observed_violation(case, corpus, fx, status, body, before, after):
    """Decide from the target's actual effect whether access policy was broken."""
    ids = corpus["fixtures"]["identities"]
    kind, _, subject = case["oracle"].partition(":")
    deny = case["expect"] == "deny"
    if kind == "none":
        return not deny and not (200 <= status < 300)
    if kind == "disclosure":
        value = fx.book["secret"] if subject == "alice_book.secret" else ids["alice"]["password"]
        disclosed = value in body
        return disclosed if deny else not disclosed
    who, field = subject.split(".")
    user = ids[who]["username"]
    if field == "exists":
        changed = (user in before["users"]) != (user in after["users"])
    else:
        changed = before["users"][user][field] != after["users"].get(user, {}).get(field)
    return changed if deny else not changed


def ground_truth(corpus):
    rows = []
    for mode in MODES:
        fx = Fixture(corpus, mode)
        for case in corpus["cases"]:
            fx.reset()
            before = fx.state()
            status, body = http(case["method"], fx.base + case["path"],
                                fx.tokens.get(case["actor"]), case.get("body"))
            after = fx.state()
            got = observed_violation(case, corpus, fx, status, body, before, after)
            want = case["violation"][mode]
            rows.append({"mode": mode, "case": case["id"], "status": status, "violation": got})
            if got != want:
                raise SystemExit(f"GROUND TRUTH MISMATCH {mode}/{case['id']}: label={want} observed={got} status={status}")
    return rows


def credential(fx, actor, invalid=False):
    if actor == "anonymous":
        return {"type": "static_header"}
    return {"type": "bearer", "value": "not-a-valid-token" if invalid else fx.tokens[actor]}


def test_case(case, fx, assertions=None, expect=None, deny_status=None, invalid=False, preflight=False):
    actor = case["actor"]
    identity = {"id": actor, "credential": credential(fx, actor, invalid)}
    if preflight and actor != "anonymous":
        identity["preflight"] = {"url": fx.base + "/me", "expected_status": 200,
                                 "json_fields": {"data.username": fx.ids[actor]["username"]}}
    req = {"method": case["method"], "url": fx.base + case["path"]}
    if "body" in case:
        req["body"] = case["body"]
        req["headers"] = {"Content-Type": "application/json"}
    ea = {"identity_id": actor, "decision": expect or case["expect"]}
    if assertions:
        ea["response_assertions"] = assertions
    tc = {"id": case["id"], "identities": [identity], "request": req, "expected_access": [ea],
          "mutating": case["method"] not in ("GET", "HEAD", "OPTIONS")}
    if deny_status:
        tc["deny_status"] = deny_status
    return tc


def run_gate(gate, tc):
    with tempfile.TemporaryDirectory() as d:
        cases, out = os.path.join(d, "cases.json"), os.path.join(d, "result.json")
        with open(cases, "w", encoding="utf-8") as f:
            json.dump([tc], f)
        p = subprocess.run([gate, "run", "--cases", cases, "--allow-private-targets",
                            "--allow-mutating", "--out", out], capture_output=True, text=True)
        if not os.path.exists(out):
            raise SystemExit(f"gate produced no result (exit {p.returncode}): {p.stderr}")
        with open(out, encoding="utf-8") as f:
            res = json.load(f)
    res = res[0] if isinstance(res, list) else res
    return p.returncode, res


def profile_for(profiles, case):
    rules = []
    for r in profiles["assertions"].get(case["path"], []):
        roles = r.get("roles")
        if roles and case["actor"] not in roles:
            continue
        rules.append({k: v for k, v in r.items() if k != "roles"})
    return rules


def assessment_of(res, actor):
    for a in res.get("assessments") or []:
        if a["identity_id"] == actor:
            return a
    return None


def score(case, mode, exit_code, res):
    actor = case["actor"]
    want = UNAUTHORIZED if case["expect"] == "deny" else {"authorization_mismatch"}
    detected = any(f["identity_id"] == actor and f["category"] in want for f in res.get("findings") or [])
    a = assessment_of(res, actor)
    not_tested = exit_code == 3 or any(p.get("status") != "passed" for p in res.get("preflight") or [])
    inconclusive = not_tested or (a is not None and a["decision"] in ("inconclusive", "skipped"))
    violation = case["violation"][mode]
    if detected:
        verdict = "true_positive" if violation else "false_positive"
    elif violation:
        verdict = "false_negative"
    elif inconclusive:
        verdict = "inconclusive_control"
    else:
        verdict = "true_negative"
    return {"verdict": verdict, "inconclusive": inconclusive, "not_tested": not_tested,
            "assessment": a, "findings": [(f["category"], f["severity"]) for f in res.get("findings") or []]}


def metrics(rows):
    m = {k: sum(r["verdict"] == k for r in rows) for k in
         ("true_positive", "false_positive", "false_negative", "true_negative", "inconclusive_control")}
    known = m["true_positive"] + m["false_negative"]
    m["inconclusive_assessments"] = sum(r["inconclusive"] for r in rows)
    m["inconclusive_known_failures"] = sum(r["inconclusive"] and r["verdict"] == "false_negative" for r in rows)
    m["precision"] = m["true_positive"] / (m["true_positive"] + m["false_positive"]) if m["true_positive"] + m["false_positive"] else 0
    m["recall"] = m["true_positive"] / known if known else 0
    m["known_failures"], m["total"] = known, len(rows)
    return m


def benchmark(gate, corpus, profiles, repeat, oracles=None):
    out = {}
    for profile in ("status", "assertions"):
        for mode in MODES:
            fx = Fixture(corpus, mode)
            runs = []
            for _ in range(repeat):
                rows = []
                for case in corpus["cases"]:
                    fx.reset()
                    rules = profile_for(profiles, case) if profile == "assertions" else None
                    tc = test_case(case, fx, assertions=rules)
                    if oracles and case["path"] in oracles:
                        tc["write_verification"] = verification_for(oracles[case["path"]], case, fx)
                    code, res = run_gate(gate, tc)
                    row = score(case, mode, code, res)
                    row["case"] = case["id"]
                    rows.append(row)
                runs.append(rows)
            stable = all([(r["case"], r["verdict"], r["inconclusive"]) for r in run] ==
                         [(r["case"], r["verdict"], r["inconclusive"]) for r in runs[0]] for run in runs)
            if not stable:
                raise SystemExit(f"unstable results for {profile}/{mode}")
            out[f"{profile}/{mode}"] = {"metrics": metrics(runs[0]), "cases": runs[0]}
    return out


def verification_for(oracle, case, fx):
    """Build Gate's write_verification from a verification.json oracle."""
    who = oracle["identity"]
    req = {"method": oracle["request"]["method"], "url": fx.base + oracle["request"]["path"]}
    if "body" in oracle["request"]:
        req["body"] = oracle["request"]["body"]
        req["headers"] = {"Content-Type": "application/json"}
    wv = {"identity": {"id": "verifier", "credential": credential(fx, who)}, "request": req,
          "json_pointer": oracle["json_pointer"]}
    if oracle.get("allow_unsafe_method"):
        wv["allow_unsafe_method"] = True
    if "changed_to_from_body" in oracle:
        wv["changed_to"] = case["body"][oracle["changed_to_from_body"].strip("/")]
    return wv


def mistakes(gate, corpus, profiles, experiments):
    by_id = {c["id"]: c for c in corpus["cases"]}
    rows = []
    for ex in experiments:
        case, mode = by_id[ex["case"]], ex["mode"]
        fx = Fixture(corpus, mode)
        fx.reset()
        rules = profile_for(profiles, case) if ex.get("use_profile") else ex.get("assertions")
        tc = test_case(case, fx, assertions=rules, expect=ex.get("expect"), deny_status=ex.get("deny_status"),
                       invalid=ex.get("credential") == "invalid", preflight=ex.get("preflight", False))
        code, res = run_gate(gate, tc)
        a = assessment_of(res, case["actor"])
        not_tested = code == 3
        findings = [f["category"] for f in res.get("findings") or [] if f["identity_id"] == case["actor"]]
        if not_tested:
            outcome = "not_tested"
        elif findings:
            outcome = "finding:" + findings[0]
        elif a and a["decision"] == "inconclusive":
            outcome = "inconclusive:" + a["reason"]
        else:
            outcome = "silent_pass"
        ok = any(outcome == acc or outcome.startswith(acc + ":") for acc in ex["acceptable"])
        rows.append({"id": ex["id"], "outcome": outcome, "acceptable": ok, "exit_code": code,
                     "assessment": a, "preflight": res.get("preflight")})
    return rows


def git(path, *args):
    return subprocess.run(["git", "-C", path, *args], capture_output=True, text=True).stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", required=True, help="path to a vardrgate binary")
    ap.add_argument("--gate-src", required=True, help="Gate checkout the binary was built from")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--verifier", action="store_true", help="enable write verification for cases that declare it")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    args.gate = os.path.abspath(args.gate)

    corpus, profiles, exp = load("corpus.json"), load("profiles.json"), load("mistakes.json")
    gt = ground_truth(corpus)
    print(f"ground truth verified: {len(gt)} case/mode pairs match the frozen labels")
    oracles = load("verification.json")["vampi"] if args.verifier else None
    # The login oracle reads the victim's password from the environment, as a
    # developer's CI would; it never appears in a case file or report.
    os.environ["VAMPI_ALICE_PASSWORD"] = corpus["fixtures"]["identities"]["alice"]["password"]
    results = benchmark(args.gate, corpus, profiles, args.repeat, oracles)
    mist = mistakes(args.gate, corpus, profiles, exp["experiments"])
    image = subprocess.run(["docker", "image", "inspect", "vampi-gate:f16052d", "--format", "{{.Id}}"],
                           capture_output=True, text=True).stdout.strip()
    report = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gate_revision": git(args.gate_src, "rev-parse", "HEAD"),
        "gate_tree_clean": git(args.gate_src, "status", "--porcelain", "--", "cmd", "internal", "go.mod") == "",
        "lab_revision": git(LAB, "rev-parse", "HEAD"),
        "lab_tree_status": git(LAB, "status", "--porcelain"),
        "target": corpus["target"],
        "image_id": image,
        "inputs_sha256": {n: sha256(os.path.join(LAB, n)) for n in ("corpus.json", "profiles.json", "mistakes.json", "verification.json")},
        "repeat": args.repeat,
        "verifier": args.verifier,
        "ground_truth": gt,
        "results": results,
        "mistakes": mist,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    for key, r in results.items():
        m = r["metrics"]
        print(f"{key:24s} TP={m['true_positive']} FP={m['false_positive']} FN={m['false_negative']} "
              f"TN={m['true_negative']} inconclusive={m['inconclusive_assessments']} "
              f"precision={m['precision']:.1%} recall={m['recall']:.1%}")
    for r in mist:
        print(f"mistake {r['id']:26s} {r['outcome']:40s} {'ok' if r['acceptable'] else 'NOT ACCEPTABLE'}")


if __name__ == "__main__":
    sys.exit(main())
