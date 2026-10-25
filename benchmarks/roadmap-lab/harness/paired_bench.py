"""VardrGate with the same identities the replay tools see (competitors/plan.json
gate_paired_configuration): each deny case also carries its authorized original
as an allow-expected identity, a positive control. Only the actor row is scored.
Run with:
  python -I harness/paired_bench.py --gate bin/vardrgate.exe --gate-src ../VardrGate --out reports/paired-<rev>.json
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authzlab_bench as ab  # noqa: E402
import vampi_bench as vb  # noqa: E402

PLAN = os.path.join(vb.LAB, "competitors", "plan.json")


def eligible(app_plan, excluded):
    return {cid: p for cid, p in app_plan["cases"].items()
            if cid not in excluded and p["original"] and p["original"] in p["authorized"]}


def add_control(tc, who, token, rules):
    tc["identities"].append({"id": who, "credential": ab.credential(token)})
    ea = {"identity_id": who, "decision": "allow"}
    if rules:
        ea["response_assertions"] = rules
    tc["expected_access"].append(ea)
    return tc


def authzlab_case(fx, case, original, profiles, oracles, use_a, use_v):
    rules = profiles["assertions"].get(case["id"]) if use_a else None
    tc = ab.test_case(case, fx, rules, oracles.get(case["id"]) if use_v else None)
    return add_control(tc, original, fx.tokens.get(original), ab.resolve_rules(rules, fx) if rules else None)


def vampi_case(fx, case, original, profiles, oracles, use_a, use_v):
    rules = vb.profile_for(profiles, case) if use_a else None
    tc = vb.test_case(case, fx, assertions=rules)
    if use_v and case["path"] in oracles:
        tc["write_verification"] = vb.verification_for(oracles[case["path"]], case, fx)
    control_rules = vb.profile_for(profiles, dict(case, actor=original)) if use_a else None
    return add_control(tc, original, fx.tokens.get(original), control_rules)


def run(gate, app, fixture_for, build, corpus, cases, profiles, oracles, repeat):
    out = {}
    for profile, use_a in (("status", False), ("assertions", True)):
        for use_v in (False, True):
            for mode in corpus["target"]["modes"]:
                fx = fixture_for(mode)
                runs = []
                for _ in range(repeat):
                    rows = []
                    for case in corpus["cases"]:
                        if case["id"] not in cases:
                            continue
                        fx.reset()
                        tc = build(fx, case, cases[case["id"]]["original"], profiles, oracles, use_a, use_v)
                        try:
                            code, res = vb.run_gate(gate, tc)
                        except SystemExit as e:
                            # Gate refused the configuration before sending traffic: not expressible, not a miss.
                            rows.append({"case": case["id"], "verdict": "not_expressible", "inconclusive": True,
                                         "not_tested": True, "assessment": None, "findings": [], "exit_code": 1,
                                         "control": None, "error": next((ln.strip() for ln in str(e).splitlines()
                                                                         if case["id"] + ":" in ln), str(e))[:200]})
                            continue
                        row = vb.score(case, mode, code, res)
                        control = vb.assessment_of(res, cases[case["id"]]["original"])
                        row.update(case=case["id"], exit_code=code, control=control,
                                   error=None if res.get("assessments") else res.get("error"))
                        rows.append(row)
                    runs.append(rows)
                key = [[(r["case"], r["verdict"], r["inconclusive"]) for r in run] for run in runs]
                if any(k != key[0] for k in key):
                    raise SystemExit(f"unstable results {app} {profile} {mode}")
                out[f"{app}:{profile}{'+verify' if use_v else ''}/{mode}"] = {"metrics": vb.metrics(runs[0]), "cases": runs[0]}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", required=True)
    ap.add_argument("--gate-src", required=True)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    gate = os.path.abspath(args.gate)
    plan = json.load(open(PLAN, encoding="utf-8"))
    excluded = set(plan["gate_paired_configuration"]["excluded"])

    results = {}
    c = vb.load("corpus-authzlab.json")
    oracles = {k: v for k, v in vb.load("verification-authzlab.json").items() if isinstance(v, dict)}
    results.update(run(gate, "authzlab", lambda m: ab.Fixture(c, m), authzlab_case, c,
                       {k: v for k, v in eligible(plan["apps"]["authzlab"], excluded).items()
                        if next(x for x in c["cases"] if x["id"] == k)["expect"] == "deny"},
                       vb.load("profiles-authzlab.json"), oracles, args.repeat))
    c2 = vb.load("corpus.json")
    os.environ["VAMPI_ALICE_PASSWORD"] = c2["fixtures"]["identities"]["alice"]["password"]
    results.update(run(gate, "vampi", lambda m: vb.Fixture(c2, m), vampi_case, c2,
                       {k: v for k, v in eligible(plan["apps"]["vampi"], excluded).items()
                        if next(x for x in c2["cases"] if x["id"] == k)["expect"] == "deny"},
                       vb.load("profiles.json"), vb.load("verification.json")["vampi"], args.repeat))

    names = ("competitors/plan.json", "corpus-authzlab.json", "corpus.json", "profiles-authzlab.json", "profiles.json",
             "verification-authzlab.json", "verification.json")
    report = {"schema_version": 1, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "gate_revision": vb.git(args.gate_src, "rev-parse", "HEAD"),
              "gate_tree_clean": vb.git(args.gate_src, "status", "--porcelain", "--", "cmd", "internal", "go.mod") == "",
              "inputs_sha256": {n: vb.sha256(os.path.join(vb.LAB, n)) for n in names},
              "repeat": args.repeat, "results": results}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    for k, r in results.items():
        m = r["metrics"]
        print(f"{k:40s} TP={m['true_positive']} FP={m['false_positive']} FN={m['false_negative']} "
              f"TN={m['true_negative']} inconclusive={m['inconclusive_assessments']}")
        for row in r["cases"]:
            a, ctl = row["assessment"] or {}, row["control"] or {}
            if row["inconclusive"] or row["error"] or row["verdict"] in ("false_positive", "false_negative"):
                print(f"    {row['case']:20s} {row['verdict']:20s} actor={a.get('decision')}/{a.get('reason')} "
                      f"control={ctl.get('decision')}/{ctl.get('reason')} {('ERROR ' + str(row['error'])[:80]) if row['error'] else ''}")


if __name__ == "__main__":
    sys.exit(main())
