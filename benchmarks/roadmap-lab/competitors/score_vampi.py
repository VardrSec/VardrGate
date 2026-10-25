"""Score pinned ZAP VAmPI exports without response bodies or credentials."""
import hashlib
import html
import json
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
output = {"schema_version": 1, "mapping": "pre-registered plan.json zap_access_control; actor rows only; status identity gate; independent database ground truth", "modes": {}}
for mode in ("vulnerable", "protected"):
    path = os.path.join(HERE, "results", f"zap-vampi-{mode}.json")
    report = json.load(open(path, encoding="utf-8"))
    runs = []
    for run in report["runs"]:
        rows = []
        for row in run:
            names = [html.unescape(n) for n in row["report_rows"]["header"][2:] if n not in ("Method", "URL", "Authorized?", "Access Control")]
            actor = "<< Unauthenticated >>" if row["actor"] == "anonymous" else row["actor"]
            order = [u for u in row["users"] if u != "anonymous"] + (["anonymous"] if "anonymous" in row["users"] else [])
            statuses = [r["status"] for r in row["replay_statuses"] if r["type"] == 13]
            if len(row["report_rows"]["rows"]) != 1 or len(statuses) != len(order) or actor not in names:
                raise SystemExit(f"{row['case']}: incomplete scanner provenance")
            status = statuses[order.index(row["actor"])]
            if status != row["ground_truth_status"]:
                raise SystemExit(f"{row['case']}: replay identity/status mismatch")
            raw = row["report_rows"]["rows"][0][3 + 2 * names.index(actor)]
            if raw not in ("Valid", "Invalid", "Unknown"):
                raise SystemExit(f"unknown ZAP verdict: {raw}")
            violation = row["ground_truth_violation"]
            verdict = ("TP" if violation else "FP") if raw == "Invalid" else (("FN" if violation else "TN") if raw == "Valid" else ("FN" if violation else "inconclusive"))
            rows.append({"case": row["case"], "actor_status": status, "scanner_result": raw, "ground_truth_violation": violation, "verdict": verdict})
        runs.append(rows)
    if any(run != runs[0] for run in runs[1:]):
        raise SystemExit("unstable repeated classifications")
    output["modes"][mode] = {"repeats": len(runs), "metrics": dict(Counter(r["verdict"] for r in runs[0])), "cases": runs[0], "source_sha256": hashlib.sha256(open(path,"rb").read()).hexdigest()}
out = os.path.join(HERE,"results","score-zap-vampi.json")
with open(out,"w",encoding="utf-8") as f:
    json.dump(output,f,indent=2)
for mode, result in output["modes"].items():
    print(mode, result["metrics"], "repeats", result["repeats"])
