"""ZAP Access Control over the frozen AuthZLab corpus, in a disposable container.

Configuration is pre-registered in plan.json (zap_configuration, verdict_mapping.
zap_access_control). Per case: fresh fixture, fresh ZAP session and context, one
unauthenticated seed request through ZAP's proxy, rules for the case's users, one
Access Control scan, then the tool's HTML report and a sanitized result row set.

Run with:
  python -I competitors/zap_bench.py --mode vulnerable|protected [--dead-token charlie] [--repeat 3]
Writes competitors/results/zap/<tag>-r<n>/ (HTML reports) and competitors/results/zap-<tag>.json.
Tokens go only to results/zap/tokens.local.json, deleted when the run ends.
"""

import argparse
import http.client
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import replay  # noqa: E402

PLAN = json.load(open(os.path.join(HERE, "plan.json"), encoding="utf-8"))
CONFIG = PLAN["zap_configuration"]
IMAGE = "zaproxy/zap-stable:2.17.0@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6"
ADDON_VERSION = "13.0.0"
NAME = "vgbench-zap"
PORT = 8090
WRK = os.path.join(replay.RESULTS, "zap")
# Container-side base URLs: ZAP joins only the AuthZLab network and reaches the services by name.
CONTAINER_BASE = {"vulnerable": "http://host.docker.internal:5101", "protected": "http://host.docker.internal:5102"}
SCAN_TIMEOUT = 120
RUN_TIMEOUT = 3600


def docker_run_args(key):
    return ["docker", "run", "--rm", "-d", "--name", NAME,
            "--network", "authzlab-network", "-p", f"127.0.0.1:{PORT}:{PORT}",
            "--cpus", "2", "--memory", "4g", "--pids-limit", "1024",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{os.path.join(HERE, 'zap')}:/zap/bench:ro", "-v", f"{WRK}:/zap/wrk",
            IMAGE, "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", str(PORT),
            "-config", f"api.key={key}", "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true"]


class Zap:
    def __init__(self, key):
        self.key = key

    def call(self, kind, component, endpoint, **params):
        params["apikey"] = self.key
        url = f"http://127.0.0.1:{PORT}/JSON/{component}/{kind}/{endpoint}/?" + urllib.parse.urlencode(params)
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise SystemExit(f"ZAP {component}/{kind}/{endpoint}: {e.code} {e.read().decode(errors='replace')[:300]}")

    def action(self, component, endpoint, **params):
        return self.call("action", component, endpoint, **params)

    def view(self, component, endpoint, **params):
        return self.call("view", component, endpoint, **params)


def start(log):
    os.makedirs(WRK, exist_ok=True)
    key = secrets.token_hex(16)
    args = docker_run_args(key)
    log["docker_run"] = shlex.join(a if not a.startswith("api.key=") else "api.key=<random per run>" for a in args)
    t0 = time.time()
    subprocess.run(args, check=True, capture_output=True)
    zap = Zap(key)
    for _ in range(120):
        try:
            zap.view("core", "version")
            break
        except (OSError, SystemExit):
            time.sleep(1)
    else:
        raise SystemExit("ZAP did not start")
    log["startup_seconds"] = round(time.time() - t0, 1)
    t0 = time.time()
    zap.action("autoupdate", "installAddon", id="accessControl")
    addons = {a["id"]: a["version"] for a in zap.view("autoupdate", "installedAddons")["installedAddons"]}
    if addons.get("accessControl") != ADDON_VERSION:
        raise SystemExit(f"accessControl add-on is {addons.get('accessControl')}, pre-registered {ADDON_VERSION}")
    log["addon_install_seconds"] = round(time.time() - t0, 1)
    log["zap_version"] = zap.view("core", "version")["version"]
    log["addons"] = {k: addons[k] for k in ("accessControl", "graaljs", "commonlib")}
    engine = next(e for e in zap.view("script", "listEngines")["listEngines"] if "Graal" in e)
    zap.action("script", "load", scriptName="bench_tokens", scriptType="httpsender", scriptEngine=engine,
               fileName="/zap/bench/bench_tokens.js")
    zap.action("script", "enable", scriptName="bench_tokens")
    zap.action("script", "load", scriptName="bench_rules", scriptType="standalone", scriptEngine=engine,
               fileName="/zap/bench/bench_rules.js")
    return zap


def stop():
    subprocess.run(["docker", "stop", NAME], capture_output=True)


def seed(method, url, body):
    """One unauthenticated request through ZAP's proxy, so the URL is in the Sites tree."""
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Connection": "close"}
    if data:
        headers["Content-Type"] = "application/json"
    conn.request(method, url, body=data, headers=headers)
    r = conn.getresponse()
    r.read()
    conn.close()
    return r.status


def case_users(case, plan_case):
    users = [case["actor"]]
    original = plan_case["original"]
    if original and original != case["actor"] and original in plan_case["authorized"]:
        users.append(original)
    if all(u == "anonymous" for u in users):
        users.append("alice")  # API requires an authenticated user; score actor only.
    return users


def rule(user, plan_case):
    return "ALLOWED" if user in plan_case["authorized"] else "DENIED"


def deny_regex(markers):
    return "|".join(re.escape(m) for m in markers)


def parse_report(path):
    """Rows of the add-on's HTML report: url, method, user, authorization, access-control result."""
    html = open(path, encoding="utf-8", errors="replace").read()
    def text(c):
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c)).strip()
    header = [text(c) for c in re.findall(r"<th[^>]*>(.*?)</th>", html, re.S | re.I)]
    rows = []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S | re.I):
        cells = [text(c) for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S | re.I)]
        if cells:
            rows.append(cells)
    return {"header": header, "rows": rows}


def run_case(zap, app, case, rnd, outdir):
    plan_case = app.plan["cases"][case["id"]]
    resolved = app.reset()
    before = app.fx.state()
    case_query = "&vg_" + case["id"].replace("-", "_") + "=1"
    gt_status, gt_body = replay.send(app.base, case["method"], app.path(case, resolved) + case_query, app.fx.tokens.get(case["actor"]), case.get("body"))
    actual = replay.vb.observed_violation(case, app.corpus, app.fx, gt_status, gt_body, before, app.fx.state())
    if actual != case["violation"][app.mode]:
        raise SystemExit(f"{case['id']}: independent ground truth disagrees")
    app.reset()
    url = CONTAINER_BASE[app.mode] + app.path(case, resolved) + case_query
    # One ZAP session per run and a new context per case: the add-on caches rules managers by
    # context id across sessions (ExtensionAccessControl.contextManagers), so a new session's reused
    # id would get the previous context's stale manager and no rules.
    name = f"{case['id']}-r{rnd}"
    ctx = zap.action("context", "newContext", contextName=name)["contextId"]
    # ZAP matches include regexes against the URL without its query, so match the path and any query.
    zap.action("context", "includeInContext", contextName=name, regex=re.escape(url.split("?")[0]) + r"(\?.*)?")
    zap.action("authorization", "setBasicAuthorizationDetectionMethod", contextId=ctx,
               bodyRegex=deny_regex(app.plan["deny_markers"]), statusCode="-1", logicalOperator="OR")
    users = case_users(case, plan_case)
    ids, rules = {}, {}
    for u in users:
        if u == "anonymous":
            rules["-1"] = rule(u, plan_case)
            continue
        uid = zap.action("users", "newUser", contextId=ctx, name=u)["userId"]
        zap.action("users", "setUserEnabled", contextId=ctx, userId=uid, enabled="true")
        ids[u] = uid
        rules[str(uid)] = rule(u, plan_case)
    if (rule(case["actor"], plan_case) == "ALLOWED") != (case["expect"] == "allow"):
        raise SystemExit(f"{case['id']}: plan 'authorized' disagrees with the corpus label")

    seed_status = seed(case["method"], url, case.get("body"))
    # The Sites tree is updated asynchronously; rules can only be set once the URL is in the context.
    for _ in range(100):
        if url in zap.view("context", "urls", contextName=name)["urls"]:
            break
        time.sleep(0.1)
    else:
        raise SystemExit(f"{case['id']}: seeded URL never reached the context")
    with open(os.path.join(WRK, "case.json"), "w", encoding="utf-8") as f:
        json.dump({"contextId": int(ctx), "rules": rules}, f)
    zap.action("script", "runStandAloneScript", scriptName="bench_rules")
    applied = json.load(open(os.path.join(WRK, "rules-applied.json"), encoding="utf-8"))
    if not any(a["userId"] == int(uid) for a in applied for uid in rules):
        raise SystemExit(f"{case['id']}: no Access Control rules were set")

    # Seeding may itself mutate a vulnerable VAmPI fixture. Reset after the
    # node/rules exist and before the scan; retain scanner replay order as-is.
    app.reset()
    with open(os.path.join(WRK, "tokens.local.json"), "w", encoding="utf-8") as f:
        json.dump(app.fx.tokens, f)
    msgs_before = max([int(m["id"]) for m in zap.view("core", "messages", baseurl=url)["messages"]] or [0])
    t0 = time.time()
    params = {"contextId": ctx, "userId": ",".join(ids[u] for u in users if u in ids),
              "scanAsUnAuthUser": str("anonymous" in users).lower(), "raiseAlert": "true"}
    if not ids:
        raise SystemExit(f"{case['id']}: ZAP's scan API needs at least one authenticated user")
    zap.action("accessControl", "scan", **params)
    while True:
        status = zap.view("accessControl", "getScanStatus", contextId=ctx)["getScanStatus"]
        progress = zap.view("accessControl", "getScanProgress", contextId=ctx)["getScanProgress"]
        print("    scan", status, progress) if os.environ.get("ZAP_DEBUG") else None
        if status not in ("NOT_STARTED", "RUNNING", "PAUSED"):
            break
        if time.time() - t0 > SCAN_TIMEOUT:
            raise SystemExit(f"{case['id']}: scan timed out")
        time.sleep(0.2)
    scan_seconds = round(time.time() - t0, 2)
    report = f"{case['id']}.html"
    zap.action("accessControl", "writeHTMLreport", contextId=ctx, fileName=f"/zap/wrk/{os.path.basename(outdir)}/{report}")
    rows = parse_report(os.path.join(outdir, report))
    statuses = scan_statuses(zap, url, msgs_before)
    zap.action("context", "removeContext", contextName=name)
    zap.action("core", "deleteSiteNode", url=CONTAINER_BASE[app.mode])
    return {"case": case["id"], "expect": case["expect"], "label_violation": case["violation"][app.mode],
            "actor": case["actor"], "users": users, "rules": {u: rule(u, plan_case) for u in users},
            "ground_truth_status": gt_status, "ground_truth_violation": actual,
            "seed_status": seed_status, "rules_applied": len(applied), "scan_status": status,
            "scan_seconds": scan_seconds, "report": os.path.relpath(os.path.join(outdir, report), replay.RESULTS),
            "report_rows": rows, "replay_statuses": statuses}


def scan_statuses(zap, url, after):
    """Status code of each message the scan sent for the URL, in send order. No headers kept."""
    msgs = zap.view("core", "messages", baseurl=url)["messages"]
    return [{"id": int(m["id"]), "type": int(m["type"]),
             "status": int(m["responseHeader"].split()[1]) if m.get("responseHeader") else None}
            for m in msgs if int(m["id"]) > after]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=("vulnerable", "protected"))
    ap.add_argument("--dead-token", metavar="USER")
    ap.add_argument("--repeat", type=int, default=CONFIG["repeats"])
    ap.add_argument("--cases", help="comma-separated case ids (exploration only)")
    args = ap.parse_args()

    app = replay.App("vampi", args.mode)
    app.dead = args.dead_token
    if args.dead_token:
        app.kill_token(args.dead_token)
    tag = replay.tag(app)
    log = {"tool": "zap_access_control", "app": "vampi", "mode": args.mode, "dead_token": args.dead_token,
           "image": IMAGE, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    tokens_path = os.path.join(WRK, "tokens.local.json")
    deadline = time.time() + RUN_TIMEOUT
    zap = start(log)
    try:
        with open(tokens_path, "w", encoding="utf-8") as f:
            json.dump({u: t for u, t in app.tool_tokens.items() if t}, f)
        app.assert_live()
        runs = []
        for rnd in range(1, args.repeat + 1):
            outdir = os.path.join(WRK, f"{tag}-r{rnd}")
            os.makedirs(outdir, exist_ok=True)
            rows = []
            for case in app.corpus["cases"]:
                if args.cases and case["id"] not in args.cases.split(","):
                    continue
                if time.time() > deadline:
                    raise SystemExit("run time limit reached")
                rows.append(run_case(zap, app, case, rnd, outdir))
                print(f"r{rnd} {case['id']:22s} users={rows[-1]['users']} report={rows[-1]['report_rows']} "
                      f"statuses={[s['status'] for s in rows[-1]['replay_statuses']]}")
            runs.append(rows)
        log["runs"] = runs
    finally:
        stop()
        if os.path.exists(tokens_path):
            os.remove(tokens_path)
    log["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = os.path.join(replay.RESULTS, f"zap-{tag}{'-explore' if args.cases else ''}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)
    print("wrote", out)


if __name__ == "__main__":
    sys.exit(main())
