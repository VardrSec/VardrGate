"""Drive Burp authorization extensions over the frozen corpora.

  check      send every case's actor request directly (no proxy) with the case tag
             and confirm the frozen labels still hold, so the tag is harmless
  proxy      for Autorize / Auth Analyzer: per case, set up fresh resources
             directly, then send only the original identity's request through
             the Burp proxy for the extension to replay
  authmatrix seed one resource set per case and write an AuthMatrix state file
             to load, run and save back

Tokens go only to competitors/results/*.local.* files, never to stdout.
Run with: python -I competitors/replay.py <command> --app authzlab|vampi --mode vulnerable|protected
"""

import argparse
import base64
import http.client
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "harness"))
import authzlab_bench as ab  # noqa: E402
import vampi_bench as vb  # noqa: E402

RESULTS = os.path.join(HERE, "results")


class App:
    """Uniform fixture access over the two harnesses."""

    def __init__(self, name, mode):
        self.name, self.mode = name, mode
        self.plan = json.load(open(os.path.join(HERE, "plan.json"), encoding="utf-8"))["apps"][name]
        self.corpus = vb.load(self.plan["corpus"])
        if name == "authzlab":
            self.fx = ab.Fixture(self.corpus, mode)
            self.base = self.fx.base
        else:
            self.fx = vb.Fixture(self.corpus, mode)
            self.base = self.fx.base
            self.fx.reset()
        self.session_tokens = dict(self.fx.tokens)
        self.tool_tokens = dict(self.session_tokens)
        self.dead = None

    def probe(self, token):
        return send(self.base, "GET", "/api/v1/invoices" if self.name == "authzlab" else "/me", token, None)[0]

    def kill_token(self, user):
        """Give the tool a token the target rejects: same user, signed by the other mode's app.
        Originals keep valid tokens."""
        other = App(self.name, "protected" if self.mode == "vulnerable" else "vulnerable")
        self.tool_tokens[user] = other.session_tokens[user]
        s = self.probe(self.tool_tokens[user])
        if s != 401:
            raise SystemExit(f"dead token for {user} was not rejected (status {s})")

    def assert_live(self):
        """Abort if any token the run depends on is already rejected (e.g. expired during GUI setup)."""
        dead = [f"{kind}:{u}" for kind, toks in (("tool", self.tool_tokens), ("original", self.session_tokens))
                for u, t in toks.items() if not (kind == "tool" and u == self.dead) and self.probe(t) == 401]
        if dead:
            raise SystemExit(f"tokens rejected before the run: {', '.join(dead)}. Regenerate and reconfigure.")
        exp = [jwt_exp(t) for t in self.tool_tokens.values()]
        exp = [e for e in exp if e]
        if exp:
            left = (min(exp) - time.time()) / 60
            print(f"all tokens live; earliest expiry in {left:.0f} min ({time.strftime('%H:%M', time.localtime(min(exp)))})")

    def reset(self):
        self.fx.reset()
        return dict(self.fx.resolved) if self.name == "authzlab" else {}

    def path(self, case, resolved):
        p = case["path"]
        for k, v in resolved.items():
            p = p.replace("{" + k + "}", v)
        return p + ("&" if "?" in p else "?") + "bench_case=" + case["id"]

    def token(self, who):
        return None if who in (None, "anonymous") else self.session_tokens[who]


def jwt_exp(token):
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("exp")
    except (IndexError, ValueError):
        return None


def send(base, method, path, token, body, proxy=None):
    u = urllib.parse.urlsplit(base)
    headers = {"Connection": "close"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    if proxy:
        p = urllib.parse.urlsplit(proxy)
        conn, target = http.client.HTTPConnection(p.hostname, p.port, timeout=30), base + path
    else:
        conn, target = http.client.HTTPConnection(u.hostname, u.port, timeout=30), path
    conn.request(method, target, body=data, headers=headers)
    r = conn.getresponse()
    out = r.status, r.read().decode(errors="replace")
    conn.close()
    return out


def write_local(name, obj):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    return path


def tag(app):
    return f"{app.name}-{app.mode}" + (f"-deadtoken-{app.dead}" if app.dead else "")


def session_file(app, tool):
    users = {u: ("(no Authorization header)" if u == "anonymous" else "Authorization: Bearer " + app.tool_tokens[u])
             for u in app.plan["users"]}
    return write_local(f"session-{tag(app)}-{tool}.local.json", {
        "replay_users": app.plan["replay_users"], "users": users, "deny_markers": app.plan["deny_markers"]})


def check(app):
    bad = 0
    for case in app.corpus["cases"]:
        resolved = app.reset()
        if app.name == "authzlab":
            target = case["oracle"].partition(":")[2].partition(".")[0]
            before = app.fx.row(target)
            status, body = send(app.base, case["method"], app.path(case, resolved), app.fx.tokens.get(case["actor"]), case.get("body"))
            got = ab.observed_violation(case, app.fx, status, body, before)
        else:
            before = app.fx.state()
            status, body = send(app.base, case["method"], app.path(case, resolved), app.fx.tokens.get(case["actor"]), case.get("body"))
            got = vb.observed_violation(case, app.corpus, app.fx, status, body, before, app.fx.state())
        want = case["violation"][app.mode]
        bad += got != want
        print(f"{case['id']:22s} status={status} violation={got} label={want} {'ok' if got == want else 'MISMATCH'}")
    print("tag is harmless" if not bad else f"{bad} MISMATCHES: do not use the tag")
    return 1 if bad else 0


def proxy(app, args):
    print("Session headers:", session_file(app, args.tool))
    input("Configure the extension with those headers, turn it on, then press Enter...")
    app.assert_live()
    log = []
    for case in app.corpus["cases"]:
        plan = app.plan["cases"][case["id"]]
        if plan["original"] is None:
            print(f"{case['id']:22s} skipped: {plan['replay_tools']}")
            continue
        resolved = app.reset()
        path = app.path(case, resolved)
        status, _ = send(app.base, case["method"], path, app.token(plan["original"]), case.get("body"), args.proxy)
        log.append({"case": case["id"], "method": case["method"], "path": path, "original": plan["original"],
                    "actor": case["actor"], "original_status": status, "sent_at": time.time()})
        warn = "  WARNING: original rejected, this row will be NOT TESTED" if status == 401 else ""
        print(f"{case['id']:22s} original={plan['original']:8s} status={status}{warn}")
        time.sleep(args.delay)
    out = write_local(f"proxy-{tag(app)}-{args.tool}.json", log)
    print("Sent log:", out, "\nExport the extension's table into competitors/results/ (see README).")


def raw_request(app, case, path):
    u = urllib.parse.urlsplit(app.base)
    body = json.dumps(case["body"]) if "body" in case else ""
    head = [f"{case['method']} {path} HTTP/1.1", f"Host: {u.hostname}:{u.port}", "Connection: close"]
    if body:
        head += ["Content-Type: application/json", f"Content-Length: {len(body.encode())}"]
    return ("\r\n".join(head) + "\r\n\r\n" + body).encode()


def authmatrix(app):
    users = app.plan["users"]
    roles = [{"index": i, "column": i, "name": u, "deleted": False, "singleUser": True} for i, u in enumerate(users)]
    am_users = [{"index": i, "tableRow": i, "name": u, "roles": {str(j): i == j for j in range(len(users))},
                 "deleted": False, "enabled": True, "cookiesBase64": "",
                 "headersBase64": [base64.b64encode(("" if u == "anonymous" else
                                    "Authorization: Bearer " + app.tool_tokens[u]).encode()).decode()]}
                for i, u in enumerate(users)]
    u = urllib.parse.urlsplit(app.base)
    messages, index, seen = [], {}, {}
    for case in app.corpus["cases"]:
        plan = app.plan["cases"][case["id"]]
        # VAmPI shares one fixture, so identical requests become one message; AuthZLab seeds per case.
        key = (case["method"], case["path"], json.dumps(case.get("body"))) if app.name == "vampi" else case["id"]
        if key in seen:
            index[case["id"]] = seen[key]
            continue
        resolved = app.reset() if app.name == "authzlab" else {}
        path = app.path(case, resolved)
        regex = plan["success_regex"]
        for k, v in resolved.items():
            regex = regex.replace("{" + k + "}", v)
        i = len(messages)
        seen[key] = index[case["id"]] = i
        messages.append({"index": i, "tableRow": i, "name": f"{case['id']} {case['method']} {case['path']}",
                         "roles": {str(j): users[j] in plan["authorized"] for j in range(len(users))},
                         "requestBase64": base64.b64encode(raw_request(app, case, path)).decode(),
                         "protocol": "http", "port": u.port, "host": u.hostname, "deleted": False, "enabled": True,
                         "regexBase64": base64.b64encode(regex.encode()).decode(), "failureRegexMode": False})
    state = {"version": "0.8", "arrayOfRoles": roles, "arrayOfUsers": am_users, "arrayOfMessages": messages,
             "arrayOfChains": [], "arrayOfChainSources": []}
    path = write_local(f"authmatrix-{tag(app)}-input.local.json", state)
    write_local(f"authmatrix-{tag(app)}-index.json", {"users": users, "case_to_message": index})
    print("AuthMatrix state:", path)
    app.assert_live()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=("check", "proxy", "authmatrix"))
    ap.add_argument("--app", required=True, choices=("authzlab", "vampi"))
    ap.add_argument("--mode", required=True, choices=("vulnerable", "protected"))
    ap.add_argument("--tool", choices=("autorize", "authanalyzer"), help="proxy only")
    ap.add_argument("--proxy", default="http://127.0.0.1:8080")
    ap.add_argument("--dead-token", metavar="USER", help="configure the tool with a rejected token for USER")
    ap.add_argument("--delay", type=float, default=3.0, help="seconds between cases so replays finish before the next reset")
    args = ap.parse_args()
    if args.command == "proxy" and not args.tool:
        ap.error("proxy needs --tool")
    app = App(args.app, args.mode)
    app.dead = args.dead_token
    if args.dead_token:
        app.kill_token(args.dead_token)
    if args.command == "check":
        return check(app)
    if args.command == "proxy":
        return proxy(app, args)
    return authmatrix(app)


if __name__ == "__main__":
    sys.exit(main())
