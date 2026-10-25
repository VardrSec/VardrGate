"""Deduplicate frozen AuthZLab denial assertions through real suite compilation."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import authzlab_bench as ab
import vampi_bench as vb

ap=argparse.ArgumentParser();ap.add_argument("--gate",required=True);args=ap.parse_args();gate=os.path.abspath(args.gate)
corpus=vb.load("corpus-authzlab.json");frozen=vb.load("profiles-authzlab.json")
profiles={};references={}
for case in corpus["cases"]:
    endpoint=case["method"]+" "+case["path"]
    for rule in frozen["assertions"].get(case["id"],[]):
        if rule["decision"]!="deny":continue
        key=rule["equals"].lower().replace(" ","_")
        profile=profiles.setdefault(key,{"confirmed":True,"endpoints":[],"rules":[{"json_pointer":rule["json_pointer"],"equals":rule["equals"]}]})
        if endpoint not in profile["endpoints"]:profile["endpoints"].append(endpoint)
        references.setdefault(endpoint,[])
        if key not in references[endpoint]:references[endpoint].append(key)
results={}
ground_truth=ab.ground_truth(corpus)
for mode in ("vulnerable","protected"):
    fx=ab.Fixture(corpus,mode);rows=[]
    for case in corpus["cases"]:
        fx.reset()
        endpoint=case["method"]+" "+case["path"]
        allow=ab.resolve_rules([r for r in frozen["assertions"].get(case["id"],[]) if r["decision"]=="allow"],fx)
        policy={"api":{"endpoint":endpoint,"mutating":case["method"] not in ("GET","HEAD","OPTIONS")},"expect":{"actor":case["expect"]},"response":{"denial_profiles":references.get(endpoint,[]),"assertions":allow}}
        if "body" in case:policy["api"].update(body=json.dumps(case["body"]),headers={"Content-Type":"application/json"})
        identity={"id":case["actor"],"role":"actor","credential":ab.credential(fx.tokens.get(case["actor"]))}
        with tempfile.TemporaryDirectory() as d:
            for name,value in (("policy.yaml",policy),("identities.json",[identity]),("suite.yaml",{"base":fx.base,"identities":"identities.json","denial_profiles":profiles,"policies":[{"policy":"policy.yaml","id":case["id"],"params":fx.resolved}]})):
                with open(os.path.join(d,name),"w",encoding="utf-8") as f:json.dump(value,f)
            out=os.path.join(d,"result.json")
            p=subprocess.run([gate,"policy","run","--suite",os.path.join(d,"suite.yaml"),"--allow-private-targets","--out",out],capture_output=True,text=True)
            if p.returncode!=0:raise SystemExit(f"{case['id']}: {p.stderr}")
            res=json.load(open(out,encoding="utf-8"))
            # Suite output carries engine results directly.
            r=res[0] if isinstance(res,list) else res
            scored=vb.score(case,mode,p.returncode,r)
            scored["case"]=case["id"];rows.append(scored)
    results[mode]={"metrics":vb.metrics(rows),"cases":rows}
    print(mode,results[mode]["metrics"])
    assert results[mode]["metrics"]["false_positive"]==0 and results[mode]["metrics"]["false_negative"]==0
with open(os.path.join(vb.LAB,"reports","profiles-authzlab.json"),"w",encoding="utf-8") as f:json.dump({"schema_version":1,"profiles":profiles,"ground_truth":ground_truth,"results":results,"baseline":"frozen 612fa42: status-only protected inconclusive 7; individual assertions 2","inputs_sha256":{n:vb.sha256(os.path.join(vb.LAB,n)) for n in ("corpus-authzlab.json","profiles-authzlab.json")}},f,indent=2)
