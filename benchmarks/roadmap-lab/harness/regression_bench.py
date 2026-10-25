"""Save and rerun a real VAmPI password defect across fix/reintroduction."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import vampi_bench as vb
import paired_bench as pb

ap=argparse.ArgumentParser();ap.add_argument("--gate",required=True);args=ap.parse_args()
gate=os.path.abspath(args.gate)
corpus=vb.load("corpus.json");profiles=vb.load("profiles.json");oracles=vb.load("verification.json")["vampi"]
case=next(c for c in corpus["cases"] if c["id"]=="password-peer")
os.environ["VAMPI_ALICE_PASSWORD"]=corpus["fixtures"]["identities"]["alice"]["password"]
os.environ["VAMPI_NEW_PASSWORD"]=case["body"]["password"]
fx=vb.Fixture(corpus,"vulnerable");fx.reset()
tc=pb.vampi_case(fx,case,"alice",profiles,oracles,True,True)
tc["require_identity_preflight"]=True
tc["request"]["url"]="${VAMPI_BASE}"+case["path"]
tc["request"]["body"]["password"]="${VAMPI_NEW_PASSWORD}"
for identity in tc["identities"]:
    who=identity["id"]
    identity["credential"]["value"]="${VAMPI_"+who.upper()+"_TOKEN}"
    identity["preflight"]={"url":"${VAMPI_BASE}/me","expected_status":200,"json_fields":{"data.username":corpus["fixtures"]["identities"][who]["username"]}}
wv=tc["write_verification"];wv["environment"]="synchronous_isolated";wv["strategy"]="changed"
wv["request"]["url"]="${VAMPI_BASE}/users/v1/login"
wv["reset"]={"name":"restore-original-password","as":"alice","request":{"method":"PUT","url":"${VAMPI_BASE}"+case["path"],"headers":{"Content-Type":"application/json"},"body":{"password":"${VAMPI_ALICE_PASSWORD}"}}}
rows=[]
with tempfile.TemporaryDirectory() as d:
    source=os.path.join(d,"template.json");result=os.path.join(d,"result.json");saved=os.path.join(d,"saved")
    with open(source,"w",encoding="utf-8") as f:json.dump([tc],f)
    for index,(mode,expected) in enumerate((("vulnerable",2),("protected",0),("vulnerable",2))):
        fx=vb.Fixture(corpus,mode);fx.reset()
        os.environ["VAMPI_BASE"]=fx.base
        for who in ("alice","bob"):os.environ["VAMPI_"+who.upper()+"_TOKEN"]=fx.tokens[who]
        path=source if index==0 else os.path.join(saved,"cases.json")
        p=subprocess.run([gate,"run","--cases",path,"--out",result,"--allow-private-targets","--fail-on","high","--fail-on-inconclusive"],capture_output=True,text=True)
        if p.returncode!=expected:raise SystemExit(f"{mode}: expected exit {expected}, got {p.returncode}: {p.stderr}")
        r=json.load(open(result,encoding="utf-8"))[0]
        rows.append({"mode":mode,"phase":("reproduce","fixed","reintroduced")[index],"exit":p.returncode,"assessments":r["assessments"],"preflight":r.get("preflight",[])})
        if index==0:
            subprocess.run([gate,"regression","save","--cases",source,"--result",result,"--case",case["id"],"--out",saved,"--confirmed"],check=True,capture_output=True)
    artifact=os.path.join(vb.LAB,"regression-example");os.makedirs(artifact,exist_ok=True)
    for name in ("cases.json","confirmation.json"):
        with open(os.path.join(saved,name),"rb") as f:data=f.read()
        with open(os.path.join(artifact,name),"wb") as f:f.write(data)
with open(os.path.join(vb.LAB,"reports","regression-replay.json"),"w",encoding="utf-8") as f:json.dump({"schema_version":1,"rows":rows},f,indent=2)
print("real VAmPI regression: reproduce=2, fixed=0, reintroduced=2; all principal preflights passed")
