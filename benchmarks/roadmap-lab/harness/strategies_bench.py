"""Replay the three formerly inexpressible paired VAmPI writes.

Uses frozen corpus ground truth and public API readback; credentials/bodies are
never retained. Existing credential_rejected uncertainty is intentionally kept.
"""
import argparse
import json
import os
import sys
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import vampi_bench as vb
import paired_bench as pb

ap=argparse.ArgumentParser()
ap.add_argument("--gate",required=True)
args=ap.parse_args()
corpus=vb.load("corpus.json")
profiles=vb.load("profiles.json")
oracles=vb.load("verification.json")["vampi"]
os.environ["VAMPI_ALICE_PASSWORD"]=corpus["fixtures"]["identities"]["alice"]["password"]
rows=[]
for mode in ("vulnerable","protected"):
    fx=vb.Fixture(corpus,mode)
    for case in corpus["cases"]:
        if case["id"] not in ("password-peer","password-anonymous","delete-peer"):
            continue
        for repeat in range(3):
            fx.reset()
            before=fx.state()
            status,body=vb.http(case["method"],fx.base+case["path"],fx.tokens.get(case["actor"]),case.get("body"))
            actual=vb.observed_violation(case,corpus,fx,status,body,before,fx.state())
            assert actual==case["violation"][mode]
            fx.reset()
            original="admin" if case["id"]=="delete-peer" else "alice"
            tc=pb.vampi_case(fx,case,original,profiles,oracles,True,True)
            wv=tc["write_verification"]
            wv["environment"]="synchronous_isolated"
            wv["strategy"]="deleted" if case["id"]=="delete-peer" else "changed"
            if wv["strategy"]=="changed":
                wv["reset"]={"name":"restore-original-password","as":"alice","request":{"method":"PUT","url":fx.base+case["path"],"headers":{"Content-Type":"application/json"},"body":{"password":"${VAMPI_ALICE_PASSWORD}"}}}
            code,res=vb.run_gate(os.path.abspath(args.gate),tc)
            row=vb.score(case,mode,code,res)
            row.update(case=case["id"],mode=mode,repeat=repeat+1,control=vb.assessment_of(res,original),ground_truth_status=status,ground_truth_violation=actual)
            rows.append(row)
            print(mode,case["id"],repeat+1,row["verdict"],row["assessment"]["decision"],row["assessment"]["reason"])
            assert row["verdict"] not in ("false_positive","false_negative")
            assert len(res["executions"])==2
with open(os.path.join(vb.LAB,"reports","strategies-vampi.json"),"w",encoding="utf-8") as f:
    json.dump({"schema_version":1,"repeat":3,"rows":rows,"inputs_sha256":{n:vb.sha256(os.path.join(vb.LAB,n)) for n in ("corpus.json","verification.json","profiles.json")}},f,indent=2)
