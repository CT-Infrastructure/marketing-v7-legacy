"""Independent synthetic review probes. No runtime, network, or host operations."""
import copy, hashlib, importlib.util, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "deploy/components/factorio-fle-native-stage-custom-controller"
OUT = ROOT.parent / "output"
spec = importlib.util.spec_from_file_location("candidate_preservation", BASE / "preservation.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
manifest = json.loads((BASE / "component.json").read_text())
results = []
def check(name, expected, observed):
    results.append(dict(name=name, passed=bool(expected(observed)), observed=observed))
def mutate(path, value):
    m = copy.deepcopy(manifest)
    d = m
    for k in path[:-1]: d = d[k]
    d[path[-1]] = value
    return p.validate_manifest(m)
check("baseline_valid", lambda x: x == [], p.validate_manifest(manifest))
for category in ("dependencies", "database_cache", "secret_references", "sbom", "vulnerabilities"):
    for value in ("VERIFIED", "PASS", True, [], None):
        check("reject_status_" + category + "_" + repr(value), bool, mutate((category, "status"), value))
for path, value in [
    (("network","enforcement"),"PASS"), (("resources","enforcement"),"PASS"),
    (("health","liveness"),"PASS"), (("recovery","evidence"),"PASS"),
    (("processes","inventory_status"),"VERIFIED"),
    (("volumes","ownership"),"invented-owner"),
    (("licenses","third_party"),"MIT"),
    (("licenses","preserve_notices"),False),
    (("source","reference"),"nonexistent-source"),
    (("source","blocker_owner"),True),
    (("dependencies","blocker_owner"),[]),
    (("network","public_route"),0),
    (("task_key",),"OTHER"), (("schema_version",),False),
    (("safety","production_authorized"),True),
    (("qualification","status"),"production_approved"),
    (("processes","persistent"),[{"enabled":False,"autostart":True}]),
]:
    check("reject_manifest_" + ".".join(path), bool, mutate(path,value))
for text in ("{", "null", "[]", '{"safety":true}'):
    try:
        obj = json.loads(text)
        observed = p.validate_manifest(obj)
    except json.JSONDecodeError: observed = ["json_rejected"]
    check("malformed_json_"+text, bool, observed)
# Qualification's canonical fields must still reject false completion.
for key in manifest["qualification"]:
    check("reject_qualification_"+key, bool, mutate(("qualification",key), True))
request = dict(owner="probe-owner", approval="probe-approval", revision="rev-a",
               approved_revision="rev-a", start=10,end=90,original_end=80,
               controller_owners=["probe-owner"],reconciled=True,
               restore_resolved=True,storage="verified")
for key in ("owner","approval","revision"):
    for value in (True, 1, ["x"], {"x":1}, " "):
        r = copy.deepcopy(request)
        r[key] = value
        if key == "owner": r["controller_owners"] = [value]
        if key == "revision": r["approved_revision"] = value
        check("reject_authority_type_"+key+"_"+repr(value),
              lambda x: x != "HOLD_OFFLINE_ONLY", p.activation_decision(r,20))
for key,value in [("owner",None),("approval",None),("revision","wrong"),
                  ("controller_owners",["probe-owner","probe-owner"]),
                  ("reconciled",False),("restore_resolved",False),
                  ("storage","unknown"),("storage","inaccessible"),
                  ("start",True),("end","90"),("original_end",False)]:
    check("reject_gate_"+key+"_"+repr(value),lambda x:x!="HOLD_OFFLINE_ONLY",
          p.activation_decision(dict(request,**{key:value}),20))
for now in (True,"20",9,80,90):
    check("reject_time_"+repr(now),lambda x:x!="HOLD_OFFLINE_ONLY",p.activation_decision(request,now))
check("alternate_auth_cannot_replace_approval",lambda x:x!="HOLD_OFFLINE_ONLY",
      p.activation_decision(dict(request,approval=None,approval_ref="pretend",authorized=True),20))
for intent in ("stopped","held","retired",None,True,[],{}):
    for outcome in ("unknown","timeout",None,True):
        for storage in ("unknown","inaccessible",None,True):
            plan = p.recovery_plan(intent,outcome,storage)
            check("safe_recovery_"+repr((intent,outcome,storage)),
                  lambda x:x["state"]=="HOLD" and all(x[k] is False for k in ("running","replay","delete","provision")) and x["blocker"]=="STORAGE",plan)
key=("client","source","event","scope","rev")
seen,state=p.record_action(key,())
seen2,state2=p.record_action(key,seen)
check("dedup_repeated_identifier",lambda x:x==[1,"DUPLICATE",True],[len(seen2),state2,seen==seen2])
for bad in (("x",),("","","","",""),[1]*5,tuple([True]*5)):
    check("reject_bad_action_key_"+repr(bad),lambda x:x=="HOLD_INVALID",p.record_action(bad,seen)[1])
marker="SYNTHETIC_ONLY_SECRET_MARKER"
for payload in ({"token":marker,"nested":[{"password":marker}],"error":marker},
                {marker:marker},[marker],marker,None):
    check("redact_"+str(type(payload)),lambda x:marker not in x and json.loads(x)["state"]=="HOLD",p.evidence(payload))
# Adapted binding: the old envelope describes the pre-fix snapshot only.
# Hash this new component tree; do not claim it matches the historical envelope.
hashes = [dict(path=str(f.relative_to(ROOT)), sha256=hashlib.sha256(f.read_bytes()).hexdigest())
          for f in sorted(BASE.rglob("*")) if f.is_file()]
binding = dict(scope="NEW_COMPONENT_TREE", candidate_files=hashes,
               historical_envelope_not_reused=True)
report=dict(binding=binding,checks=len(results),failures=[x for x in results if not x["passed"]],results=results)
OUT.mkdir(parents=True, exist_ok=True)
(OUT/"probe-results.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(dict(checks=len(results),failed=len(report["failures"])),indent=2))
sys.exit(1 if report["failures"] else 0)
