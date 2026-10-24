"""Ghost Data Still Exists — output contract and validation entry point.

This initial implementation slice is deliberately conservative: it establishes
the required output contract but does not fabricate predictions before the
evidence-based reasoning pipeline is complete.
"""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
OPS = {
 "REPORT_REMAINING_RECORD": ("FINDING","PRESENT",0),
 "REPORT_EXPOSED_PII": ("FINDING","PRESENT",1),
 "REPORT_ACTIVE_DATA_FLOW": ("FINDING","ACTIVE",2),
 "REPORT_RESTORE_RISK": ("FINDING","ACTIVE",3),
 "DISABLE_DATA_FLOW": ("REMEDIATION","DISABLED",0),
 "BLOCK_RESTORE": ("REMEDIATION","BLOCKED",1),
 "DELETE_RECORD": ("REMEDIATION","ABSENT",2),
 "REDACT_RECORD": ("REMEDIATION","REDACTED",3),
 "ANONYMIZE_RECORD": ("REMEDIATION","ANONYMIZED",4),
 "VERIFY_RECORD_ABSENT": ("VERIFICATION","ABSENT",0),
 "VERIFY_RECORD_PRESENT": ("VERIFICATION","PRESENT",1),
 "VERIFY_RECORD_REDACTED": ("VERIFICATION","REDACTED",2),
 "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION","ANONYMIZED",3),
 "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION","DISABLED",4),
 "VERIFY_RESTORE_BLOCKED": ("VERIFICATION","BLOCKED",5),
}
PHASE_ORDER={"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}

def read_csv(path: Path) -> list[dict[str,str]]:
    if not path.is_file(): raise FileNotFoundError(f"Required file not found: {path}")
    with path.open(encoding="utf-8-sig",newline="") as f: return list(csv.DictReader(f))

def load_requests(dataset_dir: Path=DATASET) -> list[dict[str,str]]:
    rows=read_csv(dataset_dir/"deletion_requests.csv")
    required={"case_id","email","requested_at","reported_status","reported_at","audit_at","request_text"}
    if rows and not required.issubset(rows[0]): raise ValueError(f"Missing columns: {sorted(required-set(rows[0]))}")
    ids=[r["case_id"] for r in rows]
    if len(ids)!=len(set(ids)): raise ValueError("Duplicate case_id values")
    return sorted(rows,key=lambda r:r["case_id"])

def make_step(step_no:int,system_id:str,resource_id:str,operation:str,evidence_id:str)->dict[str,Any]:
    if operation not in OPS: raise ValueError(f"Unsupported operation: {operation}")
    phase,state,_=OPS[operation]
    if not system_id or not resource_id or not isinstance(evidence_id,str): raise ValueError("Invalid step fields")
    return {"step_no":step_no,"phase":phase,"system_id":system_id,"resource_id":resource_id,
            "operation":operation,"state":state,"evidence_id":evidence_id}

def validate_case(case_id:str,status:str,steps:list[dict[str,Any]])->None:
    if status not in {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"}: raise ValueError(f"{case_id}: invalid status {status}")
    if status=="NOT_APPLICABLE":
        if steps: raise ValueError(f"{case_id}: NOT_APPLICABLE must use []")
        return
    required={"step_no","phase","system_id","resource_id","operation","state","evidence_id"}
    prev=None
    for i,s in enumerate(steps,1):
        if set(s)!=required: raise ValueError(f"{case_id}: step {i} has incorrect keys")
        if s["step_no"]!=i: raise ValueError(f"{case_id}: step numbers must be consecutive")
        if s["operation"] not in OPS: raise ValueError(f"{case_id}: unsupported operation {s['operation']}")
        phase,state,op_order=OPS[s["operation"]]
        if (s["phase"],s["state"])!=(phase,state): raise ValueError(f"{case_id}: wrong phase/state")
        if status=="COMPLETE" and phase!="VERIFICATION": raise ValueError(f"{case_id}: COMPLETE only permits verification")
        if status=="COMPLETE" and not s["evidence_id"]: raise ValueError(f"{case_id}: COMPLETE step needs evidence")
        if status=="INCOMPLETE":
            if phase=="FINDING" and not s["evidence_id"]: raise ValueError(f"{case_id}: finding requires evidence")
            if phase!="FINDING" and s["evidence_id"]: raise ValueError(f"{case_id}: future step must have empty evidence_id")
        key=(PHASE_ORDER[phase],op_order,str(s["system_id"]),str(s["resource_id"]))
        if prev is not None and key<prev: raise ValueError(f"{case_id}: steps violate canonical ordering")
        prev=key

def write_output(requests:list[dict[str,str]],predictions:dict[str,dict[str,Any]],path:Path)->None:
    want={r["case_id"] for r in requests}
    if set(predictions)!=want: raise ValueError(f"Coverage mismatch: missing={len(want-set(predictions))},extra={len(set(predictions)-want)}")
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"],lineterminator="\n"); w.writeheader()
        for req in requests:
            cid=req["case_id"]; pred=predictions[cid]; steps=pred["steps"]; status=pred["deletion_status"]
            validate_case(cid,status,steps)
            w.writerow({"case_id":cid,"deletion_status":status,"steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))})

def validate_output(path:Path,requests:list[dict[str,str]])->dict[str,int]:
    with path.open(encoding="utf-8-sig",newline="") as f:
        reader=csv.DictReader(f)
        if reader.fieldnames!=["case_id","deletion_status","steps_json"]: raise ValueError(f"Invalid output header: {reader.fieldnames}")
        rows=list(reader)
    if [r["case_id"] for r in rows]!=[r["case_id"] for r in requests]: raise ValueError("Output case IDs must match sorted input IDs")
    total_steps=0
    for row in rows:
        try: steps=json.loads(row["steps_json"])
        except json.JSONDecodeError as exc: raise ValueError(f"{row['case_id']}: invalid steps_json") from exc
        if not isinstance(steps,list): raise ValueError(f"{row['case_id']}: steps_json must be array")
        validate_case(row["case_id"],row["deletion_status"],steps); total_steps+=len(steps)
    return {"rows":len(rows),"steps":total_steps}

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-dir",type=Path,default=DATASET); p.add_argument("--output",type=Path,default=OUTPUT)
    p.add_argument("--validate-only",action="store_true"); args=p.parse_args()
    requests=load_requests(args.dataset_dir)
    if args.validate_only:
        result=validate_output(args.output,requests); print(f"Validated {result['rows']} rows and {result['steps']} steps"); return 0
    raise SystemExit("Prediction engine is not implemented yet; refusing to generate speculative output.")

if __name__=="__main__": raise SystemExit(main())
