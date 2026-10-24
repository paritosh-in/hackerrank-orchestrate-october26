"""Compare predictions with the public sample output."""
from __future__ import annotations
import argparse,csv,json
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parents[2]; DATASET=ROOT/"dataset"; DEFAULT_OUTPUT=ROOT/"output.csv"

def read_rows(path:Path)->dict[str,dict[str,str]]:
    with path.open(encoding="utf-8-sig",newline="") as f: return {r["case_id"]:r for r in csv.DictReader(f)}
def parse_steps(row:dict[str,str])->list[dict[str,Any]]:
    v=json.loads(row["steps_json"])
    if not isinstance(v,list): raise ValueError(f"{row['case_id']}: steps_json must be list")
    return v
def evaluate(pred_path:Path,gold_path:Path)->dict[str,Any]:
    pred,gold=read_rows(pred_path),read_rows(gold_path); n=len(gold)
    status_ok=exact_ok=exact_arrays=field_ok=field_total=seq_ok=seq_total=0
    for cid,g in gold.items():
        if cid not in pred: continue
        p=pred[cid]; status_ok += p["deletion_status"]==g["deletion_status"]
        try: ps,gs=parse_steps(p),parse_steps(g)
        except (json.JSONDecodeError,ValueError): continue
        exact_arrays += ps==gs; exact_ok += (p["deletion_status"]==g["deletion_status"] and ps==gs)
        for i in range(max(len(ps),len(gs))):
            if i>=len(ps) or i>=len(gs): field_total+=6; seq_total+=1; continue
            for k in ("phase","system_id","resource_id","operation","state","evidence_id"):
                field_total+=1; field_ok += ps[i].get(k)==gs[i].get(k)
            seq_total+=1; seq_ok += ps[i].get("step_no")==gs[i].get("step_no")
    return {"sample_cases":n,"prediction_coverage":sum(c in pred for c in gold)/n if n else 0,
      "status_accuracy":status_ok/n if n else 0,"exact_case_accuracy":exact_ok/n if n else 0,
      "exact_step_arrays":exact_arrays,"step_field_accuracy":field_ok/field_total if field_total else 1,
      "sequence_accuracy":seq_ok/seq_total if seq_total else 1,
      "missing_prediction_cases":sorted(set(gold)-set(pred)),"extra_prediction_cases":sorted(set(pred)-set(gold))}
def main()->int:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--predictions",type=Path,default=DEFAULT_OUTPUT)
    p.add_argument("--gold",type=Path,default=DATASET/"sample_output.csv"); p.add_argument("--json",action="store_true"); a=p.parse_args()
    result=evaluate(a.predictions,a.gold); print(json.dumps(result,indent=2) if a.json else "\n".join(f"{k}: {v}" for k,v in result.items())); return 0
if __name__=="__main__": raise SystemExit(main())
