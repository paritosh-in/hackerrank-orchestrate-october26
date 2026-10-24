"""Evaluate predictions against the participant-facing sample output."""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"

def read_rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as h:
        return {r["case_id"]: r for r in csv.DictReader(h)}

def steps(row: dict[str, str]) -> list[dict[str, Any]]:
    value = json.loads(row["steps_json"])
    if not isinstance(value, list): raise ValueError(f"{row['case_id']}: steps_json must be an array")
    return value

def evaluate(pred_path: Path, sample_path: Path) -> dict[str, Any]:
    pred, gold = read_rows(pred_path), read_rows(sample_path)
    total = len(gold)
    status_ok = 0; exact_ok = 0; field_ok = 0; field_total = 0; order_ok = 0; order_total = 0
    exact_steps = 0
    for cid, g in gold.items():
        if cid not in pred: continue
        p = pred[cid]
        status_ok += p["deletion_status"] == g["deletion_status"]
        try: ps, gs = steps(p), steps(g)
        except (ValueError, json.JSONDecodeError): continue
        exact_steps += ps == gs
        exact_ok += (p["deletion_status"] == g["deletion_status"] and ps == gs)
        for idx in range(max(len(ps), len(gs))):
            if idx >= len(ps) or idx >= len(gs):
                field_total += 6; order_total += 1
                continue
            for k in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1; field_ok += ps[idx].get(k) == gs[idx].get(k)
            order_total += 1; order_ok += ps[idx].get("step_no") == gs[idx].get("step_no")
    return {
        "sample_cases": total,
        "prediction_coverage": sum(cid in pred for cid in gold) / total if total else 0.0,
        "status_accuracy": status_ok / total if total else 0.0,
        "exact_case_accuracy": exact_ok / total if total else 0.0,
        "exact_step_arrays": exact_steps,
        "step_field_accuracy": field_ok / field_total if field_total else 1.0,
        "sequence_accuracy": order_ok / order_total if order_total else 1.0,
        "missing_prediction_cases": sorted(set(gold)-set(pred)),
        "extra_prediction_cases": sorted(set(pred)-set(gold)),
    }

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--predictions", type=Path, default=OUTPUT)
    p.add_argument("--gold", type=Path, default=DATASET / "sample_output.csv")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    report = evaluate(a.predictions, a.gold)
    print(json.dumps(report, indent=2) if a.json else "\n".join(f"{k}: {v}" for k, v in report.items()))
    return 0

if __name__ == "__main__": raise SystemExit(main())
