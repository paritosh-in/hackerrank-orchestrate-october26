"""Ghost Data Still Exists — output contract and validation entry point.

This initial slice intentionally does not fabricate predictions. It establishes
the output contract while the evidence/identity reasoning pipeline is built.
"""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"

ALLOWED = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT", 0),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT", 1),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE", 2),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE", 3),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED", 0),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED", 1),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT", 2),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED", 3),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED", 4),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT", 0),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT", 1),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED", 2),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED", 3),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED", 4),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED", 5),
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(f"Required input file not found: {path}")
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))

def load_requests(dataset_dir: Path = DATASET) -> list[dict[str, str]]:
    rows = load_csv(dataset_dir / "deletion_requests.csv")
    required = {"case_id", "email", "requested_at", "reported_status",
                "reported_at", "audit_at", "request_text"}
    if rows and not required.issubset(rows[0]):
        raise ValueError(f"Missing input columns: {sorted(required - set(rows[0]))}")
    ids = [r["case_id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case_id values in deletion_requests.csv")
    return sorted(rows, key=lambda r: r["case_id"])

def step(step_no: int, system_id: str, resource_id: str, operation: str,
         evidence_id: str) -> dict[str, Any]:
    if operation not in ALLOWED:
        raise ValueError(f"Unsupported operation: {operation}")
    phase, state, _ = ALLOWED[operation]
    if not system_id or not resource_id or not isinstance(evidence_id, str):
        raise ValueError("system_id, resource_id, and string evidence_id are required")
    return {"step_no": step_no, "phase": phase, "system_id": system_id,
            "resource_id": resource_id, "operation": operation, "state": state,
            "evidence_id": evidence_id}

def validate_case(case_id: str, status: str, steps: list[dict[str, Any]]) -> None:
    if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
        raise ValueError(f"{case_id}: invalid deletion_status {status!r}")
    if status == "NOT_APPLICABLE":
        if steps: raise ValueError(f"{case_id}: NOT_APPLICABLE requires []")
        return
    keys = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
    prev_key = None
    for i, s in enumerate(steps, 1):
        if set(s) != keys: raise ValueError(f"{case_id}: step {i} has wrong fields")
        if s["step_no"] != i: raise ValueError(f"{case_id}: step numbers must be consecutive")
        if s["operation"] not in ALLOWED: raise ValueError(f"{case_id}: unknown operation")
        phase, state, op_order = ALLOWED[s["operation"]]
        if (s["phase"], s["state"]) != (phase, state):
            raise ValueError(f"{case_id}: invalid phase/state for {s['operation']}")
        if status == "COMPLETE" and phase != "VERIFICATION":
            raise ValueError(f"{case_id}: COMPLETE may contain only verification steps")
        if phase not in PHASE_ORDER: raise ValueError(f"{case_id}: invalid phase")
        if not isinstance(s["evidence_id"], str): raise ValueError(f"{case_id}: evidence_id must be a string")
        if status == "COMPLETE" and not s["evidence_id"]:
            raise ValueError(f"{case_id}: COMPLETE verification requires evidence")
        if status == "INCOMPLETE":
            if phase == "FINDING" and not s["evidence_id"]:
                raise ValueError(f"{case_id}: findings require evidence")
            if phase != "FINDING" and s["evidence_id"]:
                raise ValueError(f"{case_id}: future steps must have empty evidence_id")
        key = (PHASE_ORDER[phase], op_order, str(s["system_id"]), str(s["resource_id"]))
        if prev_key is not None and key < prev_key:
            raise ValueError(f"{case_id}: steps violate canonical order")
        prev_key = key

def write_output(requests: list[dict[str, str]], predictions: dict[str, dict[str, Any]], path: Path) -> None:
    expected = {r["case_id"] for r in requests}
    if set(predictions) != expected:
        raise ValueError(f"Prediction coverage mismatch: missing={len(expected-set(predictions))}, extra={len(set(predictions)-expected)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as h:
        w = csv.DictWriter(h, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        w.writeheader()
        for request in requests:
            cid = request["case_id"]
            status, steps = predictions[cid]["deletion_status"], predictions[cid]["steps"]
            validate_case(cid, status, steps)
            w.writerow({"case_id": cid, "deletion_status": status,
                        "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})

def validate_output(path: Path, requests: list[dict[str, str]]) -> dict[str, int]:
    with path.open(encoding="utf-8-sig", newline="") as h:
        reader = csv.DictReader(h)
        if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
            raise ValueError(f"Invalid header: {reader.fieldnames}")
        rows = list(reader)
    expected_ids = [r["case_id"] for r in requests]
    if [r["case_id"] for r in rows] != expected_ids:
        raise ValueError("Output case IDs must exactly match sorted input case IDs")
    n_steps = 0
    for r in rows:
        try: steps = json.loads(r["steps_json"])
        except json.JSONDecodeError as e: raise ValueError(f"{r['case_id']}: invalid steps_json") from e
        if not isinstance(steps, list): raise ValueError(f"{r['case_id']}: steps_json must be array")
        validate_case(r["case_id"], r["deletion_status"], steps)
        n_steps += len(steps)
    return {"rows": len(rows), "steps": n_steps}

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-dir", type=Path, default=DATASET)
    p.add_argument("--output", type=Path, default=OUTPUT)
    p.add_argument("--validate-only", action="store_true")
    args = p.parse_args()
    requests = load_requests(args.dataset_dir)
    if args.validate_only:
        stats = validate_output(args.output, requests)
        print(f"Validated {stats['rows']} rows and {stats['steps']} steps: {args.output}")
        return 0
    raise SystemExit("Prediction engine is not yet implemented; refusing to generate speculative answers.")

if __name__ == "__main__":
    raise SystemExit(main())
