#!/usr/bin/env python3
"""Evaluate predictions against the public sample answers and custom tests."""
import csv, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "code"
sys.path.insert(0, str(CODE))
import main as audit

def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f: return list(csv.DictReader(f))
def norm_steps(value):
    try: return json.loads(value)
    except Exception: return None
def sequence(xs):
    return [(s.get("phase"),s.get("operation"),s.get("system_id"),s.get("resource_id"),s.get("state")) for s in xs]
def evaluate(ds=ROOT/"dataset"):
    sample=read_csv(ds/"sample_deletion_requests.csv")
    expected_rows=read_csv(ds/"sample_output.csv")
    expected={r["case_id"]:r for r in expected_rows}
    predicted_rows=audit.predict(sample,ds)
    predicted={r["case_id"]:r for r in predicted_rows}
    ncases=len(sample)
    status_ok=sum(predicted.get(cid,{}).get("deletion_status")==r["deletion_status"] for cid,r in expected.items())
    exact_ok=sequence_ok=steps_ok=steps_total=fields_ok=fields_total=0
    failures=[]
    for cid,exp in expected.items():
        got=predicted.get(cid)
        es=norm_steps(exp["steps_json"]); gs=norm_steps(got["steps_json"]) if got else None
        if got and got["deletion_status"]==exp["deletion_status"] and es==gs: exact_ok+=1
        if es is not None and gs is not None and sequence(es)==sequence(gs): sequence_ok+=1
        if es is None or gs is None: continue
        steps_total+=max(len(es),len(gs))
        for i in range(max(len(es),len(gs))):
            if i>=len(es) or i>=len(gs): continue
            steps_ok+=int(es[i]==gs[i])
            for key in ("step_no","phase","system_id","resource_id","operation","state","evidence_id"):
                fields_total+=1; fields_ok+=int(es[i].get(key)==gs[i].get(key))
        if got is None or got["deletion_status"]!=exp["deletion_status"] or es!=gs:
            failures.append((cid,exp["deletion_status"],got.get("deletion_status") if got else "MISSING",len(es or []),len(gs or [])))
    custom=[
      ("non-deletion marketing opt-out",not audit.authorized("Please stop marketing emails and unsubscribe me.")),
      ("Spanish deletion request",audit.authorized("Quiero eliminar mi cuenta y borrar mis datos personales.")),
      ("tombstone PII requires redaction",audit.policy("ACCOUNT_TOMBSTONE",{"subject_reference":"user_77","email":"person@example.com"},"2026-10-01T00:00:00Z")=="REDACT"),
      ("operation ordering is deterministic",audit.ordered([audit.step("VERIFICATION","integration_service","flow_1","VERIFY_DATA_FLOW_DISABLED","DISABLED"),audit.step("FINDING","search_service","search_1","REPORT_REMAINING_RECORD","PRESENT")])[0]["phase"]=="FINDING")]
    report=["# Evaluation Report","","## Public sample regression","",
      f"- Sample cases evaluated: **{ncases}**",
      f"- Status accuracy: **{status_ok}/{ncases} ({status_ok/ncases:.1%})**" if ncases else "- Status accuracy: N/A",
      f"- Exact case output accuracy (status + ordered steps): **{exact_ok}/{ncases} ({exact_ok/ncases:.1%})**" if ncases else "- Exact case output accuracy: N/A",
      f"- Sequence accuracy: **{sequence_ok}/{ncases} ({sequence_ok/ncases:.1%})**" if ncases else "- Sequence accuracy: N/A",
      f"- Step exact match: **{steps_ok}/{steps_total} ({steps_ok/steps_total:.1%})**" if steps_total else "- Step exact match: N/A",
      f"- Field accuracy across aligned steps: **{fields_ok}/{fields_total} ({fields_ok/fields_total:.1%})**" if fields_total else "- Field accuracy: N/A",
      "","## Additional participant-created evaluation cases",""]
    for name,passed in custom: report.append(f"- {'PASS' if passed else 'FAIL'} — {name}")
    report += ["","## Failures found",""]
    if failures:
        report += [f"- {cid}: expected status {exp}, predicted {got}; expected/predicted step counts {en}/{gn}." for cid,exp,got,en,gn in failures[:50]]
        if len(failures)>50: report.append(f"- Plus {len(failures)-50} additional failures.")
    else: report.append("- No sample mismatches detected.")
    report += ["","## Improvements to prioritize","",
      "1. Inspect each mismatch against public evidence and policy; do not hardcode case IDs or sample labels.",
      "2. Improve historical identity resolution and enforce audit_at for evidence files and observations.",
      "3. Improve JSON, SQL, log, PDF, and image evidence parsing where local extraction support is available.",
      "4. Re-run this report after each change and validate the full 518-row output independently.",
      "","These metrics measure public sample behavior, not hidden-grader performance."]
    (CODE/"evaluation"/"evaluation_report.md").write_text("\n".join(report)+"\n",encoding="utf-8")
    usage=("# Token Usage and Cost Report\n\n## Final full-dataset run\n\n"
      "- Architecture: deterministic Python evidence parser and rule engine; no external model calls.\n"
      "- Model provider/name: none.\n- Model calls: 0.\n- Input tokens: 0 (no model requests).\n"
      "- Output tokens: 0 (no model responses).\n- Total tokens: 0.\n"
      "- Average tokens per request: 0 model tokens/request; this excludes local CPU parsing and is not an LLM token estimate.\n"
      "- Estimated model cost: $0.00 total and $0.00/request.\n\n"
      "Run this evaluator after the final full-dataset execution and update this report if model-backed extraction is introduced.")
    (CODE/"evaluation"/"usage_report.md").write_text(usage,encoding="utf-8")
    print(f"Sample cases: {ncases}; status accuracy: {status_ok}/{ncases}; exact output: {exact_ok}/{ncases}; sequence: {sequence_ok}/{ncases}")
    print(f"Custom tests passed: {sum(p for _,p in custom)}/{len(custom)}")
    return 1 if any(not p for _,p in custom) else 0
if __name__=="__main__": raise SystemExit(evaluate(Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT/"dataset"))
