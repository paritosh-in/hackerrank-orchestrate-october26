from __future__ import annotations
import csv,importlib.util,json,tempfile,unittest
from pathlib import Path
SPEC=importlib.util.spec_from_file_location("ghost_main",Path(__file__).resolve().parents[1]/"main.py")
ghost=importlib.util.module_from_spec(SPEC); assert SPEC and SPEC.loader; SPEC.loader.exec_module(ghost)
class ContractTests(unittest.TestCase):
 def test_allowed_step(self):
  s=ghost.make_step(1,"search_service","search_1","REPORT_REMAINING_RECORD","evidence_1"); self.assertEqual(s["state"],"PRESENT")
 def test_unknown_operation(self):
  with self.assertRaises(ValueError): ghost.make_step(1,"x","y","UNKNOWN","")
 def test_not_applicable_empty(self):
  ghost.validate_case("x","NOT_APPLICABLE",[])
  with self.assertRaises(ValueError): ghost.validate_case("x","NOT_APPLICABLE",[{}])
 def test_complete_evidence(self):
  s=ghost.make_step(1,"account_service","account_1","VERIFY_RECORD_ABSENT","evidence_1"); ghost.validate_case("x","COMPLETE",[s])
  s["evidence_id"]=""
  with self.assertRaises(ValueError): ghost.validate_case("x","COMPLETE",[s])
 def test_incomplete_evidence(self):
  ss=[ghost.make_step(1,"search_service","search_1","REPORT_REMAINING_RECORD","evidence_1"),ghost.make_step(2,"search_service","search_1","DELETE_RECORD",""),ghost.make_step(3,"search_service","search_1","VERIFY_RECORD_ABSENT","")]
  ghost.validate_case("x","INCOMPLETE",ss); ss[0]["evidence_id"]=""
  with self.assertRaises(ValueError): ghost.validate_case("x","INCOMPLETE",ss)
 def test_csv_roundtrip(self):
  req=[{"case_id":"case_01"},{"case_id":"case_02"}]; preds={x["case_id"]:{"deletion_status":"NOT_APPLICABLE","steps":[]} for x in req}
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/"output.csv"; ghost.write_output(req,preds,path); self.assertEqual(ghost.validate_output(path,req),{"rows":2,"steps":0})
   with path.open(encoding="utf-8",newline="") as f: self.assertEqual(json.loads(next(csv.DictReader(f))["steps_json"]),[])
if __name__=="__main__": unittest.main()
