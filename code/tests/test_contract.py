from __future__ import annotations
import importlib.util, json, tempfile, unittest, csv
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "main.py"
SPEC = importlib.util.spec_from_file_location("ghost_main", MODULE)
ghost = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(ghost)

class ContractTests(unittest.TestCase):
    def test_operation_vocabulary(self):
        s = ghost.step(1, "search_service", "search_1", "REPORT_REMAINING_RECORD", "evidence_1")
        self.assertEqual(s["state"], "PRESENT")
    def test_unknown_operation_rejected(self):
        with self.assertRaises(ValueError):
            ghost.step(1, "x", "y", "UNKNOWN_OPERATION", "")
    def test_non_applicable_must_be_empty(self):
        ghost.validate_case("case_x", "NOT_APPLICABLE", [])
        with self.assertRaises(ValueError):
            ghost.validate_case("case_x", "NOT_APPLICABLE", [{}])
    def test_complete_needs_verification_evidence(self):
        s = ghost.step(1, "account_service", "account_1", "VERIFY_RECORD_ABSENT", "evidence_1")
        ghost.validate_case("case_x", "COMPLETE", [s])
        s["evidence_id"] = ""
        with self.assertRaises(ValueError):
            ghost.validate_case("case_x", "COMPLETE", [s])
    def test_incomplete_evidence_rules(self):
        ss = [
            ghost.step(1, "search_service", "search_1", "REPORT_REMAINING_RECORD", "evidence_1"),
            ghost.step(2, "search_service", "search_1", "DELETE_RECORD", ""),
            ghost.step(3, "search_service", "search_1", "VERIFY_RECORD_ABSENT", ""),
        ]
        ghost.validate_case("case_x", "INCOMPLETE", ss)
        ss[0]["evidence_id"] = ""
        with self.assertRaises(ValueError):
            ghost.validate_case("case_x", "INCOMPLETE", ss)
    def test_output_round_trip(self):
        requests = [{"case_id":"case_01"}, {"case_id":"case_02"}]
        preds = {x["case_id"]:{"deletion_status":"NOT_APPLICABLE","steps":[]} for x in requests}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"output.csv"
            ghost.write_output(requests,preds,p)
            stats=ghost.validate_output(p,requests)
            self.assertEqual(stats,{"rows":2,"steps":0})
            with p.open(encoding="utf-8",newline="") as h: rows=list(csv.DictReader(h))
            self.assertEqual(json.loads(rows[0]["steps_json"]),[])
if __name__=="__main__": unittest.main()
