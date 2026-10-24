import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))
import main as audit


class AuthorizationTests(unittest.TestCase):
    def test_english_deletion(self):
        self.assertTrue(audit.authorized("Please delete my account and remove personal data."))

    def test_multilingual_deletion(self):
        self.assertTrue(audit.authorized("Quiero eliminar mi cuenta y borrar mis datos personales."))

    def test_japanese_deletion(self):
        self.assertTrue(audit.authorized("このアカウントの完全な削除を依頼します。"))

    def test_marketing_opt_out_is_not_deletion(self):
        self.assertFalse(audit.authorized("Please stop marketing emails and unsubscribe me."))

    def test_access_request_is_not_deletion(self):
        self.assertFalse(audit.authorized("Please export and send me a copy of my personal data."))

    def test_negated_deletion_is_not_authorized(self):
        self.assertFalse(audit.authorized("Please do not delete my account."))


class PolicyAndOrderingTests(unittest.TestCase):
    def test_tombstone_with_email_requires_redaction(self):
        self.assertEqual(
            audit.policy("ACCOUNT_TOMBSTONE", {"subject_reference": "user_7", "email": "person@example.com"}, "2026-10-01T00:00:00Z"),
            "REDACT",
        )

    def test_analytics_policy_is_anonymization(self):
        self.assertEqual(
            audit.policy("ANALYTICS_PROFILE", {"resource_id": "analytics_1", "email": None}, "2026-10-01T00:00:00Z"),
            "ANONYMIZE",
        )

    def test_phase_order_and_consecutive_numbers(self):
        steps = audit.ordered([
            audit.step("VERIFICATION", "integration_service", "data_flow_1", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            audit.step("FINDING", "search_service", "search_1", "REPORT_REMAINING_RECORD", "PRESENT"),
            audit.step("REMEDIATION", "search_service", "search_1", "DELETE_RECORD", "ABSENT"),
        ])
        self.assertEqual([s["phase"] for s in steps], ["FINDING", "REMEDIATION", "VERIFICATION"])
        self.assertEqual([s["step_no"] for s in steps], [1, 2, 3])


    def test_trace_identity_is_propagated_to_resource_line(self):
        text = (
            '2026-09-17T22:00:02Z level=DEBUG service=support_replica trace_id=tr-002 '
            'event=contact_query_started lookup_key=person@example.com\\n'
            '2026-09-17T22:00:05Z level=INFO service=support_replica trace_id=tr-002 '
            'event=contact_query_completed resource_id=support_002 rows=1'
        )
        records = audit.text_records(text, "evidence_61", "2026-09-17T22:00:19Z", "support_replica.log")
        self.assertTrue(any(r.rid == "support_002" and audit.matches(r, {"person@example.com"}, set()) for r in records))


class OutputValidationTests(unittest.TestCase):
    def test_not_applicable_empty_array_validates(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "output.csv"
            with p.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
                w.writeheader()
                w.writerow({"case_id": "case_01", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"})
            self.assertEqual(audit.validate(p, 1), [])


if __name__ == "__main__":
    unittest.main()
