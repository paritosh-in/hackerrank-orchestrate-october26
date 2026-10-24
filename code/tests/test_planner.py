from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from planner import DeletionPlanner


class PlannerIntegrationTests(unittest.TestCase):
    def _dataset(self, root: Path, state: str) -> Path:
        dataset = root / "dataset"
        evidence = dataset / "evidence" / "records"
        evidence.mkdir(parents=True)
        snapshot = {
            "captured_at": "2026-01-01T10:00:00Z",
            "data_store": "account_service",
            "collection": "customer_profiles",
            "records": [{
                "resource_id": "account_001",
                "email": "person@example.com",
                "account_status": state,
            }],
        }
        (evidence / "snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")

        def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(header)
                writer.writerows(rows)

        write_csv(dataset / "evidence_files.csv",
            ["file_id", "file_path", "origin", "captured_at"],
            [["evidence_01", "evidence/records/snapshot.json", "test", "2026-01-01T10:00:00Z"]])
        write_csv(dataset / "system_activity.csv",
            ["activity_id", "event_time", "target_system", "resource_id", "event_type", "reported_result", "details"], [])
        write_csv(dataset / "user_identities.csv",
            ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
            [["user_001", "Test User", "person@example.com", "+1 555 0100", "hash1", "2025-12-01T00:00:00Z"]])
        write_csv(dataset / "user_audit_log.csv",
            ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"], [])
        write_csv(dataset / "deletion_rules.csv",
            ["rule_id", "data_category", "condition", "required_action"],
            [["rule_01", "USER_PROFILE", "Always", "DELETE"]])
        return dataset

    def _request(self) -> dict[str, str]:
        return {
            "case_id": "case_01",
            "email": "person@example.com",
            "requested_at": "2026-01-01T09:00:00Z",
            "reported_status": "SUCCESS",
            "reported_at": "2026-01-01T09:30:00Z",
            "audit_at": "2026-01-02T00:00:00Z",
            "request_text": "Please permanently delete my account.",
        }

    def test_existing_profile_produces_evidence_backed_remediation(self):
        with tempfile.TemporaryDirectory() as temp:
            planner = DeletionPlanner(self._dataset(Path(temp), "ACTIVE"))
            prediction = planner.plan(self._request())
        self.assertEqual(prediction["deletion_status"], "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in prediction["steps"]],
            ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
        )
        self.assertEqual(prediction["steps"][0]["evidence_id"], "evidence_01")
        self.assertEqual(prediction["steps"][1]["evidence_id"], "")
        self.assertEqual(prediction["steps"][2]["evidence_id"], "")

    def test_explicit_absence_can_be_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            planner = DeletionPlanner(self._dataset(Path(temp), "NOT_FOUND"))
            prediction = planner.plan(self._request())
        self.assertEqual(prediction["deletion_status"], "COMPLETE")
        self.assertEqual(len(prediction["steps"]), 1)
        self.assertEqual(prediction["steps"][0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(prediction["steps"][0]["evidence_id"], "evidence_01")


if __name__ == "__main__":
    unittest.main()
