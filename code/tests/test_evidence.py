from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from evidence import EvidenceIndex
from identities import resolve_identifiers


class EvidenceParserTests(unittest.TestCase):
    def _dataset(self, root: Path) -> Path:
        dataset = root / "dataset"
        (dataset / "evidence" / "records").mkdir(parents=True)
        return dataset

    def _write_csv(self, path: Path, header: list[str], rows: list[list[str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)

    def test_json_snapshot_time_is_inherited_by_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            dataset = self._dataset(Path(temp))
            payload = {
                "exported_at": "2026-01-01T10:00:00Z",
                "snapshots": [{
                    "captured_at": "2026-01-01T09:00:00Z",
                    "data_store": "account_service",
                    "collection": "customer_profiles",
                    "records": [{
                        "resource_id": "account_001",
                        "email": "person@example.com",
                        "status_code": 404,
                    }],
                }],
            }
            evidence = dataset / "evidence" / "records" / "snapshot.json"
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            self._write_csv(dataset / "evidence_files.csv",
                ["file_id", "file_path", "origin", "captured_at"],
                [["evidence_01", "evidence/records/snapshot.json", "test", "2026-01-01T10:00:00Z"]])
            self._write_csv(dataset / "system_activity.csv",
                ["activity_id", "event_time", "target_system", "resource_id", "event_type", "reported_result", "details"], [])

            index = EvidenceIndex(dataset)
            records = index.for_subject({"person@example.com"}, "2026-01-01T11:00:00Z")
            matching = [r for r in records if r.resource_id == "account_001"]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0].observed_at, "2026-01-01T09:00:00Z")
            self.assertEqual(matching[0].category, "customer_profiles")
            self.assertEqual(matching[0].system_id, "account_service")

    def test_evidence_captured_after_audit_cutoff_is_excluded(self):
        with tempfile.TemporaryDirectory() as temp:
            dataset = self._dataset(Path(temp))
            payload = {"records": [{
                "resource_id": "account_002",
                "email": "person@example.com",
                "status": "ACTIVE",
            }]}
            evidence = dataset / "evidence" / "records" / "later.json"
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            self._write_csv(dataset / "evidence_files.csv",
                ["file_id", "file_path", "origin", "captured_at"],
                [["evidence_02", "evidence/records/later.json", "test", "2026-01-02T00:00:00Z"]])
            self._write_csv(dataset / "system_activity.csv",
                ["activity_id", "event_time", "target_system", "resource_id", "event_type", "reported_result", "details"], [])
            index = EvidenceIndex(dataset)
            self.assertEqual(index.for_subject({"person@example.com"}, "2026-01-01T23:59:59Z"), [])

    def test_bullet_prefixed_handover_row_is_structured(self):
        with tempfile.TemporaryDirectory() as temp:
            dataset = self._dataset(Path(temp))
            self._write_csv(dataset / "evidence_files.csv",
                ["file_id", "file_path", "origin", "captured_at"], [])
            self._write_csv(dataset / "system_activity.csv",
                ["activity_id", "event_time", "target_system", "resource_id", "event_type", "reported_result", "details"], [])
            index = EvidenceIndex(dataset)
            index._append_text_line(
                "evidence_03", "evidence/records/handover.txt",
                "- 2026-01-01T12:00:00Z | account_service | account_003 | USER_PROFILE | NOT_FOUND | person@example.com",
                1, "2026-01-01T12:00:00Z")
            record = index.records[-1]
            self.assertEqual(record.resource_id, "account_003")
            self.assertEqual(record.system_id, "account_service")
            self.assertEqual(record.category, "USER_PROFILE")
            self.assertEqual(record.record["result"], "NOT_FOUND")
            self.assertIn("person@example.com", record.identifiers)


class HistoricalIdentityTests(unittest.TestCase):
    def test_historical_email_maps_only_after_change_event(self):
        with tempfile.TemporaryDirectory() as temp:
            dataset = Path(temp)
            with (dataset / "user_identities.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["user_id", "name", "email", "phone", "email_hash", "updated_at"])
                writer.writeheader()
                writer.writerow({"user_id":"user_001","name":"Test User","email":"new@example.com",
                                 "phone":"+1 555 0100","email_hash":"hash1","updated_at":"2026-01-02T00:00:00Z"})
            with (dataset / "user_audit_log.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["audit_id","user_id","event_time","field_name","old_value","new_value"])
                writer.writeheader()
                writer.writerow({"audit_id":"audit_01","user_id":"user_001","event_time":"2026-01-02T00:00:00Z",
                                 "field_name":"email","old_value":"old@example.com","new_value":"new@example.com"})
            user_id, identifiers = resolve_identifiers(dataset, "old@example.com", "2026-01-03T00:00:00Z")
            self.assertEqual(user_id, "user_001")
            self.assertIn("old@example.com", identifiers)
            before_id, _ = resolve_identifiers(dataset, "old@example.com", "2026-01-01T23:59:59Z")
            self.assertIsNone(before_id)


if __name__ == "__main__":
    unittest.main()
