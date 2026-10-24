"""Evidence-grounded deletion planning for Ghost Data Still Exists."""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from evidence import EvidenceIndex, parse_time, request_authorizes_deletion
from identities import resolve_identifiers
from main import make_step

SYSTEM_DEFAULTS = {
    "USER_PROFILE": "account_service",
    "SECONDARY_IDENTIFIER": "identity_service",
    "SEARCH_INDEX_ENTRY": "search_service",
    "CACHE_ENTRY": "cache_service",
    "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform",
    "ANALYTICS_PROFILE": "analytics_platform",
    "PRODUCT_TELEMETRY": "analytics_platform",
    "USER_EXPORT": "export_service",
    "MARKETING_PROFILE": "marketing_platform",
    "EMAIL_DELIVERY_LOG": "email_delivery_service",
    "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "legal_service",
    "BACKUP_ARCHIVE": "backup_service",
    "ACCOUNT_TOMBSTONE": "identity_service",
}

RESOURCE_KIND = {
    "account": "USER_PROFILE",
    "profile": "USER_PROFILE",
    "identifier": "SECONDARY_IDENTIFIER",
    "secondary_id": "SECONDARY_IDENTIFIER",
    "search": "SEARCH_INDEX_ENTRY",
    "cache": "CACHE_ENTRY",
    "support": "SUPPORT_MESSAGE",
    "export": "USER_EXPORT",
    "analytics": "ANALYTICS_PROFILE",
    "telemetry": "PRODUCT_TELEMETRY",
    "data_flow": "DATA_FLOW",
    "backup": "BACKUP_ARCHIVE",
    "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "marketing": "MARKETING_PROFILE",
    "delivery": "EMAIL_DELIVERY_LOG",
    "email_log": "EMAIL_DELIVERY_LOG",
}

CATEGORY_KIND = {
    "USER_PROFILE": "USER_PROFILE",
    "CUSTOMER_PROFILES": "USER_PROFILE",
    "PROFILE_LOOKUPS": "USER_PROFILE",
    "SECONDARY_IDENTIFIER": "SECONDARY_IDENTIFIER",
    "SECONDARY_IDENTIFIERS": "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
    "CUSTOMER_SEARCH_DOCUMENTS": "SEARCH_INDEX_ENTRY",
    "SEARCH_DOCUMENTS": "SEARCH_INDEX_ENTRY",
    "INDEX_QUERIES": "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY": "CACHE_ENTRY",
    "CACHE_ENTRIES": "CACHE_ENTRY",
    "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
    "SUPPORT_CONVERSATIONS": "SUPPORT_MESSAGE",
    "SUPPORT_MESSAGES": "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
    "SUPPORT_ATTACHMENTS": "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
    "CUSTOMER_ANALYTICS_REPORTS": "ANALYTICS_PROFILE",
    "PROFILES": "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY": "PRODUCT_TELEMETRY",
    "TELEMETRY": "PRODUCT_TELEMETRY",
    "USER_EXPORT": "USER_EXPORT",
    "CUSTOMER_EXPORT_JOBS": "USER_EXPORT",
    "EXPORTS": "USER_EXPORT",
    "MARKETING_PROFILE": "MARKETING_PROFILE",
    "MARKETING_PROFILES": "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
    "DELIVERY_LOGS": "EMAIL_DELIVERY_LOG",
    "EMAIL_DELIVERY_LOGS": "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
    "SECURITY_AUDIT_EVENTS": "SECURITY_AUDIT_LOG",
    "SECURITY_AUDIT_RECORDS": "SECURITY_AUDIT_LOG",
    "AUDIT_RECORDS": "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
    "LEGAL_HOLDS": "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
    "BACKUP_CATALOG": "BACKUP_ARCHIVE",
    "BACKUP_RESTORE_ENTRIES": "BACKUP_ARCHIVE",
    "RESTORE_ENTRIES": "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
    "DELETED_CUSTOMER_REFERENCES": "ACCOUNT_TOMBSTONE",
    "CONNECTOR_CONFIGURATIONS": "DATA_FLOW",
    "CONNECTOR_SUBSCRIPTIONS": "DATA_FLOW",
    "CONNECTORS": "DATA_FLOW",
    "DATA_FLOW": "DATA_FLOW",
}

# This mirrors participant-visible deletion_rules.csv, with condition-specific
# handling applied below rather than treating every RETAIN as a data violation.
POLICY_ACTION = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN_IF_ACTIVE",
    "BACKUP_ARCHIVE": "RETAIN_IF_RESTORABLE",
    "ACCOUNT_TOMBSTONE": "REDACT",
}

def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))

def _norm(value: Any) -> str:
    return str(value).strip().casefold() if value is not None else ""

def _flatten(obj: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if child is not None and not isinstance(child, (dict, list)):
                    result.setdefault(str(key).casefold(), []).append(str(child))
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(obj)
    return result

def _bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    value = str(value).strip().casefold()
    if value in {"true", "1", "yes", "enabled", "active", "allowed"}:
        return True
    if value in {"false", "0", "no", "disabled", "inactive", "blocked", "stopped"}:
        return False
    return None

def _has_direct_identifier(record: dict[str, Any], identifiers: set[str]) -> bool:
    fields = _flatten(record)
    candidate_keys = {
        "email", "owner_email", "customer_email", "requester_email",
        "email_address", "phone", "owner_phone", "customer_phone",
        "requester_phone", "email_hash", "name", "full_name",
        "display_name", "requester_name",
    }
    candidates = {_norm(value) for key in candidate_keys for value in fields.get(key, [])}
    wanted = {_norm(value) for value in identifiers if value}
    if candidates & wanted:
        return True
    text = str(record).casefold()
    return any(("@" in value or value.startswith("+")) and _norm(value) in text for value in identifiers)

def _subject_match(record: dict[str, Any], identifiers: set[str], user_id: str | None) -> bool:
    wanted = {_norm(value) for value in identifiers if value}
    if user_id:
        wanted.add(user_id.casefold())
    flat = _flatten(record)
    observed = {_norm(value) for values in flat.values() for value in values}
    if wanted & observed:
        return True
    text = str(record).casefold()
    return any(value and (("@" in value or value.startswith("+")) and value in text) for value in wanted)

def _resource_kind(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    prefix = re.split(r"_\d+$", resource_id.casefold(), maxsplit=1)[0]
    return RESOURCE_KIND.get(prefix)

def _row_to_kind(rec) -> str | None:
    # Activity is useful for temporal correlation and recreation hypotheses,
    # but operation results alone are not ground truth for resource state.
    if rec.path == "system_activity.csv":
        return None
    category = (rec.category or "").replace("-", "_").replace(" ", "_").upper()
    if category in CATEGORY_KIND:
        return CATEGORY_KIND[category]
    rid_kind = _resource_kind(rec.resource_id)
    # A support attachment is a special policy category; distinguish it before
    # falling back to the generic support-message prefix.
    if "ATTACHMENT" in category or "ATTACHMENT" in rec.path.upper():
        return "SUPPORT_ATTACHMENT"
    if rid_kind:
        return rid_kind
    system = (rec.system_id or "").casefold()
    if system == "account_service":
        return "USER_PROFILE"
    if system == "identity_service":
        return "ACCOUNT_TOMBSTONE" if "tombstone" in category.casefold() else "SECONDARY_IDENTIFIER"
    if system == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if system == "cache_service":
        return "CACHE_ENTRY"
    if system == "analytics_platform":
        return "PRODUCT_TELEMETRY" if "telemetry" in category.casefold() else "ANALYTICS_PROFILE"
    if system == "support_platform":
        return "SUPPORT_ATTACHMENT" if "attachment" in category.casefold() else "SUPPORT_MESSAGE"
    if system == "export_service":
        return "USER_EXPORT"
    if system == "marketing_platform":
        return "MARKETING_PROFILE"
    if system == "email_delivery_service":
        return "EMAIL_DELIVERY_LOG"
    if system == "integration_service":
        return "DATA_FLOW"
    if system == "backup_service":
        return "BACKUP_ARCHIVE"
    if system == "security_service":
        return "SECURITY_AUDIT_LOG"
    if system == "legal_service":
        return "LEGAL_HOLD_RECORD"
    # Last resort: source filename sometimes gives the service identity.
    path = rec.path.casefold()
    for token, kind in (("account", "USER_PROFILE"), ("search", "SEARCH_INDEX_ENTRY"),
        ("cache", "CACHE_ENTRY"), ("support", "SUPPORT_MESSAGE"),
        ("export", "USER_EXPORT"), ("analytics", "ANALYTICS_PROFILE"),
        ("connector", "DATA_FLOW"), ("backup", "BACKUP_ARCHIVE"),
        ("security", "SECURITY_AUDIT_LOG"), ("marketing", "MARKETING_PROFILE")):
        if token in path:
            return kind
    return None

def _state(rec, kind: str, identifiers: set[str]) -> str:
    raw = rec.record
    flat = _flatten(raw)
    vals = {key: [str(value).strip().casefold() for value in values] for key, values in flat.items()}
    def first(*keys: str) -> str | None:
        for key in keys:
            if vals.get(key):
                return vals[key][0]
        return None

    explicit = first("result", "state", "status", "operation_state")
    if kind == "USER_PROFILE":
        status_code = first("status_code", "http_status")
        if status_code in {"200", "ok"}:
            return "FOUND"
        if status_code in {"404", "not_found", "not found"}:
            return "NOT_FOUND"
        state = first("result", "account_status", "status")
        if state:
            state = state.upper().replace(" ", "_")
            if state in {"NOT_FOUND", "ABSENT", "DELETED", "GONE"}:
                return "NOT_FOUND"
            if state in {"FOUND", "PRESENT", "ACTIVE", "OPEN"}:
                return "FOUND"
        return "FOUND" if any(vals.get(key) for key in ("email", "customer_reference", "user_id")) else "UNKNOWN"

    if kind in {"SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SECONDARY_IDENTIFIER", "USER_EXPORT", "MARKETING_PROFILE"}:
        status_code = first("status_code", "http_status")
        if status_code in {"200", "ok"}:
            return "FOUND"
        if status_code in {"404", "not_found", "not found"}:
            return "NOT_FOUND"
        if explicit:
            value = explicit.upper().replace(" ", "_")
            if value in {"NOT_FOUND", "ABSENT", "DELETED", "EXPIRED", "GONE"}:
                return "NOT_FOUND"
            if value in {"FOUND", "PRESENT", "ACTIVE", "IDENTIFIABLE", "READY", "AVAILABLE"}:
                return "FOUND"
        if kind == "USER_EXPORT":
            available = _bool(first("download_available", "available"))
            if available is not None:
                return "FOUND" if available else "NOT_FOUND"
        return "FOUND"

    if kind in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if explicit:
            value = explicit.upper().replace(" ", "_")
            if value in {"ANONYMIZED", "ANONYMOUS", "UNLINKED"}:
                return "ANONYMIZED"
            if value in {"IDENTIFIABLE", "ATTRIBUTABLE", "FOUND", "PRESENT"}:
                return "IDENTIFIABLE"
        # Internal stable IDs also make a record attributable, even without an email.
        for key in ("user_id", "customer_reference", "subject_reference", "email", "phone", "email_hash"):
            if any(value and value not in {"none", "null", "redacted", "[redacted]"} for value in vals.get(key, [])):
                return "IDENTIFIABLE"
        return "ANONYMIZED"

    if kind == "SUPPORT_MESSAGE":
        if explicit:
            value = explicit.upper().replace(" ", "_")
            if value in {"REDACTED", "ANONYMIZED", "REDACT"}:
                return "REDACTED"
            if value in {"IDENTIFIABLE", "FOUND", "PRESENT", "EXPOSED"}:
                return "IDENTIFIABLE"
        if _has_direct_identifier(raw, identifiers):
            return "IDENTIFIABLE"
        # An unredacted text field can still contain identifiers not represented
        # as dedicated columns; do not infer compliance just from missing columns.
        text = str(raw).casefold()
        if "[redacted]" in text or "no direct identifier" in text:
            return "REDACTED"
        return "UNKNOWN"

    if kind == "SUPPORT_ATTACHMENT":
        if explicit:
            value = explicit.upper().replace(" ", "_")
            if value in {"NOT_FOUND", "ABSENT", "DELETED", "GONE"}:
                return "NOT_FOUND"
            if value in {"FOUND", "PRESENT", "ACTIVE", "IDENTIFIABLE"}:
                return "FOUND"
        return "FOUND"

    if kind == "DATA_FLOW":
        enabled = _bool(first("enabled", "is_enabled"))
        if enabled is not None:
            return "ACTIVE" if enabled else "DISABLED"
        value = (explicit or "").upper().replace(" ", "_")
        if value in {"ACTIVE", "ENABLED", "DELIVERED", "RUNNING"}:
            return "ACTIVE"
        if value in {"DISABLED", "STOPPED", "INACTIVE"}:
            return "DISABLED"
        return "UNKNOWN"

    if kind == "BACKUP_ARCHIVE":
        allowed = _bool(first("restore_allowed", "restore_enabled", "can_restore"))
        if allowed is not None:
            return "ACTIVE" if allowed else "BLOCKED"
        value = (explicit or "").upper().replace(" ", "_")
        if value in {"ACTIVE", "RESTORABLE", "ALLOWED", "AVAILABLE"}:
            return "ACTIVE"
        if value in {"BLOCKED", "DISABLED", "NOT_RESTORABLE"}:
            return "BLOCKED"
        return "UNKNOWN"

    if kind == "ACCOUNT_TOMBSTONE":
        if explicit and explicit.upper() in {"REDACTED", "ANONYMIZED"}:
            return "REDACTED"
        flatvals = _flatten(raw)
        stable_reference = first("subject_reference", "user_id", "customer_reference")
        direct = any(
            value and value.casefold() not in {"none", "null", "[redacted]", "redacted"}
            for key in ("name", "full_name", "email", "phone", "email_hash", "display_name")
            for value in flatvals.get(key, [])
        )
        return "IDENTIFIABLE" if direct else ("REDACTED" if stable_reference else "UNKNOWN")

    if kind == "SECURITY_AUDIT_LOG":
        return "FOUND" if rec.resource_id else "UNKNOWN"

    if kind == "LEGAL_HOLD_RECORD":
        active = _bool(first("active", "is_active", "hold_active"))
        if active is not None:
            return "ACTIVE" if active else "INACTIVE"
        value = (explicit or "").upper().replace(" ", "_")
        return "ACTIVE" if value in {"FOUND", "ACTIVE", "PRESENT"} else "INACTIVE"

    if kind == "EMAIL_DELIVERY_LOG":
        if _has_direct_identifier(raw, identifiers):
            return "IDENTIFIABLE"
        value = (explicit or "").upper().replace(" ", "_")
        return "REDACTED" if value in {"REDACTED", "ANONYMIZED"} else "FOUND"
    return explicit.upper() if explicit else "UNKNOWN"

def _system_for(rec, kind: str) -> str:
    system = rec.system_id or ""
    known = set(SYSTEM_DEFAULTS.values())
    if system in known:
        return system
    return SYSTEM_DEFAULTS.get(kind, system or "unknown_service")

class DeletionPlanner:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.index = EvidenceIndex(dataset_dir)
        self.rules = read_csv(dataset_dir / "deletion_rules.csv")
        self.rule_actions = {row["data_category"].strip().upper(): row["required_action"].strip().upper() for row in self.rules}

    def _latest_subject_records(self, identifiers: set[str], user_id: str | None, audit_at: str):
        candidates = self.index.for_subject(identifiers, audit_at)
        by_key = {}
        for rec in candidates:
            kind = _row_to_kind(rec)
            if not kind or not rec.resource_id:
                continue
            if not _subject_match(rec.record, identifiers, user_id):
                continue
            key = (_system_for(rec, kind), rec.resource_id, kind)
            observed = parse_time(rec.observed_at)
            rank = observed.timestamp() if observed else float("-inf")
            prior = by_key.get(key)
            if prior is None or rank > prior[0]:
                by_key[key] = (rank, rec, kind, _state(rec, kind, identifiers))
            elif prior is not None and rank == prior[0]:
                # A same-time conflicting state is treated conservatively: keep
                # the record with the stronger identifiable/present signal.
                new_state = _state(rec, kind, identifiers)
                old_state = prior[3]
                severity = {"FOUND": 5, "IDENTIFIABLE": 5, "ACTIVE": 5, "UNKNOWN": 4, "NOT_FOUND": 1, "REDACTED": 1, "ANONYMIZED": 1, "DISABLED": 1, "BLOCKED": 1, "INACTIVE": 1}
                if severity.get(new_state, 3) > severity.get(old_state, 3):
                    by_key[key] = (rank, rec, kind, new_state)
        return [(rec, kind, state) for _, rec, kind, state in by_key.values()]

    def plan(self, request: dict[str, str]) -> dict[str, Any]:
        if not request_authorizes_deletion(request.get("request_text", "")):
            return {"deletion_status": "NOT_APPLICABLE", "steps": []}
        audit_at = request["audit_at"]
        user_id, identifiers = resolve_identifiers(self.dataset_dir, request.get("email", ""), audit_at)
        identifiers = {value for value in identifiers if value}
        if user_id:
            identifiers.add(user_id)

        relevant = self._latest_subject_records(identifiers, user_id, audit_at)
        findings: list[tuple[str,str,str,str,str]] = []
        remediation: list[tuple[str,str,str,str,str]] = []
        verifications: list[tuple[str,str,str,str,str]] = []
        has_account_absence = False

        def finding(system: str, resource: str, operation: str, evidence: str) -> None:
            findings.append(("FINDING", system, resource, operation, evidence))
        def remediate(system: str, resource: str, operation: str) -> None:
            remediation.append(("REMEDIATION", system, resource, operation, ""))
        def verify(system: str, resource: str, operation: str, evidence: str) -> None:
            verifications.append(("VERIFICATION", system, resource, operation, evidence))

        for rec, kind, state in relevant:
            system = _system_for(rec, kind)
            resource = rec.resource_id
            action = POLICY_ACTION.get(kind)
            if not action:
                continue

            # Policy-retained records are not violations. Backup restore access
            # and legal holds are condition-sensitive.
            if action == "RETAIN":
                verify(system, resource, "VERIFY_RECORD_PRESENT", rec.evidence_id)
                continue
            if action == "RETAIN_IF_ACTIVE" and state == "ACTIVE":
                verify(system, resource, "VERIFY_RECORD_PRESENT", rec.evidence_id)
                continue
            if action == "RETAIN_IF_RESTORABLE":
                if state == "ACTIVE":
                    finding(system, resource, "REPORT_RESTORE_RISK", rec.evidence_id)
                    remediate(system, resource, "BLOCK_RESTORE")
                    verify(system, resource, "VERIFY_RESTORE_BLOCKED", "")
                elif state == "BLOCKED":
                    verify(system, resource, "VERIFY_RESTORE_BLOCKED", rec.evidence_id)
                continue

            if kind == "ACCOUNT_TOMBSTONE":
                if state == "IDENTIFIABLE":
                    finding(system, resource, "REPORT_EXPOSED_PII", rec.evidence_id)
                    remediate(system, resource, "REDACT_RECORD")
                    verify(system, resource, "VERIFY_RECORD_REDACTED", "")
                elif state == "REDACTED":
                    verify(system, resource, "VERIFY_RECORD_REDACTED", rec.evidence_id)
                continue

            if kind == "LEGAL_HOLD_RECORD":
                if state == "ACTIVE":
                    verify(system, resource, "VERIFY_RECORD_PRESENT", rec.evidence_id)
                elif state == "INACTIVE":
                    finding(system, resource, "REPORT_REMAINING_RECORD", rec.evidence_id)
                    remediate(system, resource, "DELETE_RECORD")
                    verify(system, resource, "VERIFY_RECORD_ABSENT", "")
                continue

            if kind == "DATA_FLOW":
                if state == "ACTIVE":
                    finding(system, resource, "REPORT_ACTIVE_DATA_FLOW", rec.evidence_id)
                    remediate(system, resource, "DISABLE_DATA_FLOW")
                    verify(system, resource, "VERIFY_DATA_FLOW_DISABLED", "")
                elif state == "DISABLED":
                    verify(system, resource, "VERIFY_DATA_FLOW_DISABLED", rec.evidence_id)
                continue

            if kind == "SUPPORT_MESSAGE":
                if state == "IDENTIFIABLE":
                    finding(system, resource, "REPORT_EXPOSED_PII", rec.evidence_id)
                    remediate(system, resource, "REDACT_RECORD")
                    verify(system, resource, "VERIFY_RECORD_REDACTED", "")
                elif state == "REDACTED":
                    verify(system, resource, "VERIFY_RECORD_REDACTED", rec.evidence_id)
                continue

            if kind in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
                if state == "IDENTIFIABLE":
                    finding(system, resource, "REPORT_EXPOSED_PII", rec.evidence_id)
                    remediate(system, resource, "ANONYMIZE_RECORD")
                    verify(system, resource, "VERIFY_RECORD_ANONYMIZED", "")
                elif state == "ANONYMIZED":
                    verify(system, resource, "VERIFY_RECORD_ANONYMIZED", rec.evidence_id)
                continue

            if kind == "EMAIL_DELIVERY_LOG":
                if state == "IDENTIFIABLE":
                    finding(system, resource, "REPORT_EXPOSED_PII", rec.evidence_id)
                    remediate(system, resource, "REDACT_RECORD")
                    verify(system, resource, "VERIFY_RECORD_REDACTED", "")
                elif state == "REDACTED":
                    verify(system, resource, "VERIFY_RECORD_REDACTED", rec.evidence_id)
                continue

            # All remaining data categories are delete-entire-record policies.
            if state in {"FOUND", "IDENTIFIABLE", "ACTIVE", "PRESENT", "UNKNOWN"}:
                finding(system, resource, "REPORT_REMAINING_RECORD", rec.evidence_id)
                remediate(system, resource, "DELETE_RECORD")
                verify(system, resource, "VERIFY_RECORD_ABSENT", "")
            elif state in {"NOT_FOUND", "ABSENT", "DELETED", "GONE"}:
                verify(system, resource, "VERIFY_RECORD_ABSENT", rec.evidence_id)

        # For an authorized case we only return COMPLETE when state evidence
        # proves absence of the account profile as well as all other required
        # states. The profile may be represented by an explicit 404 readback.
        has_account_absence = any(
            kind == "USER_PROFILE" and state in {"NOT_FOUND", "ABSENT", "DELETED", "GONE"}
            for _, kind, state in relevant
        )
        incomplete = bool(findings) or not has_account_absence or not verifications
        phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        steps_source = findings + remediation + verifications
        operation_order = {
            "REPORT_REMAINING_RECORD":0, "REPORT_EXPOSED_PII":1,
            "REPORT_ACTIVE_DATA_FLOW":2, "REPORT_RESTORE_RISK":3,
            "DISABLE_DATA_FLOW":0, "BLOCK_RESTORE":1, "DELETE_RECORD":2,
            "REDACT_RECORD":3, "ANONYMIZE_RECORD":4,
            "VERIFY_RECORD_ABSENT":0, "VERIFY_RECORD_PRESENT":1,
            "VERIFY_RECORD_REDACTED":2, "VERIFY_RECORD_ANONYMIZED":3,
            "VERIFY_DATA_FLOW_DISABLED":4, "VERIFY_RESTORE_BLOCKED":5,
        }
        ordered = sorted(steps_source, key=lambda item: (
            phase_order[item[0]], operation_order[item[3]], item[1], item[2]
        ))
        steps = []
        for phase, system, resource, operation, evidence in ordered:
            # In an INCOMPLETE case all remediation and verification evidence is
            # prospective. Only existing findings cite current evidence.
            if incomplete and phase != "FINDING":
                evidence = ""
            steps.append(make_step(len(steps) + 1, system, resource, operation, evidence))
        return {"deletion_status": "INCOMPLETE" if incomplete else "COMPLETE", "steps": steps}
