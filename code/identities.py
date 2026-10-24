"""Resolve current and historical identifiers for a deletion request."""
from __future__ import annotations
import csv
from datetime import datetime, timezone
from pathlib import Path

def load_csv(path:Path)->list[dict[str,str]]:
    with path.open(encoding="utf-8-sig",newline="") as f: return list(csv.DictReader(f))

def _timestamp(value:str)->datetime:
    return datetime.fromisoformat(value.replace("Z","+00:00")).astimezone(timezone.utc)

def resolve_identifiers(dataset_dir:Path,request_email:str,audit_at:str)->tuple[str|None,set[str]]:
    users=load_csv(dataset_dir/"user_identities.csv")
    audits=load_csv(dataset_dir/"user_audit_log.csv")
    email=request_email.strip().casefold()
    matched=[u for u in users if u.get("email","").strip().casefold()==email]
    # Old email -> stable user via history. Only consider identity changes at/before audit_at.
    cutoff=_timestamp(audit_at)
    for a in audits:
        if a.get("field_name")!="email" or a.get("old_value","").strip().casefold()!=email: continue
        try:
            if _timestamp(a["event_time"])>cutoff: continue
        except (ValueError,KeyError): continue
        matched.extend(u for u in users if u["user_id"]==a.get("user_id"))
    if not matched: return None,{request_email.strip()}
    uid=matched[0]["user_id"]
    current=next((u for u in users if u["user_id"]==uid),matched[0])
    identifiers={request_email.strip(),uid}
    for f in ("name","email","phone","email_hash"):
        if current.get(f): identifiers.add(current[f])
    for a in audits:
        if a.get("user_id")!=uid: continue
        try:
            if _timestamp(a["event_time"])>cutoff: continue
        except (ValueError,KeyError): continue
        if a.get("field_name") in {"name","email","phone","email_hash"}:
            identifiers.update(v for v in (a.get("old_value"),a.get("new_value")) if v)
    return uid,{x for x in identifiers if x}
