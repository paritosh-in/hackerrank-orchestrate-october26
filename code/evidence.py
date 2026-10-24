"""Evidence discovery and normalization for Ghost Data Still Exists."""
from __future__ import annotations
import csv, json, re, sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
RESOURCE_RE = re.compile(r"\b(?:account|search|cache|support|export|analytics|backup|data_flow|audit_record|marketing|object|tombstone|delivery|telemetry|profile|legal_hold|secondary_id|identifier|email_log)_\d+\b", re.I)
USER_RE = re.compile(r"\buser_\d+\b", re.I)

def parse_time(value: str | None) -> datetime | None:
    if not value: return None
    try:
        dt = datetime.fromisoformat(value.replace("Z","+00:00"))
        if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError,TypeError): return None

def read_csv(path: Path) -> list[dict[str,str]]:
    with path.open(encoding="utf-8-sig",newline="") as f: return list(csv.DictReader(f))

@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    observed_at: str | None
    system_id: str | None
    resource_id: str | None
    category: str | None
    identifiers: tuple[str,...]
    user_refs: tuple[str,...]
    text: str
    path: str
    record: dict[str,Any]

class EvidenceIndex:
    def __init__(self,dataset_dir:Path):
        self.dataset_dir=dataset_dir
        self.manifest=read_csv(dataset_dir/"evidence_files.csv")
        self.activity=read_csv(dataset_dir/"system_activity.csv")
        self.records:list[EvidenceRecord]=[]
        self._load_manifest()
        self._load_activity()

    def _append(self,evidence_id,path,obj,observed,system,category):
        if not isinstance(obj,dict): return
        vals=[]
        def walk(v):
            if isinstance(v,dict):
                for z in v.values(): walk(z)
            elif isinstance(v,list):
                for z in v: walk(z)
            elif v is not None:
                s=str(v).strip()
                if s and s.casefold() not in {"true","false","null","none"}: vals.append(s)
        walk(obj)
        vals += EMAIL_RE.findall(json.dumps(obj,ensure_ascii=False))
        vals += RESOURCE_RE.findall(json.dumps(obj,ensure_ascii=False))
        vals += USER_RE.findall(json.dumps(obj,ensure_ascii=False))
        resource=obj.get("resource_id")
        self.records.append(EvidenceRecord(evidence_id,observed,system,resource,
            str(category) if category else None,tuple(sorted(set(vals))),
            tuple(sorted(set(USER_RE.findall(" ".join(vals))))),
            json.dumps(obj,ensure_ascii=False,sort_keys=True),path,obj))

    def _walk_json(self,evidence_id,path,obj,file_time,system=None,category=None,parent_time=None):
        known_systems={"account_service","identity_service","search_service","cache_service","analytics_platform","support_platform","export_service","object_storage","marketing_platform","integration_service","backup_service","security_service","notification_service","email_delivery_service","profile_service","legal_service"}
        category_by_key={
            "profile_lookups":"USER_PROFILE","customer_profiles":"USER_PROFILE",
            "search_documents":"SEARCH_INDEX_ENTRY","customer_search_documents":"SEARCH_INDEX_ENTRY",
            "search_index_entries":"SEARCH_INDEX_ENTRY","cache_entries":"CACHE_ENTRY",
            "profiles":"ANALYTICS_PROFILE","customer_analytics_reports":"ANALYTICS_PROFILE",
            "telemetry":"PRODUCT_TELEMETRY","product_telemetry":"PRODUCT_TELEMETRY",
            "support_conversations":"SUPPORT_MESSAGE","support_messages":"SUPPORT_MESSAGE",
            "support_attachments":"SUPPORT_ATTACHMENT","attachments":"SUPPORT_ATTACHMENT",
            "customer_export_jobs":"USER_EXPORT","exports":"USER_EXPORT",
            "connectors":"DATA_FLOW","connector_configurations":"DATA_FLOW","connector_subscriptions":"DATA_FLOW",
            "backup_catalog":"BACKUP_ARCHIVE","restore_entries":"BACKUP_ARCHIVE",
            "security_audit_events":"SECURITY_AUDIT_LOG","security_audit_records":"SECURITY_AUDIT_LOG",
            "audit_records":"SECURITY_AUDIT_LOG","deleted_customer_references":"ACCOUNT_TOMBSTONE",
            "marketing_profiles":"MARKETING_PROFILE","delivery_logs":"EMAIL_DELIVERY_LOG",
            "email_delivery_logs":"EMAIL_DELIVERY_LOG","secondary_identifiers":"SECONDARY_IDENTIFIER",
            "legal_holds":"LEGAL_HOLD_RECORD"
        }
        if isinstance(obj,dict):
            current_system=obj.get("data_store") or obj.get("system") or system
            current_category=obj.get("record_type") or obj.get("collection") or category
            own_time=next((obj.get(k) for k in ("observed_at","captured_at","recorded_at","event_time","updated_at","created_at") if isinstance(obj.get(k),str)),None)
            current_time=own_time or parent_time or file_time
            if obj.get("resource_id"):
                self._append(evidence_id,path,obj,own_time or parent_time or file_time,current_system,current_category)
            for key,val in obj.items():
                next_system=key if key in known_systems else current_system
                key_category=category_by_key.get(str(key).casefold())
                next_category=obj.get("record_type") or obj.get("collection") or key_category or current_category
                self._walk_json(evidence_id,path,val,file_time,next_system,next_category,current_time)
        elif isinstance(obj,list):
            for v in obj:
                self._walk_json(evidence_id,path,v,file_time,system,category,parent_time)

    def _append_text_line(self,evidence_id,path,line,line_no,captured_at):
        if not line.strip(): return
        # Handover documents may prefix structured rows with a bullet.
        clean_line=line.strip().lstrip("-*• ").strip()
        parts=[part.strip() for part in clean_line.split("|")]
        parsed_time=parts[0] if parts and parse_time(parts[0]) else None
        if len(parts)>=6 and parsed_time and parts[1] and parts[2]:
            observed,system,resource,category,state,subject=parts[:6]
            obj={"line_no":line_no,"raw_line":line,"resource_id":resource,
                 "record_type":category,"result":state,"subject_reference":subject,
                 "system_id":system,"observed_at":observed}
            self._append(evidence_id,path,obj,observed,system,category)
            return
        timestamp=re.match(r"^(\d{4}-\d\d-\d\dT[^\s|]+)",line)
        observed=timestamp.group(1) if timestamp else captured_at
        resource_match=RESOURCE_RE.search(clean_line)
        sys_match=re.search(r"(?:service=|\|\s*)([a-z_]+(?:_service|_platform|_storage))",line,re.I)
        system=sys_match.group(1) if sys_match else None
        category=None
        upper=clean_line.upper()
        for token,kind in (("USER_PROFILE","USER_PROFILE"),("SEARCH_INDEX_ENTRY","SEARCH_INDEX_ENTRY"),
            ("ANALYTICS_PROFILE","ANALYTICS_PROFILE"),("PRODUCT_TELEMETRY","PRODUCT_TELEMETRY"),
            ("SUPPORT_ATTACHMENT","SUPPORT_ATTACHMENT"),("SUPPORT_MESSAGE","SUPPORT_MESSAGE"),
            ("USER_EXPORT","USER_EXPORT"),("DATA_FLOW","DATA_FLOW"),("BACKUP_ARCHIVE","BACKUP_ARCHIVE"),
            ("SECURITY_AUDIT_LOG","SECURITY_AUDIT_LOG"),("ACCOUNT_TOMBSTONE","ACCOUNT_TOMBSTONE"),
            ("EMAIL_DELIVERY_LOG","EMAIL_DELIVERY_LOG"),("LEGAL_HOLD_RECORD","LEGAL_HOLD_RECORD")):
            if token in upper: category=kind; break
        obj={"line_no":line_no,"line":line,"resource_id":resource_match.group(0) if resource_match else None}
        self._append(evidence_id,path,obj,observed,system,category)

    def _load_manifest(self):
        for m in self.manifest:
            p=self.dataset_dir/m["file_path"]
            if not p.is_file(): continue
            cap=parse_time(m.get("captured_at"))
            try:
                suffix=p.suffix.casefold()
                if suffix==".json":
                    with p.open(encoding="utf-8-sig") as f: payload=json.load(f)
                    self._walk_json(m["file_id"],m["file_path"],payload,m.get("captured_at"))
                elif suffix==".sql":
                    con=sqlite3.connect(":memory:")
                    try:
                        con.executescript(p.read_text(encoding="utf-8-sig"))
                        tables=[x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                        scopes={}
                        if "snapshot_scope" in tables:
                            scopes={r[0]:r[1] for r in con.execute("SELECT origin_system,captured_at FROM snapshot_scope")}
                        for table in tables:
                            if table=="snapshot_scope": continue
                            qt='"'+table.replace('"','""')+'"'
                            cols=[x[1] for x in con.execute(f"PRAGMA table_info({qt})")]
                            for row in con.execute(f"SELECT * FROM {qt}"):
                                obj=dict(zip(cols,row))
                                sys=obj.get("system") or obj.get("origin_system") or table
                                observed=next((obj.get(k) for k in ("observed_at","captured_at","recorded_at","updated_at","event_time") if obj.get(k)),None)
                                observed=observed or scopes.get(str(sys)) or m.get("captured_at")
                                self._append(m["file_id"],m["file_path"],obj,str(observed),str(sys),table)
                    finally: con.close()
                elif suffix in {".txt",".log"}:
                    for ln,line in enumerate(p.read_text(encoding="utf-8-sig",errors="replace").splitlines(),1):
                        self._append_text_line(m["file_id"],m["file_path"],line,ln,m.get("captured_at"))
                elif suffix==".pdf":
                    try:
                        from pypdf import PdfReader
                    except ImportError:
                        continue
                    reader=PdfReader(str(p))
                    full_text="\\n".join(page.extract_text() or "" for page in reader.pages)
                    resource_ids=sorted(set(RESOURCE_RE.findall(full_text)))
                    if resource_ids:
                        upper=full_text.upper()
                        category="SUPPORT_ATTACHMENT" if "ATTACHMENT" in p.name.upper() or "SUPPORT_ATTACHMENT" in upper else None
                        system="support_platform" if "SUPPORT" in p.name.upper() or "ATTACHMENT" in p.name.upper() else None
                        for resource_id in resource_ids:
                            obj={"resource_id":resource_id,"document_text":full_text}
                            if category: obj["record_type"]=category
                            self._append(m["file_id"],m["file_path"],obj,m.get("captured_at"),system,category)
                    else:
                        for ln,line in enumerate(full_text.splitlines(),1):
                            self._append_text_line(m["file_id"],m["file_path"],line,ln,m.get("captured_at"))
                elif suffix in {".png",".jpg",".jpeg",".webp"}:
                    try:
                        from PIL import Image
                        import pytesseract
                    except ImportError:
                        continue
                    try:
                        text=pytesseract.image_to_string(Image.open(p))
                    except Exception:
                        continue
                    for ln,line in enumerate(text.splitlines(),1):
                        self._append_text_line(m["file_id"],m["file_path"],line,ln,m.get("captured_at"))
            except (OSError,json.JSONDecodeError,sqlite3.Error,UnicodeError):
                continue

    def _load_activity(self):
        for r in self.activity:
            d=r.get("details","")
            identifiers=set(EMAIL_RE.findall(d)+USER_RE.findall(d)+RESOURCE_RE.findall(d))
            identifiers.update(x for x in (r.get("resource_id"),r.get("source_system"),r.get("target_system")) if x)
            self.records.append(EvidenceRecord(r["activity_id"],r.get("event_time"),r.get("target_system"),r.get("resource_id"),
              r.get("event_type"),tuple(sorted(identifiers)),tuple(sorted(set(USER_RE.findall(d)))),d,"system_activity.csv",r))

    def for_subject(self,identifiers:set[str],audit_at:str)->list[EvidenceRecord]:
        cutoff=parse_time(audit_at)
        if cutoff is None: raise ValueError(f"Invalid audit_at: {audit_at}")
        wanted={x.strip().casefold() for x in identifiers if x}
        cap_map={m["file_id"]:parse_time(m.get("captured_at")) for m in self.manifest}
        result=[]
        for r in self.records:
            observed=parse_time(r.observed_at)
            if observed and observed>cutoff: continue
            cap=cap_map.get(r.evidence_id)
            if cap and cap>cutoff: continue
            if wanted.intersection(x.casefold() for x in r.identifiers): result.append(r)
        return result

def request_authorizes_deletion(text:str)->bool:
    t=" ".join(text.casefold().split())
    non_delete=("marketing opt-out","opt out of marketing","stop marketing","correct my","correction of",
                "change my email","update my email","access request","request access","download my data",
                "export my data","send me my data","right to access","unsubscribe","remove me from marketing")
    if any(x in t for x in non_delete): return False
    delete_terms=("delete","deletion","erase","erasure","remove my account","close my account","close this account",
                  "account closure","permanent account","permanently delete","eliminar","eliminación","eliminacion",
                  "exclusão","exclusao","supprimer","suppression","effacer","löschen","삭제","영구 삭제","アカウントの完全な削除")
    return any(x in t for x in delete_terms)
