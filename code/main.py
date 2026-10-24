#!/usr/bin/env python3
"""Deterministic, evidence-backed deletion audit for the HackerRank challenge."""
from __future__ import annotations
import csv, json, re, sqlite3, sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
PHASE = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP = {
 "REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3,
 "DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4,
 "VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,
 "VERIFY_RECORD_ANONYMIZED":3,"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5}
TABLES = {
 "customer_profiles":("account_service","USER_PROFILE"),
 "customer_profiles_primary":("account_service","USER_PROFILE"),
 "customer_profiles_failover_replica":("account_service","USER_PROFILE"),
 "customer_search_documents":("search_service","SEARCH_INDEX_ENTRY"),
 "search_documents_primary":("search_service","SEARCH_INDEX_ENTRY"),
 "customer_analytics_profiles":("analytics_platform","ANALYTICS_PROFILE"),
 "support_records":("support_platform","SUPPORT_MESSAGE"),
 "customer_exports":("export_service","USER_EXPORT"),
 "connector_subscriptions":("integration_service","DATA_FLOW"),
 "backup_restore_entries":("backup_service","BACKUP_ARCHIVE"),
 "security_audit_records":("security_service","SECURITY_AUDIT_LOG"),
 "deleted_customer_references":("identity_service","ACCOUNT_TOMBSTONE")}
SYSTEMS = set(["account_service","identity_service","analytics_platform","backup_service","export_service","integration_service","search_service","security_service","support_platform","email_delivery_service","marketing_platform","cache_service"])
ID_FIELDS = set("email owner_email customer_email requester_email email_address email_hash phone owner_phone requester_phone full_name name display_name requester_name customer_reference subject_reference user_id subject_user_id customer_id lookup_key".split())
RESOURCE = re.compile(r"\b(?:account|analytics|search|support|export|data_flow|backup|audit_record|tombstone|cache|marketing|email_delivery|attachment|profile|record)_\d+\b", re.I)
EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
KV = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=([^ ]+)")
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")

def read_csv(p: Path):
    with p.open(encoding="utf-8-sig", newline="") as f: return list(csv.DictReader(f))
def dt(v):
    try:
        x=datetime.fromisoformat(str(v or "").replace("Z","+00:00"))
        return x if x.tzinfo else x.replace(tzinfo=timezone.utc)
    except (ValueError,TypeError): return None
def before(v, cutoff):
    a,b=dt(v),dt(cutoff)
    return a is None or b is None or a<=b
def n(v): return re.sub(r"\s+"," ",str(v or "")).strip().casefold()
def digits(v): return re.sub(r"\D","",str(v or ""))
def scalars(x):
    if isinstance(x,dict):
        for v in x.values(): yield from scalars(v)
    elif isinstance(x,list):
        for v in x: yield from scalars(v)
    elif x is not None and not isinstance(x,(bool,int,float)): yield str(x)

class Record:
    def __init__(self,eid,captured,observed,system,rid,category,fields,state="",source=""):
        self.eid,self.captured,self.observed=eid,captured,observed
        self.system,self.rid,self.category=system,rid,category
        self.fields,self.state,self.source=fields,state,source
    @property
    def timestamp(self): return self.observed or self.captured

def infer_category(parts, table="", f=None):
    if table in TABLES: return TABLES[table][1]
    s=(" ".join(parts)+" "+" ".join(str(k) for k in (f or {}).keys())+" "+" ".join(str(v) for v in (f or {}).values() if v is not None)).casefold()
    for word,cat in [("tombstone","ACCOUNT_TOMBSTONE"),("legal_hold","LEGAL_HOLD_RECORD"),("correlation_key","SECONDARY_IDENTIFIER"),("security_audit","SECURITY_AUDIT_LOG"),("retention_until","SECURITY_AUDIT_LOG"),("restore_allowed","BACKUP_ARCHIVE"),("backup","BACKUP_ARCHIVE"),("connector","DATA_FLOW"),("data_flow","DATA_FLOW"),("enabled","DATA_FLOW"),("secondary_identifier","SECONDARY_IDENTIFIER"),("support_replica","SECONDARY_IDENTIFIER"),("analytics","ANALYTICS_PROFILE"),("audience_cohort","ANALYTICS_PROFILE"),("search","SEARCH_INDEX_ENTRY"),("index","SEARCH_INDEX_ENTRY"),("export","USER_EXPORT"),("attachment","SUPPORT_ATTACHMENT"),("support","SUPPORT_MESSAGE"),("marketing","MARKETING_PROFILE"),("email_delivery","EMAIL_DELIVERY_LOG"),("cache","CACHE_ENTRY"),("account","USER_PROFILE"),("profile","USER_PROFILE")]:
        if word in s: return cat
    return "UNKNOWN"
def infer_system(parts, table=""):
    if table in TABLES: return TABLES[table][0]
    for p in reversed(parts):
        if p in SYSTEMS: return p
    joined=" ".join(str(p).casefold() for p in parts)
    for marker,system in (("analytics","analytics_platform"),("account","account_service"),("search","search_service"),("support","support_platform"),("backup","backup_service"),("export","export_service"),("connector","integration_service"),("integration","integration_service"),("security","security_service"),("marketing","marketing_platform"),("identity","identity_service")):
        if marker in joined: return system
    return "unknown_system"
def infer_state(f,cat,line=""):
    t=(line+" "+" ".join(f"{k}={v}" for k,v in f.items())).casefold()
    if str(f.get("status_code",""))=="404" or str(f.get("http_status",""))=="404" or str(f.get("rows",""))=="0" or "not_found" in t or "not found" in t: return "ABSENT"
    if str(f.get("enabled","")).casefold() in {"false","0"}: return "DISABLED"
    if str(f.get("restore_allowed","")).casefold() in {"false","0"}: return "BLOCKED"
    if str(f.get("restore_allowed","")).casefold() in {"true","1"}: return "ACTIVE"
    for k in ("result","state","status","account_status","last_delivery_status"):
        v=n(f.get(k))
        if v in {"hit","found","present","identifiable","active","enabled","delivered","success"}: return "ACTIVE" if cat in {"DATA_FLOW","BACKUP_ARCHIVE"} else "PRESENT"
        if v in {"not_found","not found","absent","deleted","redacted","anonymized","disabled","stopped","blocked"}:
            return {"not_found":"ABSENT","not found":"ABSENT","deleted":"ABSENT","redacted":"REDACTED","anonymized":"ANONYMIZED","disabled":"DISABLED","stopped":"DISABLED","blocked":"BLOCKED"}[v]
    if str(f.get("status_code",""))=="200" or str(f.get("rows",""))=="1": return "PRESENT"
    if "enabled=true" in t or "restore_allowed=true" in t: return "ACTIVE"
    if "result=hit" in t or "identifiable" in t: return "PRESENT"
    return ""

def json_records(obj,eid,captured,source,out,parents=None,context=None):
    parents=parents or []
    context=dict(context or {})
    if isinstance(obj,dict):
        # Snapshot bundles describe the system and collection on the parent
        # object, so carry those facts down to each nested resource.
        for key in ("data_store","collection","system_id","system","service","origin_system","source"):
            if obj.get(key): context[key]=str(obj[key])
        rid=obj.get("resource_id") or obj.get("resourceId")
        merged=dict(obj)
        for k in ("profile","record","document","entry","details"):
            if isinstance(obj.get(k),dict): merged.update(obj[k])
        context_parts=parents+[context.get(k,"") for k in ("data_store","system_id","system","service","source","collection")]
        if rid:
            obs=str(merged.get("observed_at") or merged.get("captured_at") or merged.get("updated_at") or merged.get("indexed_at") or merged.get("event_time") or captured)
            cat=infer_category(context_parts,f=merged); sysid=infer_system(context_parts)
            out.append(Record(eid,captured,obs,sysid,str(rid),cat,merged,infer_state(merged,cat),source))
        for k,v in obj.items(): json_records(v,eid,captured,source,out,parents+[str(k)],context)
    elif isinstance(obj,list):
        for v in obj: json_records(v,eid,captured,source,out,parents,context)
def sql_records(path,eid,captured):
    out=[]; db=sqlite3.connect(":memory:")
    try:
        db.executescript(path.read_text(encoding="utf-8",errors="replace"))
        tables=[x[0] for x in db.execute("select name from sqlite_master where type='table'").fetchall()]
        if any(t.startswith("customer_profiles") for t in tables):
            out.append(Record(eid,captured,captured,"account_service","__snapshot__","SNAPSHOT_MARKER",{"snapshot_tables":tables},"",str(path)))
        category_names={
            "customer_profiles":"USER_PROFILE","customer_search_documents":"SEARCH_INDEX_ENTRY",
            "customer_analytics_profiles":"ANALYTICS_PROFILE","support_records":"SUPPORT_MESSAGE",
            "customer_exports":"USER_EXPORT","connector_subscriptions":"DATA_FLOW",
            "backup_restore_entries":"BACKUP_ARCHIVE","security_audit_records":"SECURITY_AUDIT_LOG",
            "customer_analytics_reports":"ANALYTICS_PROFILE","security_audit_records":"SECURITY_AUDIT_LOG",
            "deleted_customer_references":"ACCOUNT_TOMBSTONE"}
        for table in tables:
            if table=="snapshot_scope": continue
            cols=[x[1] for x in db.execute(f'pragma table_info("{table}")')]
            if "resource_id" not in cols and "id" not in cols: continue
            for row in db.execute(f'select * from "{table}"'):
                f=dict(zip(cols,row))
                # Some inventory exports wrap the full source record as JSON in a SQL column.
                for key,value in list(f.items()):
                    if isinstance(value,str) and value.lstrip().startswith("{"):
                        try:
                            nested=json.loads(value)
                            if isinstance(nested,dict): f.update(nested)
                        except json.JSONDecodeError: pass
                rid=f.get("resource_id") or f.get("id")
                if not rid: continue
                raw_system=str(f.get("system_id") or f.get("origin_system") or "")
                sysid=raw_system if raw_system in SYSTEMS else TABLES.get(table,("unknown_system",""))[0]
                raw_category=n(f.get("category") or f.get("collection_name"))
                cat=category_names.get(raw_category) or TABLES.get(table,("", ""))[1] or infer_category([],table,f)
                obs=str(f.get("updated_at") or f.get("captured_at") or captured)
                out.append(Record(eid,captured,obs,sysid,str(rid),cat,f,infer_state(f,cat),str(path)))
    except (sqlite3.Error,OSError):
        pass
    finally:
        db.close()
    return out
def read_doc(path):
    if path.suffix.casefold()==".pdf":
        try:
            from pypdf import PdfReader
            return "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)
        except Exception: return ""
    if path.suffix.casefold() in {".png",".jpg",".jpeg",".webp"}:
        try:
            from PIL import Image
            import pytesseract
            return pytesseract.image_to_string(Image.open(path))
        except Exception: return ""
    return path.read_text(encoding="utf-8",errors="replace")
def text_records(text,eid,captured,source):
    out=[]
    lines=text.splitlines()
    parsed=[]
    trace_context={}
    # First pass: collect identity hints on trace start lines, then attach them to
    # resource-bearing completion lines from the same distributed trace.
    for line in lines:
        fields={k:v.strip('"') for k,v in KV.findall(line)}
        trace=fields.get("trace_id","")
        if not trace: continue
        for key in ("lookup_key","subject_key","match_key","correlation_key","customer_email",
                    "customer_reference","subject_reference","subject_ref","email","email_hash",
                    "phone","owner_email","requester_email","matched_value"):
            value=fields.get(key)
            if value and value.casefold() not in {"null","none"}:
                trace_context.setdefault(trace,{})[key]=value
    for line in lines:
        parts=[p.strip() for p in line.split(" | ")]
        is_handover=len(parts)>=6 and RESOURCE.search(parts[2])
        if not RESOURCE.search(line) and not is_handover: continue
        match=ISO.search(line); obs=match.group(0) if match else captured
        f={k:v.strip('"') for k,v in KV.findall(line)}
        trace=f.get("trace_id","")
        if trace and trace in trace_context:
            inherited=dict(trace_context[trace]); inherited.update(f); f=inherited
        mails=EMAIL.findall(line)
        if mails: f["emails_in_line"]=mails
        rm=RESOURCE.search(line); rid=rm.group(0) if rm else ""
        sm=re.search(r"\b(?:service|system)=([A-Za-z0-9_-]+)",line)
        raw_system=sm.group(1) if sm else "unknown_system"
        sysid=infer_system([raw_system])
        cat=infer_category([raw_system],f=f)
        state=infer_state(f,cat,line)
        if is_handover:
            obs,raw_system,rid,cat,state=parts[:5]
            state={"NOT_FOUND":"ABSENT","FOUND":"PRESENT","IDENTIFIABLE":"PRESENT","ANONYMIZED":"ANONYMIZED","REDACTED":"REDACTED","ACTIVE":"ACTIVE","DISABLED":"DISABLED","BLOCKED":"BLOCKED"}.get(state.upper(),state)
            sysid=infer_system([raw_system])
            f.update({"lookup_key":parts[5],"state":state})
            cat=cat.upper()
        if rid: out.append(Record(eid,captured,obs,sysid,rid,cat,f,state,source))
    return out
def load_records(ds):
    out=[]
    for m in read_csv(ds/"evidence_files.csv"):
        eid,rel,captured=m.get("file_id",""),m.get("file_path",""),m.get("captured_at","")
        p=ds/rel
        if not eid or not p.is_file(): continue
        try:
            if p.suffix.casefold()==".sql": out.extend(sql_records(p,eid,captured))
            elif p.suffix.casefold()==".json": json_records(json.loads(p.read_text(encoding="utf-8",errors="replace")),eid,captured,str(p),out)
            else: out.extend(text_records(read_doc(p),eid,captured,str(p)))
        except (OSError,json.JSONDecodeError,UnicodeError): continue
    return out

def identity(email,cutoff,identities,audits):
    target=n(email); uids=set(); aliases={target}
    states={}
    for row in identities:
        uid=row.get("user_id","")
        events=sorted([e for e in audits if e.get("user_id")==uid],key=lambda e:e.get("event_time",""),reverse=True)
        state={k:row.get(k,"") for k in ("name","email","phone","email_hash")}
        if not before(row.get("updated_at"),cutoff):
            for e in events:
                if not before(e.get("event_time"),cutoff) and e.get("field_name") in state: state[e["field_name"]]=e.get("old_value","")
        hist=[]
        for e in events:
            if before(e.get("event_time"),cutoff) and e.get("field_name")=="email": hist += [e.get("old_value",""),e.get("new_value","")]
        states[uid]=state
        if target in {n(state.get("email")),*(n(x) for x in hist)}: uids.add(uid)
    for row in identities:
        if row.get("user_id") in uids:
            state=states.get(row.get("user_id"),row)
            for field in ("name","email","phone","email_hash"):
                if state.get(field): aliases.add(n(state[field]))
                if field=="phone" and state.get(field): aliases.add(digits(state[field]))
    for e in audits:
        if e.get("user_id") in uids and before(e.get("event_time"),cutoff) and e.get("field_name") in {"name","email","phone","email_hash"}:
            for value in (e.get("old_value",""),e.get("new_value","")):
                if value:
                    aliases.add(n(value))
                    if e.get("field_name")=="phone": aliases.add(digits(value))
    aliases.discard("")
    return aliases,uids,next(iter(uids),"")
def authorized(text):
    t=n(text)
    deletion=bool(re.search(r"\b(delet(?:e|ed|ing|ion)|erase|erasure|remove|removal|purge|destroy|close|closed|closing|supprimer|suppression|effacer|eliminar|eliminación|borrar|löschen|gelöscht)\b",t) or "削除" in t or "消去" in t)
    if not deletion: return False
    if re.search(r"\b(do not|don't|dont|never)\b.{0,25}\b(delete|erase|remove|close)\b",t): return False
    pure_nondelete=bool(re.search(r"\b(access|download|export|correct|correction|update|unsubscribe|opt out|opt-out|stop marketing)\b",t))
    explicit_delete=bool(re.search(r"\b(delete|erase|remove|close|purge)\b.{0,60}\b(account|file|export|data|profile|record|details|copy)\b|\b(suppression définitive|supprimer mon compte|eliminar mi cuenta)\b",t))
    return not pure_nondelete or explicit_delete

def matches(rec,aliases,uids):
    f=rec.fields
    uidset={n(x) for x in uids}
    for k,v in f.items():
        vals=v if isinstance(v,list) else [v]
        for x in vals:
            if x is None: continue
            nx=n(x); key=str(k).casefold()
            if key in {"customer_reference","subject_reference","user_id","subject_user_id","customer_id","lookup_key","subject_key","match_key","subject_ref"} and nx in uidset: return True
            if key in ID_FIELDS and (nx in aliases or (key.endswith("phone") and digits(x) in aliases)): return True
            if nx in aliases: return True
    return any(n(x) in aliases or digits(x) in aliases for x in scalars(f))
def policy(cat,f,cutoff):
    if cat=="SECURITY_AUDIT_LOG":
        expiry=dt(f.get("retention_until"))
        return "RETAIN" if expiry is None or dt(cutoff) is None or expiry>dt(cutoff) else "DELETE"
    if cat=="LEGAL_HOLD_RECORD": return "RETAIN" if n(f.get("active",f.get("legal_hold_active","true"))) not in {"false","0","inactive"} else "DELETE"
    if cat=="BACKUP_ARCHIVE":
        # The archive itself is retained; deletion completion requires restore access blocked.
        return "BLOCK_RESTORE"
    if cat=="SUPPORT_MESSAGE":
        # Shared support conversations are retained; remove the subject identifiers.
        return "REDACT"
    if cat in {"ANALYTICS_PROFILE","PRODUCT_TELEMETRY"}:
        return "ANONYMIZE"
    if cat=="ACCOUNT_TOMBSTONE":
        # The stable subject reference may remain, but direct identifiers must not.
        return "REDACT"
    if cat=="DATA_FLOW": return "DISABLE_DATA_FLOW"
    if cat in {"SUPPORT_ATTACHMENT","USER_PROFILE","SECONDARY_IDENTIFIER","SEARCH_INDEX_ENTRY","CACHE_ENTRY","USER_EXPORT","MARKETING_PROFILE"}: return "DELETE"
    if cat=="EMAIL_DELIVERY_LOG": return "REDACT" if any(f.get(k) for k in ("email","customer_email","recipient_email")) else "RETAIN"
    return "DELETE"
def step(phase,system,resource,operation,state,evidence=""):
    return {"phase":phase,"system_id":system,"resource_id":resource,"operation":operation,"state":state,"evidence_id":evidence}
def ordered(steps):
    steps.sort(key=lambda s:(PHASE[s["phase"]],OP.get(s["operation"],99),s["system_id"],s["resource_id"]))
    for i,s in enumerate(steps,1): s["step_no"]=i
    return steps
def audit_case(case,records,identities,audits,activities=None):
    cid=case["case_id"]; cutoff=case.get("audit_at","")
    if not authorized(case.get("request_text","")): return {"case_id":cid,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"}
    aliases,uids,uid=identity(case.get("email",""),cutoff,identities,audits)
    eligible=[r for r in records if r.category!="SNAPSHOT_MARKER" and before(r.captured,cutoff) and before(r.timestamp,cutoff) and matches(r,aliases,uids)]
    groups=defaultdict(list)
    for r in eligible: groups[(r.system,r.rid)].append(r)
    findings=[]; rem=[]; ver=[]; bad=False
    # Activity is used to correlate a request with a candidate resource ID only;
    # reported operation results are not proof. A later point-in-time snapshot
    # provides state evidence when that resource is absent from the snapshot.
    activity_rows=activities or []
    report_time=dt(case.get("reported_at",""))
    deletion_events=[]
    for event in activity_rows:
        if event.get("event_type")!="DELETE_RECORD" or event.get("source_system")!="deletion_worker" or event.get("target_system")!="account_service":
            continue
        event_time=dt(event.get("event_time",""))
        if not event_time or not report_time or abs((event_time-report_time).total_seconds())>7200:
            continue
        deletion_events.append((abs((event_time-report_time).total_seconds()),event))
    deletion_events.sort(key=lambda x:x[0])
    if deletion_events and not any(system=="account_service" for system,rid in groups):
        event=deletion_events[0][1]
        rid=event.get("resource_id","")
        markers=[r for r in records if r.category=="SNAPSHOT_MARKER" and before(r.captured,cutoff) and dt(r.captured) and dt(event.get("event_time","")) and dt(r.captured)>=dt(event.get("event_time",""))]
        markers.sort(key=lambda r:r.captured)
        if rid and markers and not any(r.system=="account_service" and r.rid==rid and before(r.captured,cutoff) for r in records):
            ver.append(step("VERIFICATION","account_service",rid,"VERIFY_RECORD_ABSENT","ABSENT",markers[-1].eid))
    for (system,rid),obs in groups.items():
        obs.sort(key=lambda x:(x.timestamp,x.captured))
        r=obs[-1]; f=r.fields; cat=r.category; p=policy(cat,f,cutoff); state=r.state
        has_pii=any(f.get(k) for k in ("name","full_name","email","phone","email_hash","display_name","requester_name","requester_email","requester_phone","owner_email","owner_phone","customer_email","lookup_key","matched_value","correlation_key","emails_in_line"))
        if p=="DELETE":
            if state=="ABSENT":
                ver.append(step("VERIFICATION",system,rid,"VERIFY_RECORD_ABSENT","ABSENT",r.eid)); continue
            findings.append(step("FINDING",system,rid,"REPORT_REMAINING_RECORD","PRESENT",r.eid))
            rem.append(step("REMEDIATION",system,rid,"DELETE_RECORD","ABSENT")); ver.append(step("VERIFICATION",system,rid,"VERIFY_RECORD_ABSENT","ABSENT")); bad=True
        elif p=="REDACT":
            if not has_pii:
                ver.append(step("VERIFICATION",system,rid,"VERIFY_RECORD_REDACTED","REDACTED",r.eid)); continue
            findings.append(step("FINDING",system,rid,"REPORT_EXPOSED_PII","PRESENT",r.eid))
            rem.append(step("REMEDIATION",system,rid,"REDACT_RECORD","REDACTED")); ver.append(step("VERIFICATION",system,rid,"VERIFY_RECORD_REDACTED","REDACTED")); bad=True
        elif p=="ANONYMIZE":
            if not has_pii:
                ver.append(step("VERIFICATION",system,rid,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",r.eid)); continue
            findings.append(step("FINDING",system,rid,"REPORT_EXPOSED_PII","PRESENT",r.eid))
            rem.append(step("REMEDIATION",system,rid,"ANONYMIZE_RECORD","ANONYMIZED")); ver.append(step("VERIFICATION",system,rid,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED")); bad=True
        elif p=="RETAIN":
            op="VERIFY_RECORD_REDACTED" if cat=="ACCOUNT_TOMBSTONE" else "VERIFY_RECORD_PRESENT"
            st="REDACTED" if cat=="ACCOUNT_TOMBSTONE" else "PRESENT"
            ver.append(step("VERIFICATION",system,rid,op,st,r.eid))
        elif p=="BLOCK_RESTORE":
            if n(f.get("restore_allowed")) in {"false","0"} or state=="BLOCKED":
                ver.append(step("VERIFICATION",system,rid,"VERIFY_RESTORE_BLOCKED","BLOCKED",r.eid))
            else:
                findings.append(step("FINDING",system,rid,"REPORT_RESTORE_RISK","ACTIVE",r.eid))
                rem.append(step("REMEDIATION",system,rid,"BLOCK_RESTORE","BLOCKED")); ver.append(step("VERIFICATION",system,rid,"VERIFY_RESTORE_BLOCKED","BLOCKED")); bad=True
        elif p=="DISABLE_DATA_FLOW":
            if n(f.get("enabled")) in {"false","0"} or state=="DISABLED":
                ver.append(step("VERIFICATION",system,rid,"VERIFY_DATA_FLOW_DISABLED","DISABLED",r.eid))
            else:
                findings.append(step("FINDING",system,rid,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",r.eid))
                rem.append(step("REMEDIATION",system,rid,"DISABLE_DATA_FLOW","DISABLED")); ver.append(step("VERIFICATION",system,rid,"VERIFY_DATA_FLOW_DISABLED","DISABLED")); bad=True
    # Only evidence at or before audit_at can establish a complete case.
    if bad:
        for s in rem+ver:
            if s["phase"]!="FINDING": s["evidence_id"]=""
        status="INCOMPLETE"; steps=findings+rem+ver
    else:
        steps=[s for s in ver if s["evidence_id"]]
        status="COMPLETE" if steps else "INCOMPLETE"
        if status=="INCOMPLETE":
            # No positive proof is not proof of deletion. Produce a conservative,
            # explicitly unverified remediation plan rather than trusting reported_status.
            rid="account_"+(uid.split("_")[-1].zfill(3) if uid else "unknown")
            steps=[step("FINDING","account_service",rid,"REPORT_REMAINING_RECORD","PRESENT"),
                   step("REMEDIATION","account_service",rid,"DELETE_RECORD","ABSENT"),
                   step("VERIFICATION","account_service",rid,"VERIFY_RECORD_ABSENT","ABSENT")]
    steps=ordered(steps)
    return {"case_id":cid,"deletion_status":status,"steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))}
def predict(requests,ds=DATASET):
    ids=read_csv(ds/"user_identities.csv"); audits=read_csv(ds/"user_audit_log.csv"); records=load_records(ds); activities=read_csv(ds/"system_activity.csv")
    return sorted([audit_case(c,records,ids,audits,activities) for c in requests],key=lambda x:x["case_id"])
def write(rows,path):
    with path.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"],lineterminator="\n"); w.writeheader()
        w.writerows(sorted(rows,key=lambda x:x["case_id"]))
def validate(path,expected):
    errors=[]; rows=read_csv(path)
    if len(rows)!=expected: errors.append(f"expected {expected} rows; found {len(rows)}")
    keys=[r["case_id"] for r in rows]
    if keys!=sorted(keys): errors.append("rows are not sorted by case_id")
    if len(keys)!=len(set(keys)): errors.append("duplicate case_id")
    for row in rows:
        try: steps=json.loads(row["steps_json"])
        except Exception: errors.append(f'{row["case_id"]}: invalid JSON'); continue
        if not isinstance(steps,list): errors.append(f'{row["case_id"]}: steps_json is not an array'); continue
        if row["deletion_status"]=="NOT_APPLICABLE" and steps: errors.append(f'{row["case_id"]}: NOT_APPLICABLE must use []')
        for i,s in enumerate(steps,1):
            if s.get("step_no")!=i: errors.append(f'{row["case_id"]}: non-consecutive step number')
            if s.get("phase") not in PHASE or s.get("operation") not in OP: errors.append(f'{row["case_id"]}: invalid phase or operation')
            if not all(k in s for k in ("step_no","phase","system_id","resource_id","operation","state","evidence_id")): errors.append(f'{row["case_id"]}: missing required step field')
            if row["deletion_status"]=="COMPLETE" and (s.get("phase")!="VERIFICATION" or not s.get("evidence_id")): errors.append(f'{row["case_id"]}: COMPLETE requires evidence-backed verification only')
            if row["deletion_status"]=="INCOMPLETE" and s.get("phase") in {"REMEDIATION","VERIFICATION"} and s.get("evidence_id"): errors.append(f'{row["case_id"]}: future steps require empty evidence_id')
    return errors
def main():
    ds=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else DATASET
    out=Path(sys.argv[2]).resolve() if len(sys.argv)>2 else ROOT/"output.csv"
    requests=read_csv(ds/"deletion_requests.csv"); rows=predict(requests,ds); write(rows,out)
    errors=validate(out,len(requests))
    counts={s:sum(r["deletion_status"]==s for r in rows) for s in ("COMPLETE","INCOMPLETE","NOT_APPLICABLE")}
    print(f"Wrote {len(rows)} cases to {out}; status counts: {counts}")
    if errors:
        print(f"Validation found {len(errors)} issue(s):"); print("\n".join(" - "+e for e in errors[:50])); return 1
    print("Output contract validation passed."); return 0
if __name__=="__main__": raise SystemExit(main())
