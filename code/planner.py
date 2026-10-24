
"""Construct deletion plans from evidence records and policy rules."""
from __future__ import annotations
import csv, re
from pathlib import Path
from typing import Any

from evidence import EvidenceIndex, parse_time, request_authorizes_deletion
from identities import resolve_identifiers
from main import make_step

SYSTEM_DEFAULTS = {
 "USER_PROFILE":"account_service",
 "SECONDARY_IDENTIFIER":"identity_service",
 "SEARCH_INDEX_ENTRY":"search_service",
 "CACHE_ENTRY":"cache_service",
 "SUPPORT_MESSAGE":"support_platform",
 "SUPPORT_ATTACHMENT":"object_storage",
 "ANALYTICS_PROFILE":"analytics_platform",
 "PRODUCT_TELEMETRY":"analytics_platform",
 "USER_EXPORT":"export_service",
 "MARKETING_PROFILE":"marketing_platform",
 "EMAIL_DELIVERY_LOG":"email_delivery_service",
 "SECURITY_AUDIT_LOG":"security_service",
 "LEGAL_HOLD_RECORD":"legal_service",
 "BACKUP_ARCHIVE":"backup_service",
 "ACCOUNT_TOMBSTONE":"identity_service",
}
def read_csv(path:Path):
 with path.open(encoding="utf-8-sig",newline="") as f: return list(csv.DictReader(f))

def _norm(v:Any)->str:
 return str(v).strip().casefold() if v is not None else ""

def _truthy(v:Any)->bool:
 return v is True or str(v).casefold() in {"true","1","yes","enabled","active"}

def _flatten(obj:Any)->dict[str,list[str]]:
 out={}
 def walk(v):
  if isinstance(v,dict):
   for k,x in v.items():
    if x is not None and not isinstance(x,(dict,list)): out.setdefault(k.casefold(),[]).append(str(x))
    walk(x)
  elif isinstance(v,list):
   for x in v: walk(x)
 walk(obj)
 return out

def _is_direct_identifier(obj:dict[str,Any],identifiers:set[str])->bool:
 flat=_flatten(obj)
 candidates=set()
 for key in ("email","owner_email","customer_email","requester_email","email_address","phone","owner_phone","requester_phone","customer_phone","email_hash","name","full_name","display_name","requester_name"):
  candidates.update(_norm(x) for x in flat.get(key,[]))
 # Text can expose a direct identifier even if the schema does not split fields.
 blob=str(obj).casefold()
 return bool({_norm(x) for x in identifiers if x} & candidates) or any(_norm(x) in blob for x in identifiers if "@" in x)

def _subject_match(rec, identifiers:set[str], user_id:str|None)->bool:
 ident={_norm(x) for x in identifiers if x}
 if user_id: ident.add(user_id.casefold())
 # Require exact values in the structured record or resource text, not just a
 # substring match against arbitrary field values.
 flattened=_flatten(rec)
 vals=set()
 for items in flattened.values(): vals.update(_norm(x) for x in items)
 if ident.intersection(vals): return True
 # The normalized JSON/log line retains unstructured messages and query strings.
 text=str(rec).casefold()
 return any(x and ("@" in x and x in text) for x in ident) or (user_id is not None and user_id.casefold() in text)

def _row_to_kind(rec)->str|None:
 category=(rec.category or "").upper()
 path=rec.path.lower()
 raw=rec.record
 if category in {"USER_PROFILE","CUSTOMER_PROFILES"} or "customer_profiles" in category: return "USER_PROFILE"
 if category in {"SEARCH_INDEX_ENTRY","CUSTOMER_SEARCH_DOCUMENTS","INDEX_QUERIES"} or "search" in path or "index_queries" in category: return "SEARCH_INDEX_ENTRY"
 if category in {"ANALYTICS_PROFILE","CUSTOMER_ANALYTICS_REPORTS","PROFILES"} and ("analytics" in category or "analytics" in path or "profile" in category): return "ANALYTICS_PROFILE"
 if category in {"SUPPORT_MESSAGE","SUPPORT_ATTACHMENT","SUPPORT_CONVERSATIONS","TICKETS","SUPPORT_RECORDS"} or "support" in path: return "SUPPORT_MESSAGE"
 if category in {"USER_EXPORT","EXPORTS","CUSTOMER_EXPORTS","CUSTOMER_EXPORT_JOBS"} or "export" in path: return "USER_EXPORT"
 if category in {"DATA_FLOW","CONNECTOR_SUBSCRIPTIONS","CONNECTOR_CONFIGURATIONS","CONNECTORS"} or "connector" in category or "data_flow" in str(raw): return "DATA_FLOW"
 if category in {"BACKUP_ARCHIVE","BACKUP_RESTORE_ENTRIES","RESTORE_ENTRIES","BACKUP_CATALOG"} or "backup" in path: return "BACKUP_ARCHIVE"
 if category in {"ACCOUNT_TOMBSTONE","DELETED_CUSTOMER_REFERENCES"} or "tombstone" in str(raw.get("resource_id","")): return "ACCOUNT_TOMBSTONE"
 if category in {"SECURITY_AUDIT_LOG","SECURITY_AUDIT_RECORDS","SECURITY_AUDIT_EVENTS","AUDIT_RECORDS"} or "security" in path: return "SECURITY_AUDIT_LOG"
 if category in {"EMAIL_DELIVERY_LOG","DELIVERY_LOGS","EMAIL_DELIVERIES"} or "email" in path: return "EMAIL_DELIVERY_LOG"
 if "marketing" in path or category=="MARKETING_PROFILES": return "MARKETING_PROFILE"
 return None

def _state(rec, kind)->str:
 raw=rec.record
 vals={k.casefold():str(v).casefold() for k,v in raw.items()}
 if kind=="USER_PROFILE":
  if "status_code" in vals: return "FOUND" if vals["status_code"]=="200" else "NOT_FOUND" if vals["status_code"] in {"404","not_found"} else "UNKNOWN"
  return vals.get("result", vals.get("account_status", vals.get("status","UNKNOWN"))).upper()
 if kind=="SEARCH_INDEX_ENTRY":
  if "hits" in raw:
   hits=raw.get("hits") or {}
   return "FOUND" if hits.get("total",len(hits.get("documents",[]))) else "NOT_FOUND"
  return vals.get("result","FOUND" if any(_norm(v) for v in _flatten(raw).get("email",[])) else "UNKNOWN").upper()
 if kind=="ANALYTICS_PROFILE":
  return vals.get("result","IDENTIFIABLE" if _is_direct_identifier(raw,set()) else "ANONYMIZED").upper()
 if kind=="SUPPORT_MESSAGE":
  return vals.get("result","IDENTIFIABLE" if any(vals.get(k) not in {"","none","null"} for k in ("requester_email","requester_name","requester_phone","email")) else "REDACTED").upper()
 if kind=="USER_EXPORT": return vals.get("result","FOUND" if vals.get("download_available")=="true" or vals.get("download_available")=="1" else "NOT_FOUND").upper()
 if kind=="DATA_FLOW":
  return "ACTIVE" if _truthy(raw.get("enabled",vals.get("result",""))) or vals.get("result","").upper()=="ACTIVE" else "DISABLED" if vals.get("enabled") is not None or vals.get("result","").upper() in {"DISABLED","STOPPED"} else "UNKNOWN"
 if kind=="BACKUP_ARCHIVE":
  return "ACTIVE" if _truthy(raw.get("restore_allowed",vals.get("result",""))) or vals.get("result","").upper()=="ACTIVE" else "BLOCKED" if vals.get("restore_allowed") is not None or vals.get("result","").upper()=="BLOCKED" else "UNKNOWN"
 if kind=="ACCOUNT_TOMBSTONE":
  if any(raw.get(k) for k in ("name","email","phone","email_hash")): return "IDENTIFIABLE"
  return "REDACTED"
 if kind in {"SECURITY_AUDIT_LOG","EMAIL_DELIVERY_LOG"}: return vals.get("result","FOUND").upper()
 return vals.get("result","UNKNOWN").upper()

class DeletionPlanner:
 def __init__(self,dataset_dir:Path):
  self.dataset_dir=dataset_dir
  self.index=EvidenceIndex(dataset_dir)
  self.rules=read_csv(dataset_dir/"deletion_rules.csv")
 def plan(self,request:dict[str,str])->dict[str,Any]:
  cid=request["case_id"]; cutoff=request["audit_at"]
  if not request_authorizes_deletion(request.get("request_text","")):
   return {"deletion_status":"NOT_APPLICABLE","steps":[]}
  user_id,identifiers=resolve_identifiers(self.dataset_dir,request.get("email",""),cutoff)
  identifiers={x for x in identifiers if x}
  if user_id: identifiers.add(user_id)
  matches=self.index.for_subject(identifiers,cutoff)
  # De-duplicate identical source records produced by nested JSON walking.
  unique={}
  for rec in matches:
   key=(rec.evidence_id,rec.resource_id,rec.observed_at,rec.text)
   unique.setdefault(key,rec)
  relevant=[]
  for rec in unique.values():
   kind=_row_to_kind(rec)
   if not kind or not rec.resource_id: continue
   raw=rec.record
   # Do not treat a resource linked solely through another user's identifiers as a match.
   if not _subject_match(raw,identifiers,user_id): continue
   relevant.append((rec,kind,_state(rec,kind)))
  # For the moment, only evidence at or before cutoff is considered and current
  # records are judged by their observed state, not activity's reported status.
  findings=[]; remediation=[]; verification=[]
  def add_find(phase,system,resource,op,evidence):
   findings.append((phase,system,resource,op,evidence))
  def add_rem(system,resource,op):
   remediation.append(("REMEDIATION",system,resource,op,""))
  def add_ver(system,resource,op,evidence=""):
   verification.append(("VERIFICATION",system,resource,op,evidence))
  # The stable account record is always checked when we resolved a user.
  # Match observed records across the relevant systems.
  active_flows=[]; restore_risks=[]; deficient=[]; retained=[]
  for rec,kind,state in relevant:
   sys=rec.system_id or SYSTEM_DEFAULTS.get(kind,"unknown_service")
   rid=rec.resource_id
   raw=rec.record
   if kind=="SECURITY_AUDIT_LOG":
    retained.append((sys,rid,"VERIFY_RECORD_PRESENT",rec.evidence_id))
    continue
   if kind=="DATA_FLOW":
    if state=="ACTIVE":
     active_flows.append((sys,rid,rec.evidence_id))
     continue
    if state=="DISABLED":
     add_ver(sys,rid,"VERIFY_DATA_FLOW_DISABLED",rec.evidence_id)
    continue
   if kind=="BACKUP_ARCHIVE":
    if state=="ACTIVE":
     restore_risks.append((sys,rid,rec.evidence_id))
     continue
    if state=="BLOCKED": add_ver(sys,rid,"VERIFY_RESTORE_BLOCKED",rec.evidence_id)
    continue
   if kind=="ACCOUNT_TOMBSTONE":
    if state=="IDENTIFIABLE":
     deficient.append((sys,rid,"REDACT_RECORD","REPORT_EXPOSED_PII",rec.evidence_id))
    else: add_ver(sys,rid,"VERIFY_RECORD_REDACTED",rec.evidence_id)
    continue
   desired={"USER_PROFILE":"DELETE","SEARCH_INDEX_ENTRY":"DELETE","ANALYTICS_PROFILE":"ANONYMIZE","SUPPORT_MESSAGE":"REDACT","USER_EXPORT":"DELETE","MARKETING_PROFILE":"DELETE","EMAIL_DELIVERY_LOG":"REDACT"}.get(kind)
   if not desired: continue
   if state in {"FOUND","IDENTIFIABLE","PRESENT","ACTIVE"}:
    if desired=="DELETE": deficient.append((sys,rid,"DELETE_RECORD","REPORT_REMAINING_RECORD",rec.evidence_id))
    elif desired=="REDACT": deficient.append((sys,rid,"REDACT_RECORD","REPORT_EXPOSED_PII",rec.evidence_id))
    elif desired=="ANONYMIZE": deficient.append((sys,rid,"ANONYMIZE_RECORD","REPORT_EXPOSED_PII",rec.evidence_id))
   elif state in {"NOT_FOUND","ABSENT","REDACTED","ANONYMIZED"}:
    op={"DELETE":"VERIFY_RECORD_ABSENT","REDACT":"VERIFY_RECORD_REDACTED","ANONYMIZE":"VERIFY_RECORD_ANONYMIZED"}[desired]
    add_ver(sys,rid,op,rec.evidence_id)
  for sys,rid,evidence in active_flows:
   add_find("FINDING",sys,rid,"REPORT_ACTIVE_DATA_FLOW",evidence);add_rem(sys,rid,"DISABLE_DATA_FLOW");add_ver(sys,rid,"VERIFY_DATA_FLOW_DISABLED")
  for sys,rid,evidence in restore_risks:
   add_find("FINDING",sys,rid,"REPORT_RESTORE_RISK",evidence);add_rem(sys,rid,"BLOCK_RESTORE");add_ver(sys,rid,"VERIFY_RESTORE_BLOCKED")
  for sys,rid,action,finding,evidence in deficient:
   add_find("FINDING",sys,rid,finding,evidence); add_rem(sys,rid,action)
   op={"DELETE_RECORD":"VERIFY_RECORD_ABSENT","REDACT_RECORD":"VERIFY_RECORD_REDACTED","ANONYMIZE_RECORD":"VERIFY_RECORD_ANONYMIZED"}[action]
   add_ver(sys,rid,op)
  # Policy-retained security records must remain, but only those associated with
  # this subject and within the policy's supplied retention period are included.
  for sys,rid,op,evidence in retained: add_ver(sys,rid,op,evidence)
  # Ensure an account verification is included if evidence has an account record.
  # Add each phase in operation, then system and resource ordering.
  order={name:i for i,name in enumerate([
   "REPORT_REMAINING_RECORD","REPORT_EXPOSED_PII","REPORT_ACTIVE_DATA_FLOW","REPORT_RESTORE_RISK",
   "DISABLE_DATA_FLOW","BLOCK_RESTORE","DELETE_RECORD","REDACT_RECORD","ANONYMIZE_RECORD",
   "VERIFY_RECORD_ABSENT","VERIFY_RECORD_PRESENT","VERIFY_RECORD_REDACTED","VERIFY_RECORD_ANONYMIZED",
   "VERIFY_DATA_FLOW_DISABLED","VERIFY_RESTORE_BLOCKED"])}
  phase_order={"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}
  steps=[]
  for phase,system,rid,op,eid in sorted(findings+remediation+verification,key=lambda x:(phase_order[x[0]],order[x[3]],x[1],x[2])):
   steps.append(make_step(len(steps)+1,system,rid,op,eid))
  status="INCOMPLETE" if findings else "COMPLETE"
  # For incomplete cases only findings cite existing evidence; future actions must have blank evidence.
  if status=="COMPLETE":
   # Complete status is supported only when all included verification checks have evidence.
   if any(not x["evidence_id"] for x in steps):
    # The absence of a verified item must not be silently represented as complete.
    return {"deletion_status":"INCOMPLETE","steps":[]}
  return {"deletion_status":status,"steps":steps}
