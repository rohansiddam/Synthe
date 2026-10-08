# SPDX-License-Identifier: Apache-2.0
"""Read-only broker -> Mini Studio state projection."""
from __future__ import annotations
import datetime as dt
import re
_CONTROL=re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
def clean(v, one_line=False):
    s="" if v is None else str(v)
    if one_line: s=s.replace("\n","\\n")
    return _CONTROL.sub(lambda m:f"\\x{ord(m.group()):02x}" if ord(m.group())<256 else f"\\u{ord(m.group()):04x}",s)
def _refs(r):
    out=set()
    for k in ("proposal_id","staged_id","idempotency_key","handoff_id","proposal_reference"):
        if isinstance(r.get(k),str): out.add(r[k])
    for box in ("effect","params"):
        x=r.get(box)
        if isinstance(x,dict):
            for k in ("proposal_id","staged_id","idempotency_key","handoff_id"):
                if isinstance(x.get(k),str): out.add(x[k])
    return out
def _box(r,k): return r.get(k) if isinstance(r.get(k),dict) else {}
def _broker_ids(r):
    # The broker's own receipts: staged.id is the proposal id; otherwise handoff.idempotency_key plus the
    # action named by the effect (proposal receipts) or by the approval (approval receipts).
    out=set(); sid=_box(r,"staged").get("id")
    if isinstance(sid,str): out.add(sid)
    idem=_box(r,"handoff").get("idempotency_key")
    for act in (_box(r,"effect").get("action"),_box(r,"approval").get("action")):
        if isinstance(idem,str) and isinstance(act,str): out.add(f"{idem}/{act}")
    return out
def _correlates(r,p):
    # Never by idempotency key alone: one key can carry several actions.
    refs=_refs(r)|_broker_ids(r); pid=p["id"]; idem=p.get("idempotency_key")
    return pid in refs or bool(idem and p.get("action") and f"{idem}/{p['action']}" in refs)
def _decision(r): return str(r.get("decision") or r.get("state") or r.get("status") or "unknown")
def _state(d): return {"executed":"confirmed","unconfirmed":"unconfirmed","approval_accepted":"approved_waiting","staged":"waiting","denied":"denied","errored":"error"}.get(d,"unknown")
def normalize_snapshot(hello, staged, receipts, mode="live", observed_at=None):
    observed=observed_at or dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z")
    hs=hello if isinstance(hello,dict) else None
    ss=staged.get("staged",[]) if isinstance(staged,dict) else []
    rs=receipts.get("receipts",[]) if isinstance(receipts,dict) else []
    ss=ss if isinstance(ss,list) else []; rs=rs if isinstance(rs,list) else []
    proposals=[]
    for x in ss:
        if not isinstance(x,dict): continue
        idem=x.get("idempotency_key") if isinstance(x.get("idempotency_key"),str) else None
        action=x.get("action") if isinstance(x.get("action"),str) else None
        pid=f"{idem}/{action}" if idem and action else idem or "unknown-proposal"
        staged_now=x.get("state")=="STAGED"
        # The broker keeps waiting_for after a proposal executes; only a still-staged one is waiting on anything.
        waiting=x.get("waiting_for") if staged_now and isinstance(x.get("waiting_for"),list) else []
        waiting=[clean(v,True) for v in waiting if isinstance(v,(str,int))]
        msgs={"approval":"Ready for your review","approval_expired":"Approval needs renewal",
              "branch_changed":"Change needs refreshing","remote_moved":"Change needs refreshing",
              "dependency_incomplete":"Waiting on another task","dependency_unknown":"Waiting on another task",
              "scope_denied":"Proposed files exceed the allowed paths"}
        reasons=[{"code":c,"message":msgs.get(c,c)} for c in waiting]
        p={"id":clean(pid,True),"idempotency_key":clean(idem,True) if idem else None,"action":clean(action,True) if action else None,
           "target":clean((x.get("params") or {}).get("branch"),True),"remote":clean((x.get("params") or {}).get("remote"),True),
           "commit":(x.get("params") or {}).get("commit"),"state":"waiting" if staged_now else clean(x.get("state") or "unknown",True).lower(),
           "reasons":reasons,"suggested_action":("Review exact diff and approve once" if "approval" in waiting else "Inspect the authoritative reason") if staged_now else "Nothing to approve; check the receipt"}
        hits=[r for r in rs if isinstance(r,dict) and _correlates(r,p)]
        if hits:
            d=_decision(hits[-1])
            if d not in ("staged",):
                # A refused or duplicate approval leaves the proposal where it was; it is still shown as the outcome.
                if d not in ("approval_rejected","approval_duplicate"): p["state"]=_state(d)
                p["outcome"]={"decision":d,"receipt_sequence":hits[-1].get("seq")}
        proposals.append(p)
    recent=[{"proposal_reference":clean(next(iter(sorted(_refs(r)|_broker_ids(r))),None),True) or None,"decision":_decision(r),
             "receipt_sequence":r.get("seq"),"commit":(r.get("effect") or {}).get("commit") if isinstance(r.get("effect"),dict) else None,
             "correlated":any(_correlates(r,p) for p in proposals)} for r in rs[-20:] if isinstance(r,dict)]
    return {"schema_version":1,"mode":mode,"observed_at":observed,
            "connection":{"status":"connected" if hs else "unavailable","broker_id":clean(hs.get("broker_id"),True) if hs else None,
                          "broker_version":clean(hs.get("version"),True) if hs else None,"last_success_at":observed if hs else None,
                          "isolation":hs.get("isolation") if hs else None},
            "proposals":proposals,"recent":recent,
            "receipt_verification":"ok" if isinstance(receipts,dict) and receipts.get("ok") is True else "failed" if isinstance(receipts,dict) and receipts.get("ok") is False else "unavailable"}
def render_snapshot(s,sample=False):
    c=s["connection"]; lines=[("SYNTHE MINI STUDIO · SAMPLE" if sample else "SYNTHE MINI STUDIO"),"OpenClaw developer preview",
        f"Broker: {c['status']}"+(f" · {c['broker_id']} · {c['broker_version']}" if c.get("broker_id") else ""),
        f"Observed: {s['observed_at']}","","REVIEW                         RECENT",
        f"{len(s['proposals'])} proposal(s)                    {len(s['recent'])} outcome(s)"]
    if not s["proposals"]: lines.append("No staged proposals observed.")
    for i,p in enumerate(s["proposals"],1):
        o=p.get("outcome")
        reason=(p["reasons"][0]["message"] if p["reasons"] else f"Receipt #{o['receipt_sequence']}: {o['decision']}" if o else "Reason unavailable")
        lines += [f"{i}. {p['id']}  {p['state']}  {p.get('target') or 'target unknown'}  {(p.get('commit') or 'unknown')[:12]}",
                  f"   {reason}"]
    lines += ["",f"Receipt verification: {s['receipt_verification']}","Note: missing evidence remains unknown; approval is not proof of execution."]
    return "\n".join(lines)
def render_detail(d):
    e=d.get("effect") or {}; c=d.get("changes") or {}
    lines=["","="*72," BROKER-DERIVED REVIEW","="*72,
           f" Proposal  {clean(d.get('id'),True)}",f" Target    {clean(e.get('remote'),True) or 'unknown'} / {clean(e.get('branch'),True) or 'unknown'}",
           f" Commit    {clean(e.get('commit'),True) or 'unknown'}",
           f" Evidence  {'broker diff available' if c.get('available') else 'diff unavailable'}"," Tests     not verified here"]
    for f in (c.get("files") or [])[:40]:
        if isinstance(f,dict): lines.append(f"   {clean(f.get('status'),True):<2} {clean(f.get('path'),True)}")
    a=d.get("agent_says") or {}
    if a: lines += ["-"*72," Agent says (not verified by Synthe):"]+[f"   {x}" for x in clean(a.get("purpose")).splitlines()]
    if c.get("patch"): lines += ["-"*72," Diff (broker copy)"]+[f"   {x}" for x in clean(c["patch"]).splitlines()[:60]]
    return "\n".join(lines+["-"*72])
