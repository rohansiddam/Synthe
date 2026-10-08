import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/"src"))
from synthe_studio_model import normalize_snapshot,render_detail,render_snapshot,clean

def test_missing_correlation_stays_unknown():
 s=normalize_snapshot({"broker_id":"b","version":"1","isolation":{}},{"staged":[{"idempotency_key":"task:1","action":"push_branch","state":"STAGED","waiting_for":["approval"],"params":{"branch":"agent/x","commit":"a"*40}}]},{"ok":True,"receipts":[{"seq":9,"decision":"executed","effect":{"branch":"agent/x","commit":"a"*40}}]})
 assert s["proposals"][0]["state"]=="waiting" and s["proposals"][0].get("outcome") is None
 assert s["recent"][0]["correlated"] is False

def test_explicit_correlation_confirms_execution():
 s=normalize_snapshot({"broker_id":"b","version":"1","isolation":{}},{"staged":[{"idempotency_key":"task:1","action":"push_branch","state":"STAGED","waiting_for":["approval"],"params":{"branch":"agent/x","commit":"a"*40}}]},{"ok":True,"receipts":[{"seq":10,"decision":"executed","proposal_id":"task:1/push_branch","effect":{"commit":"a"*40}}]})
 assert s["proposals"][0]["state"]=="confirmed" and s["proposals"][0]["outcome"]["receipt_sequence"]==10

def test_agent_text_is_terminal_safe():
 v="hello\x1b[2J\u202e spoof"
 assert "\x1b" not in clean(v) and "\u202e" not in clean(v)

def test_detail_labels_unverified_tests():
 t=render_detail({"id":"x","effect":{"branch":"agent/x","commit":"a"*40},"changes":{"available":True,"files":[{"path":"x.py","status":"M"}],"patch":"+print('x')"},"agent_says":{"purpose":"claimed complete"}})
 assert "Tests     not verified here" in t and "Agent says (not verified by Synthe)" in t

# ---- the broker's own receipt shape (handoff / effect / approval / staged boxes) ----
import importlib.util
import pytest
STAGED={"staged":[{"idempotency_key":"k1","action":"push_branch","state":"STAGED","waiting_for":["approval"],"params":{"branch":"feature/x","commit":"a"*40}}]}
HELLO={"broker_id":"b","version":"1","isolation":{}}
def _rcpt(seq,decision,**boxes): return {"seq":seq,"decision":decision,"handoff":{"id":"h-k1","idempotency_key":"k1"},**boxes}

def test_same_key_other_action_never_correlates():
 s=normalize_snapshot(HELLO,STAGED,{"ok":True,"receipts":[_rcpt(5,"executed",effect={"action":"merge_pr","commit":"b"*40})]})
 assert s["proposals"][0]["state"]=="waiting" and s["proposals"][0].get("outcome") is None and s["recent"][0]["correlated"] is False

def test_rejected_approval_leaves_the_proposal_waiting():
 s=normalize_snapshot(HELLO,STAGED,{"ok":True,"receipts":[_rcpt(6,"approval_rejected",approval={"action":"push_branch"})]})
 p=s["proposals"][0]
 assert p["state"]=="waiting" and p["outcome"]["decision"]=="approval_rejected" and p["reasons"][0]["code"]=="approval"

def test_executed_proposal_is_not_offered_for_review():
 done={"staged":[dict(STAGED["staged"][0],state="EXECUTED")]}
 s=normalize_snapshot(HELLO,done,{"ok":True,"receipts":[_rcpt(7,"executed",effect={"action":"push_branch"},staged={"id":"k1/push_branch"})]})
 p=s["proposals"][0]
 assert p["state"]=="confirmed" and p["reasons"]==[] and p["suggested_action"]!="Review exact diff and approve once"
 assert "Receipt #7: executed" in render_snapshot(s)

def test_a_real_broker_push_is_confirmed_by_its_receipt(tmp_path):
 # End to end on a real broker: stage, approve the exact commit, push; Mini Studio links all three receipts.
 from test_isolation import daemon
 from test_speculative import PUSH,stage
 from world import World
 import synthe_approve as sa, synthe_client as scl
 w=World(tmp_path); stage(w)
 with daemon(w.cfg) as url:
  c=scl.BrokerClient(url)
  before=normalize_snapshot(c.call("hello"),c.call("staged"),c.call("receipts",limit=20))
  c.call("submit_approval",approval=sa.build_approval(c.call("staged_detail",id=f"k1/{PUSH}"),w.keys["rishab"],30))
  after=normalize_snapshot(c.call("hello"),c.call("staged"),c.call("receipts",limit=20))
 assert before["proposals"][0]["state"]=="waiting" and before["proposals"][0]["reasons"][0]["code"]=="approval"
 p=after["proposals"][0]
 assert p["state"]=="confirmed" and p["outcome"]["decision"]=="executed" and p["reasons"]==[]
 assert [r["decision"] for r in after["recent"]]==["staged","approval_accepted","executed"] and all(r["correlated"] for r in after["recent"])

# ---- mutation check: each guard above, removed in a copy, makes its test fail ----
SRC=Path(__file__).resolve().parent.parent/"src"/"synthe_studio_model.py"
MUTATIONS=[
 ("idempotency key alone", "or bool(idem and p.get(\"action\") and f\"{idem}/{p['action']}\" in refs)", "or bool(idem and idem in refs|{x.split('/')[0] for x in refs})", test_same_key_other_action_never_correlates),
 ("rejected approval flips state", "if d not in (\"approval_rejected\",\"approval_duplicate\"): p[\"state\"]=_state(d)", "p[\"state\"]=_state(d)", test_rejected_approval_leaves_the_proposal_waiting),
 ("executed still waiting", "if staged_now and isinstance(x.get(\"waiting_for\"),list) else []", "if isinstance(x.get(\"waiting_for\"),list) else []", test_executed_proposal_is_not_offered_for_review),
 ("broker receipt boxes ignored", "refs=_refs(r)|_broker_ids(r)", "refs=_refs(r)", test_executed_proposal_is_not_offered_for_review),
]

@pytest.mark.parametrize("name,anchor,mutant,check",MUTATIONS,ids=[m[0] for m in MUTATIONS])
def test_mutation_is_caught(name,anchor,mutant,check,monkeypatch):
 text=SRC.read_text(encoding="utf-8")
 assert text.count(anchor)==1, f"anchor for {name!r} must appear exactly once"
 spec=importlib.util.spec_from_loader("mutant_studio_model",loader=None); m=importlib.util.module_from_spec(spec)
 exec(compile(text.replace(anchor,mutant),str(SRC),"exec"),m.__dict__)
 for fn in ("normalize_snapshot","render_snapshot"): monkeypatch.setitem(check.__globals__,fn,getattr(m,fn))
 with pytest.raises(AssertionError): check()

def test_unmutated_code_passes():
 for _,_,_,check in MUTATIONS: check()
