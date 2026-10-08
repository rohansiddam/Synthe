from synthe_studio_model import normalize_snapshot,render_detail,clean

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
