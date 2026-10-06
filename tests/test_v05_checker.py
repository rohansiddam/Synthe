"""v0.4/v0.5 checker features, on the public v0.3 examples and their test-only keys:
approvals that pin effect params, detached and deferred approvals, wait-for dependencies,
exclusive paths, and domain-separated receipt signatures."""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc      # noqa: E402
import synthe_crypto as sc      # noqa: E402
import synthe_sign as ss        # noqa: E402

V3 = ROOT / "examples" / "v03"
KEYS = V3 / "test-keys"
FAR = "2999-01-01T00:00:00Z"


def reg(**policy):
    r = json.loads((V3 / "registry.json").read_text())
    r["agents"]["caddy"]["policy"].update(policy)
    return r


def packet(key="k-v05", params=None, approve=True, approval_params=None, depends_on=None, owned=None):
    """The public valid-signed packet with a fresh key, re-approved by rohan and re-signed by cora."""
    p = json.loads((V3 / "packets" / "valid-signed.json").read_text())
    h = p["handoff"]
    h["idempotency_key"], h["id"] = key, f"h-{key}"
    h["authority"]["approvals"] = []
    if params is not None:
        next(a for a in h["planned_actions"] if a["name"] == "send_email")["params"] = params
    if depends_on is not None:
        h["depends_on"] = depends_on
    if owned is not None:
        h["scope"]["owned_paths"] = owned
    if approve:
        ss.approve_packet(p, ss.load_key(KEYS / "rohan.key.json"), "send_email", FAR, approval_params)
    return ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))


def check(p, registry=None, ledger=None, tmp=None, **kw):
    lp = None
    if ledger is not None:
        lp = tmp / "ledger.json"
        lp.write_text(json.dumps(ledger))
    return hc.check(copy.deepcopy(p), registry=registry or reg(), ledger_path=lp,
                    workspace=V3 / "workspace", dry_run=True, **kw)


def codes(v):
    return {r["code"] for r in v.get("reasons", [])}


# ---- approvals that pin params (v0.4) ---------------------------------------
def test_pinned_approval_covers_exactly_the_planned_params():
    to = {"to": "team@example.com"}
    assert check(packet(params=to, approval_params=to))["decision"] == "ACCEPT"


def test_sender_cannot_retarget_a_pinned_approval():
    v = check(packet(params={"to": "attacker@example.com"}, approval_params={"to": "team@example.com"}))
    assert v["decision"] == "REJECT" and "approval_params_mismatch" in codes(v)


def test_pinned_params_are_inside_the_approval_signature():
    p = packet(params={"to": "a@example.com"}, approval_params={"to": "a@example.com"})
    p["handoff"]["authority"]["approvals"][0]["params"] = {"to": "b@example.com"}
    p["handoff"]["planned_actions"][1]["params"] = {"to": "b@example.com"}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))  # sender re-signs; approver can't be forged
    v = check(p)
    assert v["decision"] == "REJECT" and "approval_signature_invalid" in codes(v)


def test_unpinned_approval_still_works_as_in_v03():
    assert check(packet(params={"to": "team@example.com"}))["decision"] == "ACCEPT"


# ---- detached and deferred approvals (v0.5) ---------------------------------
def test_detached_approval_counts_like_an_embedded_one():
    p = packet(approve=False)
    detached = ss.detached_approval(p, ss.load_key(KEYS / "rohan.key.json"), "send_email", FAR)
    assert check(p)["decision"] == "REJECT"
    assert check(p, extra_approvals=[detached])["decision"] == "ACCEPT"


def test_detached_approval_for_another_handoff_is_refused():
    other = packet(key="k-other", approve=False)
    detached = ss.detached_approval(other, ss.load_key(KEYS / "rohan.key.json"), "send_email", FAR)
    assert check(packet(approve=False), extra_approvals=[detached])["decision"] == "REJECT"


def test_deferred_approval_is_recorded_not_skipped():
    v = check(packet(approve=False), defer_approvals=["send_email"])
    assert v["decision"] == "ACCEPT" and v["approvals_deferred"] == ["send_email"]
    assert "approvals_deferred" not in check(packet())  # default verdicts unchanged


def test_defer_never_excuses_a_bad_approval():
    v = check(packet(params={"to": "x@example.com"}, approval_params={"to": "y@example.com"}),
              defer_approvals=["send_email"])
    assert v["decision"] == "REJECT" and "approval_params_mismatch" in codes(v)


# ---- wait-for dependencies (v0.5) -------------------------------------------
def test_dependency_is_checked_at_commit_unknown_incomplete_then_ok(tmp_path):
    """SPEC §8: the claim records depends_on; complete() (and fenced()) refuse until upstream is COMPLETED."""
    p, lp = packet(depends_on=["k-up"]), tmp_path / "ledger.json"
    claim = hc.check(copy.deepcopy(p), registry=reg(), ledger_path=lp, workspace=V3 / "workspace")
    assert claim["decision"] == "ACCEPT", claim
    token = claim["claim"]["token"]
    assert "dependency_unknown" in codes(hc.complete(p, lp, claim_token=token))
    ledger = json.loads(lp.read_text())
    ledger["k-up"] = {"state": "RESERVED", "to": "caddy"}
    lp.write_text(json.dumps(ledger))
    assert "dependency_incomplete" in codes(hc.complete(p, lp, claim_token=token))
    ledger["k-up"]["state"] = "COMPLETED"
    lp.write_text(json.dumps(ledger))
    assert hc.complete(p, lp, claim_token=token)["decision"] == "COMPLETED"


def test_dependency_cycle_is_refused(tmp_path):
    p = packet(key="k-a", depends_on=["k-b"])
    v = check(p, ledger={"k-b": {"state": "RESERVED", "depends_on": ["k-a"]}}, tmp=tmp_path)
    assert v["decision"] == "REJECT" and "dependency_cycle" in codes(v)
    assert "dependency_cycle" in codes(check(packet(key="k-self", depends_on=["k-self"]), ledger={}, tmp=tmp_path))


# ---- exclusive paths (v0.5) -------------------------------------------------
def test_exclusive_paths_refuse_overlapping_live_claims(tmp_path):
    live = {"k-live": {"state": "RESERVED", "to": "caddy", "owned_paths": ["src/**"]}}
    r = reg(exclusive_paths=True)
    v = check(packet(owned=["src/app.py"]), registry=r, ledger=live, tmp=tmp_path)
    assert v["decision"] == "REJECT" and "claim_conflict" in codes(v)
    assert check(packet(owned=["docs/**"]), registry=r, ledger=live, tmp=tmp_path)["decision"] == "ACCEPT"
    assert check(packet(owned=["src/app.py"]), ledger=live, tmp=tmp_path)["decision"] == "ACCEPT"  # off by default


# ---- receipt signatures (v0.4) ----------------------------------------------
def test_receipt_signatures_are_domain_separated():
    key = ss.load_key(KEYS / "rohan.key.json")
    receipt = {"seq": 1, "decision": "executed", "prev": None}
    data = sc.receipt_signing_input(receipt)
    assert data.startswith(sc.RECEIPT_SIG_DOMAIN.encode() + b"\n")
    assert sc.receipt_signing_input({**receipt, "sig": "anything"}) == data
    sig = sc.sign_bytes(key["_secret"], data)
    pub = sc.public_key(key["_secret"])
    assert sc.verify_bytes(pub, data, sig)
    assert not sc.verify_bytes(pub, sc.canonical_json(receipt), sig)  # not valid as a bare payload
