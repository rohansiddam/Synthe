"""T2.3 depends_on: chains, diamonds, cycles, released and unclaimed upstreams.

v0.5 wait-for: a handoff's depends_on lists idempotency keys that must be
COMPLETED before it may commit. The check runs inside the fence, so the
dependency check and the effect are one atomic step.

  1. Chain A->B->C: A is blocked while B is RESERVED, proceeds after B completes.
  2. Diamond A->{B,C}, B->D, C->D: A waits for both branches, not just one.
  3. Cycle A->B->A: the second claim is refused at claim time; no one commits.
  4. Released upstream: A depends on B which was RELEASED (never completed)
     -> A stays blocked with dependency_incomplete.
  5. Unclaimed upstream: depends_on names a key the ledger never saw ->
     dependency_unknown.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

import handoff_check as hc  # noqa: E402
from world import World  # noqa: E402


@pytest.fixture
def dep_world(tmp_path):
    return World(tmp_path)


def _codes(v):
    return [r["code"] for r in v.get("reasons", [])]


def _complete(w, packet, token):
    c = hc.complete(packet, w.tmp / "ledger.json", claim_token=token)
    assert c["decision"] == "COMPLETED", c
    return c


def test_chain_blocks_until_upstream_complete(dep_world):
    w = dep_world
    pc, pb, pa = w.packet(idem="c"), w.packet(idem="b", depends_on=["c"]), w.packet(idem="a", depends_on=["b"])
    tc, tb, ta = w.claim(pc), w.claim(pb), w.claim(pa)

    # A is blocked while B is still RESERVED.
    with pytest.raises(hc.FenceError) as fe:
        with hc.fenced(pa, w.tmp / "ledger.json", ta):
            pass
    assert "dependency_incomplete" in _codes(fe.value.verdict)

    # Complete the chain bottom-up; A proceeds once B is COMPLETED.
    _complete(w, pc, tc)
    _complete(w, pb, tb)
    with hc.fenced(pa, w.tmp / "ledger.json", ta):
        pass
    assert w.ledger()["a"]["state"] == "COMPLETED"


def test_diamond_waits_for_both_branches(dep_world):
    w = dep_world
    pd = w.packet(idem="d")
    pb = w.packet(idem="b", depends_on=["d"])
    pc = w.packet(idem="c", depends_on=["d"])
    pa = w.packet(idem="a", depends_on=["b", "c"])
    td, tb, tc, ta = w.claim(pd), w.claim(pb), w.claim(pc), w.claim(pa)

    _complete(w, pd, td)
    _complete(w, pb, tb)
    # Only b done: a still blocked on c.
    with pytest.raises(hc.FenceError) as fe:
        with hc.fenced(pa, w.tmp / "ledger.json", ta):
            pass
    assert "dependency_incomplete" in _codes(fe.value.verdict)

    _complete(w, pc, tc)
    with hc.fenced(pa, w.tmp / "ledger.json", ta):
        pass
    assert w.ledger()["a"]["state"] == "COMPLETED"


def test_cycle_refused_at_claim_time(dep_world):
    w = dep_world
    pa = w.packet(idem="a", depends_on=["b"])
    ta = w.claim(pa)
    # b depends on a: claiming b would close the cycle a->b->a.
    pb = w.packet(idem="b", depends_on=["a"])
    v = w.check(pb)
    assert v["decision"] == "REJECT", v
    codes = _codes(v)
    assert any("cycle" in c for c in codes), codes
    # Neither side can commit through the cycle.
    with pytest.raises(hc.FenceError):
        with hc.fenced(pa, w.tmp / "ledger.json", ta):
            pass


def test_released_upstream_keeps_downstream_blocked(dep_world):
    w = dep_world
    import datetime as dt
    import json as _json
    pb = w.packet(idem="b")
    pa = w.packet(idem="a", depends_on=["b"])
    tb, ta = w.claim(pb), w.claim(pa)

    # Age and release b: it never completed.
    ledger = w.tmp / "ledger.json"
    data = _json.loads(ledger.read_text())
    for entry in data.values():
        if isinstance(entry, dict):
            entry["reserved_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=48)).isoformat()
    ledger.write_text(_json.dumps(data))
    rel = hc.release(pb, ledger)
    assert rel["decision"] == "RELEASED"

    # a is still blocked: its upstream never completed.
    with pytest.raises(hc.FenceError) as fe:
        with hc.fenced(pa, w.tmp / "ledger.json", ta):
            pass
    assert "dependency_incomplete" in _codes(fe.value.verdict)


def test_unclaimed_upstream_is_unknown(dep_world):
    w = dep_world
    pa = w.packet(idem="a", depends_on=["ghost"])
    ta = w.claim(pa)
    with pytest.raises(hc.FenceError) as fe:
        with hc.fenced(pa, w.tmp / "ledger.json", ta):
            pass
    assert "dependency_unknown" in _codes(fe.value.verdict)
