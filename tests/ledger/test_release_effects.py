"""release() must refuse a RESERVED claim that already carries effect records.

Without the guard: claim -> fenced_effect("charge") EXECUTED (claim stays
RESERVED because a later final action is pending) -> release --force (or a
TTL-expired release without --force) -> re-claim wins epoch 2 with a fresh
entry that carries no effects -> fenced_effect("charge") EXECUTES AGAIN.
One idempotency_key, two charges. The epoch fence only fences the *old*
holder; the new holder is the one that double-fires.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

import handoff_check as hc  # noqa: E402
from world import World  # noqa: E402

FINAL = ("charge", "receipt")


def _claim_and_charge(w, packet):
    v = hc.check(packet, registry=w.registry, ledger_path=w.tmp / "ledger.json",
                 workspace=w.tmp / "workspace")
    assert v["decision"] == "ACCEPT"
    fired = []
    with hc.fenced_effect(packet, w.tmp / "ledger.json", v["claim"]["token"], "charge",
                          final_actions=FINAL):
        fired.append(v["claim"]["epoch"])
    entry = w.ledger_entry()
    assert entry["state"] == "RESERVED" and entry["effects"]["charge"]["state"] == "EXECUTED"
    return v, fired


@pytest.mark.parametrize("force,ttl", [(True, 24.0), (False, 0.0)])
def test_release_refuses_claim_with_recorded_effect(tmp_path, force, ttl):
    w = World(tmp_path)
    packet = w.packet()
    _claim_and_charge(w, packet)

    r = hc.release(packet, ledger_path=w.tmp / "ledger.json", reserve_ttl_hours=ttl, force=force)
    assert r["decision"] == "REJECT", r
    assert r["reasons"][0]["code"] == "release_effect_unreconciled"
    assert w.ledger_entry()["state"] == "RESERVED"
    assert w.chain()["ok"]


def test_release_refusal_prevents_second_fire(tmp_path):
    w = World(tmp_path)
    packet = w.packet()
    v1, fired = _claim_and_charge(w, packet)

    # Same-epoch replay is already refused.
    with pytest.raises(hc.FenceError) as ei:
        with hc.fenced_effect(packet, w.tmp / "ledger.json", v1["claim"]["token"], "charge",
                              final_actions=FINAL):
            fired.append("replay")
    assert ei.value.verdict["reasons"][0]["code"] == "effect_already_executed"

    # The release path must not reopen the key while 'charge' is on record.
    hc.release(packet, ledger_path=w.tmp / "ledger.json", force=True)
    v2 = hc.check(packet, registry=w.registry, ledger_path=w.tmp / "ledger.json",
                  workspace=w.tmp / "workspace")
    assert v2["decision"] == "REJECT"
    assert "idempotency_key_reserved" in [r["code"] for r in v2["reasons"]]
    assert fired == [1], f"charge fired more than once: {fired}"


def test_bare_reservation_still_releasable(tmp_path):
    w = World(tmp_path)
    packet = w.packet()
    v = hc.check(packet, registry=w.registry, ledger_path=w.tmp / "ledger.json",
                 workspace=w.tmp / "workspace")
    assert v["decision"] == "ACCEPT"
    r = hc.release(packet, ledger_path=w.tmp / "ledger.json", force=True)
    assert r["decision"] == "RELEASED"
