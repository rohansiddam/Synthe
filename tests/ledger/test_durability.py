"""T2.6 ledger durability: corrupt, truncated, concurrently replaced files.

The ledger is the broker's ground truth, so its file handling must be
crash-safe:

  1. Corrupt file (garbage bytes) -> every operation refuses cleanly with
     `ledger_corrupt`; nothing is recorded, nothing wedges.
  2. Truncated file (torn JSON, as from a killed non-atomic writer) -> same
     clean refusal; after the file is restored, the ledger works again.
  3. Concurrent replacement under load -> 40 processes hammering claim and
     complete on distinct keys never observe a torn file (no reader ever
     sees invalid JSON), and the final ledger is valid with all entries.
  4. Atomic save guarantee -> save_ledger writes temp + os.replace, so even
     a writer killed mid-save leaves the primary ledger either old or new,
     never partial. A SIGKILL may leave that process's private temp file;
     readers ignore it because only the primary path is authoritative.
"""
import json
import multiprocessing as mp
import os
import signal
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

import handoff_check as hc  # noqa: E402
from world import World  # noqa: E402


@pytest.fixture
def dur_world(tmp_path):
    w = World(tmp_path)
    return w


def _refuse_codes(verdict):
    return [r["code"] for r in verdict.get("reasons", [])]


def test_corrupt_ledger_refuses_everything_cleanly(dur_world):
    w = dur_world
    packet = w.packet()
    ledger = w.tmp / "ledger.json"
    ledger.write_text("this is not json {{{ garbage")

    for op, args in [
        ("check", (packet,)),
        ("release", (packet,)),
    ]:
        if op == "check":
            v = hc.check(packet, registry=w.registry, ledger_path=ledger,
                         workspace=w.tmp / "workspace")
        else:
            v = hc.release(packet, ledger)
        assert v["decision"] == "REJECT", (op, v)
        assert "ledger_corrupt" in _refuse_codes(v), (op, v)

    # Nothing was recorded and the file is untouched.
    assert ledger.read_text() == "this is not json {{{ garbage"


@pytest.mark.xfail(strict=True, reason="T2.6: fenced() on corrupt ledger raises completion_unknown_key instead of ledger_corrupt")
def test_fenced_on_corrupt_ledger_reports_ledger_corrupt(dur_world):
    """FINDING: fenced() skips the _corrupt check that check/complete/release/
    fenced_effect all perform, so a corrupt ledger surfaces as the misleading
    `completion_unknown_key` instead of `ledger_corrupt`."""
    w = dur_world
    packet = w.packet()
    ledger = w.tmp / "ledger.json"
    ledger.write_text("this is not json {{{ garbage")
    token = "deadbeef"
    with pytest.raises(hc.FenceError) as fe:
        with hc.fenced(packet, ledger, token):
            pass
    assert "ledger_corrupt" in _refuse_codes(fe.value.verdict)


def test_truncated_ledger_refuses_then_recovers(dur_world):
    w = dur_world
    packet = w.packet()
    ledger = w.tmp / "ledger.json"

    # A good claim first, so we know what "healthy" looks like.
    token = w.claim(packet)
    assert w.ledger_entry()["state"] == "RESERVED"

    # Simulate a torn write: valid JSON cut mid-object.
    good = ledger.read_text()
    ledger.write_text(good[: len(good) // 2])
    v = hc.check(w.packet(idem="k2"), registry=w.registry, ledger_path=ledger,
                 workspace=w.tmp / "workspace")
    assert v["decision"] == "REJECT"
    assert "ledger_corrupt" in _refuse_codes(v)

    # Restore the file: the ledger works again, old claim intact.
    ledger.write_text(good)
    v2 = hc.check(w.packet(idem="k3"), registry=w.registry, ledger_path=ledger,
                  workspace=w.tmp / "workspace")
    assert v2["decision"] == "ACCEPT", v2
    assert w.ledger_entry()["state"] == "RESERVED"  # k1 still there


def _hammer_child(ledger_path, registry, workspace, packet, out_path, idx):
    """Claim then complete a distinct key; record any anomaly."""
    try:
        v = hc.check(packet, registry=registry, ledger_path=Path(ledger_path),
                     workspace=Path(workspace))
        if v["decision"] != "ACCEPT":
            open(f"{out_path}-{idx}", "w").write(f"BAD-CLAIM {v['decision']} {_refuse_codes(v)}\n")
            return
        token = v["claim"]["token"]
        c = hc.complete(packet, Path(ledger_path), claim_token=token)
        if c["decision"] != "COMPLETED":
            open(f"{out_path}-{idx}", "w").write(f"BAD-COMPLETE {c['decision']}\n")
            return
        open(f"{out_path}-{idx}", "w").write("OK\n")
    except BaseException as e:  # noqa: BLE001
        open(f"{out_path}-{idx}", "w").write(f"EXC {type(e).__name__}: {e}\n")


def test_concurrent_replacement_never_shows_torn_file(tmp_path, dur_world):
    w = dur_world
    n = 40
    # Pre-build one packet per hammer child (distinct idempotency keys).
    packets = [w.packet(idem=f"hammer-{i}") for i in range(n)]
    out = str(tmp_path / "hammer")
    ctx = mp.get_context("fork")
    procs = [
        ctx.Process(target=_hammer_child,
                    args=(str(w.tmp / "ledger.json"), w.registry,
                          str(w.tmp / "workspace"), packets[i], out, i))
        for i in range(n)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=120)
        assert not p.is_alive(), "hammer child hung"

    anomalies = []
    for i in range(n):
        line = open(f"{out}-{i}").read().strip()
        if line != "OK":
            anomalies.append((i, line))
    assert not anomalies, f"anomalies under concurrent replacement: {anomalies[:5]}"

    # Final ledger is valid JSON with all 40 completions, no corruption flag.
    data = json.loads((w.tmp / "ledger.json").read_text())
    assert "_corrupt" not in data
    done = [k for k, e in data.items()
            if isinstance(e, dict) and e.get("state") == "COMPLETED"]
    assert len(done) == n, f"expected {n} completions, got {len(done)}"
    assert w.chain()["ok"]


def test_killed_writer_leaves_valid_primary_ledger(tmp_path, dur_world):
    w = dur_world
    ledger = w.tmp / "ledger.json"
    w.claim(w.packet())  # healthy baseline

    # Fork a child that starts many saves and gets SIGKILLed mid-stream.
    def writer():
        for i in range(10000):
            d = json.loads(ledger.read_text()) if ledger.exists() else {}
            d[f"spin-{i}"] = {"state": "RESERVED"}
            hc.save_ledger(ledger, d)

    ctx = mp.get_context("fork")
    p = ctx.Process(target=writer)
    p.start()
    time.sleep(0.5)
    os.kill(p.pid, signal.SIGKILL)
    p.join(timeout=10)
    assert not p.is_alive()

    # The ledger is either the baseline or a complete newer write: always
    # valid JSON, never partial. SIGKILL cannot run userspace cleanup, so the
    # killed process may leave its private temp file; that file is not the
    # ledger and readers must ignore it.
    raw = ledger.read_text()
    data = json.loads(raw)  # raises if torn
    assert "_corrupt" not in data
    tmps = list(w.tmp.glob(".ledger.json.*.tmp"))
    assert {t.name for t in tmps} <= {f".ledger.json.{p.pid}.tmp"}, tmps
    # And the ledger still accepts new claims.
    v = hc.check(w.packet(idem="after-kill"), registry=w.registry,
                 ledger_path=ledger, workspace=w.tmp / "workspace")
    assert v["decision"] == "ACCEPT", v
