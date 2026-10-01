"""Conformance tests for the v0.2 idempotency claim state machine.

Motivated by a real external review (crewAIInc/crewAI#5802): the v0.1
claim-on-accept ledger collapsed RESERVED and effect-completed. These tests
pin the fixed semantics end-to-end through the CLI:

  (a) completed-effect retry            -> REJECT duplicate
  (b) crash-before-complete, within TTL -> REJECT duplicate (still claimed)
  (c) crash-before-complete, past TTL   -> REJECT unknown
  (d) concurrent presentations          -> exactly one ACCEPT

Plus unit-level checks that pre-v0.2 ledger entries count as COMPLETED.
"""
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from threading import Thread

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import handoff_check as hc

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "src" / "handoff_check.py"
REGISTRY = ROOT / "examples" / "registry.json"
KEY = "cadros:verdict-pack:m1-os-pl:rev-7"  # idempotency key of examples/valid.json
AT = dt.datetime(2026, 9, 30, 20, 0, tzinfo=dt.timezone.utc)


def base_packet():
    return json.loads((ROOT / "examples" / "valid.json").read_text())


def invoke(packet_path: Path, ledger_path: Path, *extra: str):
    cmd = [sys.executable, str(CHECKER), str(packet_path),
           "--registry", str(REGISTRY), "--workspace", str(ROOT),
           "--ledger", str(ledger_path), *extra]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.returncode, json.loads(r.stdout)


def write_packet(tmp_path: Path, packet: dict) -> Path:
    p = tmp_path / "packet.json"
    p.write_text(json.dumps(packet))
    return p


def accept_and_claim(tmp_path: Path):
    """ACCEPT the valid packet; return (packet_path, ledger_path)."""
    pkt = write_packet(tmp_path, base_packet())
    ledger = tmp_path / "ledger.json"
    code, out = invoke(pkt, ledger)
    assert code == 0 and out["decision"] == "ACCEPT", out
    entry = json.loads(ledger.read_text())[KEY]
    assert entry["state"] == "RESERVED" and "reserved_at" in entry
    return pkt, ledger


def test_completed_effect_retry_rejected_duplicate(tmp_path):
    pkt, ledger = accept_and_claim(tmp_path)
    code, out = invoke(pkt, ledger, "--complete")
    assert code == 0 and out["decision"] == "COMPLETED", out
    entry = json.loads(ledger.read_text())[KEY]
    assert entry["state"] == "COMPLETED" and "completed_at" in entry

    code, out = invoke(pkt, ledger)
    assert code == 2 and out["decision"] == "REJECT"
    assert out["state"] == "duplicate"
    assert "already completed" in out["reasons"][0]["message"]


def test_complete_is_idempotent(tmp_path):
    pkt, ledger = accept_and_claim(tmp_path)
    assert invoke(pkt, ledger, "--complete")[0] == 0
    code, out = invoke(pkt, ledger, "--complete")
    assert code == 0 and out["decision"] == "COMPLETED"


def test_crash_before_complete_within_ttl_rejected_duplicate(tmp_path):
    pkt, ledger = accept_and_claim(tmp_path)
    code, out = invoke(pkt, ledger)
    assert code == 2 and out["state"] == "duplicate"
    msg = out["reasons"][0]["message"]
    assert "claimed by handoff h-0001" in msg and "reconcile before redispatch" in msg
    assert out["reasons"][0]["code"] == "idempotency_key_reserved"


def test_crash_before_complete_past_ttl_rejected_unknown(tmp_path):
    pkt, ledger = accept_and_claim(tmp_path)
    # Age the claim beyond the TTL, as if the receiver crashed long ago.
    data = json.loads(ledger.read_text())
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=72)
    data[KEY]["reserved_at"] = old.isoformat()
    ledger.write_text(json.dumps(data))

    code, out = invoke(pkt, ledger, "--reserve-ttl-hours", "24")
    assert code == 2 and out["state"] == "unknown"
    assert out["reasons"][0]["code"] == "unknown_outcome"
    assert "effect receipt" in out["reasons"][0]["message"]


def test_concurrent_presentations_exactly_one_accept(tmp_path):
    pkt = write_packet(tmp_path, base_packet())
    ledger = tmp_path / "ledger.json"
    results: list = []

    def worker():
        results.append(invoke(pkt, ledger))

    threads = [Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = sorted(c for c, _ in results)
    assert codes.count(0) == 1, results
    assert codes.count(2) == len(results) - 1
    for code, out in results:
        if code == 2:
            assert out["state"] in {"duplicate", "conflicting"}


def run_validate(ledger, packet=None):
    return hc.validate(packet or base_packet(),
                       registry=json.loads(REGISTRY.read_text()),
                       ledger=ledger, workspace=ROOT, at=AT)


def test_legacy_ledger_entry_counts_as_completed():
    ledger = {KEY: {"handoff_id": "h-0001", "trace_id": "trace-cadros-2026-09-30-001"}}
    ok, reasons = run_validate(ledger)
    assert not ok
    assert reasons[0]["state"] == "duplicate"
    assert "already completed" in reasons[0]["message"]


def test_reserved_state_transitions_by_age():
    reserved_at = (AT - dt.timedelta(hours=1)).isoformat()
    ledger = {KEY: {"state": "RESERVED", "handoff_id": "h-0001",
                    "trace_id": "trace-cadros-2026-09-30-001",
                    "reserved_at": reserved_at}}
    ok, reasons = run_validate(ledger)
    assert not ok and reasons[0]["state"] == "duplicate"

    ok, reasons = hc.validate(base_packet(),
                              registry=json.loads(REGISTRY.read_text()),
                              ledger=ledger, workspace=ROOT, at=AT,
                              reserve_ttl_hours=0.5)
    assert not ok and reasons[0]["state"] == "unknown"
    assert reasons[0]["code"] == "unknown_outcome"
