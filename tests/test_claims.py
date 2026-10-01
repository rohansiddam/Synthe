"""Claim binding, release and fenced effects: the fixes for two claim-ledger
bugs (anyone holding a packet could complete someone else's claim; a slow
receiver could act twice after release and redispatch). Each failing
sequence is replayed here against the real checker."""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc  # noqa: E402

V3 = ROOT / "examples" / "v03"


def claim(ledger):
    packet = json.loads((V3 / "packets" / "valid-signed.json").read_text())
    reg = json.loads((V3 / "registry.json").read_text())
    verdict = hc.check(packet, registry=reg, ledger_path=ledger, workspace=V3 / "workspace")
    assert verdict["decision"] == "ACCEPT", verdict
    return packet, reg, verdict


def age_claim(ledger, hours=48):
    data = json.loads(ledger.read_text())
    for entry in data.values():
        entry["reserved_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).isoformat()
    ledger.write_text(json.dumps(data))


def test_accept_returns_bound_claim(tmp_path):
    ledger = tmp_path / "ledger.json"
    packet, _, verdict = claim(ledger)
    entry = json.loads(ledger.read_text())[packet["handoff"]["idempotency_key"]]
    assert verdict["claim"]["epoch"] == entry["epoch"] == 1
    assert entry["packet_sha256"] == hc.handoff_digest(packet["handoff"])
    assert verdict["claim"]["token"] not in ledger.read_text()  # only its hash is stored


def test_trace_v03_forged_completion_is_refused(tmp_path):
    """Receiver r2 claims; r1, which also saw the packet, tries to complete it."""
    ledger = tmp_path / "ledger.json"
    packet, _, verdict = claim(ledger)
    h = packet["handoff"]
    forged = {"handoff": {"idempotency_key": h["idempotency_key"], "id": h["id"], "to": "mallory"}}
    out = hc.complete(forged, ledger)
    assert out["decision"] == "REJECT" and out["reasons"][0]["code"] == "completion_packet_mismatch"
    assert hc.complete(packet, ledger, claim_token="guess")["reasons"][0]["code"] == "claim_token_invalid"
    assert hc.complete(packet, ledger, require_token=True)["reasons"][0]["code"] == "claim_token_required"
    assert hc.complete(packet, ledger, claim_token=verdict["claim"]["token"])["decision"] == "COMPLETED"


def test_trace_ttl_reclaim_zombie_cannot_act_twice(tmp_path):
    """Claim(r1) -> TTL expires -> release -> r1 acts late -> Claim(r2) ->
    r2 acts: without fencing that is two effects. With fenced() the stale
    holder is refused, so the effect happens exactly once."""
    ledger = tmp_path / "ledger.json"
    effects = []
    packet, reg, first = claim(ledger)                        # Claim(r1)
    assert hc.release(packet, ledger)["reasons"][0]["code"] == "release_claim_fresh"
    age_claim(ledger)                                         # Expire
    released = hc.release(packet, ledger)                     # Reconcile (no effect on record)
    assert released["decision"] == "RELEASED"
    with pytest.raises(hc.FenceError) as stale:               # Effect(r1): zombie wakes up
        with hc.fenced(packet, ledger, first["claim"]["token"]):
            effects.append("r1")
    assert stale.value.verdict["reasons"][0]["code"] == "completion_unknown_key"
    second = hc.check(packet, registry=reg, ledger_path=ledger, workspace=V3 / "workspace")
    assert second["decision"] == "ACCEPT" and second["claim"]["epoch"] == 2  # Claim(r2)
    with pytest.raises(hc.FenceError) as old_token:           # zombie retries on the new claim
        with hc.fenced(packet, ledger, first["claim"]["token"]):
            effects.append("r1-again")
    assert old_token.value.verdict["reasons"][0]["code"] == "claim_token_invalid"
    with hc.fenced(packet, ledger, second["claim"]["token"]) as epoch:  # Effect(r2)
        effects.append("r2")
        assert epoch == 2
    assert effects == ["r2"]
    entry = json.loads(ledger.read_text())[packet["handoff"]["idempotency_key"]]
    assert entry["state"] == "COMPLETED"
    with pytest.raises(hc.FenceError):                        # and never again
        with hc.fenced(packet, ledger, second["claim"]["token"]):
            effects.append("r2-again")
    assert effects == ["r2"]


def test_failed_effect_leaves_claim_reserved(tmp_path):
    ledger = tmp_path / "ledger.json"
    packet, _, verdict = claim(ledger)
    with pytest.raises(RuntimeError):
        with hc.fenced(packet, ledger, verdict["claim"]["token"]):
            raise RuntimeError("smtp down")
    entry = json.loads(ledger.read_text())[packet["handoff"]["idempotency_key"]]
    assert entry["state"] == "RESERVED"  # outcome unknown: reconcile, don't assume


def test_release_cli_and_legacy_entries(tmp_path):
    ledger = tmp_path / "ledger.json"
    packet, _, _ = claim(ledger)
    pfile = tmp_path / "p.json"
    pfile.write_text(json.dumps(packet))
    assert hc.main([str(pfile), "--ledger", str(ledger), "--release"]) == 2      # fresh
    assert hc.main([str(pfile), "--ledger", str(ledger), "--release", "--force"]) == 0
    # a v0.2 entry (no digest, no token) still completes by key + id
    key = packet["handoff"]["idempotency_key"]
    ledger.write_text(json.dumps({key: {"state": "RESERVED", "handoff_id": packet["handoff"]["id"],
                                        "reserved_at": dt.datetime.now(dt.timezone.utc).isoformat()}}))
    assert hc.complete(packet, ledger)["decision"] == "COMPLETED"


def test_action_log_never_prints_the_claim_token(tmp_path):
    """Action logs can be public. run_check.sh must blank claim.token while
    keeping the verdict, the exit code and the reject summary intact."""
    import os
    import subprocess
    ledger = tmp_path / "ledger.json"
    env = {**os.environ, "HANDOFF_PACKET": str(V3 / "packets" / "valid-signed.json"),
           "HANDOFF_REGISTRY": str(V3 / "registry.json"), "HANDOFF_LEDGER": str(ledger),
           "HANDOFF_WORKSPACE": str(V3 / "workspace")}
    script = ROOT / "github-action" / "checker" / "run_check.sh"
    out = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    printed = json.loads(out.stdout.split("\nHandoff ACCEPTED")[0])
    assert printed["decision"] == "ACCEPT"
    assert printed["claim"] == {"epoch": 1, "token": "<redacted>"}
    # the claim itself is still recorded, and completion (as the Action does it) still works
    assert json.loads(ledger.read_text())["cadros:verdict-pack:m1:rev-7"]["claim_token_sha256"]
    packet = json.loads((V3 / "packets" / "valid-signed.json").read_text())
    assert hc.complete(packet, ledger)["decision"] == "COMPLETED"
    # a replay is still a clean REJECT with its reasons in the log
    again = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    assert again.returncode == 1 and "duplicate" in again.stdout and "<redacted>" not in again.stdout
