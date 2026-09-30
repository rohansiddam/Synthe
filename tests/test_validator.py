"""Tests for the Handoff Contract v0.1 validator.

Scenarios mirror real Cadros failure classes: paraphrased 'verbatim' quotes,
aliased/unknown agents, stale artifacts, missing artifacts, expired handoffs,
forbidden actions without approval, budget overruns, duplicate executions.
"""
import copy
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import handoff_check as hc

ROOT = Path(__file__).resolve().parents[1]
AT = dt.datetime(2026, 9, 30, 20, 0, tzinfo=dt.timezone.utc)


def base_packet():
    return json.loads((ROOT / "examples" / "valid.json").read_text())


def registry():
    return json.loads((ROOT / "examples" / "registry.json").read_text())


def run(packet, ledger=None):
    ok, reasons = hc.validate(packet, registry=registry(), ledger=ledger or {},
                              workspace=ROOT, at=AT)
    return ok, {r["code"] for r in reasons}


def test_valid_packet_accepted():
    ok, codes = run(base_packet())
    assert ok and codes == set()


def test_paraphrase_quote_rejected():  # Cadros: 7 condensed quotes passed as code text
    p = base_packet()
    p["handoff"]["acceptance"]["evidence"][0]["verbatim"] = False
    ok, codes = run(p)
    assert not ok and "evidence_not_verbatim" in codes


def test_alias_sender_rejected():  # Cadros: 'LeBron crown' alias vs canonical id
    p = base_packet()
    p["handoff"]["from"] = "lebron-crown"
    ok, codes = run(p)
    assert not ok and "alias_not_canonical:from" in codes


def test_unknown_agent_rejected():
    p = base_packet()
    p["handoff"]["to"] = "mystery-agent"
    ok, codes = run(p)
    assert not ok and "unknown_agent:to" in codes


def test_missing_artifact_rejected():  # Cadros: use_allowance.py claimed, file absent
    p = base_packet()
    p["handoff"]["inputs"]["artifact_refs"][0]["path"] = "examples/does-not-exist.txt"
    ok, codes = run(p)
    assert not ok and "artifact_missing" in codes


def test_stale_artifact_rejected():  # Cadros: 19-vs-51 stale count
    p = base_packet()
    p["handoff"]["inputs"]["artifact_refs"][0]["sha256"] = "0" * 64
    ok, codes = run(p)
    assert not ok and "artifact_hash_mismatch" in codes


def test_expired_handoff_rejected():
    p = base_packet()
    p["handoff"]["acceptance"]["expires_at"] = "2026-09-01T00:00:00Z"
    ok, codes = run(p)
    assert not ok and "handoff_expired" in codes


def test_forbidden_action_blocked():  # Cadros: duplicate draft sends without approval
    p = base_packet()
    p["handoff"]["planned_actions"].append(
        {"name": "send_email", "tool": "gmail_send",
         "est_tokens": 10, "est_usd": 0.01, "est_minutes": 1})
    ok, codes = run(p)
    assert not ok and {"forbidden_action", "approval_missing", "tool_not_allowed"} & codes


def test_approval_expired_blocked():
    p = base_packet()
    h = p["handoff"]
    h["scope"]["forbidden"] = []
    h["authority"]["allowed_tools"].append("gmail_send")
    h["authority"]["approvals"] = [
        {"action": "send_email", "approver": "rohan", "expires_at": "2026-01-01T00:00:00Z"}]
    h["planned_actions"].append(
        {"name": "send_email", "tool": "gmail_send",
         "est_tokens": 10, "est_usd": 0.01, "est_minutes": 1})
    ok, codes = run(p)
    assert not ok and "approval_expired" in codes


def test_budget_exceeded_blocked():
    p = base_packet()
    p["handoff"]["planned_actions"][0]["est_tokens"] = 10_000_000
    ok, codes = run(p)
    assert not ok and "budget_exceeded" in codes


def test_missing_evidence_rejected():  # Cadros: 'done' claims without proof
    p = base_packet()
    p["handoff"]["acceptance"]["evidence"] = [{"kind": "verbatim_quote", "verbatim": True}]
    ok, codes = run(p)
    assert not ok and "evidence_missing" in codes


def test_duplicate_idempotency_rejected():  # Cadros: 9 duplicate Gmail drafts
    ledger = {"cadros:verdict-pack:m1-os-pl:rev-7": {
        "handoff_id": "h-0001", "trace_id": "trace-cadros-2026-09-30-001"}}
    ok, codes = run(base_packet(), ledger=ledger)
    assert not ok and "duplicate_idempotency_key" in codes


def test_conflicting_idempotency_rejected():
    ledger = {"cadros:verdict-pack:m1-os-pl:rev-7": {
        "handoff_id": "h-other", "trace_id": "trace-other"}}
    ok, codes = run(base_packet(), ledger=ledger)
    assert not ok and "duplicate_idempotency_key" in codes


def test_missing_field_rejected():
    p = base_packet()
    del p["handoff"]["inputs"]["state_revision"]
    ok, codes = run(p)
    assert not ok and "missing_field:inputs.state_revision" in codes
