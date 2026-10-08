"""Stored-result replay: exact completed effects replay; everything else fails closed."""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

from world import World

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_commit as cm  # noqa: E402
import synthe_crypto as sc  # noqa: E402
import synthe_mcp as mcp  # noqa: E402
import synthe_sign as ss  # noqa: E402


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def call(server, name, args, mid=1):
    response = server.handle({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                              "params": {"name": name, "arguments": args}})
    return response["result"]["structuredContent"]


def server(w):
    return mcp.SyntheServer(str(w.tmp / "registry.json"), w.tmp / "ledger.json",
                            w.tmp / "workspace", broker_config=str(w.config_path))


def proposal(w, packet, token, commit):
    return {"packet": packet, "claim_token": token, "action": "push_branch",
            "params": {"remote": "origin", "branch": "feature/x", "commit": commit},
            "source": str(w.agent)}


def claimed(server, packet):
    out = call(server, "synthe_validate_handoff", {"packet": packet})
    assert out["decision"] == "ACCEPT", out
    return out["claim"]["token"]


def codes(result):
    return {reason["code"] for reason in result.get("reasons", [])}


def test_mcp_replay_returns_identical_result_without_reexecuting(w, monkeypatch):
    srv = server(w)
    packet = w.packet()
    token = claimed(srv, packet)
    commit = w.commit({"src/app.py": "replay once\n"})
    effects = 0
    real = cm.GitPush.commit

    def counted(self, prepared, scope, dry_run=False):
        nonlocal effects
        if not dry_run:
            effects += 1
        return real(self, prepared, scope, dry_run=dry_run)

    monkeypatch.setattr(cm.GitPush, "commit", counted)
    args = proposal(w, packet, token, commit)
    first = call(srv, "synthe_propose_effect", args, 2)
    replay = call(srv, "synthe_propose_effect", args, 3)

    assert first["decision"] == "executed"
    assert replay == first
    assert effects == 1
    assert w.remote_ref("feature/x") == commit
    assert w.chain()["count"] == 1  # replay is the stored receipt, not a new receipt or write


def test_changed_effect_under_same_identity_conflicts_without_reexecuting(w, monkeypatch):
    srv = server(w)
    packet = w.packet()
    token = claimed(srv, packet)
    first_commit = w.commit({"src/app.py": "first\n"})
    effects = 0
    real = cm.GitPush.commit

    def counted(self, prepared, scope, dry_run=False):
        nonlocal effects
        if not dry_run:
            effects += 1
        return real(self, prepared, scope, dry_run=dry_run)

    monkeypatch.setattr(cm.GitPush, "commit", counted)
    assert call(srv, "synthe_propose_effect", proposal(w, packet, token, first_commit), 2)["decision"] == "executed"
    changed_commit = w.commit({"src/app.py": "changed\n"})
    conflict = call(srv, "synthe_propose_effect", proposal(w, packet, token, changed_commit), 3)

    assert conflict["decision"] == "denied"
    assert "effect_fingerprint_mismatch" in codes(conflict)
    assert conflict["reasons"][0]["state"] == "conflicting"
    assert effects == 1
    assert w.remote_ref("feature/x") == first_commit


def test_never_completed_duplicate_stays_unknown_and_requires_reconciliation(w):
    srv = server(w)
    packet = w.packet()
    claimed(srv, packet)
    ledger = w.ledger()
    entry = ledger[packet["handoff"]["idempotency_key"]]
    entry["reserved_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=48)).isoformat()
    (w.tmp / "ledger.json").write_text(json.dumps(ledger))

    retry = call(srv, "synthe_validate_handoff", {"packet": packet}, 2)
    assert retry["decision"] == "REJECT"
    assert retry["state"] == "unknown"
    assert codes(retry) == {"unknown_outcome"}
    assert w.remote_ref("feature/x") is None


def test_replay_requires_the_exact_verified_receipt(w, monkeypatch):
    srv = server(w)
    packet = w.packet()
    token = claimed(srv, packet)
    commit = w.commit({"src/app.py": "strict receipt\n"})
    effects = 0
    real = cm.GitPush.commit

    def counted(self, prepared, scope, dry_run=False):
        nonlocal effects
        if not dry_run:
            effects += 1
        return real(self, prepared, scope, dry_run=dry_run)

    monkeypatch.setattr(cm.GitPush, "commit", counted)
    args = proposal(w, packet, token, commit)
    assert call(srv, "synthe_propose_effect", args, 2)["decision"] == "executed"

    ledger = w.ledger()
    effect = ledger[packet["handoff"]["idempotency_key"]]["effects"]["push_branch"]
    effect["receipt_seq"] += 1  # a valid result exists, but this pointer does not name it exactly
    (w.tmp / "ledger.json").write_text(json.dumps(ledger))
    refused = call(srv, "synthe_propose_effect", args, 3)

    assert refused["decision"] == "denied"
    assert codes(refused) == {"replay_receipt_mismatch"}
    assert refused["reasons"][0]["state"] == "unknown"
    assert effects == 1
    assert w.remote_ref("feature/x") == commit


def test_replay_rejects_a_valid_receipt_for_another_identity(w, monkeypatch):
    srv = server(w)
    packet = w.packet()
    token = claimed(srv, packet)
    commit = w.commit({"src/app.py": "identity bound\n"})
    effects = 0
    real = cm.GitPush.commit

    def counted(self, prepared, scope, dry_run=False):
        nonlocal effects
        if not dry_run:
            effects += 1
        return real(self, prepared, scope, dry_run=dry_run)

    monkeypatch.setattr(cm.GitPush, "commit", counted)
    args = proposal(w, packet, token, commit)
    original = call(srv, "synthe_propose_effect", args, 2)
    forged = {k: v for k, v in original.items() if k not in {"seq", "prev", "broker", "kid", "sig"}}
    forged = json.loads(json.dumps(forged))
    forged["handoff"]["idempotency_key"] = "some-other-logical-operation"
    key = ss.load_key(str(w.cfg.key_path))
    other = cm.append_receipt(w.cfg, key, forged)  # cryptographically valid, semantically wrong

    ledger = w.ledger()
    ledger[packet["handoff"]["idempotency_key"]]["effects"]["push_branch"]["receipt_seq"] = other["seq"]
    (w.tmp / "ledger.json").write_text(json.dumps(ledger))
    refused = call(srv, "synthe_propose_effect", args, 3)

    assert refused["decision"] == "denied"
    assert codes(refused) == {"replay_receipt_mismatch"}
    assert effects == 1
    assert w.remote_ref("feature/x") == commit


def test_replay_refuses_a_matching_receipt_signed_by_another_registered_agent(w, monkeypatch):
    srv = server(w)
    packet = w.packet()
    token = claimed(srv, packet)
    commit = w.commit({"src/app.py": "issuer bound\n"})
    args = proposal(w, packet, token, commit)
    original = call(srv, "synthe_propose_effect", args, 2)
    assert original["decision"] == "executed"
    forged = {k: v for k, v in original.items() if k not in {"seq", "prev", "broker", "kid", "sig"}}
    other = cm.append_receipt(w.cfg, w.keys["mallory"], forged)
    # Every semantic field matches, but the signature belongs to a registered non-broker key.
    assert other["broker"] == "mallory"
    ledger = w.ledger()
    ledger[packet["handoff"]["idempotency_key"]]["effects"]["push_branch"]["receipt_seq"] = other["seq"]
    (w.tmp / "ledger.json").write_text(json.dumps(ledger))
    monkeypatch.setattr(cm.GitPush, "commit", lambda *a, **k: pytest.fail("re-executed completed effect"))
    refused = call(srv, "synthe_propose_effect", args, 3)
    assert refused["decision"] == "denied"
    assert codes(refused) == {"replay_receipt_unverified"}
    assert w.remote_ref("feature/x") == commit


def test_fingerprint_preserves_proto_named_effect_inputs():
    """A JavaScript object-prototype trap must not collapse distinct effects."""
    common = {"remote": "origin", "branch": "feature/x", "commit": "0" * 40}
    left = cm.effect_fingerprint(
        "push_branch", "git_push", {**common, "__proto__": {"target": "A"}})
    right = cm.effect_fingerprint(
        "push_branch", "git_push", {**common, "__proto__": {"target": "B"}})
    assert left != right


def test_canonical_json_sorts_numeric_looking_keys_lexically():
    """Integer-looking object keys follow canonical string order, not JS enumeration order."""
    assert sc.canonical_json({"2": "b", "10": "a"}) == b'{"10":"a","2":"b"}'
