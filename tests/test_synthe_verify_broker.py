"""synthe-verify on receipts the real broker wrote, and the broker's own `receipts verify` pinned
to its signer. Private (uses the broker); the standalone tests are tests/test_synthe_verify.py."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import synthe_commit as cm   # noqa: E402
import synthe_crypto as sc   # noqa: E402
import synthe_verify as sv   # noqa: E402
from world import World, git  # noqa: E402


def _real_chain(w):
    """One executed push, one denied push, one test receipt: what a broker really writes."""
    p = w.packet()
    token = w.claim(p)
    bad = w.commit({"README.md": "# changed\n"})
    assert w.propose(p, token, bad)["decision"] == "denied"
    git(w.agent, "reset", "-q", "--hard", "HEAD~1")
    good = w.commit({"src/app.py": "print('v2')\n"})
    assert w.propose(p, token, good)["decision"] == "executed"
    return w.cfg.receipts_path.read_bytes()


def _trust(w, signer="synthe-broker"):
    return sv.load_trust(json.loads((w.tmp / "registry.json").read_text()), signer)


def test_verifies_real_broker_receipts_and_agrees_with_the_broker(tmp_path):
    w = World(tmp_path)
    data = _real_chain(w)
    rep = sv.verify(data, _trust(w))
    mine = cm.verify_receipts(w.cfg.receipts_path, w.registry, w.cfg.broker_id)
    assert rep["ok"] is mine["ok"] is True
    assert (rep["count"], rep["head"]) == (mine["count"], mine["head"]) == (2, mine["head"])
    assert rep["decisions"] == {"denied": 1, "executed": 1}


def test_published_key_form_matches_registry_form(tmp_path):
    w = World(tmp_path)
    data = _real_chain(w)
    entry = w.registry["agents"]["synthe-broker"]["keys"][0]
    pub = {"broker": "synthe-broker", **{k: entry[k] for k in ("kid", "alg", "public_key")}}
    assert sv.verify(data, sv.load_trust(pub)) == sv.verify(data, _trust(w))


def test_every_tampering_is_caught_by_both_verifiers(tmp_path):
    w = World(tmp_path)
    lines = _real_chain(w).splitlines(keepends=True)
    first, second = (json.loads(x) for x in lines)
    edited = {**second, "decision": "denied"}
    tampered = {
        "edit": lines[0] + json.dumps(edited, sort_keys=True).encode() + b"\n",
        "delete": lines[1],
        "reorder": lines[1] + lines[0],
        "drop_sig": lines[0] + json.dumps({k: v for k, v in second.items() if k != "sig"}).encode() + b"\n",
        "garbage": lines[0] + b"{garbage\n",
    }
    for name, data in tampered.items():
        w.cfg.receipts_path.write_bytes(data)
        assert sv.verify(data, _trust(w))["ok"] is False, name
        assert cm.verify_receipts(w.cfg.receipts_path, w.registry, w.cfg.broker_id)["ok"] is False, name
    assert first["seq"] == 1


def _forge_as(w, agent):
    """An agent with its own registered key writes a whole chain, signed as itself."""
    key = w.keys[agent]
    w.cfg.receipts_path.unlink(missing_ok=True)
    cm._receipt_tip_path(w.cfg.receipts_path).unlink(missing_ok=True)
    return cm.append_receipt(w.cfg, key, {"v": 1, "kind": "effect", "decision": "executed",
                                          "time": "2026-10-07T00:00:00+00:00", "reasons": []})


def test_chain_signed_by_another_registered_agent_is_refused(tmp_path):
    w = World(tmp_path)
    forged = _forge_as(w, "mallory")
    assert forged["broker"] == "mallory" and sc.find_key(w.registry, "mallory", forged["kid"])
    # The gap this closes: with the signer taken from the receipt itself, this verified.
    assert cm.verify_receipts(w.cfg.receipts_path, w.registry)["ok"] is True
    assert cm.verify_receipts(w.cfg.receipts_path, w.registry, w.cfg.broker_id)["ok"] is False
    assert w.chain()["ok"] is False
    assert sv.verify(w.cfg.receipts_path.read_bytes(), _trust(w))["errors"][0]["code"] == "signer_untrusted"


def test_receipts_cli_and_console_pin_the_broker(tmp_path, capsys):
    w = World(tmp_path)
    _forge_as(w, "mallory")
    assert cm.main(["receipts", "verify", "--config", str(w.cfg.path)]) == 2
    assert "not by this broker" in capsys.readouterr().out
    assert cm.console_state(w.cfg)["chain"]["ok"] is False
