"""v0.3 trust layer: signatures, receiver policy (attenuation), evidence
pinning, fail-closed parsing, MCP server, A2A adapter."""
import copy
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc      # noqa: E402
import synthe_a2a as a2a        # noqa: E402
import synthe_crypto as sc      # noqa: E402
import synthe_mcp as mcp        # noqa: E402

V3 = ROOT / "examples" / "v03"
AT = dt.datetime(2026, 10, 1, 6, 0, tzinfo=dt.timezone.utc)


def reg():
    return json.loads((V3 / "registry.json").read_text())


def pkt(name):
    return json.loads((V3 / "packets" / f"{name}.json").read_text())


def run(packet, registry=None, **kw):
    info = {}
    ok, reasons = hc.validate(packet, registry=registry or reg(), ledger={},
                              workspace=V3 / "workspace", at=AT, info=info, **kw)
    return ok, {r["code"] for r in reasons}, info


# ---- crypto ---------------------------------------------------------------
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
     "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


def test_pure_python_ed25519_matches_rfc8032():
    for sk, pk, msg, sig in RFC8032:
        sk, pk, msg, sig = map(bytes.fromhex, (sk, pk, msg, sig))
        assert sc._py_public(sk) == pk
        assert sc._py_sign(sk, msg) == sig
        assert sc._py_verify(pk, msg, sig)
        assert not sc._py_verify(pk, msg + b"x", sig)


def test_canonical_json_is_order_and_float_stable():
    assert sc.canonical_json({"b": 2.0, "a": [1, "é"]}) == '{"a":[1,"é"],"b":2}'.encode()


# ---- example matrix --------------------------------------------------------
EXPECT = {
    "valid-signed": (True, set()),
    "attack-tampered-after-signing": (False, {"signature_invalid"}),
    "attack-spoofed-sender": (False, {"signature_invalid"}),
    "attack-self-granted-authority": (False, {"approval_missing"}),
    "attack-forged-approval": (False, {"approval_unsigned"}),
    "attack-replayed-approval": (False, {"approval_signature_invalid"}),
    "attack-exceeds-receiver-policy": (False, {"authority_exceeds_receiver_policy"}),
    "attack-paraphrased-verbatim": (False, {"evidence_hash_mismatch"}),
    "attack-undeclared-actions": (False, {"planned_actions_missing"}),
}


def test_example_matrix():
    for name, (want_ok, want_codes) in EXPECT.items():
        ok, codes, _ = run(pkt(name))
        assert ok == want_ok, (name, codes)
        assert want_codes <= codes, (name, codes)


def test_defaults_reported_and_do_not_break_signature():
    ok, _, info = run(pkt("valid-signed"))
    assert ok and info["signature"] == "verified"
    assert "acceptance.output_schema" in info["defaults_applied"]


def test_evidence_verification_without_workspace_fails_closed():
    info = {}
    ok, reasons = hc.validate(pkt("valid-signed"), registry=reg(), ledger={},
                              workspace=None, at=AT, info=info)
    assert not ok and "workspace_required" in {r["code"] for r in reasons}


def test_unsigned_packet_rejected_when_policy_requires_signatures():
    p = pkt("valid-signed")
    p.pop("signature")
    ok, codes, _ = run(p)
    assert not ok and "signature_missing" in codes


def test_untrusted_approver_blocked():
    r = reg()
    r["agents"]["caddy"]["policy"]["trusted_approvers"] = ["someone-else"]
    ok, codes, _ = run(pkt("valid-signed"), registry=r)
    assert not ok and "approver_not_trusted" in codes


def test_policy_merge_unions_restrictions_and_intersects_grants():
    r = {"policy": {"forbidden": ["delete"], "allowed_tools": ["a", "b"], "budget": {"usd": 5}},
         "agents": {"x": {"policy": {"forbidden": ["publish"], "allowed_tools": ["b", "c"],
                                     "budget": {"usd": 9, "tokens": 10}}}}}
    pol = hc.receiver_policy(r, "x")
    assert pol["forbidden"] == ["delete", "publish"]
    assert pol["allowed_tools"] == ["b"]
    assert pol["budget"] == {"usd": 5, "tokens": 10}


def test_defaults_never_fill_sender_facts():
    p = pkt("valid-signed")
    del p["handoff"]["inputs"]["artifact_refs"]
    r = reg()
    r["agents"]["caddy"]["policy"]["defaults"]["artifact_refs"] = [{"path": "input.txt"}]
    ok, codes, _ = run(p, registry=r)
    assert not ok and "missing_field:inputs.artifact_refs" in codes


# ---- fail-closed hardening (apply with or without policy) -----------------
def legacy():
    return json.loads((ROOT / "examples" / "valid.json").read_text())


def legacy_run(p):
    reg0 = json.loads((ROOT / "examples" / "registry.json").read_text())
    ok, reasons = hc.validate(p, registry=reg0, ledger={}, workspace=ROOT, at=AT)
    return ok, {r["code"] for r in reasons}


def test_path_traversal_and_absolute_paths_rejected():
    for bad in ("../../../etc/hostname", "/etc/hostname", "~/x"):
        p = legacy()
        p["handoff"]["inputs"]["artifact_refs"] = [{"path": bad}]
        ok, codes = legacy_run(p)
        assert not ok and "artifact_path_escapes_workspace" in codes, bad


def test_naive_timestamp_is_invalid_not_a_crash():
    p = legacy()
    p["handoff"]["acceptance"]["expires_at"] = "2999-01-01T00:00:00"
    ok, codes = legacy_run(p)
    assert not ok and "bad_expires_at" in codes


def test_malformed_action_is_invalid_not_a_crash():
    p = legacy()
    p["handoff"]["planned_actions"] = [{"name": "x"}]
    ok, codes = legacy_run(p)
    assert not ok and "malformed:planned_actions[0]" in codes


def test_abbreviated_hash_rejected_explicitly():
    p = legacy()
    p["handoff"]["inputs"]["artifact_refs"][0]["sha256"] = "3cfde1592d02"
    ok, codes = legacy_run(p)
    assert not ok and "bad_sha256:inputs.artifact_refs[0]" in codes


def test_non_object_packet_is_rejected():
    assert hc.check([1, 2], registry=None, ledger_path=None, workspace=None)["decision"] == "REJECT"


# ---- CLI round trip ---------------------------------------------------------
def test_cli_keygen_approve_sign_verify(tmp_path):
    py, src = sys.executable, ROOT / "src"
    for who in ("cora", "rohan"):
        out = subprocess.run([py, src / "synthe_sign.py", "keygen", "--agent", who,
                              "--out", tmp_path / f"{who}.json"], capture_output=True, text=True)
        assert out.returncode == 0
        entry = json.loads(out.stdout)
        r = reg()
        r["agents"][who]["keys"] = [entry]
        (tmp_path / "reg.json").write_text(json.dumps(r))
    r = reg()
    for who in ("cora", "rohan"):
        k = json.loads((tmp_path / f"{who}.json").read_text())
        r["agents"][who]["keys"] = [{"kid": k["kid"], "alg": "Ed25519", "public_key": sc.b64u(
            sc.public_key(sc.unb64u(k["private_key"])))}]
    (tmp_path / "reg.json").write_text(json.dumps(r))
    p = pkt("valid-signed")
    p.pop("signature")
    p["handoff"]["authority"]["approvals"] = []
    (tmp_path / "p.json").write_text(json.dumps(p))
    subprocess.run([py, src / "synthe_sign.py", "approve", tmp_path / "p.json", "--key", tmp_path / "rohan.json",
                    "--action", "send_email", "--out", tmp_path / "p.json"], check=True)
    subprocess.run([py, src / "synthe_sign.py", "sign", tmp_path / "p.json", "--key", tmp_path / "cora.json",
                    "--out", tmp_path / "p.json"], check=True)
    v = subprocess.run([py, src / "synthe_sign.py", "verify", tmp_path / "p.json", "--registry",
                        tmp_path / "reg.json"], capture_output=True, text=True)
    assert v.returncode == 0, v.stdout
    res = subprocess.run([py, src / "handoff_check.py", tmp_path / "p.json", "--registry", tmp_path / "reg.json",
                          "--workspace", V3 / "workspace", "--dry-run"], capture_output=True, text=True)
    assert json.loads(res.stdout)["decision"] == "ACCEPT", res.stdout


# ---- MCP + A2A ---------------------------------------------------------------
def test_mcp_server_validate_claim_and_complete(tmp_path):
    srv = mcp.SyntheServer(str(V3 / "registry.json"), tmp_path / "ledger.json", V3 / "workspace")
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "0"}}})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    names = [t["name"] for t in srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
    assert "synthe_validate_handoff" in names

    def call(name, args, i):
        return srv.handle({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                           "params": {"name": name, "arguments": args}})["result"]["structuredContent"]
    p = pkt("valid-signed")
    accepted = call("synthe_validate_handoff", {"packet": p}, 3)
    assert accepted["decision"] == "ACCEPT" and accepted["claim"]["epoch"] == 1
    assert call("synthe_validate_handoff", {"packet": p}, 4)["state"] == "duplicate"
    # holding the packet is not enough on a shared endpoint (the sender has it too)
    no_token = call("synthe_complete_handoff", {"packet": p}, 5)
    assert no_token["reasons"][0]["code"] == "claim_token_required"
    wrong = call("synthe_complete_handoff", {"packet": p, "claim_token": "guess"}, 5)
    assert wrong["reasons"][0]["code"] == "claim_token_invalid"
    token = accepted["claim"]["token"]
    assert call("synthe_complete_handoff", {"packet": p, "claim_token": token}, 5)["decision"] == "COMPLETED"
    assert srv.handle({"jsonrpc": "2.0", "id": 6, "method": "nope"})["error"]["code"] == -32601


def test_a2a_round_trip_and_state_mapping():
    kw = dict(registry=reg(), ledger_path=None, workspace=V3 / "workspace", dry_run=True)
    assert a2a.check_message(a2a.to_message(pkt("valid-signed")), **kw)["state"] == "TASK_STATE_SUBMITTED"
    assert a2a.check_message(a2a.to_message(pkt("attack-forged-approval")), **kw)["state"] == "TASK_STATE_INPUT_REQUIRED"
    assert a2a.check_message(a2a.to_message(pkt("attack-spoofed-sender")), **kw)["state"] == "TASK_STATE_REJECTED"
    m = a2a.to_message(pkt("valid-signed"))
    m["messageId"] = "something-else"
    assert a2a.check_message(m, **kw)["state"] == "TASK_STATE_REJECTED"
