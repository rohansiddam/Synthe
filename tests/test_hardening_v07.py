"""Hardening found by the round-2 benchmark scenarios (research-implementation/DEEP-DIVE.md):

- A1 strict parsing: a duplicate JSON key (S14) is refused as duplicate_field:<key>; NaN, Infinity
  and numbers that overflow (S13) are refused as malformed:non_finite_number, never a crash.
- A2 kid required: with more than one key on record, a signature (S05) or an approval must name
  its kid, or an old rotated-out key could still be picked.
- A3 receiver binding: an endpoint that knows its authenticated agent identity rejects a valid
  packet addressed to a different receiver (S07).
- A5 max TTL: a receiver policy max_ttl_hours refuses long-lived handoffs (S22) as ttl_exceeded.

tests/test_hardening_v07_mutations.py removes each guard in a copy and checks this file catches it.
"""
import copy
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import handoff_check as hc      # noqa: E402
import synthe_crypto as sc      # noqa: E402
import synthe_mcp as mcp        # noqa: E402

V3 = ROOT / "examples" / "v03"
AT = dt.datetime(2026, 10, 1, 6, 0, tzinfo=dt.timezone.utc)
UTC = dt.timezone.utc


def reg():
    return json.loads((V3 / "registry.json").read_text())


def pkt(name="valid-signed"):
    return json.loads((V3 / "packets" / f"{name}.json").read_text())


def key(agent):
    k = json.loads((V3 / "test-keys" / f"{agent}.key.json").read_text())
    k["_secret"] = sc.unb64u(k["private_key"])
    return k


def new_key(agent, kid):
    secret = sc.generate_secret()
    return {"agent": agent, "kid": kid, "_secret": secret,
            "entry": {"kid": kid, "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}}


def sign(packet, k, with_kid=True):
    h = packet["handoff"]
    packet["signature"] = {"signer": k["agent"], "alg": sc.ALG,
                           "sig": sc.b64u(sc.sign_bytes(k["_secret"], sc.packet_signing_input(h)))}
    if with_kid:
        packet["signature"]["kid"] = k["kid"]
    return packet


def approve(packet, k, action="send_email", with_kid=True):
    """Replace the packet's approvals with one signed by k (approvers sign before the sender)."""
    h = packet["handoff"]
    appr = {"action": action, "approver": k["agent"], "expires_at": "2999-01-01T00:00:00Z"}
    appr["sig"] = sc.b64u(sc.sign_bytes(k["_secret"], sc.approval_signing_input(appr, h)))
    if with_kid:
        appr["kid"] = k["kid"]
    h["authority"]["approvals"] = [appr]
    packet.pop("signature", None)
    return packet


def codes_of(packet, registry, at=AT):
    ok, reasons = hc.validate(packet, registry=registry, ledger={}, workspace=V3 / "workspace", at=at, info={})
    return ok, {r["code"] for r in reasons}


def reasons(result):
    return {r["code"] for r in result.get("reasons", [])}


def baseline_is_valid():
    ok, codes = codes_of(pkt(), reg())
    assert ok, codes


# ---- A1: strict parsing -------------------------------------------------------

@pytest.mark.parametrize("text, code", [
    ('{"from": "a", "from": "b"}', "duplicate_field:from"),
    ('{"handoff": {"to": "a", "to": "b"}}', "duplicate_field:to"),
    ('[{"x": 1}, {"y": 2, "y": 3}]', "duplicate_field:y"),
    ('{"n": NaN}', "malformed:non_finite_number"),
    ('{"n": Infinity}', "malformed:non_finite_number"),
    ('{"n": -Infinity}', "malformed:non_finite_number"),
    ('{"n": 1e999}', "malformed:non_finite_number"),
    ('{"n": -1e999}', "malformed:non_finite_number"),
])
def test_strict_loads_refuses_what_parsers_disagree_on(text, code):
    with pytest.raises(hc.StrictJSONError) as e:
        hc.strict_loads(text)
    assert e.value.code == code


def test_strict_loads_keeps_ordinary_json():
    assert hc.strict_loads('{"a": 1.5, "b": -0.0, "c": 1e308, "d": [1, {"e": null}]}') == \
        {"a": 1.5, "b": -0.0, "c": 1e308, "d": [1, {"e": None}]}
    assert hc.strict_loads(b'{"bytes": true}') == {"bytes": True}


def test_strict_loads_bounds_an_attacker_chosen_key_name():
    name = "k" * 500
    with pytest.raises(hc.StrictJSONError) as e:
        hc.strict_loads(json.dumps({name: 1})[:-1] + f', "{name}": 2}}')
    assert len(e.value.code) < 100 and e.value.code.startswith("duplicate_field:")


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_check_refuses_a_non_finite_number_instead_of_crashing(bad, tmp_path):
    p = pkt()
    p["handoff"]["planned_actions"][0]["est_tokens"] = bad
    for result in (hc.check(p, registry=reg(), ledger_path=None, workspace=V3 / "workspace", dry_run=True),
                   hc.complete(p, tmp_path / "ledger.json"),
                   hc.release(p, tmp_path / "ledger.json")):
        assert result["decision"] == "REJECT", result
        assert reasons(result) == {"malformed:non_finite_number"}, result
        assert "planned_actions[0].est_tokens" in result["reasons"][0]["message"]


def _cli(tmp_path, text):
    f = tmp_path / "packet.json"
    f.write_text(text)
    run = subprocess.run([sys.executable, str(ROOT / "src" / "handoff_check.py"), str(f),
                          "--registry", str(V3 / "registry.json"), "--workspace", str(V3 / "workspace"),
                          "--dry-run"], capture_output=True, text=True)
    return run.returncode, json.loads(run.stdout)


def test_cli_refuses_duplicate_keys_and_non_finite_numbers_with_a_verdict(tmp_path):
    raw = (V3 / "packets" / "valid-signed.json").read_text()
    code, out = _cli(tmp_path, raw)
    assert code == 0 and out["decision"] == "ACCEPT", out
    dup, n = re.subn(r'"from": "cora"', '"from": "cora", "from": "mallory"', raw, count=1)
    assert n == 1
    code, out = _cli(tmp_path, dup)
    assert code == 2 and reasons(out) == {"duplicate_field:from"}, out
    nan, n = re.subn(r'"est_tokens": 4000', '"est_tokens": NaN', raw, count=1)
    assert n == 1
    code, out = _cli(tmp_path, nan)
    assert code == 2 and reasons(out) == {"malformed:non_finite_number"}, out


def test_mcp_stdio_refuses_duplicate_keys_and_keeps_serving(tmp_path):
    lines = [
        '{"jsonrpc": "2.0", "id": 1, "id": 2, "method": "tools/list"}',
        '{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "synthe_validate_handoff",'
        ' "arguments": {"packet": {"handoff": {"n": NaN}}, "dry_run": true}}}',
        '{"jsonrpc": "2.0", "id": 4, "method": "tools/list"}',
    ]
    run = subprocess.run([sys.executable, str(ROOT / "src" / "synthe_mcp.py"),
                          "--registry", str(V3 / "registry.json"), "--ledger", str(tmp_path / "ledger.json"),
                          "--workspace", str(V3 / "workspace")],
                         input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60)
    out = [json.loads(x) for x in run.stdout.splitlines() if x.strip()]
    assert len(out) == 3, run.stdout + run.stderr
    assert out[0]["error"]["code"] == -32700 and "duplicate_field:id" in out[0]["error"]["message"]
    assert out[1]["error"]["code"] == -32700 and "malformed:non_finite_number" in out[1]["error"]["message"]
    assert out[2]["id"] == 4 and out[2]["result"]["tools"], out[2]


def test_mcp_tool_refuses_a_non_finite_number_reaching_check(tmp_path):
    srv = mcp.SyntheServer(str(V3 / "registry.json"), tmp_path / "ledger.json", V3 / "workspace")
    p = pkt()
    p["handoff"]["planned_actions"][0]["est_minutes"] = float("inf")
    r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "synthe_validate_handoff", "arguments": {"packet": p, "dry_run": True}}})
    verdict = r["result"]["structuredContent"]
    assert verdict["decision"] == "REJECT" and reasons(verdict) == {"malformed:non_finite_number"}, verdict


def test_broker_refuses_duplicate_keys_on_the_wire(tmp_path):
    from world import World
    from test_isolation import daemon, raw_call
    w = World(tmp_path)
    with daemon(w.cfg) as url:
        r = raw_call(url, b'{"op": "hello", "op": "claim", "args": {}}\n')
        assert r["ok"] is False and r["error"]["code"] == "duplicate_field:op", r
        r = raw_call(url, b'{"op": "claim", "args": {"packet": {"n": Infinity}}}\n')
        assert r["ok"] is False and r["error"]["code"] == "malformed:non_finite_number", r
        assert raw_call(url, b"not json\n")["error"]["code"] == "request_malformed"  # unchanged


# ---- A2: kid required when the signer has more than one key ------------------

def _rotated_registry(old, new):
    r = reg()
    r["agents"]["cora"]["keys"] = [old["entry"], new["entry"]]  # appended, old not removed
    return r


def test_signature_without_kid_is_refused_when_the_signer_has_two_keys():
    old, new = new_key("cora", "cora-1"), new_key("cora", "cora-2")
    registry = _rotated_registry(old, new)
    ok, codes = codes_of(sign(pkt(), old, with_kid=False), registry)
    assert not ok and codes == {"signature_kid_required"}, codes
    ok, codes = codes_of(sign(pkt(), new), registry)       # naming the kid works
    assert ok, codes
    ok, codes = codes_of(sign(pkt(), old), registry)       # the old key is still on record here
    assert ok, codes


def test_signature_without_kid_still_works_with_a_single_key():
    only = new_key("cora", "cora-only")
    r = reg()
    r["agents"]["cora"]["keys"] = [only["entry"]]
    ok, codes = codes_of(sign(pkt(), only, with_kid=False), r)
    assert ok, codes


def test_approval_without_kid_is_refused_when_the_approver_has_two_keys():
    old, new = new_key("rohan", "rohan-1"), new_key("rohan", "rohan-2")
    r = reg()
    r["agents"]["rohan"]["keys"] = [old["entry"], new["entry"]]
    p = sign(approve(pkt(), old, with_kid=False), key("cora"))
    ok, codes = codes_of(p, r)
    assert not ok and "approval_kid_required" in codes, codes
    p = sign(approve(pkt(), new), key("cora"))
    ok, codes = codes_of(p, r)
    assert ok, codes


# ---- A3: bind the packet to the authenticated receiver -----------------------

def test_receiver_identity_accepts_its_packet_and_refuses_another_receivers():
    p = pkt()
    ok, codes = codes_of(p, reg())
    assert ok, codes                                                        # optional: offline compatibility
    ok, reasons = hc.validate(p, registry=reg(), ledger={}, workspace=V3 / "workspace", at=AT,
                              info={}, as_receiver="caddy")
    assert ok, reasons
    ok, reasons = hc.validate(p, registry=reg(), ledger={}, workspace=V3 / "workspace", at=AT,
                              info={}, as_receiver="agent-cy")
    assert not ok and {r["code"] for r in reasons} == {"receiver_mismatch"}


def test_mcp_pins_the_operator_configured_receiver(tmp_path):
    srv = mcp.SyntheServer(str(V3 / "registry.json"), tmp_path / "ledger.json", V3 / "workspace",
                           as_receiver="agent-cy")
    out = srv.tool_validate({"packet": pkt(), "dry_run": True})
    assert out["decision"] == "REJECT" and reasons(out) == {"receiver_mismatch"}
    assert not (tmp_path / "ledger.json").exists()


def test_forwarding_mcp_refuses_mismatch_before_sending_the_packet():
    class Client:
        def __init__(self):
            self.called = False

        def call(self, *args, **kwargs):
            self.called = True
            return {"decision": "ACCEPT"}

    srv = mcp.SyntheServer(None, None, None, as_receiver="agent-cy")
    srv.client = Client()
    out = srv.tool_validate({"packet": pkt(), "dry_run": False})
    assert out["decision"] == "REJECT" and reasons(out) == {"receiver_mismatch"}
    assert srv.client.called is False


def test_broker_uses_its_configured_receiver_not_a_client_claim(tmp_path):
    from world import World
    import synthe_broker as sb
    import synthe_commit as cm
    w = World(tmp_path)
    raw = json.loads(w.config_path.read_text())
    raw["receiver"] = "agent-cy"
    w.config_path.write_text(json.dumps(raw))
    broker = sb.Broker(cm.BrokerConfig(w.config_path), "unix")
    out = broker.op_claim({"packet": w.packet(), "dry_run": False}, {"mode": "none"})
    assert out["decision"] == "REJECT" and reasons(out) == {"receiver_mismatch"}
    assert not w.cfg.ledger_path.exists()


# ---- A5: a receiver's maximum handoff lifetime ---------------------------------

def _ttl_registry(caddy=None, top=None):
    r = reg()
    if caddy is not None:
        r["agents"]["caddy"]["policy"]["max_ttl_hours"] = caddy
    if top is not None:
        r.setdefault("policy", {})["max_ttl_hours"] = top
    return r


def _expiring(hours):
    p = pkt()
    p["handoff"]["acceptance"]["expires_at"] = (AT + dt.timedelta(hours=hours)).isoformat()
    return sign(approve(p, key("rohan")), key("cora"))


def test_max_ttl_refuses_a_ten_year_handoff():
    ok, codes = codes_of(_expiring(24 * 365 * 10), _ttl_registry(caddy=72))
    assert not ok and codes == {"ttl_exceeded"}, codes
    ok, codes = codes_of(_expiring(48), _ttl_registry(caddy=72))
    assert ok, codes
    ok, codes = codes_of(_expiring(24 * 365 * 10), _ttl_registry())  # no ceiling set: unchanged
    assert ok, codes


def test_max_ttl_layers_take_the_smaller_ceiling():
    assert not codes_of(_expiring(48), _ttl_registry(caddy=72, top=24))[0]
    assert not codes_of(_expiring(48), _ttl_registry(caddy=24, top=72))[0]
    assert codes_of(_expiring(12), _ttl_registry(caddy=24, top=72))[0]


@pytest.mark.parametrize("bad", ["72", -1, 0, True, None, [72]])
def test_max_ttl_that_is_not_a_positive_number_fails_closed(bad):
    r = _ttl_registry(caddy=bad)
    if bad is None:
        ok, codes = codes_of(_expiring(48), r)   # explicitly unset: no ceiling
        assert ok, codes
        return
    ok, codes = codes_of(_expiring(1), r)
    assert not ok and "registry_malformed" in codes, codes


def test_spec_documents_the_new_codes():
    spec = (ROOT / "SPEC.md").read_text()
    section_10 = spec[spec.index("## 10. Reason codes"):spec.index("## 11.")]
    for code in ("duplicate_field:<f>", "malformed:non_finite_number", "signature_kid_required",
                 "receiver_mismatch", "ttl_exceeded", "approval_kid_required"):
        assert code in section_10, code
    assert "max_ttl_hours" in spec[spec.index("## 4. Receiver policy"):spec.index("## 5.")]
