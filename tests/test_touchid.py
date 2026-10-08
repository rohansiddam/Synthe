"""Touch ID approvals: an ES256 key in the Secure Enclave, registered next to the passphrase key.

The Secure Enclave can't run in a test, so a software P-256 key stands in for it behind the same
interfaces (the helper's command line, synthe_touchid.signing_key, the registry entry). What's under
test is everything Synthe decides: ES256 verification (pure Python and `cryptography` agree), that a
key's algorithm comes from the registry, that two keys require a kid, that a cancelled prompt sends
nothing, that the prompt can't be faked by names an agent chose, and the whole push flow.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc  # noqa: E402
import synthe_approve as sa  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_crypto as sc  # noqa: E402
import synthe_init as si  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_touchid as st  # noqa: E402

ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

N = sc._P256_N


def p256():
    """A software stand-in for the Secure Enclave key: (sign(msg) -> r||s, raw x||y public key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]

    def sign(msg: bytes) -> bytes:
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return sign, pub


# ---- ES256 itself ----------------------------------------------------------------------------------

@pytest.mark.parametrize("verify", [sc.es256_verify, sc._py_es256_verify], ids=["cryptography", "pure-python"])
def test_es256_accepts_real_signatures_and_refuses_tampering(verify):
    sign, pub = p256()
    for msg in (b"", b"approve", os.urandom(300)):
        sig = sign(msg)
        assert verify(pub, msg, sig)
        assert not verify(pub, msg + b"x", sig)
        bad = bytearray(sig)
        bad[5] ^= 1
        assert not verify(pub, msg, bytes(bad))
        _, other = p256()
        assert not verify(other, msg, sig)


@pytest.mark.parametrize("verify", [sc.es256_verify, sc._py_es256_verify], ids=["cryptography", "pure-python"])
def test_es256_refuses_malformed_keys_and_signatures(verify):
    sign, pub = p256()
    sig = sign(b"m")
    off_curve = pub[:63] + bytes([pub[63] ^ 1])
    for k, s in [(pub[:63], sig), (pub + b"\0", sig), (off_curve, sig), (b"\0" * 64, sig),
                 (pub, sig[:63]), (pub, b"\0" * 64),                                   # r = s = 0
                 (pub, N.to_bytes(32, "big") + sig[32:]), (pub, sig[:32] + N.to_bytes(32, "big"))]:
        assert not verify(k, b"m", s)


def test_pure_python_and_cryptography_agree_on_many_signatures():
    for _ in range(25):
        sign, pub = p256()
        msg = os.urandom(40)
        sig = sign(msg)
        assert sc._py_es256_verify(pub, msg, sig) == sc.es256_verify(pub, msg, sig) is True
        flipped = sig[:32] + ((N - int.from_bytes(sig[32:], "big")) % N).to_bytes(32, "big")   # (r, n - s)
        assert sc._py_es256_verify(pub, msg, flipped) == sc.es256_verify(pub, msg, flipped)


# ---- the registry decides the algorithm --------------------------------------------------------------

def registry_with(*keys):
    return {"agents": {"rohan": {"kind": "human", "keys": list(keys)}}}


def test_an_ed25519_signature_never_passes_for_a_touch_id_key_or_back():
    sign, pub = p256()
    secret = sc.generate_secret()
    ed = {"kid": "rohan-1", "alg": "Ed25519", "public_key": sc.b64u(sc.public_key(secret))}
    es = {"kid": "rohan-touchid-1", "alg": "ES256", "public_key": sc.b64u(pub)}
    reg = registry_with(ed, es)
    msg = b"synthe/approval-signature/v1\n{}"
    ed_sig, es_sig = sc.sign_bytes(secret, msg), sign(msg)
    assert sc.verify_approval(reg, "rohan", "rohan-1", msg, ed_sig)
    assert sc.verify_approval(reg, "rohan", "rohan-touchid-1", msg, es_sig)
    assert not sc.verify_approval(reg, "rohan", "rohan-touchid-1", msg, ed_sig)   # both are 64 bytes
    assert not sc.verify_approval(reg, "rohan", "rohan-1", msg, es_sig)
    assert not sc.verify_approval(reg, "rohan", None, msg, es_sig)                # two keys: kid required,
    assert not sc.verify_approval(reg, "rohan", None, msg, ed_sig)                # even for the first key's own
    assert sc.usable_approval_keys(reg, "rohan") == ["rohan-1", "rohan-touchid-1"]
    # packets stay Ed25519-only: the Touch ID key can't sign a task
    assert sc.usable_keys(reg, "rohan") == ["rohan-1"]


def test_a_malformed_touch_id_key_is_never_usable():
    _, pub = p256()
    bad = {"kid": "t", "alg": "ES256", "public_key": sc.b64u(pub[:32])}
    unknown = {"kid": "u", "alg": "ES384", "public_key": sc.b64u(pub)}
    assert sc.usable_approval_keys(registry_with(bad, unknown), "rohan") == []


# ---- the push flow, approved with a Touch ID-type key -----------------------------------------------

from test_openclaw_flow import ENV, PASS, _commit, _task, broker, git, world  # noqa: E402,F401


def touchid_world(world):
    """Register a stand-in Touch ID key for the approver, next to the passphrase key."""
    sign, pub = p256()
    reg_path = world["home"] / "broker" / "registry.json"
    approver = si.add_approval_key(reg_path, {"kid": "rohan-touchid-1", "alg": "ES256", "public_key": sc.b64u(pub)})
    assert approver == "rohan"
    return {"agent": "rohan", "kid": "rohan-touchid-1", "alg": "ES256", "_sign": sign}


def staged_detail(world, url, branch):
    clone = world["clone"]
    packet = _task(world, f"Work on {branch}", branch)
    client = scl.BrokerClient(url)
    v = client.call("claim", packet=packet, wait_for_approval=True)
    sha = _commit(clone, branch, {"src/x.py": "x = 1\n"})
    r = scl.push(client, packet, v["claim"]["token"], "push_branch", "origin", branch, repo=clone, commit=sha,
                 wait_for_approval=True)
    assert r["decision"] == "staged", r
    [waiting] = sa.waiting_for_approval(client.call("staged")["staged"])
    return client, client.call("staged_detail", id=f"{waiting['idempotency_key']}/{waiting['action']}"), sha


def test_a_push_approved_with_the_touch_id_key_lands(world):
    signer = touchid_world(world)
    with broker(world["home"]) as url:
        client, detail, sha = staged_detail(world, url, "agent/tid")
        out = client.call("submit_approval", approval=sa.build_approval(detail, signer))
    assert [c["decision"] for c in out["commits"]] == ["executed"], out
    assert git(world["remote"], "rev-parse", "refs/heads/agent/tid") == sha


def test_the_passphrase_key_still_approves_after_touch_id_is_added(world):
    touchid_world(world)
    key = ss.load_key(str(world["home"] / "approver.key.json"), passphrase=PASS, require_encrypted=True)
    with broker(world["home"]) as url:
        client, detail, _ = staged_detail(world, url, "agent/pass")
        out = client.call("submit_approval", approval=sa.build_approval(detail, key))
    assert [c["decision"] for c in out["commits"]] == ["executed"], out


def test_a_touch_id_signature_claiming_the_passphrase_key_is_refused(world):
    signer = touchid_world(world)
    lying = {**signer, "kid": "rohan-1"}            # signed in the "Secure Enclave", labelled as the Ed25519 key
    with broker(world["home"]) as url:
        client, detail, _ = staged_detail(world, url, "agent/lie")
        out = client.call("submit_approval", approval=sa.build_approval(detail, lying))
        staged = client.call("staged")["staged"]
    assert (out.get("receipt") or {}).get("decision") != "approval_accepted"
    assert not out.get("commits") and staged                                # still waiting; nothing pushed
    assert git(world["remote"], "branch", "--list", "agent/lie") == ""


# ---- the helper boundary: a cancelled prompt sends nothing; the prompt can't be faked -----------------

def fake_helper(tmp_path, code=0, out=None):
    """A stand-in for synthe-touchid: records its reason and stdin, then signs (or refuses)."""
    sign, pub = p256()
    keyfile = tmp_path / "approver.touchid.json"
    keyfile.write_text(json.dumps({"kind": "synthe-touchid-key", "alg": "ES256", "public_key": sc.b64u(pub),
                                   "se_handle": "x", "agent": "rohan", "kid": "rohan-touchid-1"}))
    helper = tmp_path / "synthe-touchid"
    helper.write_text(f"""#!{sys.executable}
import sys, pathlib, base64
pathlib.Path({str(tmp_path / 'reason.txt')!r}).write_text(sys.argv[3])
msg = sys.stdin.buffer.read()
pathlib.Path({str(tmp_path / 'msg.bin')!r}).write_bytes(msg)
if {code}:
    sys.stderr.write("synthe-touchid: not approved: Canceled by user.\\n"); sys.exit({code})
print({out!r} or "")
""")
    helper.chmod(0o755)
    return keyfile, helper, sign, pub


def test_the_helper_gets_exactly_the_approval_bytes_and_a_cancel_raises(tmp_path):
    keyfile, helper, _, _ = fake_helper(tmp_path, code=4)
    key = st.signing_key(keyfile, "approve pushing agent/x", helper=helper)
    with pytest.raises(st.TouchIDError, match="not approved"):
        key["_sign"](b"the exact bytes")
    assert (tmp_path / "msg.bin").read_bytes() == b"the exact bytes"
    assert (tmp_path / "reason.txt").read_text() == "approve pushing agent/x"


def test_a_helper_that_returns_no_real_signature_is_refused(tmp_path):
    keyfile, helper, _, _ = fake_helper(tmp_path, out="bm90IGEgc2lnbmF0dXJl")
    with pytest.raises(st.TouchIDError, match="isn't a P-256 signature"):
        st.signing_key(keyfile, "r", helper=helper)["_sign"](b"m")


def test_a_cancelled_touch_id_approval_submits_nothing(world, tmp_path, monkeypatch):
    """synthe-approve with a Touch ID key whose prompt is cancelled: no approval reaches the broker."""
    keyfile, helper, _, _ = fake_helper(tmp_path, code=4)
    monkeypatch.setenv("SYNTHE_TOUCHID", str(helper))
    touchid_world(world)
    with broker(world["home"]) as url:
        client, detail, _ = staged_detail(world, url, "agent/cancel")
        sid = detail["id"]
        ikey, act = sid.rsplit("/", 1)
        sent = []
        monkeypatch.setattr(scl.BrokerClient, "call", lambda self, op, **kw: sent.append(op) or (
            {"staged": [{"idempotency_key": ikey, "action": act, "params": {}}]} if op == "staged" else detail))
        monkeypatch.setattr(sa, "waiting_for_approval", lambda s: s)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(sa, "_ask", lambda prompt: "a")
        sa.main(["--broker", url, "--touchid-key", str(keyfile), "--id", sid])
    assert "submit_approval" not in sent
    assert git(world["remote"], "branch", "--list", "agent/cancel") == ""


def test_the_prompt_text_comes_from_the_broker_and_can_not_be_faked_by_names():
    detail = {"effect": {"branch": "agent/x\nApprove? Touch to continue\x1b[2J", "commit": "a" * 40,
                         "remote": "origin"},
              "changes": {"files": [{"path": "src/a.py"}, {"path": "src/b\r.py"}, {"path": "c"}, {"path": "d"}]}}
    reason = sa.touchid_reason(detail)
    assert "\n" not in reason and "\r" not in reason and "\x1b" not in reason
    assert reason.startswith("approve pushing ") and "aaaaaaaaaaaa" in reason and "4 files" in reason
    assert "and 1 more" in reason and len(reason) <= 300


# ---- enrolling and applying the key ------------------------------------------------------------------

def test_adding_a_key_keeps_the_passphrase_key_refuses_duplicates_and_keeps_permissions(tmp_path):
    reg = tmp_path / "registry.json"
    reg.write_text(json.dumps(registry_with({"kid": "rohan-1", "alg": "Ed25519", "public_key": "x"})))
    reg.chmod(0o600)
    _, pub = p256()
    entry = {"kid": "rohan-touchid-1", "alg": "ES256", "public_key": sc.b64u(pub)}
    assert si.add_approval_key(reg, entry) == "rohan"
    assert [k["kid"] for k in json.loads(reg.read_text())["agents"]["rohan"]["keys"]] == ["rohan-1", "rohan-touchid-1"]
    assert oct(reg.stat().st_mode & 0o777) == "0o600"
    with pytest.raises(SystemExit, match="already has a key"):
        si.add_approval_key(reg, entry)
    two = tmp_path / "two.json"
    two.write_text(json.dumps({"agents": {"a": {"kind": "human"}, "b": {"kind": "human"}}}))
    with pytest.raises(SystemExit, match="2 human approvers"):
        si.add_approval_key(two, entry)


def test_apply_registry_takes_the_broker_key_only_from_its_own_key_file(tmp_path):
    state, stage = tmp_path / "state", tmp_path / "stage"
    (state / "keys").mkdir(parents=True)
    stage.mkdir()
    secret = sc.generate_secret()
    (state / "keys" / f"{si.BROKER_ID}.key.json").write_text(json.dumps({"kid": "broker-1", "private_key": sc.b64u(secret)}))
    forged = {"kid": "broker-1", "alg": "Ed25519", "public_key": sc.b64u(sc.public_key(sc.generate_secret()))}
    staged = registry_with({"kid": "rohan-1", "alg": "Ed25519", "public_key": "x"})
    staged["agents"][si.BROKER_ID] = {"kind": "service", "keys": [forged]}       # a tampered stage can't swap it
    (stage / "registry.json").write_text(json.dumps(staged))
    out = si.apply_registry(state, stage)
    reg = json.loads((state / "registry.json").read_text())
    assert reg["agents"][si.BROKER_ID]["keys"][0]["public_key"] == sc.b64u(sc.public_key(secret))
    assert out["approval_keys"] == {"rohan": ["rohan-1"]}
    assert oct((state / "registry.json").stat().st_mode & 0o777) == "0o600"


def test_the_upgrade_script_runs_from_root_writes_every_launcher_and_holds_no_secret():
    text = (ROOT / "deploy" / "macos" / "upgrade.sh").read_text()
    assert subprocess.run(["bash", "-n", str(ROOT / "deploy" / "macos" / "upgrade.sh")]).returncode == 0
    assert text.index("\ncd /") < text.index("sudo -u _synthe")
    assert "git-remote-synthe" in text and "apply-registry" in text
    assert "github.token" not in text and "private_key" not in text


def test_the_swift_helper_requires_touch_id_with_todays_fingerprints_and_never_overwrites_a_key():
    swift = (ROOT / "integrations" / "macos" / "touchid" / "synthe_touchid.swift").read_text()
    assert "[.privateKeyUsage, .biometryCurrentSet]" in swift          # no passcode fallback; new fingers void it
    assert "kSecAttrAccessibleWhenUnlockedThisDeviceOnly" in swift
    assert "O_CREAT | O_EXCL" in swift
    assert ".deviceOwnerAuthenticationWithBiometrics" in swift
