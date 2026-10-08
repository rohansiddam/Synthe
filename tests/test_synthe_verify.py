"""synthe-verify: the standalone receipt verifier. Chains are built with synthe_crypto (the signer's
own code) and checked with synthe_verify (its own canonical JSON and Ed25519), so each side checks
the other. Every reason code has an attack that triggers it."""
import ast
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_crypto as sc   # noqa: E402
import synthe_verify as sv   # noqa: E402

SIGNER = "synthe-broker"


def mkkey(agent):
    secret = sc.generate_secret()
    return {"agent": agent, "kid": f"{agent}-1", "_secret": secret,
            "pub": {"kid": f"{agent}-1", "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}}


def sign(key, receipt, as_signer=None):
    receipt["broker"], receipt["kid"] = as_signer or key["agent"], key["kid"]
    receipt.pop("sig", None)
    receipt["sig"] = sc.b64u(sc.sign_bytes(key["_secret"], sc.receipt_signing_input(receipt)))
    return receipt


def chain(key, n=4, decisions=("executed", "denied", "staged", "denied")):
    out, prev = [], None
    for i in range(n):
        r = sign(key, {"v": 1, "kind": "effect", "time": "2026-10-07T00:00:00+00:00", "seq": i + 1,
                       "prev": prev, "decision": decisions[i % len(decisions)],
                       "effect": {"branch": "feature/x", "commit": f"{i:040x}", "ms": 12.5},
                       "reasons": [{"code": "ok", "note": "naïve ✓"}]})
        prev = hashlib_digest(r)
        out.append(r)
    return out


def hashlib_digest(r):
    import hashlib
    return hashlib.sha256(sc.canonical_json(r)).hexdigest()


def dump(receipts) -> bytes:
    return b"".join(json.dumps(r, sort_keys=True, separators=(",", ":")).encode() + b"\n" for r in receipts)


def trust_for(key):
    return sv.load_trust({"broker": key["agent"], **key["pub"]})


def codes(report):
    return {e["code"] for e in report["errors"]}


@pytest.fixture(scope="module")
def broker():
    return mkkey(SIGNER)


@pytest.fixture(scope="module")
def mallory():
    return mkkey("mallory")


# -- the happy path ----------------------------------------------------------------------------

def test_valid_chain_verifies_with_head_and_tally(broker):
    rs = chain(broker)
    rep = sv.verify(dump(rs), trust_for(broker))
    assert rep["ok"] is True and rep["errors"] == []
    assert rep["count"] == 4 and rep["head"] == hashlib_digest(rs[-1])
    assert rep["decisions"] == {"executed": 1, "denied": 2, "staged": 1}
    assert sv.receipt_digest(rs[-1]) == hashlib_digest(rs[-1])


def test_blank_lines_and_missing_final_newline_are_tolerated(broker):
    data = dump(chain(broker, 3))
    assert sv.verify(b"\n" + data.replace(b"\n", b"\n\n").rstrip(b"\n"), trust_for(broker))["ok"]


# -- Ed25519 against RFC 8032 and the signer's own implementation ------------------------------

RFC8032 = [  # section 7.1, tests 1-3: (public key, message, signature)
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd2"
     "5bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c38"
     "7b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc659"
     "4a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("pk,msg,sig", RFC8032)
def test_rfc8032_vectors(pk, msg, sig):
    pk, msg, sig = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
    assert sv.ed25519_verify(pk, msg, sig)
    assert not sv.ed25519_verify(pk, msg + b"!", sig)
    assert not sv.ed25519_verify(pk, msg, sig[:63] + bytes([sig[63] ^ 1]))


def test_agrees_with_the_signer_implementation_on_random_inputs():
    for i in range(12):
        secret = sc.generate_secret()
        pk, msg = sc.public_key(secret), bytes([i]) * (i * 7)
        sig = sc.sign_bytes(secret, msg)
        assert sv.ed25519_verify(pk, msg, sig) is sc._py_verify(pk, msg, sig) is True
        bad = sig[:i] + bytes([sig[i] ^ 0x40]) + sig[i + 1:]
        assert sv.ed25519_verify(pk, msg, bad) is sc._py_verify(pk, msg, bad)


def test_malleable_signature_s_plus_l_is_refused(broker):
    rs = chain(broker, 2)
    sig = sv.unb64u_strict(rs[1]["sig"])
    s = int.from_bytes(sig[32:], "little") + sv._q
    assert s < 2 ** 256
    rs[1]["sig"] = sc.b64u(sig[:32] + s.to_bytes(32, "little"))   # same point equation, s >= L
    rep = sv.verify(dump(rs), trust_for(broker))
    assert rep["ok"] is False and codes(rep) == {"signature_invalid"}


# -- tampering with the chain -------------------------------------------------------------------

def test_edited_field_breaks_signature_and_the_next_link(broker):
    rs = chain(broker)
    rs[1]["decision"] = "executed"                                 # denied -> executed
    rep = sv.verify(dump(rs), trust_for(broker))
    assert {(e["seq"], e["code"]) for e in rep["errors"]} == {(2, "signature_invalid"), (3, "prev_mismatch")}


def test_deleted_receipt_is_a_gap(broker):
    rs = chain(broker)
    del rs[1]
    assert codes(sv.verify(dump(rs), trust_for(broker))) == {"seq_gap", "prev_mismatch"}


def test_reordered_receipts_are_caught(broker):
    rs = chain(broker)
    rs[1], rs[2] = rs[2], rs[1]
    assert {"seq_gap", "prev_mismatch"} <= codes(sv.verify(dump(rs), trust_for(broker)))


def test_truncated_tail_is_caught_only_by_a_checkpoint(broker):
    rs = chain(broker)
    cp = {4: hashlib_digest(rs[3])}
    assert sv.verify(dump(rs), trust_for(broker), cp)["ok"] is True
    cut = dump(rs[:3])
    assert sv.verify(cut, trust_for(broker))["ok"] is True          # a shorter chain still links
    rep = sv.verify(cut, trust_for(broker), cp)
    assert rep["ok"] is False and codes(rep) == {"checkpoint_missing"}


def test_checkpoint_from_another_history_is_a_mismatch(broker):
    a, b = chain(broker, 3), chain(broker, 3, decisions=("denied",))
    rep = sv.verify(dump(b), trust_for(broker), {2: hashlib_digest(a[1])})
    assert codes(rep) == {"checkpoint_mismatch"}


def test_empty_chain_is_not_verified(broker):
    assert codes(sv.verify(b"", trust_for(broker))) == {"empty_chain"}
    assert codes(sv.verify(b"\n\n", trust_for(broker))) == {"empty_chain"}


# -- forged signers -----------------------------------------------------------------------------

def test_well_signed_chain_from_another_signer_is_refused(broker, mallory):
    rs = chain(mallory)                                            # valid chain, signed as mallory
    rep = sv.verify(dump(rs), trust_for(broker))
    assert rep["ok"] is False and codes(rep) == {"signer_untrusted"}


def test_claiming_the_broker_id_with_another_kid_is_refused(broker, mallory):
    rs = [sign(mallory, r, as_signer=SIGNER) for r in chain(broker, 2)]
    rs[1]["prev"] = hashlib_digest(rs[0])
    sign(mallory, rs[1], as_signer=SIGNER)
    assert codes(sv.verify(dump(rs), trust_for(broker))) == {"kid_unknown"}


def test_claiming_the_broker_kid_with_another_key_is_refused(broker, mallory):
    impostor = {**mallory, "agent": SIGNER, "kid": broker["kid"]}
    rs = chain(impostor, 2)
    assert codes(sv.verify(dump(rs), trust_for(broker))) == {"signature_invalid"}


def test_signature_without_the_domain_tag_is_refused(broker):
    rs = chain(broker, 1)
    body = {k: v for k, v in rs[0].items() if k != "sig"}
    rs[0]["sig"] = sc.b64u(sc.sign_bytes(broker["_secret"], sc.canonical_json(body)))
    assert codes(sv.verify(dump(rs), trust_for(broker))) == {"signature_invalid"}


def test_signature_under_the_approval_domain_is_refused(broker):
    rs = chain(broker, 1)
    body = {k: v for k, v in rs[0].items() if k != "sig"}
    msg = sc.APPROVAL_SIG_DOMAIN.encode() + b"\n" + sc.canonical_json(body)
    rs[0]["sig"] = sc.b64u(sc.sign_bytes(broker["_secret"], msg))
    assert codes(sv.verify(dump(rs), trust_for(broker))) == {"signature_invalid"}


@pytest.mark.parametrize("respell", ["pad", "junk", "trailing_bits", "number"])
def test_signature_has_one_spelling(broker, respell):
    rs = chain(broker, 1)
    s = rs[0]["sig"]
    abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    rs[0]["sig"] = {"pad": s + "==", "junk": s[:40] + "." + s[40:],
                    "trailing_bits": s[:-1] + abc[abc.index(s[-1]) ^ 1], "number": 7}[respell]
    if respell != "number":                                        # a lenient decoder reads the same bytes
        loose = rs[0]["sig"].rstrip("=").replace(".", "")
        assert sc.unb64u(loose) == sc.unb64u(s)
    assert codes(sv.verify(dump(rs), trust_for(broker))) == {"signature_invalid"}


# -- parser differentials -----------------------------------------------------------------------

def test_duplicate_field_is_refused_even_when_last_value_is_signed(broker):
    rs = chain(broker, 1)                                          # signed decision: executed
    line = dump(rs).decode().rstrip("\n")
    forged = line.replace('"decision":"executed"', '"decision":"denied","decision":"executed"')
    assert forged != line and json.loads(forged) == rs[0]          # a last-wins parser sees a valid receipt
    assert codes(sv.verify(forged.encode() + b"\n", trust_for(broker))) == {"duplicate_field"}


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_non_finite_numbers_are_refused(broker, token):
    line = dump(chain(broker, 1)).decode().replace('"ms":12.5', f'"ms":{token}')
    assert codes(sv.verify(line.encode(), trust_for(broker))) == {"non_finite_number"}


@pytest.mark.parametrize("raw,code", [
    (b"{not json}\n", "not_json"),
    (b"[1,2]\n", "not_object"),
    (b'{"seq":1,"x":"\xff"}\n', "not_utf8"),
    (b'{"seq":1,"prev":null,"x":"\\ud800"}\n', "field_invalid"),
])
def test_unreadable_lines_fail_closed(broker, raw, code):
    rep = sv.verify(raw, trust_for(broker))
    assert rep["ok"] is False and code in codes(rep) and rep["head"] is None


@pytest.mark.parametrize("seq", [True, "1", 1.0, None])
def test_seq_must_be_a_plain_integer(broker, seq):
    rs = chain(broker, 1)
    rs[0]["seq"] = seq
    sign(broker, rs[0])
    rep = sv.verify(dump(rs), trust_for(broker))
    assert rep["ok"] is False and ({"field_invalid", "seq_gap"} & codes(rep))


def test_bad_line_in_the_middle_does_not_hide_later_problems(broker, mallory):
    rs = chain(broker, 3)
    data = dump(rs).split(b"\n")
    data[1] = b"{oops"
    tail = dump([sign(mallory, rs[2])])
    rep = sv.verify(b"\n".join(data[:2]) + b"\n" + tail, trust_for(broker))
    assert {"not_json", "signer_untrusted"} <= codes(rep)


# -- the trust anchor ---------------------------------------------------------------------------

def test_registry_trusts_only_the_named_signer(broker, mallory):
    reg = {"agents": {SIGNER: {"keys": [broker["pub"]]}, "mallory": {"keys": [mallory["pub"]]}}}
    assert sv.load_trust(reg)["signer"] == SIGNER                   # default signer id
    assert sv.verify(dump(chain(mallory)), sv.load_trust(reg))["ok"] is False
    assert sv.verify(dump(chain(mallory)), sv.load_trust(reg, "mallory"))["ok"] is True
    with pytest.raises(sv.TrustError):
        sv.load_trust(reg, "nobody")


@pytest.mark.parametrize("bad", [
    lambda k: [],
    lambda k: {"public_key": k["pub"]["public_key"], "kid": "x"},          # names no signer
    lambda k: {"broker": SIGNER, "public_key": k["pub"]["public_key"]},    # no kid
    lambda k: {"broker": SIGNER, "kid": "x", "public_key": "AAAA"},        # wrong length
    lambda k: {"broker": SIGNER, "kid": "x", "alg": "RSA", "public_key": k["pub"]["public_key"]},
    lambda k: {"broker": SIGNER, "kid": "x", "public_key": sc.b64u(b"\xff" * 31 + b"\x7f")},  # y >= p
    lambda k: {"agents": {SIGNER: {"keys": []}}},
    lambda k: {"something": "else"},
])
def test_unusable_key_files_are_refused(broker, bad):
    with pytest.raises(sv.TrustError):
        sv.load_trust(bad(broker))


def test_published_key_for_another_signer_is_refused(broker):
    with pytest.raises(sv.TrustError):
        sv.load_trust({"broker": SIGNER, **broker["pub"]}, "other")


# -- CLI and standalone -------------------------------------------------------------------------

def test_small_order_key_does_not_make_forged_receipts_valid():
    identity = b"\x01" + b"\x00" * 31
    forged_sig = identity + b"\x00" * 32
    assert not sv.ed25519_verify(identity, b"arbitrary forged claim", forged_sig)
    with pytest.raises(sv.TrustError):
        sv.load_trust({"broker": SIGNER, "kid": "weak", "public_key": sc.b64u(identity)})


def test_ambiguous_key_list_refused(broker, mallory):
    duplicate = {**mallory["pub"], "kid": broker["pub"]["kid"]}
    with pytest.raises(sv.TrustError, match="duplicate"):
        sv.load_trust({"agents": {SIGNER: {"keys": [broker["pub"], duplicate]}}})
    for keys in (3, "key", {}, None):
        with pytest.raises(sv.TrustError):
            sv.load_trust({"agents": {SIGNER: {"keys": keys}}})


def test_all_object_fields_including_proto_and_numeric_keys_are_bound(broker):
    original = chain(broker, 1)[0]
    original["effect"] = {"__proto__": {"target": "first"}, "2": "two", "10": "ten"}
    sign(broker, original)
    assert sv.verify(dump([original]), trust_for(broker))["ok"]
    original["effect"]["__proto__"]["target"] = "changed"
    assert not sv.verify(dump([original]), trust_for(broker))["ok"]
    assert sv.canonical_json({"2": 2, "10": 10}) == b'{"10":10,"2":2}'


def test_longer_valid_fork_still_fails_independent_checkpoint(broker):
    original = chain(broker, 2)
    checkpoint = {2: hashlib_digest(original[-1])}
    fork = chain(broker, 5, decisions=("executed",))
    assert sv.verify(dump(fork), trust_for(broker))["ok"]  # crypto alone cannot establish continuity
    assert codes(sv.verify(dump(fork), trust_for(broker), checkpoint)) == {"checkpoint_mismatch"}
    extension = chain(broker, 5)
    assert sv.verify(dump(extension), trust_for(broker), checkpoint)["ok"]

def _files(tmp_path, key, receipts):
    (tmp_path / "pub.json").write_text(json.dumps({"broker": key["agent"], **key["pub"]}))
    (tmp_path / "r.jsonl").write_bytes(dump(receipts))
    return str(tmp_path / "pub.json"), str(tmp_path / "r.jsonl")


def test_cli_exit_codes_and_json(tmp_path, broker, mallory, capsys):
    pub, rec = _files(tmp_path, broker, chain(broker))
    assert sv.main([rec, "--key", pub]) == 0
    assert "VERIFIED  4 receipts" in capsys.readouterr().out
    head = hashlib_digest(chain(broker, decisions=("denied",))[0])   # another history
    assert sv.main([rec, "--key", pub, "--json", "--checkpoint", f"1:{head}"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and [e["code"] for e in out["errors"]] == ["checkpoint_mismatch"]
    (tmp_path / "r.jsonl").write_bytes(dump(chain(mallory)))
    assert sv.main([rec, "--key", pub]) == 1
    assert "signer_untrusted" in capsys.readouterr().out
    assert sv.main([rec, "--key", str(tmp_path / "missing.json")]) == 2
    assert sv.main([str(tmp_path / "missing.jsonl"), "--key", pub]) == 2
    assert sv.main([rec, "--key", pub, "--checkpoint", "zero:abc"]) == 2
    assert sv.main([rec, "--key", pub, "--checkpoint", f"1:{'a' * 64}",
                    "--checkpoint", f"1:{'b' * 64}"]) == 2


STDLIB = {"argparse", "base64", "hashlib", "json", "math", "re", "sys", "__future__"}


def test_imports_only_the_standard_library():
    tree = ast.parse((ROOT / "src" / "synthe_verify.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert names <= STDLIB, names - STDLIB


def test_runs_alone_with_no_site_packages(tmp_path, broker):
    """Copied by itself into an empty folder, run with -I -S: no repo, no installed packages."""
    alone = tmp_path / "alone"
    alone.mkdir()
    shutil.copy2(ROOT / "src" / "synthe_verify.py", alone / "synthe_verify.py")
    pub, rec = _files(tmp_path, broker, chain(broker))
    run = subprocess.run([sys.executable, "-I", "-S", "synthe_verify.py", "-", "--key", pub],
                         cwd=alone, input=Path(rec).read_bytes(), capture_output=True, timeout=60)
    assert run.returncode == 0, run.stderr.decode()
    assert b"VERIFIED  4 receipts" in run.stdout
