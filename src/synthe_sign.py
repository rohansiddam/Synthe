#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthe signing CLI (stdlib only; uses `cryptography` when installed).

  keygen   --agent ID [--kid KID] --out KEYFILE [--encrypt]
           Write a private key file (JSON, chmod 600) and print the public
           registry entry to paste under agents.<ID>.keys. --encrypt seals the
           key under a passphrase you type: use it for a human approver's key,
           so an agent running as you can't read it and approve its own work.
  protect  KEYFILE
           Encrypt an existing plaintext key file in place.
  sign     PACKET --key KEYFILE [--out FILE]
           Sender signs the handoff object. Signs exactly what the receiver
           will verify; any later edit to the handoff breaks the signature.
  approve  PACKET --key KEYFILE --action NAME [--expires-at TS] [--out FILE] [--detached]
           An approver (human or agent) signs an approval bound to this
           handoff's idempotency key, sender and receiver, and appends it to
           authority.approvals. Run this BEFORE `sign` (the sender's signature
           covers the approvals list). If the planned action carries
           `params` (branch, remote, recipients...), they are copied into the
           approval and signed too, so the approval covers exactly that effect
           (`--no-params` to approve the action without pinning them). What
           is being approved is printed to stderr before signing. With
           --detached the approval is written to --out on its own, for the
           effect executor to receive later (v0.5).
  verify   PACKET --registry REGISTRY
           Check the packet signature and every signed approval; prints a
           report. (Full validation is handoff_check.py's job.)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_crypto as sc  # noqa: E402


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _write(obj: dict, out: str | None) -> None:
    text = json.dumps(obj, indent=2) + "\n"
    if out:
        Path(out).write_text(text)
    else:
        sys.stdout.write(text)


class KeyFileError(SystemExit):
    """A key file that can't be used: locked, wrong passphrase, altered, or plaintext where an
    encrypted key is required. A SystemExit, so the CLIs exit with the message."""


# An approver's key is the human's signature: an agent that runs as the same user can read a
# plaintext key file and approve its own work (THREAT_MODEL "Leaked keys"). Encrypted key files
# need a passphrase only a person types. scrypt N=2^17, r=8, p=1 (~0.25 s on a laptop) + AES-256-GCM,
# with the file's agent, kid and alg bound as associated data, so they can't be swapped.
KEY_FORMAT = "synthe-key/v2"
KEY_KDF = {"name": "scrypt", "n": 2 ** 17, "r": 8, "p": 1}
MIN_PASSPHRASE = 12


def _key_aad(key: dict) -> bytes:
    return sc.canonical_json({"v": KEY_FORMAT, "agent": key.get("agent"), "kid": key.get("kid"),
                              "alg": key.get("alg", sc.ALG)})


def _aead():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise KeyFileError("encrypted key files need the 'cryptography' package (pip install cryptography)")
    return AESGCM, Scrypt


def is_encrypted(key: dict) -> bool:
    return isinstance(key, dict) and isinstance(key.get("encrypted"), dict)


def encrypt_key(key: dict, secret: bytes, passphrase: str) -> dict:
    """The key file with its private key sealed under `passphrase`. No `private_key` field remains."""
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise KeyFileError(f"use a passphrase of at least {MIN_PASSPHRASE} characters")
    if len(secret) != 32:
        raise KeyFileError("private key must be 32 bytes")
    AESGCM, Scrypt = _aead()
    salt, nonce = os.urandom(16), os.urandom(12)
    k = Scrypt(salt=salt, length=32, n=KEY_KDF["n"], r=KEY_KDF["r"], p=KEY_KDF["p"]).derive(passphrase.encode())
    out = {"agent": key["agent"], "kid": key["kid"], "alg": key.get("alg", sc.ALG)}
    out["encrypted"] = {"v": KEY_FORMAT, "kdf": {**KEY_KDF, "salt": sc.b64u(salt)}, "cipher": "AES-256-GCM",
                        "nonce": sc.b64u(nonce), "ct": sc.b64u(AESGCM(k).encrypt(nonce, secret, _key_aad(out)))}
    return out


def decrypt_key(key: dict, passphrase: str) -> bytes:
    enc = key.get("encrypted") if isinstance(key, dict) else None
    kdf = (enc or {}).get("kdf") or {}
    if not isinstance(enc, dict) or enc.get("v") != KEY_FORMAT or kdf.get("name") != "scrypt" \
            or enc.get("cipher") != "AES-256-GCM":
        raise KeyFileError("unsupported key file format")
    n, r, p = kdf.get("n"), kdf.get("r"), kdf.get("p")
    # bounded, so an altered file can't make us burn gigabytes of memory deriving
    if n not in (2 ** 15, 2 ** 16, 2 ** 17, 2 ** 18) or r not in (8,) or p not in (1, 2):
        raise KeyFileError("unsupported key derivation parameters")
    AESGCM, Scrypt = _aead()
    try:
        k = Scrypt(salt=sc.unb64u(kdf["salt"]), length=32, n=n, r=r, p=p).derive(str(passphrase).encode())
        secret = AESGCM(k).decrypt(sc.unb64u(enc["nonce"]), sc.unb64u(enc["ct"]), _key_aad(key))
    except Exception:  # InvalidTag, bad base64, wrong lengths: one answer, no oracle
        raise KeyFileError("wrong passphrase, or the key file was altered") from None
    if len(secret) != 32:
        raise KeyFileError("key file holds a malformed private key")
    return secret


def prompt_passphrase(message: str) -> str:
    """A passphrase typed by a person at a terminal. Refuses when there is none: an encrypted key
    is unlocked only by someone at the keyboard, never by a process piping a secret in."""
    import getpass
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise KeyFileError("this key is encrypted: run the command in your own terminal, where you can "
                           "type its passphrase")
    return getpass.getpass(message)


def new_passphrase(prompt=prompt_passphrase) -> str:
    first = prompt(f"New passphrase (at least {MIN_PASSPHRASE} characters): ")
    if len(first) < MIN_PASSPHRASE:
        raise KeyFileError(f"use a passphrase of at least {MIN_PASSPHRASE} characters")
    if prompt("Type it again: ") != first:
        raise KeyFileError("the two passphrases differ; nothing was written")
    return first


def load_key(path: str, passphrase: str | None = None, require_encrypted: bool = False,
             prompt=prompt_passphrase) -> dict:
    """A key file with its secret in `_secret`. An encrypted file asks for its passphrase (or uses
    `passphrase`); `require_encrypted` refuses a plaintext file (for human approver keys)."""
    key = _load(path)
    if is_encrypted(key):
        if passphrase is None:
            passphrase = prompt(f"Passphrase for {key.get('agent')}'s key {key.get('kid')}: ")
        secret = decrypt_key(key, passphrase)
    else:
        if require_encrypted:
            raise KeyFileError(f"{path} holds a plaintext private key, which anything running as you can read "
                               f"and sign with. Encrypt it first: synthe-sign protect {path}")
        try:
            secret = sc.unb64u(key["private_key"])
        except (KeyError, TypeError, ValueError):
            raise KeyFileError("key file: no private_key") from None
    if len(secret) != 32:
        raise SystemExit("key file: private_key must be 32 bytes")
    key["_secret"] = secret
    return key


def _write_secret(path: Path, obj: dict, overwrite: bool) -> None:
    """Write a key file 0600 from the first byte (no window where others can read it)."""
    if path.exists() and not overwrite:
        raise SystemExit(f"{path} exists; pass --force to overwrite")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(obj, indent=2) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def cmd_keygen(a) -> int:
    secret = sc.generate_secret()
    pub = sc.public_key(secret)
    kid = a.kid or f"{a.agent}-1"
    out = Path(a.out)
    if out.exists() and not a.force:
        raise SystemExit(f"{out} exists; pass --force to overwrite")
    meta = {"agent": a.agent, "kid": kid, "alg": sc.ALG}
    body = encrypt_key(meta, secret, new_passphrase()) if a.encrypt else {**meta, "private_key": sc.b64u(secret)}
    _write_secret(out, body, overwrite=a.force)
    print(json.dumps({"kid": kid, "alg": sc.ALG, "public_key": sc.b64u(pub)}, indent=2))
    print(f"# private key written to {out}" + (" (encrypted with your passphrase)" if a.encrypt else
                                                 " (keep it secret)")
          + f"; paste the object above under agents.{a.agent}.keys", file=sys.stderr)
    return 0


def cmd_protect(a) -> int:
    """Encrypt an existing plaintext key file in place."""
    path = Path(a.key)
    key = _load(str(path))
    if is_encrypted(key):
        print(f"{path} is already encrypted", file=sys.stderr)
        return 0
    secret = load_key(str(path))["_secret"]
    _write_secret(path, encrypt_key(key, secret, new_passphrase()), overwrite=True)
    print(f"# {path} is now encrypted. Copies of the old plaintext file (backups, other folders) "
          f"still hold the key: delete them, or rotate to a new key.", file=sys.stderr)
    return 0


def sign_packet(packet: dict, key: dict) -> dict:
    h = packet["handoff"]
    if h.get("from") != key["agent"]:
        raise SystemExit(f"key belongs to '{key['agent']}' but packet is from '{h.get('from')}'")
    sig = sc.sign_bytes(key["_secret"], sc.packet_signing_input(h))
    packet["signature"] = {"signer": key["agent"], "kid": key["kid"], "alg": sc.ALG,
                           "sig": sc.b64u(sig)}
    return packet


def planned_params(h: dict, action: str):
    """The `params` of the planned action named (or using tool) `action`."""
    for act in h.get("planned_actions") or []:
        if isinstance(act, dict) and action in (act.get("name"), act.get("tool")) \
                and isinstance(act.get("params"), dict):
            return act["params"]
    return None


def approve_packet(packet: dict, key: dict, action: str, expires_at: str | None,
                   params: dict | None = None) -> dict:
    h = packet["handoff"]
    appr = {"action": action, "approver": key["agent"]}
    if expires_at:
        appr["expires_at"] = expires_at
    if params is not None:
        appr["params"] = json.loads(json.dumps(params))  # a copy, never a shared reference
    msg = sc.approval_signing_input(appr, h)
    # A Touch ID key (synthe_touchid.signing_key) signs in the Secure Enclave, after a finger on the sensor.
    sig = key["_sign"](msg) if callable(key.get("_sign")) else sc.sign_bytes(key["_secret"], msg)
    appr.update(kid=key["kid"], sig=sc.b64u(sig))
    h.setdefault("authority", {}).setdefault("approvals", []).append(appr)
    packet.pop("signature", None)  # approvals changed: sender must (re)sign
    return packet


def detached_approval(packet: dict, key: dict, action: str, expires_at: str | None,
                      params: dict | None = None) -> dict:
    """An approval signed exactly like an embedded one, plus the handoff fields
    it is bound to (idempotency_key, from, to), as a standalone object."""
    scratch = json.loads(json.dumps(packet))
    approve_packet(scratch, key, action, expires_at, params)
    h = packet["handoff"]
    appr = scratch["handoff"]["authority"]["approvals"][-1]
    return {**appr, "idempotency_key": h.get("idempotency_key"), "from": h.get("from"), "to": h.get("to"),
            "handoff_id": h.get("id")}


def cmd_sign(a) -> int:
    _write(sign_packet(_load(a.packet), load_key(a.key)), a.out)
    return 0


def _approver_key(path: str) -> dict:
    key = load_key(path)
    if not is_encrypted(_load(path)):
        sys.stderr.write("warning: this approver key is a plaintext file. Anything running as you, an agent "
                         "included, can read it and approve on your behalf. Encrypt it: "
                         f"synthe-sign protect {path}\n")
    return key


def cmd_approve(a) -> int:
    packet = _load(a.packet)
    h = packet.get("handoff", {})
    params = None if a.no_params else planned_params(h, a.action)
    if getattr(a, "commit", None):
        if params is None:
            sys.stderr.write("--commit needs the planned params pinned (drop --no-params)\n")
            return 2
        params = {**params, "commit": a.commit}  # bind this approval to the commit the approver read
    sys.stderr.write(f"approving '{a.action}' as {a.key and _load(a.key).get('agent')} for handoff "
                     f"{h.get('id')} ({h.get('from')} -> {h.get('to')}): {h.get('purpose')}\n"
                     f"  params: {json.dumps(params) if params else '(none pinned)'}\n"
                     f"  expires: {a.expires_at or '(no expiry)'}\n")
    if a.detached:
        # v0.5: the same signed approval, delivered on its own to whatever
        # performs the effect, so the packet the claim is bound to never changes.
        if not a.out:
            sys.stderr.write("--detached needs --out APPROVAL.json\n")
            return 2
        _write(detached_approval(packet, _approver_key(a.key), a.action, a.expires_at, params), a.out)
        return 0
    _write(approve_packet(packet, _approver_key(a.key), a.action, a.expires_at, params), a.out)
    return 0


def cmd_verify(a) -> int:
    packet, registry = _load(a.packet), _load(a.registry)
    h = packet.get("handoff", {})
    report = {"backend": sc.BACKEND, "packet_signature": "absent", "approvals": []}
    ok = True
    sig = packet.get("signature")
    if isinstance(sig, dict):
        key = sc.find_key(registry, sig.get("signer"), sig.get("kid"))
        good = (key is not None and sig.get("signer") == h.get("from")
                and sc.verify_bytes(key, sc.packet_signing_input(h), sc.unb64u(sig.get("sig", ""))))
        report["packet_signature"] = "verified" if good else "INVALID"
        ok &= good
    for appr in (h.get("authority", {}) or {}).get("approvals", []) or []:
        if appr.get("sig") is None:
            report["approvals"].append({"action": appr.get("action"), "status": "unsigned"})
            continue
        good = sc.verify_approval(registry, appr.get("approver"), appr.get("kid"),
                                  sc.approval_signing_input(appr, h), sc.unb64u(appr["sig"]))
        report["approvals"].append({"action": appr.get("action"), "approver": appr.get("approver"),
                                    "status": "verified" if good else "INVALID"})
        ok &= good
    print(json.dumps(report, indent=2))
    return 0 if ok else 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Synthe packet/approval signing")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--agent", required=True)
    k.add_argument("--kid")
    k.add_argument("--out", required=True)
    k.add_argument("--force", action="store_true")
    k.add_argument("--encrypt", action="store_true",
                   help="seal the private key under a passphrase you type (use it for human approver keys)")
    pr = sub.add_parser("protect", help="encrypt an existing plaintext key file in place")
    pr.add_argument("key")
    s = sub.add_parser("sign")
    s.add_argument("packet")
    s.add_argument("--key", required=True)
    s.add_argument("--out")
    p = sub.add_parser("approve")
    p.add_argument("packet")
    p.add_argument("--key", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--expires-at")
    p.add_argument("--commit", help="pin the approval to this commit SHA (the one whose diff you read)")
    p.add_argument("--no-params", action="store_true",
                   help="do not pin the planned action's params into the approval")
    p.add_argument("--out")
    p.add_argument("--detached", action="store_true",
                   help="write the signed approval to --out on its own (for the effect executor) "
                        "instead of adding it to the packet")
    v = sub.add_parser("verify")
    v.add_argument("packet")
    v.add_argument("--registry", required=True)
    a = ap.parse_args(argv)
    return {"keygen": cmd_keygen, "sign": cmd_sign, "approve": cmd_approve,
            "verify": cmd_verify, "protect": cmd_protect}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
