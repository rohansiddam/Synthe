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
  sign-registry    --registry REG.json --key OPKEY.json [--kid KID] [--out FILE] [--force]
           Sign a registry with an operator key (genesis-sign, or re-sign after
           editing the body; the rotation chain is preserved). --force re-signs
           after a legitimate body edit (the stale body signature is not
           verified; the chain still is). Defaults to signing the registry
           file in place.
  rotate-registry-key --registry REG.json --old-key OLD.json --new-key NEW.json
           [--new-kid KID] [--out FILE]
           The rotation ceremony: the current operator key attests the new key,
           extending the verifiable chain; the body is re-signed by the new key.
           Defaults to updating the registry file in place.
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
           report. (Full validation is handoff_check.py's job.) A signature
           from a revoked kid reports REVOKED and fails, even if it verifies.
  revoke-kid --registry REGISTRY --agent ID --kid KID --operator-key KEYFILE
           [--reason TEXT] [--revoked-at TS] [--out FILE]
           The revocation operator signs a revocation record for one (agent,
           kid) and appends it to the registry's revocation list. From then
           on every signature verification fails closed on that key. The
           operator key file must belong to the registry's designated
           revocation operator (designated on first use). Refuses when the
           kid is not on record, so a typo can't silently leave the leaked
           key valid. Revocation is scoped to (agent, kid): another agent's
           key with the same kid string is unaffected.
  rotate-operator --registry REGISTRY --operator-key OLDKEYFILE
           --new-operator-key NEWKEYFILE [--reason TEXT] [--out FILE]
           Retire the designated revocation operator key and designate a new
           one. The old public key is kept in revocation.past_operators
           (verify-only), so revocation records it signed keep
           authenticating: a routine rotation never un-revokes anything.
  revocations --registry REGISTRY
           List the designated operator, retired operator keys, the
           authenticated revocations, and any revocation records that fail
           authentication (forged or malformed: they revoke nothing, but
           the operator should know).
"""
from __future__ import annotations

import argparse
import datetime as dt
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
    sig = sc.sign_bytes(key["_secret"], sc.handoff_signing_input(h))  # v0.7: self-issued ones in their own domain
    packet["signature"] = {"signer": key["agent"], "kid": key["kid"], "alg": sc.ALG,
                           "sig": sc.b64u(sig)}
    return packet


def sign_topology(name: str, topo: dict, key: dict) -> dict:
    """Sign a team topology declaration (SPEC section 15) with a founder key.
    The signature covers the name, version, roles, edges, role capabilities
    and members, so any change to the topology requires re-signing. Returns
    the topology object with `signed_by`, `kid` and `sig` attached."""
    sig = sc.sign_bytes(key["_secret"], sc.topology_signing_input(name, topo))
    topo = {k: v for k, v in topo.items() if k not in ("signed_by", "kid", "sig")}
    topo.update(signed_by=key["agent"], kid=key["kid"], sig=sc.b64u(sig))
    return topo


def planned_params(h: dict, action: str):
    """The `params` of the planned action named (or using tool) `action`."""
    for act in h.get("planned_actions") or []:
        if isinstance(act, dict) and action in (act.get("name"), act.get("tool")) \
                and isinstance(act.get("params"), dict):
            return act["params"]
    return None


_APPROVAL_BUDGET_DIMS = ("tokens", "usd", "minutes")


def _approval_budget_pin(h: dict, budget: dict | None, policy: dict | None,
                         action: str) -> dict:
    """The complete budget ceiling an approval pins -- the EFFECTIVE budget the
    checker will compare the packet against.

    Per-dimension precedence: the approver's explicit `budget` (the tightest
    cap, what the approver names) wins; then the packet's explicit
    `authority.budget` (what the approver reviewed); then the receiver
    policy's `defaults.budget`, which fills exactly the dimensions the packet
    omits -- the same merge rule as `handoff_check.apply_receiver_defaults`,
    so the pin is unambiguous whenever the policy is supplied.

    A v2 approval with no budget pin caps nothing, so it authorizes nothing:
    signing is REFUSED unless a complete (tokens/usd/minutes) numeric
    non-negative budget can be determined. ValueError names the remedy.
    """
    if budget is not None and not isinstance(budget, dict):
        raise ValueError(
            f"cannot sign approval for '{action}': the explicit budget must be "
            f"a JSON object of budget dimensions, e.g. "
            f"'{{\"tokens\": 1000, \"usd\": 5, \"minutes\": 30}}'")
    pin: dict = {}
    packet_budget = (h.get("authority") or {}).get("budget")
    if isinstance(packet_budget, dict):
        for dim in _APPROVAL_BUDGET_DIMS:
            if dim in packet_budget:
                pin[dim] = packet_budget[dim]
    defaults_budget = ((policy or {}).get("defaults") or {}).get("budget")
    if isinstance(defaults_budget, dict):
        for dim in _APPROVAL_BUDGET_DIMS:
            if dim not in pin and dim in defaults_budget:
                pin[dim] = defaults_budget[dim]
    if isinstance(budget, dict):
        for dim in _APPROVAL_BUDGET_DIMS:
            if dim in budget:
                pin[dim] = budget[dim]  # the approver's explicit cap wins per dimension
    missing = [d for d in _APPROVAL_BUDGET_DIMS if d not in pin]
    bad = [d for d in _APPROVAL_BUDGET_DIMS
           if d in pin and (isinstance(pin[d], bool)
                            or not isinstance(pin[d], (int, float))
                            or pin[d] < 0)]
    if missing or bad:
        detail = []
        if missing:
            detail.append(f"missing dimensions: {', '.join(missing)}")
        if bad:
            detail.append(f"invalid dimensions (must be non-negative numbers): {', '.join(bad)}")
        raise ValueError(
            f"cannot sign approval for '{action}': no budget to bind ({'; '.join(detail)}). "
            f"The packet names no usable authority.budget, so name the budget you are authorizing: "
            f"budget={{'tokens': 1000, 'usd': 5, 'minutes': 30}} "
            f"(synthe-sign approve --budget '{{\"tokens\": 1000, \"usd\": 5, \"minutes\": 30}}'), "
            f"or pass the receiver policy whose defaults.budget the checker would apply.")
    return {d: pin[d] for d in _APPROVAL_BUDGET_DIMS}


def _approval_estimates(h: dict, action: str) -> dict | None:
    """The amount-like fields (`est_tokens`/`est_usd`/`est_minutes`) of the
    planned action this approval covers, if the plan names any."""
    for act in h.get("planned_actions") or []:
        if isinstance(act, dict) and action in (act.get("name"), act.get("tool")):
            est = {k: act[k] for k in ("est_tokens", "est_usd", "est_minutes") if k in act}
            return est or None
    return None


def approve_packet(packet: dict, key: dict, action: str, expires_at: str | None,
                   params: dict | None = None, budget: dict | None = None,
                   policy: dict | None = None) -> dict:
    h = packet["handoff"]
    appr = {"action": action, "approver": key["agent"]}
    if expires_at:
        appr["expires_at"] = expires_at
    if params is not None:
        appr["params"] = json.loads(json.dumps(params))  # a copy, never a shared reference
    # The approval binds the budget (and the approved action's cost estimates)
    # the approver reviewed: the packet's spend may only come down afterwards.
    # An explicit `budget` caps tighter than the packet states, per dimension;
    # otherwise the packet's own budget is what the approver authorizes; dims
    # the packet omits are pinned from the receiver policy's defaults.budget
    # (exactly what the checker will apply). Signing without a complete
    # budget to bind is refused: an unpinned approval would cap nothing.
    appr["budget"] = _approval_budget_pin(h, budget, policy, action)
    estimates = _approval_estimates(h, action)
    if estimates is not None:
        appr["estimates"] = estimates
    msg = sc.approval_signing_input(appr, h)
    # A Touch ID key (synthe_touchid.signing_key) signs in the Secure Enclave, after a finger on the sensor.
    sig = key["_sign"](msg) if callable(key.get("_sign")) else sc.sign_bytes(key["_secret"], msg)
    appr.update(kid=key["kid"], sig=sc.b64u(sig))
    h.setdefault("authority", {}).setdefault("approvals", []).append(appr)
    packet.pop("signature", None)  # approvals changed: sender must (re)sign
    return packet


def detached_approval(packet: dict, key: dict, action: str, expires_at: str | None,
                      params: dict | None = None, budget: dict | None = None,
                      policy: dict | None = None) -> dict:
    """An approval signed exactly like an embedded one, plus the handoff fields
    it is bound to (idempotency_key, from, to), as a standalone object."""
    scratch = json.loads(json.dumps(packet))
    approve_packet(scratch, key, action, expires_at, params, budget, policy)
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
    budget = None
    if getattr(a, "budget", None):
        try:
            budget = json.loads(a.budget)
        except ValueError:
            sys.stderr.write("--budget must be JSON, e.g. '{\"tokens\":1000,\"usd\":5,\"minutes\":60}'\n")
            return 2
        if not isinstance(budget, dict):
            sys.stderr.write("--budget must be a JSON object of budget dimensions\n")
            return 2
    pinned: dict | None = None
    try:
        # The CLI has no receiver policy: the budget comes from --budget and/or
        # the packet's own authority.budget. Refusing here (not deep inside the
        # signer) keeps the failure message in front of the approver.
        pinned = _approval_budget_pin(h, budget, None, a.action)
    except ValueError as e:
        sys.stderr.write(f"{e}\n")
        return 2
    sys.stderr.write(f"approving '{a.action}' as {a.key and _load(a.key).get('agent')} for handoff "
                     f"{h.get('id')} ({h.get('from')} -> {h.get('to')}): {h.get('purpose')}\n"
                     f"  params: {json.dumps(params) if params else '(none pinned)'}\n"
                     f"  budget: {json.dumps(pinned)} (the approval caps the spend at this)\n"
                     f"  expires: {a.expires_at or '(no expiry)'}\n")
    if a.detached:
        # v0.5: the same signed approval, delivered on its own to whatever
        # performs the effect, so the packet the claim is bound to never changes.
        if not a.out:
            sys.stderr.write("--detached needs --out APPROVAL.json\n")
            return 2
        _write(detached_approval(packet, _approver_key(a.key), a.action, a.expires_at, params, budget), a.out)
        return 0
    _write(approve_packet(packet, _approver_key(a.key), a.action, a.expires_at, params, budget), a.out)
    return 0


def cmd_sign_registry(a) -> int:
    """Sign a registry file with an operator key. An unsigned registry gets a
    genesis signature (a self-issued chain of length 1). An already-signed
    registry is verified first, then re-signed with the same operator key,
    preserving the rotation chain (use this after editing the body)."""
    key = load_key(a.key)
    reg = _load(a.registry)
    try:
        if isinstance(reg.get("signature"), dict):
            kid = reg["signature"].get("kid")
            if a.kid and a.kid != kid:
                sys.stderr.write(f"note: ignoring --kid {a.kid!r}: re-sign keeps the chain's "
                                 f"current kid {kid!r}\n")
            ok, info = sc.verify_registry_signature(reg)
            if not ok and not a.force:
                sys.stderr.write(f"refusing to sign: current registry signature invalid: {info}\n"
                                 f"  (If you edited the body legitimately, re-run with --force.)\n")
                return 2
            signed = sc.resign_registry(reg, key["_secret"], kid, force=a.force)
            sys.stderr.write(f"re-signed registry with operator key {kid!r} "
                             f"(chain length {len(signed['signature']['chain'])} preserved)"
                             f"{' --force: prior body signature not verified' if a.force and not ok else ''}\n")
        else:
            kid = a.kid or key.get("kid") or "op-1"
            signed = sc.sign_registry(reg, key["_secret"], kid)
            sys.stderr.write(f"signed registry with new operator key {kid!r} (genesis chain)\n"
                             f"  public key: {sc.b64u(sc.public_key(key['_secret']))}\n"
                             f"  Distribute this public key to verifiers out of band.\n")
    except ValueError as exc:
        sys.stderr.write(f"sign-registry failed: {exc}\n")
        return 2
    _write(signed, a.out)
    return 0


def cmd_rotate_registry_key(a) -> int:
    """The operator-key rotation ceremony: the current operator key attests the
    new key, the attestation extends the chain, and the body is re-signed by the
    new key. The existing chain and body signature are verified first."""
    old = load_key(a.old_key)
    new = load_key(a.new_key)
    new_kid = a.new_kid or new.get("kid") or "op-2"
    reg = _load(a.registry)
    try:
        rotated = sc.rotate_registry_key(reg, old["_secret"], new["_secret"], new_kid)
    except ValueError as exc:
        sys.stderr.write(f"rotation failed: {exc}\n")
        return 2
    chain = rotated["signature"]["chain"]
    sys.stderr.write(f"rotated registry operator key to {new_kid!r} "
                     f"(chain length {len(chain)}; supersedes {chain[-1]['supersedes']!r})\n")
    for e in chain:
        sys.stderr.write(f"  seq {e['seq']}: {e['kid']!r} {sc.b64u(sc.unb64u(e['public_key'])[:8])}...\n")
    _write(rotated, a.out)
    return 0


def cmd_verify(a) -> int:
    packet, registry = _load(a.packet), _load(a.registry)
    h = packet.get("handoff", {})
    report = {"backend": sc.BACKEND, "packet_signature": "absent", "approvals": []}
    ok = True
    sig = packet.get("signature")
    if isinstance(sig, dict):
        revoked = (sig.get("kid") is not None
                   and sc.kid_is_revoked(registry, sig.get("signer"), sig.get("kid")))
        key = None if revoked else sc.find_key(registry, sig.get("signer"), sig.get("kid"))
        good = (key is not None and sig.get("signer") == h.get("from")
                and sc.verify_bytes(key, sc.handoff_signing_input(h), sc.unb64u(sig.get("sig", ""))))
        report["packet_signature"] = "REVOKED" if revoked else ("verified" if good else "INVALID")
        ok &= good and not revoked
    for appr in (h.get("authority", {}) or {}).get("approvals", []) or []:
        if appr.get("sig") is None:
            report["approvals"].append({"action": appr.get("action"), "status": "unsigned"})
            continue
        revoked = (appr.get("kid") is not None
                   and sc.kid_is_revoked(registry, appr.get("approver"), appr.get("kid")))
        try:
            raw_sig = sc.unb64u(appr["sig"])
        except Exception:
            raw_sig = b""
        good = (not revoked and sc.verify_approval(registry, appr.get("approver"), appr.get("kid"),
                                                   sc.approval_signing_input(appr, h), raw_sig))
        status = "REVOKED" if revoked else ("verified" if good else "INVALID")
        if not revoked and not good:
            # Name the retired scheme explicitly: it was a real approval once,
            # it just predates the budget binding and cannot be honored now.
            old = sc.verify_approval(registry, appr.get("approver"), appr.get("kid"),
                                     sc.approval_signing_input_v1(appr, h), raw_sig)
            if old:
                status = "UNSUPPORTED_VERSION"
        elif good and not isinstance(appr.get("budget"), dict):
            # The signature is real, but a v2 approval that pins no budget caps
            # nothing: the checker rejects it as approval_budget_missing.
            status = "UNPINNED_BUDGET"
            good = False
        report["approvals"].append({"action": appr.get("action"), "approver": appr.get("approver"),
                                    "status": status})
        ok &= good and not revoked
    problems = sc.revocation_problems(registry)
    if problems:
        report["revocation_problems"] = problems
    print(json.dumps(report, indent=2))
    return 0 if ok and not problems else 2


def _write_registry_atomic(path: str, registry: dict) -> None:
    """Write the registry back atomically (tmp file + rename), so a crash
    mid-write can't leave half a revocation list."""
    target = Path(path)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(registry, indent=2) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, target)


def cmd_revoke_kid(a) -> int:
    registry = _load(a.registry)
    if not isinstance(registry, dict) or not isinstance(registry.get("agents"), dict):
        raise SystemExit("registry must be a JSON object with an 'agents' object")
    opkey = load_key(a.operator_key)
    op_agent, op_kid = opkey.get("agent"), opkey.get("kid")
    if not op_agent or not op_kid:
        raise SystemExit("operator key file must name its agent and kid")
    sec = registry.get("revocation")
    if sec is None:
        sec = registry["revocation"] = {}
    if not isinstance(sec, dict):
        raise SystemExit("registry 'revocation' section is malformed")
    designated = sec.get("operator")
    if not isinstance(designated, dict) or not designated.get("agent"):
        sec["operator"] = {"agent": op_agent, "kid": op_kid}
        print(f"# no revocation operator was designated: designating {op_agent} / {op_kid}. "
              f"Guard this key: whoever holds it can revoke any kid.",
              file=sys.stderr)
    elif designated.get("agent") != op_agent or designated.get("kid") != op_kid:
        raise SystemExit(f"this key ({op_agent} / {op_kid}) is not the designated revocation "
                         f"operator ({designated.get('agent')} / {designated.get('kid')}): refusing")
    # Fail closed at issuance: a revoked operator key cannot sign new revocations.
    if sc.kid_is_revoked(registry, op_agent, op_kid):
        raise SystemExit(f"operator key '{op_kid}' of '{op_agent}' is itself revoked: rotate the "
                         f"operator with `synthe-sign rotate-operator` before issuing revocations")
    # The kid must actually be on record: a typo'd kid must not silently leave
    # the leaked key valid while the operator believes it revoked.
    entry = registry["agents"].get(a.agent) or {}
    kids = [k.get("kid") for k in entry.get("keys", []) or [] if isinstance(k, dict)]
    if a.kid not in kids:
        raise SystemExit(f"no key '{a.kid}' registered for agent '{a.agent}' "
                         f"(registered kids: {kids or 'none'}): refusing")
    if sc.kid_is_revoked(registry, a.agent, a.kid):
        print(f"# key '{a.kid}' of '{a.agent}' is already revoked: nothing to do", file=sys.stderr)
        return 0
    revoked_at = a.revoked_at or dt.datetime.now(dt.timezone.utc).isoformat()
    record = sc.sign_revocation(
        sc.make_revocation(a.agent, a.kid, revoked_at, a.reason or "", op_kid),
        opkey["_secret"])
    recs = sec.get("revoked_kids")
    if not isinstance(recs, list):
        recs = sec["revoked_kids"] = []
    # Replace any earlier entry for the same (agent, kid) (e.g. an
    # unauthenticated one someone wrote by hand); the new operator-signed
    # record is authoritative. A different agent's same kid string is a
    # different key and is left alone.
    recs[:] = [r for r in recs
               if not (isinstance(r, dict) and r.get("kid") == a.kid
                       and r.get("agent") == a.agent)] + [record]
    _write_registry_atomic(a.out or a.registry, registry)
    print(f"# revoked kid '{a.kid}' of '{a.agent}' (operator {op_agent} / {op_kid})",
          file=sys.stderr)
    _write(record, None)
    return 0


def cmd_revocations(a) -> int:
    registry = _load(a.registry)
    report = {"operator": sc.revocation_operator(registry),
              "past_operators": sc.revocation_past_operators(registry),
              "revoked_kids": sc.authenticated_revocations(registry),
              "problems": sc.revocation_problems(registry)}
    print(json.dumps(report, indent=2))
    return 0 if not report["problems"] else 2


def cmd_rotate_operator(a) -> int:
    """Retire the designated revocation operator key and designate a new one.

    The old public key is kept in revocation.past_operators (verify-only),
    so revocation records it signed keep authenticating: a routine rotation
    must never un-revoke anything. The new key must be a registered Ed25519
    key that is not itself revoked."""
    registry = _load(a.registry)
    if not isinstance(registry, dict) or not isinstance(registry.get("agents"), dict):
        raise SystemExit("registry must be a JSON object with an 'agents' object")
    oldkey = load_key(a.operator_key)
    newkey = load_key(a.new_operator_key)
    old_agent, old_kid = oldkey.get("agent"), oldkey.get("kid")
    new_agent, new_kid = newkey.get("agent"), newkey.get("kid")
    if not old_agent or not old_kid:
        raise SystemExit("old operator key file must name its agent and kid")
    if not new_agent or not new_kid:
        raise SystemExit("new operator key file must name its agent and kid")
    if (old_agent, old_kid) == (new_agent, new_kid):
        raise SystemExit("old and new operator keys are the same: nothing to rotate")
    sec = registry.get("revocation")
    if not isinstance(sec, dict):
        raise SystemExit("registry has no 'revocation' section to rotate")
    designated = sec.get("operator")
    if (not isinstance(designated, dict)
            or designated.get("agent") != old_agent or designated.get("kid") != old_kid):
        raise SystemExit(f"key ({old_agent} / {old_kid}) is not the designated revocation "
                         f"operator ({(designated or {}).get('agent')} / "
                         f"{(designated or {}).get('kid')}): refusing")
    # The new key must be on record as a usable Ed25519 key, and not revoked.
    _, new_raw = sc._raw_find_key_with_kid(registry, new_agent, new_kid)
    if new_raw is None:
        raise SystemExit(f"new operator key '{new_kid}' is not a registered Ed25519 key of "
                         f"agent '{new_agent}': register it first, then rotate")
    if sc.kid_is_revoked(registry, new_agent, new_kid):
        raise SystemExit(f"new operator key '{new_kid}' of '{new_agent}' is revoked: refusing")
    # Retire the old public key into past_operators (verify-only for old
    # records). Prefer the registry's copy; fall back to the key file.
    _, old_raw = sc._raw_find_key_with_kid(registry, old_agent, old_kid)
    if old_raw is None:
        old_raw = sc.public_key(oldkey["_secret"])
    past = sec.get("past_operators")
    if not isinstance(past, list):
        past = sec["past_operators"] = []
    if not any(isinstance(o, dict) and o.get("kid") == old_kid for o in past):
        past.append({
            "agent": old_agent, "kid": old_kid,
            "public_key": sc.b64u(old_raw),
            "retired_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "reason": a.reason or "operator key rotation",
        })
    sec["operator"] = {"agent": new_agent, "kid": new_kid}
    _write_registry_atomic(a.out or a.registry, registry)
    print(f"# rotated revocation operator: {old_agent} / {old_kid} -> "
          f"{new_agent} / {new_kid}; old public key kept in "
          f"revocation.past_operators so past revocations keep verifying",
          file=sys.stderr)
    return 0


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
    p.add_argument("--budget",
                   help="explicit budget cap as JSON, e.g. '{\"tokens\":1000,\"usd\":5,\"minutes\":60}'; "
                        "wins per dimension over the packet's own authority.budget. REQUIRED when the "
                        "packet names no authority.budget: an approval is never signed without a "
                        "budget to bind")
    p.add_argument("--out")
    p.add_argument("--detached", action="store_true",
                   help="write the signed approval to --out on its own (for the effect executor) "
                        "instead of adding it to the packet")
    v = sub.add_parser("verify")
    v.add_argument("packet")
    v.add_argument("--registry", required=True)
    r = sub.add_parser("revoke-kid", help="operator: revoke one registered kid")
    r.add_argument("--registry", required=True, help="registry JSON file (updated in place)")
    r.add_argument("--agent", required=True, help="agent that owns the kid")
    r.add_argument("--kid", required=True, help="kid to revoke")
    r.add_argument("--operator-key", required=True, help="the revocation operator's key file")
    r.add_argument("--reason", default="", help="why the key is revoked (audit trail)")
    r.add_argument("--revoked-at", help="ISO-8601 timestamp (default: now, UTC)")
    r.add_argument("--out", help="write the updated registry here instead of in place")
    l = sub.add_parser("revocations", help="list the revocation operator and authenticated revocations")
    l.add_argument("--registry", required=True)
    ro = sub.add_parser("rotate-operator",
                        help="operator: retire the designated revocation key and designate a new one")
    ro.add_argument("--registry", required=True, help="registry JSON file (updated in place)")
    ro.add_argument("--operator-key", required=True,
                    help="the CURRENT designated revocation operator's key file")
    ro.add_argument("--new-operator-key", required=True,
                    help="the new operator's key file (must be a registered, unrevoked Ed25519 key)")
    ro.add_argument("--reason", default="", help="why the operator key is being rotated (audit trail)")
    ro.add_argument("--out", help="write the updated registry here instead of in place")
    sr = sub.add_parser("sign-registry",
                        help="sign a registry file with an operator key (genesis-sign or re-sign)")
    sr.add_argument("--registry", required=True, help="registry JSON file to sign")
    sr.add_argument("--key", required=True, help="operator key file (synthe-sign keygen output)")
    sr.add_argument("--kid", help="operator key id (default: the key file's kid, else 'op-1')")
    sr.add_argument("--force", action="store_true",
                    help="re-sign after a legitimate body edit: skip verification of the "
                         "stale body signature (the rotation chain is still verified)")
    sr.add_argument("--out", help="write the signed registry here (default: overwrite --registry)")
    rr = sub.add_parser("rotate-registry-key",
                        help="rotate the registry operator key: old key attests the new key")
    rr.add_argument("--registry", required=True, help="signed registry JSON file")
    rr.add_argument("--old-key", required=True, help="current operator key file")
    rr.add_argument("--new-key", required=True, help="new operator key file")
    rr.add_argument("--new-kid", help="key id for the new operator key (default: key file's kid, else 'op-2')")
    rr.add_argument("--out", help="write the rotated registry here (default: overwrite --registry)")
    a = ap.parse_args(argv)
    if a.cmd == "sign-registry" and not a.out:
        a.out = a.registry
    if a.cmd == "rotate-registry-key" and not a.out:
        a.out = a.registry
    return {"keygen": cmd_keygen, "sign": cmd_sign, "approve": cmd_approve,
            "verify": cmd_verify, "protect": cmd_protect, "revoke-kid": cmd_revoke_kid,
            "revocations": cmd_revocations, "rotate-operator": cmd_rotate_operator,
            "sign-registry": cmd_sign_registry,
            "rotate-registry-key": cmd_rotate_registry_key}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
