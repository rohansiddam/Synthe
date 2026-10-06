#!/usr/bin/env python3
"""Synthe signing CLI (stdlib only; uses `cryptography` when installed).

  keygen   --agent ID [--kid KID] --out KEYFILE
           Write a private key file (JSON, chmod 600) and print the public
           registry entry to paste under agents.<ID>.keys.
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


def load_key(path: str) -> dict:
    key = _load(path)
    secret = sc.unb64u(key["private_key"])
    if len(secret) != 32:
        raise SystemExit("key file: private_key must be 32 bytes")
    key["_secret"] = secret
    return key


def cmd_keygen(a) -> int:
    secret = sc.generate_secret()
    pub = sc.public_key(secret)
    kid = a.kid or f"{a.agent}-1"
    out = Path(a.out)
    if out.exists() and not a.force:
        raise SystemExit(f"{out} exists; pass --force to overwrite")
    out.write_text(json.dumps({"agent": a.agent, "kid": kid, "alg": sc.ALG,
                               "private_key": sc.b64u(secret)}, indent=2) + "\n")
    os.chmod(out, 0o600)
    print(json.dumps({"kid": kid, "alg": sc.ALG, "public_key": sc.b64u(pub)}, indent=2))
    print(f"# private key written to {out} (keep it secret); "
          f"paste the object above under agents.{a.agent}.keys", file=sys.stderr)
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
    sig = sc.sign_bytes(key["_secret"], sc.approval_signing_input(appr, h))
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
        _write(detached_approval(packet, load_key(a.key), a.action, a.expires_at, params), a.out)
        return 0
    _write(approve_packet(packet, load_key(a.key), a.action, a.expires_at, params), a.out)
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
        key = sc.find_key(registry, appr.get("approver"), appr.get("kid"))
        good = key is not None and sc.verify_bytes(
            key, sc.approval_signing_input(appr, h), sc.unb64u(appr["sig"]))
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
            "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
