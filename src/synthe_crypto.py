#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthe signing primitives (stdlib only).

- Canonical JSON for signing (sorted keys, no insignificant whitespace,
  UTF-8, integral floats written as integers). This matches RFC 8785 (JCS)
  for every value Synthe packets use: strings, integers, booleans, null,
  arrays, objects, and floats that are whole numbers. Non-integral floats
  use Python's shortest round-trip repr, which agrees with JCS except for
  exponent formatting of very large/small magnitudes. Keys are sorted by
  code point (JCS sorts by UTF-16 unit); the two differ only for keys
  containing characters outside the Basic Multilingual Plane.
- Ed25519 (RFC 8032). If the `cryptography` package is installed it is
  used; otherwise a pure-Python implementation of the RFC 8032 reference
  algorithm is used. Verification is safe in pure Python (it only touches
  public data). Pure-Python *signing* is not constant-time: fine for
  development and CI fixtures, but install `cryptography` (or sign with an
  HSM/KMS) for production keys.
- ES256 (ECDSA P-256 with SHA-256, signature r||s) for approvals only: the
  Touch ID key (integrations/macos/touchid) lives in a Mac's Secure Enclave,
  which signs P-256 and nothing else. Verify-only here; pure Python unless
  `cryptography` is installed. A key's algorithm comes from the registry,
  never from the signature or approval, so one can't be passed off as the
  other.

Encodings: keys and signatures are unpadded base64url strings.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import math
import os

ALG = "Ed25519"
ALG_ES256 = "ES256"
APPROVAL_ALGS = (ALG, ALG_ES256)  # packets and receipts stay Ed25519
PACKET_SIG_DOMAIN = "synthe/handoff-signature/v1"
# v0.7: a handoff the broker issued under a human-signed lane grant (it carries `issued_under_grant`).
# Its own domain, so a checker that predates self-issued tasks fails closed on one (signature_invalid),
# and stripping or adding the field breaks the signature.
SELF_ISSUED_SIG_DOMAIN = "synthe/handoff-signature/self-issued/v1"
# A lane grant's human signature (synthe_lane_templates.py); the checker verifies the grant a
# self-issued handoff embeds with the same rule.
APPROVAL_TEMPLATE_DOMAIN = "synthe/approval-template/v1"
APPROVAL_SIG_DOMAIN = "synthe/approval-signature/v2"
# Retired approval scheme: never signs anymore. Verified only so an approval
# signed before the budget binding is rejected with
# `approval_version_unsupported`, not a confusing `approval_signature_invalid`.
APPROVAL_SIG_DOMAIN_V1 = "synthe/approval-signature/v1"
RECEIPT_SIG_DOMAIN = "synthe/effect-receipt/v1"
TOPOLOGY_SIG_DOMAIN = "synthe/topology-signature/v1"

REGISTRY_SIG_DOMAIN = "synthe/registry-signature/v1"
REGISTRY_ROTATION_DOMAIN = "synthe/registry-rotation/v1"
REGISTRY_SIGNATURE_BLOCK = "signature"  # top-level key holding the registry's signature


# --------------------------------------------------------------------------
# encoding helpers

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64url string")
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _normalize(value):
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/Infinity cannot be canonicalized")
        return int(value) if value.is_integer() else value
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    raise ValueError(f"cannot canonicalize {type(value).__name__}")


def canonical_json(value) -> bytes:
    return json.dumps(_normalize(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------
# Ed25519 — pure Python, after the RFC 8032 section 6 reference code

_p = 2 ** 255 - 19
_d = -121665 * pow(121666, _p - 2, _p) % _p
_q = 2 ** 252 + 27742317777372353535851937790883648493
_SQRT_M1 = pow(2, (_p - 1) // 4, _p)


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _q


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    return ((P[0] * Q[2] - Q[0] * P[2]) % _p == 0
            and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0)


def _recover_x(y: int, sign: int):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _SQRT_M1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P) -> bytes:
    zinv = _inv(P[2])
    x, y = P[0] * zinv % _p, P[1] * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def _expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _py_public(secret: bytes) -> bytes:
    a, _ = _expand(secret)
    return _compress(_mul(a, _G))


def _py_sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_mul(a, _G))
    r = _sha512_modq(prefix + msg)
    Rs = _compress(_mul(r, _G))
    h = _sha512_modq(Rs + A + msg)
    s = (r + h * a) % _q
    return Rs + int.to_bytes(s, 32, "little")


def _py_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _q:
        return False
    h = _sha512_modq(sig[:32] + public + msg)
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


try:  # optional fast/constant-time backend
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.exceptions import InvalidSignature  # type: ignore
    BACKEND = "cryptography"
except Exception:  # pragma: no cover - depends on environment
    Ed25519PrivateKey = Ed25519PublicKey = InvalidSignature = None
    BACKEND = "pure-python"


def public_key(secret: bytes) -> bytes:
    if Ed25519PrivateKey is not None:
        from cryptography.hazmat.primitives import serialization  # type: ignore
        return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _py_public(secret)


def sign_bytes(secret: bytes, msg: bytes) -> bytes:
    if Ed25519PrivateKey is not None:
        return Ed25519PrivateKey.from_private_bytes(secret).sign(msg)
    return _py_sign(secret, msg)


def verify_bytes(public: bytes, msg: bytes, sig: bytes) -> bool:
    if Ed25519PublicKey is not None:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except Exception:
            return False
    return _py_verify(public, msg, sig)


def generate_secret() -> bytes:
    return os.urandom(32)


# --------------------------------------------------------------------------
# Synthe payloads

def packet_signing_input(handoff: dict) -> bytes:
    """Bytes a sender signs: domain tag + canonical JSON of the handoff object."""
    return PACKET_SIG_DOMAIN.encode() + b"\n" + canonical_json(handoff)


def self_issued_signing_input(handoff: dict) -> bytes:
    """Bytes the task issuer signs for a self-issued handoff (v0.7): its own domain tag + canonical JSON."""
    return SELF_ISSUED_SIG_DOMAIN.encode() + b"\n" + canonical_json(handoff)


def handoff_signing_input(handoff: dict) -> bytes:
    """The signing input a handoff's signature covers, chosen by the SIGNED handoff itself: one that holds
    `issued_under_grant` is self-issued (v0.7), anything else is an ordinary packet. Removing the field
    from an issued handoff, or adding it to an ordinary one, therefore breaks its signature."""
    if isinstance(handoff, dict) and "issued_under_grant" in handoff:
        return self_issued_signing_input(handoff)
    return packet_signing_input(handoff)


def approval_template_signing_input(grant: dict) -> bytes:
    """Bytes a human signs for a lane grant: domain tag + canonical JSON of everything but `sig`."""
    return APPROVAL_TEMPLATE_DOMAIN.encode() + b"\n" + canonical_json(
        {k: v for k, v in grant.items() if k != "sig"})


def approval_signing_input(approval: dict, handoff: dict) -> bytes:
    """Bytes an approver signs (v2). The approval is bound to one handoff's
    idempotency key and its sender/receiver, so it cannot be replayed onto a
    different handoff, and to the budget -- plus the approved action's cost
    estimates -- the approver reviewed, so the spend it authorizes cannot be
    stretched afterwards: the packet's budget may only come down under a v2
    approval, never up (checked as `approval_budget_exceeded` /
    `approval_estimates_exceeded`).

    `budget` and `estimates` are pinned on the approval object itself (never
    read off the handoff here), because the checker's copy of the handoff has
    receiver defaults applied, and a detached approval is verified against a
    stub handoff that carries no budget at all.
    """
    payload = {
        "action": approval.get("action"),
        "approver": approval.get("approver"),
        "expires_at": approval.get("expires_at"),
        "idempotency_key": handoff.get("idempotency_key"),
        "from": handoff.get("from"),
        "to": handoff.get("to"),
        "budget": approval.get("budget"),
        "estimates": approval.get("estimates"),
    }
    # v0.4: an approval may pin the exact effect parameters (branch, remote,
    # recipients...). Only included when present, so approvals without pins
    # verify unchanged.
    if approval.get("params") is not None:
        payload["params"] = approval.get("params")
    return APPROVAL_SIG_DOMAIN.encode() + b"\n" + canonical_json(payload)


def approval_signing_input_v1(approval: dict, handoff: dict) -> bytes:
    """The retired v1 approval signing input. Never used to sign anything new:
    only to recognize an approval signed before the budget binding, so the
    checker rejects it with `approval_version_unsupported` instead of a
    confusing `approval_signature_invalid`."""
    payload = {
        "action": approval.get("action"),
        "approver": approval.get("approver"),
        "expires_at": approval.get("expires_at"),
        "idempotency_key": handoff.get("idempotency_key"),
        "from": handoff.get("from"),
        "to": handoff.get("to"),
    }
    if approval.get("params") is not None:
        payload["params"] = approval.get("params")
    return APPROVAL_SIG_DOMAIN_V1.encode() + b"\n" + canonical_json(payload)


def receipt_signing_input(receipt: dict) -> bytes:
    """Bytes an effect executor signs for one effect receipt (everything but
    the signature itself). Domain-separated from packets and approvals."""
    body = {k: v for k, v in receipt.items() if k != "sig"}
    return RECEIPT_SIG_DOMAIN.encode() + b"\n" + canonical_json(body)


_TOPOLOGY_SIG_FIELDS = ("signed_by", "kid", "sig")


def topology_signing_input(name: str, topo: dict) -> bytes:
    """Bytes a founder signs for a team topology: domain tag + canonical JSON
    of the topology payload with the registry key bound as its name. Changing
    anything (roles, edges, role capabilities, members, version) changes these
    bytes, so any topology change requires a fresh signature."""
    payload = {k: v for k, v in topo.items() if k not in _TOPOLOGY_SIG_FIELDS}
    payload["name"] = name
    return TOPOLOGY_SIG_DOMAIN.encode() + b"\n" + canonical_json(payload)


def _raw_find_key_with_kid(registry: dict | None, agent_id: str, kid: str | None):
    """(effective_kid, raw public key) for agent_id/kid, or (None, None).

    This is the raw registry lookup: it does NOT consult the revocation list.
    It exists so revocation records themselves can be authenticated against
    the operator's registered key (authenticating a revocation must not depend
    on the revocation list, or nothing could ever be revoked). Everyone else
    should use find_key, which fails closed on revoked kids."""
    if not registry:
        return None, None
    entry = registry.get("agents", {}).get(agent_id) or {}
    for k in entry.get("keys", []) or []:
        if not isinstance(k, dict) or k.get("alg", ALG) != ALG:
            continue
        if kid is None or k.get("kid") == kid:
            try:
                raw = unb64u(k.get("public_key", ""))
            except Exception:
                continue
            if len(raw) == 32:
                return k.get("kid"), raw
    return None, None


def find_key(registry: dict | None, agent_id: str, kid: str | None):
    """Return the raw public key for agent_id/kid from the registry, or None.

    A revoked (agent, kid) is no longer on record: this returns None for it
    even though the signature would otherwise verify (fail closed). Callers
    that want to tell "revoked" apart from "unknown" check kid_is_revoked()
    first."""
    ekid, raw = _raw_find_key_with_kid(registry, agent_id, kid)
    if raw is None:
        return None
    if kid_is_revoked(registry, agent_id, ekid):
        return None
    return raw


def agent_kids(registry: dict | None, agent_id: str) -> list:
    """Every Ed25519 kid registered for the agent, revoked or not, in registry
    order. For diagnostics (naming a revoked key when no kid was given); not
    for picking a signing key."""
    if not registry or not isinstance(agent_id, str):
        return []
    entry = registry.get("agents", {}).get(agent_id) or {}
    return [k.get("kid") for k in entry.get("keys", []) or []
            if isinstance(k, dict) and k.get("alg", ALG) == ALG and isinstance(k.get("kid"), str)]


def usable_keys(registry: dict | None, agent_id: str) -> list:
    """The kids of the agent's registered Ed25519 keys that decode to 32 bytes
    and are not revoked. More than one means a signature must name its kid:
    find_key(kid=None) picks the first, which after an appended rotation is the
    old key. Revoked keys are not usable: after a rotation the single live key
    needs no kid, and a revoked key can never be picked by omission."""
    if not registry or not isinstance(agent_id, str):
        return []
    entry = registry.get("agents", {}).get(agent_id) or {}
    kids = []
    for k in entry.get("keys", []) or []:
        if not isinstance(k, dict) or k.get("alg", ALG) != ALG:
            continue
        if kid_is_revoked(registry, agent_id, k.get("kid")):
            continue
        try:
            if len(unb64u(k.get("public_key", ""))) == 32:
                kids.append(k.get("kid"))
        except Exception:
            continue
    return kids


# --------------------------------------------------------------------------
# ES256 (ECDSA over P-256, SHA-256): verification for Secure Enclave approval keys

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _p256_on_curve(P) -> bool:
    x, y = P
    return 0 <= x < _P256_P and 0 <= y < _P256_P and (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256_P == 0


def _p256_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    return x3, (lam * (x1 - x3) - y1) % _P256_P


def _p256_mul(k: int, P):
    R = None
    while k:
        if k & 1:
            R = _p256_add(R, P)
        P = _p256_add(P, P)
        k >>= 1
    return R


def p256_public_point(raw: bytes):
    """A 64-byte x||y public key (CryptoKit's rawRepresentation) as a curve point, or None."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 64:
        return None
    P = (int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    return P if _p256_on_curve(P) else None


def _py_es256_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    Q = p256_public_point(public)
    if Q is None or len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < _P256_N and 0 < s < _P256_N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _P256_N)
    X = _p256_add(_p256_mul(e * w % _P256_N, _P256_G), _p256_mul(r * w % _P256_N, Q))
    return X is not None and X[0] % _P256_N == r


def es256_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    """ECDSA P-256/SHA-256 over msg, with a 64-byte x||y key and a 64-byte r||s signature."""
    if p256_public_point(public) is None or not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        return False
    try:
        from cryptography.hazmat.primitives import hashes  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import ec  # type: ignore
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # type: ignore
    except Exception:  # pragma: no cover - depends on environment
        return _py_es256_verify(public, msg, sig)
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + bytes(public))
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _approval_keys(registry: dict | None, agent_id) -> list:
    """(kid, alg, raw) for each of the approver's well-formed approval keys.
    Revoked kids are skipped: verify_approval fails closed on them without any
    caller needing a separate check."""
    if not registry or not isinstance(agent_id, str):
        return []
    entry = registry.get("agents", {}).get(agent_id) or {}
    out = []
    for k in entry.get("keys", []) or []:
        if not isinstance(k, dict):
            continue
        if kid_is_revoked(registry, agent_id, k.get("kid")):
            continue
        alg = k.get("alg", ALG)
        try:
            raw = unb64u(k.get("public_key", ""))
        except Exception:
            continue
        if (alg == ALG and len(raw) == 32) or (alg == ALG_ES256 and p256_public_point(raw) is not None):
            out.append((k.get("kid"), alg, raw))
    return out


def usable_approval_keys(registry: dict | None, agent_id) -> list:
    """The kids of an approver's keys of either approval algorithm. More than one means an approval must
    name its kid (the Touch ID key and the passphrase key are usually both registered)."""
    return [kid for kid, _, _ in _approval_keys(registry, agent_id)]


def verify_approval(registry: dict | None, approver, kid, msg: bytes, sig: bytes) -> bool:
    """Verify an approval signature with the approver's registered key named by kid (or the only one).
    The algorithm is the registered key's: an Ed25519 key never accepts an ES256 signature, or back.
    Revoked kids never verify: _approval_keys skips them, so this fails closed on revocation at every
    call site (checker, synthe-sign verify, lane templates) with no extra check needed."""
    keys = _approval_keys(registry, approver)
    if kid is None and len(keys) > 1:
        return False
    for k_kid, alg, raw in keys:
        if kid is None or k_kid == kid:
            return verify_bytes(raw, msg, sig) if alg == ALG else es256_verify(raw, msg, sig)
    return False


# --------------------------------------------------------------------------
# Key revocation
#
# A leaked key stays dangerous until it stops verifying. The registry's
# `revocation` section names one revocation operator (an ordinary registered
# Ed25519 agent key) and lists revocation records, each signed by that
# operator key, so revocations can't be forged. Every signature verification
# consults the list and fails closed on a revoked kid, even when the
# signature itself is valid.
#
#   "revocation": {
#     "operator": {"agent": "ops", "kid": "ops-1"},
#     "past_operators": [   # retired operator keys, verify-only: old records
#       {"agent": "ops", "kid": "ops-0", "public_key": "<base64url>",
#        "retired_at": "2026-10-13T00:00:00+00:00", "reason": "routine rotation"}
#     ],
#     "revoked_kids": [
#       {"v": 1, "agent": "worker", "kid": "worker-3",
#        "revoked_at": "2026-10-12T21:30:00+00:00", "reason": "key leaked in CI logs",
#        "operator_kid": "ops-1", "sig": "<base64url>"}
#     ]
#   }
#
# Revocation is scoped to (agent, kid): kids are only unique per agent.
#
# Rotating the operator key must retire the old public key into
# `past_operators` (the `synthe-sign rotate-operator` ceremony does this),
# otherwise records it signed stop authenticating. They still revoke (fail
# closed: enforced_revocations) and revocation_problems() reports them. Retired keys verify old records only; they can
# never issue new revocations.
#
# What this does NOT do: it can't detect a revocation record being *removed*
# from the registry file (rollback) — that needs the registry itself to be
# tamper-evident: the registry must be signed and pinned per the
# signed-registry work (tracked separately). Until then, deleting a
# revocation record stays undetected. The registry remains
# operator-controlled; a writer who can delete agent keys outright can
# do worse than delete a revocation.

REVOCATION_SIG_DOMAIN = "synthe/key-revocation/v1"
REVOCATION_RECORD_V = 1


def revocation_section(registry):
    """The registry's `revocation` object, or None when the deployment has no
    revocation authority configured (then nothing is ever revoked)."""
    if not isinstance(registry, dict):
        return None
    sec = registry.get("revocation")
    return sec if isinstance(sec, dict) else None


def revocation_operator(registry):
    """The (agent, kid) designated to sign revocations, or None. The operator
    key is an ordinary registered Ed25519 agent key; `kid` may be absent when
    the operator agent has exactly one key."""
    sec = revocation_section(registry)
    op = (sec or {}).get("operator")
    if not isinstance(op, dict) or not isinstance(op.get("agent"), str) or not op.get("agent"):
        return None
    kid = op.get("kid")
    return (op["agent"], kid if isinstance(kid, str) and kid else None)


def revocation_signing_input(record: dict) -> bytes:
    """Bytes the revocation operator signs. Domain-separated from packets,
    approvals and receipts; the operator kid is bound in, so a record can't be
    transplanted onto a different operator key."""
    body = {"v": REVOCATION_RECORD_V, "agent": record.get("agent"), "kid": record.get("kid"),
            "revoked_at": record.get("revoked_at"), "reason": record.get("reason"),
            "operator_kid": record.get("operator_kid")}
    return REVOCATION_SIG_DOMAIN.encode() + b"\n" + canonical_json(body)


def make_revocation(agent: str, kid: str, revoked_at: str, reason: str, operator_kid) -> dict:
    """An unsigned revocation record. `revoked_at` should be an ISO-8601 UTC
    timestamp; `reason` is free text for the audit trail."""
    return {"v": REVOCATION_RECORD_V, "agent": str(agent), "kid": str(kid),
            "revoked_at": str(revoked_at), "reason": str(reason or ""),
            "operator_kid": operator_kid}


def sign_revocation(record: dict, operator_secret: bytes) -> dict:
    """The revocation record with the operator's signature attached."""
    out = dict(record)
    out["sig"] = b64u(sign_bytes(operator_secret, revocation_signing_input(record)))
    return out


def revocation_past_operators(registry) -> list:
    """The retired operator public keys, in file order. These are used ONLY
    to authenticate revocation records they signed before being rotated out:
    a routine operator-key rotation must never un-revoke anything. A record
    signed by a retired key only authenticates when its revoked_at is not
    later than the key's retired_at, so retired keys can never issue new
    revocations. They are never used for any other verification."""
    sec = revocation_section(registry)
    ops = (sec or {}).get("past_operators") or []
    if not isinstance(ops, list):
        return []
    return [o for o in ops if isinstance(o, dict)]


def past_operator_entry(registry, kid):
    """The past_operators entry for a retired operator kid, or None."""
    if not isinstance(kid, str) or not kid:
        return None
    for o in revocation_past_operators(registry):
        if o.get("kid") == kid:
            return o
    return None


def past_operator_key(registry, kid):
    """The raw public key of a retired operator kid, or None. Consulted only
    by verify_revocation_record, and only when the record was not signed by
    the currently designated operator key."""
    o = past_operator_entry(registry, kid)
    if o is None:
        return None
    try:
        raw = unb64u(o.get("public_key", ""))
    except Exception:
        return None
    return raw if len(raw) == 32 else None


def _parse_ts(text):
    """An ISO-8601 timestamp as an aware datetime, or None. Naive values are
    read as UTC; garbage fails closed (callers reject the record)."""
    try:
        d = dt.datetime.fromisoformat(str(text))
    except Exception:
        return None
    return d if d.tzinfo is not None else d.replace(tzinfo=dt.timezone.utc)


def verify_revocation_record(registry, record) -> bool:
    """True when `record` is well-formed and carries an authorized operator
    signature over exactly these fields. This proves who issued the record;
    enforcement does not depend on it (enforced_revocations fails closed on
    unauthenticated records, and revocation_problems() reports them).

    The signer must be the *designated* operator kid: a record signed by some
    other key of the operator agent does not authenticate, even if that key
    is registered. The designated key is resolved raw, deliberately bypassing
    the revocation list, so past revocations keep authenticating even after
    the operator key itself is revoked (no chicken-and-egg).

    Records signed before a rotation authenticate against the retired key in
    `revocation.past_operators`: routine operator-key rotation must never
    un-revoke anything. Retired keys cannot issue new revocations — new
    records must carry the currently designated kid."""
    if not isinstance(record, dict) or record.get("v") != REVOCATION_RECORD_V:
        return False
    for field in ("agent", "kid", "revoked_at", "operator_kid"):
        if not isinstance(record.get(field), str) or not record.get(field):
            return False
    if not isinstance(record.get("reason"), str) or not isinstance(record.get("sig"), str):
        return False
    op = revocation_operator(registry)
    if op is None:
        return False
    rkid = record["operator_kid"]
    designated = op[1]
    if designated is None:
        # Operator kid omitted: only valid when the operator agent has exactly
        # one key, which the record must name.
        only = agent_kids(registry, op[0])
        designated = only[0] if len(only) == 1 else None
        if designated is None:
            return False
    if rkid == designated:
        _, raw = _raw_find_key_with_kid(registry, op[0], designated)
    else:
        # Retired operator key: authenticates OLD records only. The record's
        # revoked_at must not be later than the key's retirement, so a retired
        # key can never issue a *new* revocation after being rotated out.
        # (Timestamps are signer-supplied, so this is a guardrail against
        # operator error and stale tooling, not against an attacker who also
        # holds registry write access — that attacker already owns the file.)
        past = past_operator_entry(registry, rkid)
        raw = past_operator_key(registry, rkid) if past is not None else None
        if raw is not None:
            issued = _parse_ts(record["revoked_at"])
            retired = _parse_ts(past.get("retired_at", ""))
            if issued is None or retired is None or issued > retired:
                return False
    if raw is None:
        return False
    try:
        sig = unb64u(record["sig"])
    except Exception:
        return False
    return verify_bytes(raw, revocation_signing_input(record), sig)


def authenticated_revocations(registry) -> list:
    """The revocation records that verify against the designated operator or
    a retired operator key (past_operators), in file order. These are the
    records whose issuer is proven; enforcement also honors the rest (see
    enforced_revocations)."""
    sec = revocation_section(registry)
    recs = (sec or {}).get("revoked_kids") or []
    if not isinstance(recs, list):
        return []
    return [r for r in recs if verify_revocation_record(registry, r)]


def enforced_revocations(registry) -> list:
    """Every well-formed revocation record (non-empty string agent and kid),
    authenticated or not, in file order. Enforcement fails closed: a record
    whose signature cannot be checked (forged, or signed by an operator key
    that has since left the registry without being retired into
    past_operators) still revokes. Honoring it costs nothing: whoever can
    write a record into the registry can already delete the key outright.
    Unauthenticated records are reported by revocation_problems()."""
    sec = revocation_section(registry)
    recs = (sec or {}).get("revoked_kids") or []
    if not isinstance(recs, list):
        return []
    return [r for r in recs if isinstance(r, dict)
            and isinstance(r.get("agent"), str) and r.get("agent")
            and isinstance(r.get("kid"), str) and r.get("kid")]


def revoked_key_map(registry) -> dict:
    """(agent, kid) -> the latest enforced revocation record for it.

    Revocation is scoped to the owning agent: kids are only unique per agent,
    so worker/k1 and boss/k1 are different keys and revoking one must never
    affect the other."""
    out = {}
    for r in enforced_revocations(registry):
        out[(r["agent"], r["kid"])] = r
    return out


def kid_is_revoked(registry, agent, kid) -> bool:
    """True when `agent`'s `kid` has a revocation record (see enforced_revocations).
    Consulted on every signature verification; a revoked key fails closed
    even if the signature is otherwise valid. A different agent's key with
    the same kid string is unaffected."""
    return (isinstance(agent, str) and isinstance(kid, str) and bool(kid)
            and (agent, kid) in revoked_key_map(registry))


def revocation_problems(registry) -> list:
    """Human-readable problems with the revocation section for the operator's
    audit trail: no operator designated, operator key not on record, or
    records that fail authentication (forged, or signed by an operator key
    that left the registry without being retired into past_operators). Those
    records are still enforced (fail closed), but their issuer is unproven
    and the operator should know."""
    sec = revocation_section(registry)
    if sec is None:
        return []
    problems = []
    op = revocation_operator(registry)
    recs = sec.get("revoked_kids") or []
    if not isinstance(recs, list):
        return ["revocation.revoked_kids must be a list"]
    if op is None:
        problems.append("no revocation operator designated: no revocation record can authenticate")
    else:
        _, raw = _raw_find_key_with_kid(registry, op[0], op[1])
        if raw is None:
            problems.append(f"designated revocation operator '{op[0]}' (kid={op[1]}) has no usable "
                            f"Ed25519 key on record: new revocation records cannot authenticate; "
                            f"records signed by retired operator keys survive only via "
                            f"revocation.past_operators")
    if not isinstance(sec.get("past_operators", []), list):
        problems.append("revocation.past_operators must be a list")
    for i, r in enumerate(recs):
        if not verify_revocation_record(registry, r):
            agent = r.get("agent") if isinstance(r, dict) else None
            kid = r.get("kid") if isinstance(r, dict) else None
            problems.append(f"revoked_kids[{i}] ({agent}/{kid}) fails authentication: still enforced "
                            f"(fail closed), but its issuer is unproven; re-issue it with "
                            f"synthe-sign revoke-kid or retire the signing key into past_operators")
    return problems

# Signed agent registry
#
# A registry file may carry a top-level "signature" block:
#
#   {"agents": {...},
#    "signature": {"alg": "Ed25519", "kid": "op-2",
#                  "sig": "<operator signs REGISTRY_SIG_DOMAIN + canonical(body)>",
#                  "chain": [ {"seq": 0, "kid": "op-1", "public_key": "<b64u>",
#                              "sig": "<op-1 self-issues the genesis attestation>"},
#                             {"seq": 1, "kid": "op-2", "public_key": "<b64u>",
#                              "supersedes": "op-1",
#                              "sig": "<op-1 signs REGISTRY_ROTATION_DOMAIN + canonical(attestation)>"},
#                             ... ]}}
#
# The chain makes key rotation verifiable: every operator key change is an
# attestation signed by the key it replaces, linked back to a genesis
# self-issuance. The loader verifies the whole chain, then verifies the body
# signature under the chain's current key, so rotating the key does not break
# verification of history and a tampered chain fails closed.
#
# Trust anchor honesty: the genesis entry is self-issued (anyone can mint
# one), so the FIRST time you accept a registry you must get the genesis
# operator key out of band (trust on first use). After that, every rotation
# is cryptographically bound to its predecessor: an attacker who steals the
# registry file but not the operator private key cannot add agents, remove
# agents, or rotate to their own key without detection.

def registry_body(reg: dict) -> dict:
    """The registry payload the signature covers: everything but the signature block."""
    return {k: v for k, v in reg.items() if k != REGISTRY_SIGNATURE_BLOCK}


def registry_signing_input(reg: dict) -> bytes:
    """Bytes the operator signs: domain tag + canonical JSON of the registry body."""
    return REGISTRY_SIG_DOMAIN.encode() + b"\n" + canonical_json(registry_body(reg))


def rotation_signing_input(attestation: dict) -> bytes:
    """Bytes an outgoing operator key signs to authorize its replacement."""
    body = {k: v for k, v in attestation.items() if k != "sig"}
    return REGISTRY_ROTATION_DOMAIN.encode() + b"\n" + canonical_json(body)


def _decode_b64u_field(value, what: str) -> bytes:
    try:
        return unb64u(value)
    except Exception:
        raise ValueError(f"bad base64url in {what}")


def _parse_genesis_pin(value: str):
    """Parse a genesis pin value into ("pubkey", 32-byte-key) or
    ("fingerprint", 32-byte-sha256-digest). Accepts the base64url encoding of
    the 32-byte genesis Ed25519 public key, or the 64-char hex sha256
    fingerprint of that key. Comment lines (#...) and blank lines are ignored
    so the value can come straight from a registry-genesis.key file. Raises
    ValueError on anything else."""
    text = "\n".join(
        line for line in value.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ).strip()
    if not text:
        raise ValueError("genesis pin is empty")
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        return ("fingerprint", bytes.fromhex(text))
    try:
        raw = unb64u(text)
    except Exception:
        raise ValueError(
            "genesis pin is neither base64url of a 32-byte Ed25519 public key "
            "nor a 64-char hex sha256 fingerprint of one")
    if len(raw) != 32:
        raise ValueError("genesis pin public key is not 32 bytes")
    return ("pubkey", raw)


def genesis_pin_matches(pin_value: str, genesis_pub: bytes) -> bool:
    """True when the genesis public key matches the pin (raw key or sha256
    fingerprint form). Raises ValueError when the pin value is unparseable."""
    kind, val = _parse_genesis_pin(pin_value)
    if kind == "pubkey":
        return val == genesis_pub
    return hashlib.sha256(genesis_pub).digest() == val


def _verify_chain(chain):
    """Verify the rotation chain link by link. Returns (True, (key, kid)) or
    (False, reason). The genesis entry is self-issued; each later attestation
    must be signed by the key it supersedes."""
    prev_key = None
    prev_kid = None
    seen_kids = set()
    for i, entry in enumerate(chain):
        where = f"signature.chain[{i}]"
        if not isinstance(entry, dict):
            return False, f"{where} is malformed", None
        if entry.get("seq") != i:
            return False, f"{where}.seq must be {i}", None
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid:
            return False, f"{where}.kid must be a non-empty string", None
        if kid in seen_kids:
            return False, f"{where}.kid {kid!r} already appears in the rotation chain", None
        seen_kids.add(kid)
        try:
            pub = _decode_b64u_field(entry.get("public_key"), f"{where}.public_key")
        except ValueError as exc:
            return False, str(exc), None
        if len(pub) != 32:
            return False, f"{where}.public_key is not a 32-byte Ed25519 key", None
        try:
            att_sig = _decode_b64u_field(entry.get("sig"), f"{where}.sig")
        except ValueError as exc:
            return False, str(exc), None
        if i == 0:
            # Genesis: self-issued. Proves the issuer holds the private key;
            # the operator must still distribute this key out of band.
            anchor, why = pub, "genesis attestation is not self-signed"
        else:
            if entry.get("supersedes") != prev_kid:
                return False, f"{where}.supersedes must name the previous key {prev_kid!r}", None
            anchor, why = prev_key, f"rotation attestation not signed by the previous key {prev_kid!r}"
        if not verify_bytes(anchor, rotation_signing_input(entry), att_sig):
            return False, why, None
        prev_key, prev_kid = pub, kid
    return True, "", (prev_key, prev_kid)


def verify_registry_signature(reg: dict, genesis_pin: str | None = None):
    """Verify a signed registry's chain and body signature.

    Returns (True, {"kid": current_kid, "chain_length": n}) or
    (False, "<human-readable reason>"). A missing signature block is a
    failure here too: the loader turns it into the registry_signature_invalid
    rejection unless the operator explicitly allowed unsigned registries.

    genesis_pin (base64url of the 32-byte genesis public key, or its 64-char
    hex sha256 fingerprint) closes the trust-anchor hole: without it any
    self-consistent chain verifies, so the pin is what binds "this registry"
    to "the operator we trust". A registry whose genesis key does not match
    the pin is rejected even if every signature in it verifies.
    """
    sig = reg.get(REGISTRY_SIGNATURE_BLOCK)
    if not isinstance(sig, dict):
        return False, "registry has no 'signature' block: it is unsigned"
    if sig.get("alg") != ALG:
        return False, f"unsupported or missing registry signature alg {sig.get('alg')!r} (only Ed25519)"
    chain = sig.get("chain")
    if not isinstance(chain, list) or not chain:
        return False, "'signature.chain' must be a non-empty list of key attestations"
    ok, reason, current = _verify_chain(chain)
    if not ok:
        return False, reason
    prev_key, prev_kid = current
    if genesis_pin is not None:
        try:
            genesis_pub = unb64u(chain[0]["public_key"])
        except Exception:
            return False, "genesis attestation public_key is not valid base64url"
        try:
            pin_ok = genesis_pin_matches(genesis_pin, genesis_pub)
        except ValueError as exc:
            return False, f"bad genesis pin: {exc}"
        if not pin_ok:
            return False, ("genesis operator key does not match the pinned genesis key "
                           "(--registry-genesis-key / SYNTHE_REGISTRY_GENESIS_KEY / "
                           "registry-genesis.key): this registry was signed by someone else")
    if sig.get("kid") != prev_kid:
        return False, "signature.kid does not match the chain's current key"
    try:
        body_sig = _decode_b64u_field(sig.get("sig"), "signature.sig")
    except ValueError as exc:
        return False, str(exc)
    if not verify_bytes(prev_key, registry_signing_input(reg), body_sig):
        return False, "registry body signature does not verify under the current operator key"
    return True, {"kid": prev_kid, "chain_length": len(chain)}


def sign_registry(reg: dict, secret: bytes, kid: str) -> dict:
    """Genesis-sign a registry: returns a new dict with a signature block whose
    chain is a single self-issued attestation for (kid, secret). Any existing
    signature block is replaced."""
    if len(secret) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    if not isinstance(kid, str) or not kid:
        raise ValueError("kid must be a non-empty string")
    body = registry_body(reg)
    genesis = {"seq": 0, "kid": kid, "public_key": b64u(public_key(secret))}
    genesis["sig"] = b64u(sign_bytes(secret, rotation_signing_input(genesis)))
    block = {"alg": ALG, "kid": kid, "chain": [genesis]}
    block["sig"] = b64u(sign_bytes(secret, registry_signing_input(body)))
    return {**body, "signature": block}


def resign_registry(reg: dict, secret: bytes, kid: str | None = None, force: bool = False) -> dict:
    """Re-sign an already-signed registry after editing its body, preserving the
    rotation chain. The key must be the chain's current operator key. By default
    the existing signature is verified first, so a tampered registry cannot be
    laundered by re-signing; pass force=True when the body was legitimately
    edited (the old body signature is then expected to be stale, but the chain
    itself must still verify)."""
    sig = reg.get(REGISTRY_SIGNATURE_BLOCK)
    if not isinstance(sig, dict):
        raise ValueError("registry has no signature block: use sign_registry for a genesis signature")
    chain = sig.get("chain")
    if not isinstance(chain, list) or not chain:
        raise ValueError("signature chain is missing or empty")
    if not force:
        ok, info = verify_registry_signature(reg)
        if not ok:
            raise ValueError(f"cannot re-sign: current registry signature invalid: {info}")
    else:
        ok, reason, _ = _verify_chain(chain)
        if not ok:
            raise ValueError(f"cannot re-sign: rotation chain invalid: {reason}")
    if public_key(secret) != unb64u(chain[-1]["public_key"]):
        raise ValueError("re-signing key is not the registry's current operator key")
    kid = kid or sig.get("kid") or chain[-1].get("kid")
    body = registry_body(reg)
    block = {"alg": ALG, "kid": kid, "chain": chain}
    block["sig"] = b64u(sign_bytes(secret, registry_signing_input(body)))
    return {**body, "signature": block}


def rotate_registry_key(reg: dict, old_secret: bytes, new_secret: bytes, new_kid: str) -> dict:
    """The rotation ceremony: the current operator key attests the new key, the
    attestation is appended to the chain, and the body is re-signed by the new
    key. The existing chain and body signature are verified first, so the
    ceremony fails closed on a tampered registry or a wrong old key."""
    ok, info = verify_registry_signature(reg)
    if not ok:
        raise ValueError(f"cannot rotate: current registry signature invalid: {info}")
    if len(new_secret) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    if not isinstance(new_kid, str) or not new_kid:
        raise ValueError("new_kid must be a non-empty string")
    chain = reg["signature"]["chain"]
    old_entry = chain[-1]
    if public_key(old_secret) != unb64u(old_entry["public_key"]):
        raise ValueError("old key does not match the registry's current operator key")
    if any(e.get("kid") == new_kid for e in chain):
        raise ValueError(f"kid {new_kid!r} already appears in the rotation chain")
    attestation = {"seq": len(chain), "kid": new_kid,
                   "public_key": b64u(public_key(new_secret)),
                   "supersedes": old_entry["kid"]}
    attestation["sig"] = b64u(sign_bytes(old_secret, rotation_signing_input(attestation)))
    body = registry_body(reg)
    block = {"alg": ALG, "kid": new_kid, "chain": [*chain, attestation]}
    block["sig"] = b64u(sign_bytes(new_secret, registry_signing_input(body)))
    return {**body, "signature": block}
