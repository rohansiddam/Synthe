#!/usr/bin/env python3
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

Encodings: keys and signatures are unpadded base64url strings.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os

ALG = "Ed25519"
PACKET_SIG_DOMAIN = "synthe/handoff-signature/v1"
APPROVAL_SIG_DOMAIN = "synthe/approval-signature/v1"


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


def approval_signing_input(approval: dict, handoff: dict) -> bytes:
    """Bytes an approver signs. The approval is bound to one handoff's
    idempotency key and its sender/receiver, so it cannot be replayed onto a
    different handoff."""
    payload = {
        "action": approval.get("action"),
        "approver": approval.get("approver"),
        "expires_at": approval.get("expires_at"),
        "idempotency_key": handoff.get("idempotency_key"),
        "from": handoff.get("from"),
        "to": handoff.get("to"),
    }
    return APPROVAL_SIG_DOMAIN.encode() + b"\n" + canonical_json(payload)


def find_key(registry: dict | None, agent_id: str, kid: str | None):
    """Return the raw public key for agent_id/kid from the registry, or None."""
    if not registry:
        return None
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
                return raw
    return None
