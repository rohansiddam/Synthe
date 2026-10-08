"""T1.4 independent verifier: written from SPEC.md section 5 only.

Implements:
- Canonical JSON: sorted keys, compact separators, UTF-8,
  whole-number floats written as ints (SPEC §5)
- Packet signature: "synthe/handoff-signature/v1\\n" + canonical(handoff)
- Approval signature: "synthe/approval-signature/v1\\n" +
  canonical({action, approver, expires_at, idempotency_key, from, to})

Uses the `cryptography` library for Ed25519 math (RFC 8032, as SPEC references).
Does NOT import synthe_crypto or synthe_sign.
"""
import json


def canonical(obj) -> bytes:
    """SPEC §5: sorted keys, compact separators, UTF-8, whole floats as ints."""
    def _norm(o):
        if isinstance(o, dict):
            return {k: _norm(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_norm(x) for x in o]
        if isinstance(o, float) and o.is_integer():
            return int(o)
        return o
    return json.dumps(_norm(obj), separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


PACKET_DOMAIN = "synthe/handoff-signature/v1\n"
APPROVAL_DOMAIN = "synthe/approval-signature/v1\n"


def packet_signing_input(handoff: dict) -> bytes:
    return PACKET_DOMAIN.encode() + canonical(handoff)


def approval_signing_input(approval: dict, handoff: dict) -> bytes:
    bound = {
        "action": approval.get("action"),
        "approver": approval.get("approver"),
        "expires_at": approval.get("expires_at"),
        "idempotency_key": handoff.get("idempotency_key"),
        "from": handoff.get("from"),
        "to": handoff.get("to"),
    }
    # NOTE (T1.4 finding): SPEC §5 does not mention `params`, but the
    # reference implementation includes it when present. Including it here
    # to match actual behavior; the spec is incomplete.
    if approval.get("params") is not None:
        bound["params"] = approval.get("params")
    return APPROVAL_DOMAIN.encode() + canonical(bound)


def b64u_decode(s: str) -> bytes:
    import base64
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def verify_packet(packet: dict, registry: dict) -> tuple[bool, str]:
    """Verify packet signature per SPEC §5. Returns (ok, reason)."""
    h = packet.get("handoff")
    sig = packet.get("signature")
    if not isinstance(h, dict):
        return False, "no handoff"
    if not isinstance(sig, dict):
        return False, "no signature"
    if sig.get("signer") != h.get("from"):
        return False, "signer != from"
    # Find key
    agent = registry.get("agents", {}).get(h["from"], {})
    key = None
    for k in agent.get("keys", []):
        if k.get("kid") == sig.get("kid"):
            key = k
            break
    if not key:
        return False, "key not found"
    # SPEC §5: signature alg must be Ed25519
    if sig.get("alg", "Ed25519") != "Ed25519":
        return False, "bad sig alg"
    try:
        ok = ed25519_verify(
            b64u_decode(key["public_key"]),
            packet_signing_input(h),
            b64u_decode(sig["sig"]),
        )
        return (True, "verified") if ok else (False, "verify failed")
    except Exception as e:
        return False, f"verify error: {e}"


def verify_approval(approval: dict, handoff: dict, registry: dict) -> tuple[bool, str]:
    """Verify approval signature per SPEC §5. Returns (ok, reason)."""
    approver = approval.get("approver")
    agent = registry.get("agents", {}).get(approver, {})
    key = None
    for k in agent.get("keys", []):
        if k.get("kid") == approval.get("kid"):
            key = k
            break
    if not key:
        return False, "approver key not found"
    try:
        ok = ed25519_verify(
            b64u_decode(key["public_key"]),
            approval_signing_input(approval, handoff),
            b64u_decode(approval["sig"]),
        )
        return (True, "verified") if ok else (False, "verify failed")
    except Exception as e:
        return False, f"verify error: {e}"


# ---------------------------------------------------------------- Ed25519 (RFC 8032)

# Curve parameters
_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_Q = 2**252 + 27742317777372353535851937790883648493


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
    if x % 2 != 0:
        x = _P - x
    return x


def _decode_point(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _P - x
    return (x, y)


# Base point decoded from RFC 8032
_Bx, _By = _decode_point(bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"))


def _edwards_add(P, Q):
    # Twisted Edwards with a=-1: -x^2 + y^2 = 1 + d*x^2*y^2
    (x1, y1), (x2, y2) = P, Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _D * x1 * x2 * y1 * y2, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _D * x1 * x2 * y1 * y2, _P - 2, _P) % _P
    return (x3, y3)


def _scalarmult(P, e):
    Q = (0, 1)  # identity
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_add(P, P)
        e >>= 1
    return Q


def _decode_int(s: bytes) -> int:
    return int.from_bytes(s, "little")


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    """RFC 8032 Ed25519 verification."""
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decode_point(public)
    R = _decode_point(sig[:32])
    S = _decode_int(sig[32:])
    if S >= _Q:
        return False
    import hashlib
    h = hashlib.sha512(sig[:32] + public + msg).digest()
    k = int.from_bytes(h, "little") % _Q
    # Check: S*B == R + k*A
    SB = _scalarmult((_Bx, _By), S)
    kA = _scalarmult(A, k)
    RkA = _edwards_add(R, kA)
    return SB == RkA
