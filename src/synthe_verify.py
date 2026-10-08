#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""synthe-verify: check a Synthe receipt chain with nothing but Python's standard library.

    synthe-verify receipts.jsonl --key broker.pub.json
    synthe-verify receipts.jsonl --key registry.json --broker synthe-broker
    synthe-verify receipts.jsonl --key broker.pub.json --checkpoint 44:<sha256 hex> --json

One file, no dependencies, no network, no server: copy it anywhere Python 3.9+ runs. It trusts only
the key you hand it, and it fails closed: anything it cannot check is a failure with a reason code.

What it checks, for every line of the receipt file:
- the line is strict JSON: one object, no duplicate fields, no NaN or Infinity;
- `seq` counts 1, 2, 3... with no gaps, and `prev` is the SHA-256 of the canonical JSON of the
  receipt before it (null for the first), so an edit, deletion or reordering anywhere breaks it;
- `broker` is the identity you trust and `kid` names one of its keys (another signer's receipts,
  even if well signed, are refused);
- the Ed25519 signature (RFC 8032, strict: canonical encodings, s < L) over
  "synthe/effect-receipt/v1" + "\\n" + canonical JSON of the receipt without `sig`;
- each `--checkpoint SEQ:DIGEST` you recorded earlier is still in the chain, unchanged. A chain cut
  short at the end still links, so a checkpoint is how you catch a truncated tail.

Exit 0: verified. Exit 1: not verified (reasons printed). Exit 2: it could not run (bad key file,
unreadable receipt file, bad arguments).

Reason codes: not_utf8, not_json, duplicate_field, non_finite_number, not_object, field_invalid,
seq_gap, prev_mismatch, signer_untrusted, kid_unknown, signature_invalid, checkpoint_mismatch,
checkpoint_missing, empty_chain.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys

RECEIPT_SIG_DOMAIN = b"synthe/effect-receipt/v1"
ALG = "Ed25519"
DEFAULT_SIGNER = "synthe-broker"
_B64U = re.compile(r"[A-Za-z0-9_-]*")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class TrustError(ValueError):
    """The key file can't be used as a trust anchor."""


# --------------------------------------------------------------------------
# canonical JSON (sorted keys, no whitespace, UTF-8, whole floats as integers)

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


def receipt_digest(receipt: dict) -> str:
    """What the next receipt's `prev` holds, and what a checkpoint records."""
    return hashlib.sha256(canonical_json(receipt)).hexdigest()


def signing_input(receipt: dict) -> bytes:
    body = {k: v for k, v in receipt.items() if k != "sig"}
    return RECEIPT_SIG_DOMAIN + b"\n" + canonical_json(body)


class _Strict(ValueError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Strict("duplicate_field", f"field {k!r} appears twice")
        out[k] = v
    return out


def _finite(text):
    value = float(text)
    if math.isinf(value):
        raise _Strict("non_finite_number", f"{text} overflows to infinity")
    return value


def _bad_constant(text):
    raise _Strict("non_finite_number", f"{text} is not JSON")


def strict_loads(text: str):
    """json.loads that refuses what a different parser could read differently."""
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_float=_finite,
                          parse_constant=_bad_constant)
    except _Strict:
        raise
    except (ValueError, RecursionError) as e:
        raise _Strict("not_json", str(e)[:120]) from None


def unb64u_strict(text) -> bytes:
    """Unpadded base64url, one spelling only (no padding, junk or loose trailing bits)."""
    if not isinstance(text, str) or not _B64U.fullmatch(text):
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        raise ValueError("non-canonical base64url")
    return raw


# --------------------------------------------------------------------------
# Ed25519 verification, after the RFC 8032 section 6 reference code (public data only)

_p = 2 ** 255 - 19
_d = -121665 * pow(121666, _p - 2, _p) % _p
_q = 2 ** 252 + 27742317777372353535851937790883648493
_SQRT_M1 = pow(2, (_p - 1) // 4, _p)


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
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p) % _p
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


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


_gy = 4 * pow(5, _p - 2, _p) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)
_IDENTITY = (0, 1, 1, 0)


def _valid_public_point(point) -> bool:
    # A small-order public key can admit signatures without a signing secret.
    return point is not None and not _equal(_mul(8, point), _IDENTITY) and _equal(_mul(_q, point), _IDENTITY)


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _decompress(public), _decompress(sig[:32])
    if A is None or R is None:
        return False
    if not _valid_public_point(A):
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _q
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


# --------------------------------------------------------------------------
# trust anchor

def _key_entry(k) -> tuple[str, bytes] | None:
    if not isinstance(k, dict) or k.get("alg", ALG) != ALG or not isinstance(k.get("kid"), str):
        return None
    try:
        raw = unb64u_strict(k.get("public_key"))
    except ValueError:
        return None
    return (k["kid"], raw) if len(raw) == 32 and _decompress(raw) is not None and _valid_public_point(_decompress(raw)) else None


def load_trust(obj, signer: str | None = None) -> dict:
    """{"signer": id, "keys": {kid: raw}} from a published key ({"broker", "kid", "alg",
    "public_key"}) or a registry ({"agents": {id: {"keys": [...]}}}, one signer picked by id)."""
    if not isinstance(obj, dict):
        raise TrustError("key file is not a JSON object")
    if "agents" in obj:
        signer = signer or DEFAULT_SIGNER
        agents = obj.get("agents")
        entry = agents.get(signer) if isinstance(agents, dict) else None
        if not isinstance(entry, dict):
            raise TrustError(f"registry has no signer {signer!r}")
        entries = entry.get("keys")
        if not isinstance(entries, list):
            raise TrustError("signer keys must be a list")
        keys = [_key_entry(k) for k in entries]
    elif "public_key" in obj:
        named = obj.get("broker")
        if not isinstance(named, str) or not named:
            raise TrustError("published key names no signer (field 'broker')")
        if signer is not None and signer != named:
            raise TrustError(f"published key is for {named!r}, not {signer!r}")
        signer, keys = named, [_key_entry(obj)]
    else:
        raise TrustError("key file is neither a published key nor a registry")
    if any(k is None for k in keys):
        raise TrustError("invalid signing key")
    found = dict(keys)
    if len(found) != len(keys):
        raise TrustError("duplicate signing kid")
    if not found:
        raise TrustError(f"no usable {ALG} key with a kid for {signer!r}")
    return {"signer": signer, "keys": found}


# --------------------------------------------------------------------------
# the chain

def parse_checkpoint(text: str) -> tuple[int, str]:
    seq, _, digest = text.partition(":")
    if not seq.isdigit() or int(seq) < 1 or not _HEX64.fullmatch(digest):
        raise ValueError(f"checkpoint {text!r} is not SEQ:SHA256HEX")
    return int(seq), digest


def verify(data: bytes, trust: dict, checkpoints: dict | None = None) -> dict:
    """Verify a receipt file's bytes against one trusted signer. Never raises on bad input."""
    errors, decisions, digests = [], {}, {}
    prev_digest, linked, count, line_no = None, True, 0, 0

    def fail(code, detail, seq=None):
        errors.append({"line": line_no, "seq": seq, "code": code, "detail": detail})

    for line_no, raw in enumerate(data.split(b"\n"), 1):
        if not raw.strip():
            continue
        count += 1
        try:
            r = strict_loads(raw.decode("utf-8"))
        except UnicodeDecodeError:
            fail("not_utf8", "line is not UTF-8")
            prev_digest, linked = None, False
            continue
        except _Strict as e:
            fail(e.code, str(e))
            prev_digest, linked = None, False
            continue
        if not isinstance(r, dict):
            fail("not_object", "line is not a JSON object")
            prev_digest, linked = None, False
            continue
        seq = r.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            fail("field_invalid", "seq is not an integer")
            seq = None
        elif seq != count:
            fail("seq_gap", f"expected seq {count}", seq)
        try:
            digest = receipt_digest(r)
        except (ValueError, UnicodeEncodeError, RecursionError) as e:
            fail("field_invalid", f"cannot canonicalize: {str(e)[:80]}", seq)
            prev_digest, linked = None, False
            continue
        if linked and r.get("prev") != prev_digest:
            fail("prev_mismatch", "prev is not the digest of the receipt before it", seq)
        _check_signature(r, trust, seq, fail)
        decision = r.get("decision")
        if isinstance(decision, str):
            decisions[decision] = decisions.get(decision, 0) + 1
        digests[count] = digest
        prev_digest, linked = digest, True

    line_no = None
    if count == 0:
        fail("empty_chain", "no receipts to verify")
    for seq, want in sorted((checkpoints or {}).items()):
        if seq not in digests:
            fail("checkpoint_missing", f"the chain has {count} receipts; checkpoint {seq} is gone", seq)
        elif digests[seq] != want:
            fail("checkpoint_mismatch", f"receipt {seq} is not the one recorded", seq)
    head = digests.get(count) if linked else None
    return {"ok": not errors, "count": count, "head": head, "signer": trust["signer"],
            "decisions": decisions, "errors": errors}


def _check_signature(r: dict, trust: dict, seq, fail) -> None:
    signer, kid = r.get("broker"), r.get("kid")
    if signer != trust["signer"]:
        fail("signer_untrusted", f"signed as {signer!r}, not {trust['signer']!r}", seq)
        return
    key = trust["keys"].get(kid) if isinstance(kid, str) else None
    if key is None:
        fail("kid_unknown", f"kid {kid!r} is not a trusted key of {signer!r}", seq)
        return
    try:
        sig = unb64u_strict(r.get("sig"))
        good = ed25519_verify(key, signing_input(r), sig)
    except (ValueError, UnicodeEncodeError):
        good = False
    if not good:
        fail("signature_invalid", "the signature does not verify", seq)


# --------------------------------------------------------------------------
# CLI

def _render(report: dict, trust: dict) -> str:
    kids = ", ".join(sorted(trust["keys"]))
    if report["ok"]:
        tally = ", ".join(f"{k} {v}" for k, v in sorted(report["decisions"].items())) or "none"
        return (f"VERIFIED  {report['count']} receipts signed by {report['signer']} (kid {kids})\n"
                f"head      {report['head']}  (seq {report['count']})\n"
                f"decisions {tally}")
    out = [f"NOT VERIFIED  {report['count']} receipts, {len(report['errors'])} problem(s); "
           f"trusted signer {report['signer']} (kid {kids})"]
    for e in report["errors"]:
        where = (f"line {e['line']}" if e["line"] else "chain") + (f" seq {e['seq']}" if e["seq"] else "")
        out.append(f"  {where}: {e['code']}: {e['detail']}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="synthe-verify", description=__doc__.split("\n\n")[0])
    ap.add_argument("receipts", help="receipt file (one JSON receipt per line), or - for stdin")
    ap.add_argument("--key", required=True,
                    help="the signer's published key (broker.pub.json) or a registry.json")
    ap.add_argument("--broker", dest="signer", default=None,
                    help=f"signer id to trust in a registry (default {DEFAULT_SIGNER})")
    ap.add_argument("--checkpoint", action="append", default=[], metavar="SEQ:DIGEST",
                    help="a head you recorded earlier; it must still be in the chain (repeatable)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args(argv)
    try:
        with open(a.key, encoding="utf-8") as fh:
            trust = load_trust(strict_loads(fh.read()), a.signer)
        checkpoints = {}
        for c in a.checkpoint:
            seq, digest = parse_checkpoint(c)
            if checkpoints.get(seq, digest) != digest:
                raise ValueError(f"two different checkpoints for seq {seq}")
            checkpoints[seq] = digest
        if a.receipts == "-":
            data = sys.stdin.buffer.read()
        else:
            with open(a.receipts, "rb") as fh:
                data = fh.read()
    except (OSError, ValueError) as e:
        print(f"synthe-verify: {e}", file=sys.stderr)
        return 2
    report = verify(data, trust, checkpoints)
    print(json.dumps(report, indent=2) if a.json else _render(report, trust))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
