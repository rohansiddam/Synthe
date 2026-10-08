"""T1.4: independent verifier vs reference on example packets.

Loads vectors from examples/vectors/, runs the SPEC-§5-only verifier,
and checks agreement with the expected signature validity.
Disagreements are findings.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))
from independent_verifier import verify_packet, verify_approval  # noqa: E402

VECTORS_DIR = ROOT / "examples" / "vectors"


def _load_vectors():
    vecs = []
    for path in sorted(VECTORS_DIR.glob("v*.json")):
        vecs.append((path.name, json.loads(path.read_text())))
    return vecs


def _expected_sig_valid(vec):
    """From the vector's expected codes: is the signature supposed to verify?"""
    codes = vec["expected"].get("codes", [])
    packet = vec["packet"]
    # No handoff or no signature: nothing to verify
    if not isinstance(packet.get("handoff"), dict):
        return None
    if not packet.get("signature"):
        return None
    sig_codes = [c for c in codes if c.startswith("signature_")]
    return len(sig_codes) == 0


@pytest.mark.parametrize(
    "name,vec",
    _load_vectors(),
    ids=[n for n, _ in _load_vectors()],
)
def test_independent_verifier_agrees(name, vec):
    packet = vec["packet"]
    registry = vec.get("registry")
    if not packet.get("signature") or registry is None:
        pytest.skip("no signature or registry")
    expected = _expected_sig_valid(vec)
    if expected is None:
        pytest.skip("no signature")
    ok, reason = verify_packet(packet, registry)
    assert ok == expected, (
        f"{name}: independent verifier says {'valid' if ok else 'invalid'} "
        f"({reason}), expected {'valid' if expected else 'invalid'}"
    )


def test_independent_verifier_approvals():
    """Verify approvals on a sample of vectors with approvals."""
    checked = 0
    for name, vec in _load_vectors():
        packet = vec["packet"]
        h = packet.get("handoff", {})
        registry = vec.get("registry")
        if not registry:
            continue
        for appr in h.get("authority", {}).get("approvals", []):
            if not appr.get("sig"):
                continue  # unsigned approval; skip
            ok, reason = verify_approval(appr, h, registry)
            # If the vector expects approval_signature_invalid, ok should be False
            codes = vec["expected"].get("codes", [])
            expect_invalid = "approval_signature_invalid" in codes
            assert ok != expect_invalid, (
                f"{name}: approval verifier says {'valid' if ok else 'invalid'}, "
                f"expected {'invalid' if expect_invalid else 'valid'} ({reason})"
            )
            checked += 1
            if checked >= 20:
                return
    assert checked > 0, "no approvals to verify"
