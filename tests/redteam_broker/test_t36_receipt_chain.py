"""T3.6: Receipt chain -- edit, delete, reorder, re-sign; swap the broker key.

Intent key: redteam-receipts. Receipts are the library's provenance
(source_receipts): if a receipt can be edited, deleted, reordered, or
re-signed under a swapped key without detection, the provenance is worthless.

Done-when: receipt verification fails EVERY time and NAMES the offending
receipt (by sequence number).

Attacks:
1. edit      -- a receipt's body altered after signing
2. delete    -- a receipt removed from the chain
3. reorder   -- two receipts swapped in position
4. re-sign   -- tampered receipt re-signed with an attacker's swapped key

All signatures here are HMAC-SHA256 under explicit throwaway test keys
(TEST_KEY for the broker, ATTACKER_KEY for the adversary), labeled
DO-NOT-USE-IN-PROD. Nothing forges a real broker signature; the fixtures
only prove tampering is detectable and attributable in principle.

TARGET STATUS (2026-10-05): broker receipt verification is not present in
this repo snapshot. The denial tests below are therefore marked
xfail(strict=True): they record the missing target as evidence and become
the live battery the moment verification lands (rewire
`_require_broker_receipts()` to the real entry point and remove the marks).

The `test_attack_*` tests run NOW against a local reference verifier and
prove each attack is both detected AND attributed to the right receipt --
no broker needed to see that the requirement is statable and testable.
"""

import copy
import hashlib
import hmac
import json

import pytest

_NO_BROKER = (
    "T3.6: broker receipt verification not present in repo snapshot"
)

TEST_KEY = b"t3.6-redteam-test-key-DO-NOT-USE-IN-PROD"
ATTACKER_KEY = b"t3.6-redteam-attacker-key-DO-NOT-USE-IN-PROD"
GENESIS = "GENESIS"


def _canonical(receipt):
    body = {k: receipt[k] for k in sorted(receipt) if k != "sig"}
    return json.dumps(body, separators=(",", ":"), sort_keys=True)


def _receipt_hash(receipt):
    return hashlib.sha256(_canonical(receipt).encode()).hexdigest()


def _sign(receipt, key=TEST_KEY):
    return hmac.new(key, _canonical(receipt).encode(),
                    hashlib.sha256).hexdigest()


def _make_receipt(seq, prev, handoff_id="h-board-T9-v1", key=TEST_KEY):
    r = {"seq": seq, "prev": prev, "handoff_id": handoff_id,
         "decision": "executed", "commit": f"deadbeef{seq:04d}"}
    r["sig"] = _sign(r, key)
    return r


def _good_chain(n=3):
    chain, prev = [], GENESIS
    for i in range(1, n + 1):
        r = _make_receipt(i, prev)
        chain.append(r)
        prev = _receipt_hash(r)
    return chain


def _local_verify(chain, key=TEST_KEY):
    """Reference verifier. Returns (ok, failing_seq_or_None).

    Checks, in order: signature under the broker key, seq continuity from
    1, prev-hash linkage, genesis anchor. Names the first failing receipt.
    """
    for i, r in enumerate(chain, start=1):
        if r["seq"] != i:
            return False, r["seq"]
        if not hmac.compare_digest(_sign(r, key), r["sig"]):
            return False, r["seq"]
        want_prev = GENESIS if i == 1 else _receipt_hash(chain[i - 2])
        if r["prev"] != want_prev:
            return False, r["seq"]
    return True, None


def _require_broker_receipts():
    """Seam for the broker's receipt-chain verification.

    Rewire to the real entry point when it lands. Must return an object
    with:
        verify_chain(receipts) -> denial with .code startswith "receipt_"
        and .receipt_seq naming the offending receipt.
    """
    raise RuntimeError(_NO_BROKER)


# --------------------------------------------------------------------------
# attack builders
# --------------------------------------------------------------------------

def build_edited_receipt():
    chain = _good_chain()
    chain[1]["decision"] = "denied"  # edited after signing
    chain[1]["commit"] = None
    return chain


def build_deleted_receipt():
    chain = _good_chain()
    del chain[1]  # seq 2 gone; chain reads 1, 3
    return chain


def build_reordered_receipts():
    chain = _good_chain()
    chain[1], chain[2] = chain[2], chain[1]  # positions swapped
    return chain


def build_resigned_swapped_key():
    chain = _good_chain()
    chain[1]["decision"] = "denied"  # tamper...
    chain[1]["commit"] = None
    chain[1]["sig"] = _sign(chain[1], ATTACKER_KEY)  # ...re-signed by attacker
    return chain


# --------------------------------------------------------------------------
# Part 1 (runs NOW): every attack is detected AND attributed by the
# reference verifier.
# --------------------------------------------------------------------------

def test_attack_edited_receipt():
    ok, failing = _local_verify(build_edited_receipt())
    assert not ok and failing == 2  # detected, names receipt 2


def test_attack_deleted_receipt():
    ok, failing = _local_verify(build_deleted_receipt())
    assert not ok and failing == 3  # gap detected at receipt 3


def test_attack_reordered_receipts():
    ok, failing = _local_verify(build_reordered_receipts())
    assert not ok and failing == 3  # prev-link breaks at receipt 3


def test_attack_resigned_swapped_key():
    ok, failing = _local_verify(build_resigned_swapped_key())
    assert not ok and failing == 2  # attacker's key rejected at receipt 2


def test_good_chain_verifies():
    ok, failing = _local_verify(_good_chain())
    assert ok and failing is None  # control: untampered chain passes


# --------------------------------------------------------------------------
# Part 2 (xfail until verification lands): verification fails every time
# and names the receipt.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_verify_fails_edited_and_names_receipt():
    denial = _require_broker_receipts().verify_chain(build_edited_receipt())
    assert denial.code.startswith("receipt_")
    assert denial.receipt_seq == 2


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_verify_fails_deleted_and_names_receipt():
    denial = _require_broker_receipts().verify_chain(build_deleted_receipt())
    assert denial.code.startswith("receipt_")
    assert denial.receipt_seq == 3


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_verify_fails_reordered_and_names_receipt():
    denial = _require_broker_receipts().verify_chain(build_reordered_receipts())
    assert denial.code.startswith("receipt_")
    assert denial.receipt_seq == 3


@pytest.mark.xfail(strict=True, reason=_NO_BROKER)
def test_broker_verify_fails_resigned_and_names_receipt():
    denial = _require_broker_receipts().verify_chain(
        build_resigned_swapped_key())
    assert denial.code.startswith("receipt_")
    assert denial.receipt_seq == 2
