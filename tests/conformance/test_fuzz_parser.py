"""T1.3 parser fuzzer: malformed input must REJECT, never crash.

Throws malformed JSON shapes, wrong types, huge arrays, confusable agent
ids, timestamps without offsets, and short hashes at handoff_check.
Every input must produce a REJECT with a reason code (or ACCEPT only for
the valid baseline). An uncaught exception is a crash and fails the test.

The fuzzer is deterministic (fixed seed) so failures reproduce.
"""
import copy
import json
import random
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc  # noqa: E402

SEED = 20261005
N_MUTATIONS = 500


def _valid_handoff():
    """Minimal valid handoff dict (unsigned; signature not needed for fuzz)."""
    return {
        "schema_version": "0.1",
        "id": "h-fuzz-1",
        "trace_id": "t-fuzz-1",
        "idempotency_key": "k-fuzz-1",
        "on_failure": "reject",
        "from": "planner",
        "to": "builder",
        "purpose": "fuzz the parser",
        "inputs": {"artifact_refs": [{"path": "task.md",
                   "sha256": "91b88140bce2e3f94d76adb8969ba95b1025b6519aff27986f9ec4ad04ebc529"}],
                   "state_revision": "rev-1"},
        "scope": {"owned_paths": ["src/**"], "forbidden": []},
        "authority": {
            "allowed_tools": ["read_repo"],
            "approval_required_for": [],
            "budget": {"tokens": 1000, "usd": 1, "minutes": 10},
            "approvals": [],
        },
        "planned_actions": [{"name": "read", "tool": "read_repo"}],
        "acceptance": {
            "expires_at": "2030-01-01T00:00:00Z",
            "output_schema": "code_change.v1",
            "required_evidence": ["test_output"],
            "evidence": [{"kind": "test_output", "ref": "task.md"}],
        },
    }


def _registry():
    return {"agents": {
        "planner": {"role": "sender", "keys": []},
        "builder": {"role": "receiver", "keys": [], "policy": {
            "allowed_tools": ["read_repo"],
            "require_signatures": False,
            "require_planned_actions": True,
            "defaults": {"owned_paths": ["src/**"], "output_schema": "code_change.v1",
                         "budget": {"tokens": 100000, "usd": 5, "minutes": 60}},
        }},
    }}


# ---------------------------------------------------------------- mutations

_WEIRD_STRINGS = [
    "", " ", "\x00", "\n", "a" * 10000,
    "planner\x00", "plаnner",  # Cyrillic 'а'
    "PLANNER", "Planner", " planner", "planner ",
    "../..", "/", "\\", "a/b/../c",
    "0.1", "null", "true", "[]", "{}",
    "\ud800",  # lone surrogate (may fail JSON encode; skip if so)
]

_WEIRD_VALUES = [
    None, True, False, 0, -1, 1.5, float("inf"), float("nan"),
    [], {}, [None], {"a": 1}, "x" * 100000,
]


def _mutate(obj, rng):
    """Apply one random mutation to a deep copy of obj."""
    o = copy.deepcopy(obj)
    h = o.get("handoff", o)

    choice = rng.randrange(12)
    if choice == 0:
        # Wrong type for a string field
        field = rng.choice(["id", "purpose", "from", "to"])
        h[field] = rng.choice(_WEIRD_VALUES)
    elif choice == 1:
        # Delete a required field
        field = rng.choice(["id", "purpose", "from", "to", "idempotency_key"])
        h.pop(field, None)
    elif choice == 2:
        # Confusable agent id
        h["from"] = rng.choice(_WEIRD_STRINGS[:8])
    elif choice == 3:
        # Timestamp without offset / malformed
        h["acceptance"]["expires_at"] = rng.choice([
            "2030-01-01 00:00:00",  # no T, no offset
            "2030-01-01",           # date only
            "not-a-time", "", "2030-13-45T99:99:99Z",
        ])
    elif choice == 4:
        # Short hash
        h["inputs"]["artifact_refs"] = [{"path": "x.md", "sha256": "abc123"}]
    elif choice == 5:
        # Huge array
        h["planned_actions"] = [{"name": f"a{i}", "tool": "read_repo"}
                                for i in range(rng.choice([1000, 10000]))]
    elif choice == 6:
        # planned_actions wrong type
        h["planned_actions"] = rng.choice([None, "read", 42, {"tool": "x"}])
    elif choice == 7:
        # authority wrong shape
        h["authority"] = rng.choice([None, [], "auth", 42])
    elif choice == 8:
        # scope.forbidden with escapes
        h["scope"]["forbidden"] = rng.choice([["../../x"], None, "forbidden"])
    elif choice == 9:
        # Top-level packet not a dict
        return rng.choice([None, [], "packet", 42, [{"handoff": h}]])
    elif choice == 10:
        # idempotency_key weird
        h["idempotency_key"] = rng.choice(["", " ", "k" * 10000, None, 0])
    else:
        # schema_version wrong
        h["schema_version"] = rng.choice(["0.2", "", None, 0.1, []])

    return {"handoff": h} if isinstance(o, dict) and "handoff" in o else o


def _check_no_crash(packet):
    """Run the checker; return (crashed, result)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        ws = tmp / "workspace"
        ws.mkdir()
        (ws / "task.md").write_text("fuzz baseline\n")
        try:
            result = hc.check(
                copy.deepcopy(packet),
                registry=_registry(),
                ledger_path=None,
                workspace=ws,
            )
            return False, result
        except Exception as e:  # noqa: BLE001 — any escape is a crash
            return True, {"crash": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------- tests

def test_fuzz_no_crash():
    """500 deterministic mutations: no uncaught exceptions.

    Some mutations are benign (e.g. stricter forbidden list) and correctly
    ACCEPT. The critical property is that malformed input never crashes the
    checker — it always returns a verdict with reasons.
    """
    rng = random.Random(SEED)
    crashes = []
    for i in range(N_MUTATIONS):
        base = {"handoff": _valid_handoff()}
        mutated = _mutate(base, rng)
        # Skip values that can't survive a JSON round-trip (not packet shapes)
        try:
            json.dumps(mutated)
        except (ValueError, TypeError):
            continue
        crashed, result = _check_no_crash(mutated)
        if crashed:
            crashes.append((i, result["crash"], json.dumps(mutated)[:200]))
        else:
            # Every non-crash must have a decision and (if REJECT) reasons
            assert result.get("decision") in ("ACCEPT", "REJECT"), \
                f"iter {i}: no decision in {result}"
            if result["decision"] == "REJECT":
                assert result.get("reasons"), f"iter {i}: REJECT without reasons"
    assert not crashes, f"{len(crashes)} crashes: {crashes[:3]}"


def test_fuzz_baseline_accepts():
    """The unmutated baseline must ACCEPT (fuzzer sanity check)."""
    crashed, result = _check_no_crash({"handoff": _valid_handoff()})
    assert not crashed, result
    assert result["decision"] == "ACCEPT", result.get("reasons")


# Hand-crafted edge cases the mutator might miss
@pytest.mark.parametrize("packet,note", [
    ({"handoff": None}, "handoff null"),
    ({"handoff": []}, "handoff array"),
    ({"handoff": "x"}, "handoff string"),
    ({}, "empty packet"),
    ({"handoff": {"id": "h1"}}, "handoff with only id"),
    ({"handoff": {**_valid_handoff(), "from": "planner\x00"}}, "null byte in from"),
    ({"handoff": {**_valid_handoff(), "acceptance": None}}, "acceptance null"),
    ({"handoff": {**_valid_handoff(), "inputs": None}}, "inputs null"),
])
def test_fuzz_edge_cases(packet, note):
    crashed, result = _check_no_crash(packet)
    assert not crashed, f"{note}: crashed with {result}"
    assert result["decision"] == "REJECT", f"{note}: got {result['decision']}"
    assert result.get("reasons"), f"{note}: REJECT without reasons"
