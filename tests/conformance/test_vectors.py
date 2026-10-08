"""T1.2 conformance vector runner.

Loads every vector from examples/vectors/, sets up the specified registry,
ledger, and workspace, runs the vector's entry point against
src/handoff_check.py, and asserts the expected decision/state/codes.

A vector that fails means the checker changed behavior: investigate before
updating the vector.
"""
import copy
from unittest import mock
import datetime as dt
import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc  # noqa: E402

VECTORS_DIR = ROOT / "examples" / "vectors"


def _load_vectors():
    vecs = []
    for path in sorted(VECTORS_DIR.glob("v*.json")):
        vecs.append(json.loads(path.read_text()))
    return vecs


def _run_vector(vec, tmp: Path):
    """Set up the vector's environment and run its entry point."""
    # Registry
    reg = vec.get("registry")
    if reg is not None:
        (tmp / "registry.json").write_text(json.dumps(reg))

    # Ledger
    ledger_path = None
    if "ledger" in vec:
        ledger_path = tmp / "ledger.json"
        ledger_path.write_text(json.dumps(vec["ledger"]))
    if vec.get("ledger_raw") is not None:
        ledger_path = tmp / "ledger.json"
        ledger_path.write_text(vec["ledger_raw"])

    # Workspace
    ws = None
    if not vec.get("no_workspace"):
        ws = tmp / "workspace"
        ws.mkdir(exist_ok=True)
        # Default task.md (matches generator)
        (ws / "task.md").write_text("add a flag\n")
        for rel, content in (vec.get("workspace_files") or {}).items():
            f = ws / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content)

    entry = vec.get("entry", "validate")
    packet = copy.deepcopy(vec["packet"])
    verify_evidence = vec.get("verify_evidence", False)

    if entry == "validate":
        return hc.check(
            packet,
            registry=reg,
            ledger_path=ledger_path,
            workspace=ws,
            verify_evidence=verify_evidence,
        )
    elif entry == "complete":
        pkt = packet["packet"] if isinstance(packet, dict) and "packet" in packet else packet
        token = packet.get("claim_token") if isinstance(packet, dict) else None
        result = hc.complete(pkt, ledger_path, token)
        if "reasons" not in result:
            result["reasons"] = []
        return result
    elif entry == "release":
        pkt = packet["packet"] if isinstance(packet, dict) and "packet" in packet else packet
        result = hc.release(pkt, ledger_path)
        if "reasons" not in result:
            result["reasons"] = []
        return result
    elif entry == "fenced_effect":
        pkt = packet["packet"]
        token = packet["claim_token"]
        action = packet["action"]
        try:
            with hc.fenced_effect(pkt, ledger_path, token, action):
                pass
            return {"decision": "NO_ERROR", "reasons": []}
        except Exception as e:
            verdict = getattr(e, "verdict", None)
            if isinstance(verdict, dict) and "reasons" in verdict:
                return verdict
            return {"decision": "REJECT", "reasons": [], "error": str(e)[:200]}
    else:
        raise ValueError(f"unknown entry: {entry}")


# The vectors hard-code claim times relative to when they were generated (Oct 5, two batches):
# "fresh" claims at 2026-10-05T20:19:38Z, stale ones 24 h before a generation time (latest
# 2026-10-04T20:51:34Z, v072). Any clock in (2026-10-05T20:51:34Z, 2026-10-06T20:19:38Z] satisfies all
# of them; pin one, or the fresh ones age out a day later (found on the Oct 6 release run).
VECTOR_NOW = dt.datetime(2026, 10, 5, 21, 0, tzinfo=dt.timezone.utc)


def _check_vector(vec):
    with tempfile.TemporaryDirectory() as tmp, mock.patch.object(hc, "now_utc", lambda: VECTOR_NOW):
        result = _run_vector(vec, Path(tmp))

    expected = vec["expected"]
    exp_d = expected["decision"]
    exp_s = expected.get("state")
    exp_codes = {c.split(":")[0] for c in expected.get("codes", [])}

    got_codes = {r["code"].split(":")[0] for r in result.get("reasons", [])}
    got_state = result.get("state")
    if got_state is None and result.get("reasons"):
        got_state = result["reasons"][0].get("state")

    assert result["decision"] == exp_d, (
        f"{vec['name']}: decision {result['decision']} != {exp_d}; "
        f"reasons={[r['code'] for r in result.get('reasons', [])]}"
    )
    if exp_s is not None:
        assert got_state == exp_s, (
            f"{vec['name']}: state {got_state} != {exp_s}"
        )
    assert exp_codes <= got_codes, (
        f"{vec['name']}: missing codes {exp_codes - got_codes}; "
        f"got {sorted(got_codes)}"
    )


@pytest.mark.parametrize(
    "vec",
    _load_vectors(),
    ids=[v["name"] for v in _load_vectors()],
)
def test_vector(vec):
    _check_vector(vec)
