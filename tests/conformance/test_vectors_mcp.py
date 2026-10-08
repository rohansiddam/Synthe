"""Phase 1 gate: the conformance vectors give the same verdict through the MCP server (the path an OpenClaw
agent uses) as through the checker directly.

Every `validate` and `complete` vector runs twice, in fresh copies of its environment, under the same
pinned clock: once through handoff_check (test_vectors.py's runner) and once through
synthe_mcp.SyntheServer's tools. Decision, state and the set of reason codes must match. The one
deliberate difference: the MCP server's completion requires the claim token, because many agents share
one endpoint and holding the packet isn't enough, so a vector that completes without a token is
stricter over MCP (claim_token_required).
"""
import copy
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from test_vectors import VECTOR_NOW, _load_vectors, _run_vector

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc  # noqa: E402
import synthe_mcp as mcp  # noqa: E402

VECTORS = [v for v in _load_vectors() if v.get("entry", "validate") in ("validate", "complete")]


def _environment(vec, tmp: Path):
    """The same registry, ledger and workspace test_vectors builds, as paths for the MCP server."""
    tmp.mkdir(parents=True, exist_ok=True)
    reg_path = None
    if vec.get("registry") is not None:
        reg_path = tmp / "registry.json"
        reg_path.write_text(json.dumps(vec["registry"]))
    ledger = None
    if "ledger" in vec:
        ledger = tmp / "ledger.json"
        ledger.write_text(json.dumps(vec["ledger"]))
    if vec.get("ledger_raw") is not None:
        ledger = tmp / "ledger.json"
        ledger.write_text(vec["ledger_raw"])
    ws = None
    if not vec.get("no_workspace"):
        ws = tmp / "workspace"
        ws.mkdir(exist_ok=True)
        (ws / "task.md").write_text("add a flag\n")
        for rel, content in (vec.get("workspace_files") or {}).items():
            (ws / rel).parent.mkdir(parents=True, exist_ok=True)
            (ws / rel).write_text(content)
    return reg_path, ledger, ws


def _verdict(result):
    state = result.get("state") or (result.get("reasons") or [{}])[0].get("state")
    return result["decision"], state, {r["code"] for r in result.get("reasons", [])}


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_mcp_gives_the_same_verdict_as_the_checker(vec):
    with tempfile.TemporaryDirectory() as tmp, mock.patch.object(hc, "now_utc", lambda: VECTOR_NOW):
        (Path(tmp) / "direct").mkdir()
        direct = _run_vector(vec, Path(tmp) / "direct")
        reg_path, ledger, ws = _environment(vec, Path(tmp) / "mcp")
        srv = mcp.SyntheServer(str(reg_path) if reg_path else None, ledger, ws,
                               verify_evidence=vec.get("verify_evidence", False))
        packet = copy.deepcopy(vec["packet"])
        if vec.get("entry", "validate") == "validate":
            name, args = "synthe_validate_handoff", {"packet": packet}
        else:
            pkt = packet["packet"] if isinstance(packet, dict) and "packet" in packet else packet
            token = packet.get("claim_token") if isinstance(packet, dict) else None
            name, args = "synthe_complete_handoff", {"packet": pkt, **({"claim_token": token} if token else {})}
        r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
        over_mcp = r["result"]["structuredContent"]
    if _verdict(over_mcp) != _verdict(direct):
        no_token = name == "synthe_complete_handoff" and "claim_token" not in args
        assert no_token and _verdict(over_mcp)[2] == {"claim_token_required"}, (
            f"{vec['name']}: direct {_verdict(direct)} vs MCP {_verdict(over_mcp)}")
