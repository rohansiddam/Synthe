"""T1.5 additivity test: public checker vs ours on every vector.

Compares upstream/main's handoff_check.py against synthe/dogfood's on all
validate-entry vectors. Only planned v0.5 differences are expected.
"""
import copy
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VECTORS_DIR = ROOT / "examples" / "vectors"
# Public checker snapshot (upstream/main's src/handoff_check.py); set SYNTHE_PUBLIC_CHECKER to run
PUBLIC_CHECKER = Path(os.environ.get("SYNTHE_PUBLIC_CHECKER", "/tmp/upstream/handoff_check.py"))


def _load_checker(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(Path(path).parent))
    spec.loader.exec_module(mod)
    return mod


def _run(hc, vec):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        reg = vec.get("registry")
        lp = None
        if "ledger" in vec:
            lp = tmp / "ledger.json"
            lp.write_text(json.dumps(vec["ledger"]))
        if vec.get("ledger_raw"):
            lp = tmp / "ledger.json"
            lp.write_text(vec["ledger_raw"])
        ws = None
        if not vec.get("no_workspace"):
            ws = tmp / "workspace"
            ws.mkdir(exist_ok=True)
            (ws / "task.md").write_text("add a flag\n")
        r = hc.check(copy.deepcopy(vec["packet"]), registry=reg,
                     ledger_path=lp, workspace=ws,
                     verify_evidence=vec.get("verify_evidence", False))
        codes = {x["code"].split(":")[0] for x in r.get("reasons", [])}
        state = r.get("state") or (r["reasons"][0]["state"] if r.get("reasons") else None)
        return (r.get("decision"), state, codes)


def _vectors():
    vecs = []
    for p in sorted(VECTORS_DIR.glob("v*.json")):
        v = json.loads(p.read_text())
        if v.get("entry", "validate") == "validate":
            vecs.append((p.name, v))
    return vecs


# Planned v0.5 differences (public checker predates them)
PLANNED_DIFFS = {
    "v024-dependency-cycle.json": "dependency_cycle (v0.5 wait-for)",
    "v037-claim-conflict.json": "claim_conflict (v0.5 exclusive_paths)",
    # approval_params_mismatch came with v0.4 Synthe Commit (0bcd788) and was never ported to the
    # public checker, which ACCEPTs an approval whose params differ from the plan. Porting it is a
    # verdict change on the public repo, so it needs both founders (a contract change).
    "v031-approval-params-mismatch.json": "approval_params_mismatch (v0.4, not yet public)",
    "v067-tamper-planned-params.json": "approval_params_mismatch (v0.4, not yet public)",
}


@pytest.mark.parametrize("name,vec", _vectors(), ids=[n for n, _ in _vectors()])
def test_additivity(name, vec):
    if not PUBLIC_CHECKER.exists():
        pytest.skip("public checker snapshot not present")
    public = _load_checker(PUBLIC_CHECKER, "hc_public")
    sys.path.insert(0, str(ROOT / "src"))
    import handoff_check as ours
    pd, ps, pc = _run(public, vec)
    od, os_, oc = _run(ours, vec)
    if (pd, ps, pc) != (od, os_, oc):
        assert name in PLANNED_DIFFS, (
            f"{name}: UNPLANNED difference\n"
            f"  public: {pd}/{ps}/{sorted(pc)}\n"
            f"  ours:   {od}/{os_}/{sorted(oc)}"
        )
