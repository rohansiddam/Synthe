"""Mutation check for the grant and delegate guards: each one removed in a copy must make
tests/test_delegate_approvals.py or tests/test_lane_templates.py fail.

Set SYNTHE_SKIP_MUTATIONS=1 to skip (each mutation runs both files in a subprocess). Not mutated: the lane
lock around dispatch (a race the serial tests can't observe; tests/test_lane_templates.py reserves under
the lock directly)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ("test_delegate_approvals.py", "test_lane_templates.py")

MUTATIONS = {
 "delegate may be a party": ("src/synthe_lane_templates.py", '    if x["approver"] in (x["from"], x["to"]):\n', '    if False:\n'),
 "any identity may be a delegate": ("src/synthe_lane_templates.py", 'entry.get("kind") != DELEGATE_KIND or ', ''),
 "delegate signature unchecked": ("src/synthe_lane_templates.py", '    if not _verifies(registry, x, delegate_input(x, escalate)):\n', '    if False:\n'),
 "unnamed delegate accepted": ("src/synthe_lane_templates.py", '    if not t or t.get("delegate") != x["approver"]:\n', '    if not t:\n'),
 "approval not pinned to the staged record": ("src/synthe_lane_templates.py", ' or not _matches(x, h, staged.get("action"), staged.get("params") or {}):', ':'),
 "commit-time match skipped": ("src/synthe_lane_templates.py", '    if not _matches(x, h, action, params):\n        fail("delegate_approval_stale")\n', ''),
 "approval lifetime unbounded": ("src/synthe_lane_templates.py", 'MAX_DELEGATE_MINUTES = 60\n', 'MAX_DELEGATE_MINUTES = 60 * 24 * 365\n'),
 "escalation not sticky at submit": ("src/synthe_lane_templates.py", '    if sid in d["escalations"]:\n        fail("delegate_escalated")\n    h = ', '    h = '),
 "escalation not sticky at commit": ("src/synthe_lane_templates.py", '    if sid in d["escalations"]:\n        fail("delegate_escalated")\n    x = d["approvals"]', '    x = d["approvals"]'),
 "no re-check at dispatch": ("src/synthe_commit.py", '                        if lane.get("delegate"):  # escalated or expired since', '                        if False:  # escalated or expired since'),
 "human approval spends a use": ("src/synthe_commit.py", '                lane = None  # a human\'s approval never spends a grant use\n', '                pass\n'),
 "delegate grant skips the delegate": ("src/synthe_commit.py", '        if not pending and (not lane or lane.get("delegate")):\n', '        if not pending and not lane:\n'),
 "revoked grant takes delegate approvals": ("src/synthe_lane_templates.py", '    if t["template_id"] in s["revoked"]:\n        fail("template_revoked")\n', ''),
 "untrusted human revokes": ("src/synthe_lane_templates.py", '        if x.get("approver") != t["approver"] and (x.get("approver") not in trusted or who.get("kind") != "human"):\n', '        if False:\n'),
 "grant expiry ignored": ("src/synthe_lane_templates.py", '    if expiry is None or expiry <= hc.now_utc():\n        fail("template_expired")\n', ''),
 "grant lineage ignored": ("src/synthe_lane_templates.py", '    if x["lineage"] != lineage(cfg, registry, x["receiver"]):\n        fail("template_stale")\n', ''),
 "grant max uses ignored": ("src/synthe_lane_templates.py", '            if s["uses"].get(tid, 0) >= t["max_uses"]:\n                fail("template_exhausted")\n            if params', '            if params'),
 "grant revocation ignored": ("src/synthe_lane_templates.py", '            if tid in s["revoked"]:\n                fail("template_revoked")\n            if s["uses"]', '            if s["uses"]'),
 "grant path scope ignored": ("src/synthe_lane_templates.py", '            if paths is not None and any(not any_match(t["path_scope"], p) for p in paths):\n', '            if False:\n'),
}


def _copy_repo(dst: Path) -> None:
    for name in ("src", "examples", "lab", "schema"):
        if not (ROOT / name).exists():
            continue
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    for name in (*FILES, "world.py", "test_speculative.py", "test_isolation.py"):
        shutil.copy2(ROOT / "tests" / name, dst / "tests" / name)


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           *(str(dst / "tests" / f) for f in FILES)],
                          cwd=dst, env=env, capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
def test_unmutated_copy_passes(tmp_path):
    _copy_repo(tmp_path)
    run = _run(tmp_path)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutation_is_caught(name, tmp_path):
    rel, original, mutated = MUTATIONS[name]
    _copy_repo(tmp_path)
    target = tmp_path / rel
    text = target.read_text()
    assert text.count(original) == 1, f"mutation anchor for {name!r} not found exactly once in {rel}"
    target.write_text(text.replace(original, mutated))
    run = _run(tmp_path)
    assert run.returncode != 0, f"mutation {name!r} survived: the grant/delegate tests did not notice"
