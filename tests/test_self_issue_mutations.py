"""Mutation check for self-issued tasks: each guard removed in a copy must make tests/test_self_issue.py fail.

Set SYNTHE_SKIP_MUTATIONS=1 to skip (each mutation runs the end-to-end file in a subprocess)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ("test_self_issue.py",)
HELPERS = ("world.py", "test_openclaw_flow.py", "test_git_push_proposal.py")
H, X, C, L, B, N, G = ("src/handoff_check.py", "src/synthe_crypto.py", "src/synthe_commit.py",
                       "src/synthe_lane_templates.py", "src/synthe_broker.py", "src/synthe_init.py",
                       "src/synthe_git_remote.py")

MUTATIONS = {
    # the checker (pure: no broker state)
    "one signing domain for every handoff": (X, '    if isinstance(handoff, dict) and "issued_under_grant" in handoff:\n',
                                             '    if False:\n'),
    "embedded grant signature not checked": (H, '    if not good:\n        fail("blocked", "self_issue_grant_invalid",',
                                             '    if False:\n        fail("blocked", "self_issue_grant_invalid",'),
    "approvals allowed on a self-issued task": (H, '    if ((h_signed.get("authority") or {}).get("approvals") or []):\n',
                                                '    if False:\n'),
    "containment not enforced": (H, '    if problems:\n        fail("blocked", "self_issue_scope",',
                                 '    if False:\n        fail("blocked", "self_issue_scope",'),
    "task lifetime not bounded": (H, '    if exp is not None and (issued is None or exp < issued or',
                                  '    if False and (issued is None or exp < issued or'),
    "issuer signs ordinary tasks": (H, '        if sender_kind == ISSUER_KIND and not issued:\n', '        if False:\n'),
    "anyone may issue": (H, '        elif issued and sender_kind != ISSUER_KIND:\n', '        elif False:\n'),
    "no sender ceiling": (H, '        if senders is not None and h["from"] not in senders', '        if False and h["from"] not in senders'),
    "control characters in the purpose": (H, '        if cat[0] == "C" or cat in ("Zl", "Zp"):\n', '        if False:\n'),
    # the broker
    "claim skips the broker's record": (B, '                lanes.check_issued(self.cfg, registry, h)\n', '                pass\n'),
    "revocation not checked for a task": (L, '    if tid in s["revoked"]:\n        fail("template_revoked")\n    validate(cfg, registry, t)\n',
                                          '    validate(cfg, registry, t)\n'),
    "any issuer-signed packet is the broker's": (L, '    if not isinstance(rec, dict) or rec.get("packet_sha256") != hc.handoff_digest(h):\n',
                                                 '    if not isinstance(rec, dict):\n'),
    "no re-check at dispatch": (C, '                        if issued:\n                            lanes.check_issued(cfg, current_registry, h)\n',
                                '                        pass\n'),
    "a human approval skips the grant re-check": (C, '                if lane or issued:\n', '                if lane:\n'),
    "max_tasks ignored": (C, '            if "max_tasks" in si and g["issued"] >= si["max_tasks"]:\n', '            if False:\n'),
    "max_open ignored": (C, '            if "max_open" in si and n_open >= si["max_open"]:\n', '            if False:\n'),
    "max_per_hour ignored": (C, '            if "max_per_hour" in si and len(g["recent"]) >= si["max_per_hour"]:\n',
                             '            if False:\n'),
    "request_id reused for other work": (C, '            if prior.get("body_sha256") != body_sha:\n', '            if False:\n'),
    "origin read from the task's text": (C, '    iug = h.get("issued_under_grant")\n    if isinstance(iug, dict):\n        import synthe_lane_templates as lanes\n',
                                         '    iug = h.get("issued_under_grant")\n    if False:\n        import synthe_lane_templates as lanes\n'),
    # the grant
    "unreviewed self-issue allowed": (L, '    if "delegate" not in x and ("auto_approve" not in x or "high" in x["auto_approve"]):\n',
                                      '    if False:\n'),
    "any registered issuer may be named": (L, '            or mine is None or mine["issuer"] != issuer:\n        fail("issuer_invalid")\n',
                                           ':\n        fail("issuer_invalid")\n'),
    "escalate_at ignored": (L, '        tiers = [x for x in tiers if x == "routine"]\n', '        pass\n'),
    # setup and the helper
    "setup writes no sender ceiling": (N, '"trusted_senders": [approver],', ''),
    "the helper ignores the human's task": (G, '                packet, action, path = find_task(branch, Path(inbox) if inbox else None, explicit)\n',
                                            '                raise scl.BrokerError("no_task_for_branch", "skipped")\n'),
}


def _copy_repo(dst: Path) -> None:
    for name in ("src", "examples", "lab", "schema", "deploy"):
        if not (ROOT / name).exists():
            continue
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    for name in (*FILES, *HELPERS):
        shutil.copy2(ROOT / "tests" / name, dst / "tests" / name)


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           *(str(dst / "tests" / f) for f in FILES)],
                          cwd=dst, env=env, capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL)


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
    assert run.returncode != 0, f"mutation {name!r} survived: the self-issue tests did not notice"
