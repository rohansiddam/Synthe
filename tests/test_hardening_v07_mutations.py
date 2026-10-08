"""Mutation check for tests/test_hardening_v07.py: each guard removed in a copy of the code must make
that file fail. A guard no test notices is a guard nobody would notice going missing.

Set SYNTHE_SKIP_MUTATIONS=1 to skip (each mutation runs the hardening tests in a subprocess)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# (file, original text, mutated text): each one removes or weakens exactly one guard.
MUTATIONS = {
    "duplicate keys accepted": ("src/handoff_check.py", "        if k in obj:\n", "        if False:\n"),
    "NaN literal accepted": ("src/handoff_check.py",
                             '    raise StrictJSONError("malformed:non_finite_number", f"{name} is not a JSON number")',
                             '    return float("nan")'),
    "overflowing number accepted": ("src/handoff_check.py", "    if not math.isfinite(value):\n        raise",
                                    "    if False:\n        raise"),
    "check() skips the non-finite walk": ("src/handoff_check.py",
                                          "    bad = _non_finite_reject(packet)\n    if bad:\n        return bad\n"
                                          "    h = packet.get(\"handoff\") if isinstance(packet.get(\"handoff\"), dict) else {}",
                                          "    bad = None\n    if bad:\n        return bad\n"
                                          "    h = packet.get(\"handoff\") if isinstance(packet.get(\"handoff\"), dict) else {}"),
    "packet kid not required": ("src/handoff_check.py",
                                'if sig.get("kid") is None and len(sc.usable_keys(registry, signer)) > 1:',
                                'if sig.get("kid") is None and len(sc.usable_keys(registry, signer)) > 99:'),
    "approval kid not required": ("src/handoff_check.py",
                                  'and len(sc.usable_keys(registry, appr.get("approver"))) > 1)',
                                  'and len(sc.usable_keys(registry, appr.get("approver"))) > 99)'),
    "receiver identity ignored": ("src/handoff_check.py",
                                    '    if as_receiver is not None and h.get("to") != as_receiver:\n',
                                    '    if False:\n'),
    "MCP receiver identity dropped": ("src/synthe_mcp.py",
                                       '        if self.as_receiver is not None and isinstance(h, dict) and h.get("to") != self.as_receiver:\n',
                                       '        if False:\n'),
    "broker receiver identity dropped": ("src/synthe_broker.py",
                                          "                           defer_approvals=defer, as_receiver=self.cfg.receiver_id)\n",
                                          "                           defer_approvals=defer, as_receiver=None)\n"),
    "max TTL ignored": ("src/handoff_check.py", "(exp - at).total_seconds() > max_ttl * 3600",
                        "(exp - at).total_seconds() > max_ttl * 3600 * 1e6"),
    "max TTL layers widen": ("src/handoff_check.py", "merged[k] = min(merged[k], v)", "merged[k] = max(merged[k], v)"),
    "bad max TTL accepted": ("src/handoff_check.py", "(_is_number(max_ttl) and max_ttl <= 0)",
                             "(_is_number(max_ttl) and max_ttl <= -1e9)"),
    "CLI parses leniently": ("src/handoff_check.py", "packet = strict_loads(Path(args.packet).read_text())",
                             "packet = json.loads(Path(args.packet).read_text())"),
    "MCP stdio parses leniently": ("src/synthe_mcp.py", "msg = hc.strict_loads(line)", "msg = json.loads(line)"),
    "broker parses leniently": ("src/synthe_broker.py", 'req = hc.strict_loads(line or b"null")',
                                'req = json.loads(line or b"null")'),
}


def _copy_repo(dst: Path) -> None:
    for name in ("src", "examples", "lab", "schema"):
        if not (ROOT / name).exists():  # the Lab isn't in the public repo
            continue
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    for name in ("test_hardening_v07.py", "world.py", "test_isolation.py"):
        shutil.copy2(ROOT / "tests" / name, dst / "tests" / name)
    shutil.copy2(ROOT / "SPEC.md", dst / "SPEC.md")


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           str(dst / "tests" / "test_hardening_v07.py")],
                          cwd=dst, env=env, capture_output=True, text=True, timeout=600)


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
    assert run.returncode != 0, f"mutation {name!r} survived: the hardening tests did not notice"
