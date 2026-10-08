"""Each changed setup/adapter boundary has a mutation with a passing, isolated baseline."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = "integrations/claude-code/hooks/pre_tool_use.py"
MUTATIONS = {
    "push filter removed": (HOOK, "return any(re.search(rule, command) for rule in RULES)", "return False"),
    "approval delivery allowed": (HOOK, 'if tool.endswith(("__synthe_submit_approval", "__github_publish")):', 'if False:'),
    "malformed hook allowed": (HOOK, "except (ValueError, RecursionError):\n        block = True", "except (ValueError, RecursionError):\n        block = False"),
    "hook authorizes tools": (HOOK, "    # No allow decision:", '    print("allow")\n    # No allow decision:'),
    "generic setup allows human identity": ("src/synthe_init.py", "if agent_account == approver:", "if False:"),
    "broker identity allowed": ("src/synthe_init.py", 'if agent_account in ("root", "synthe", "_synthe"):', 'if False:'),
    "agent key allowed": ("src/synthe_init.py", 'if (home / "approver.key.json").exists():', 'if False:'),
    "Linux loses separate clients": ("src/synthe_init.py", 'cfg["isolation"]["clients"] = clients', 'pass'),
    "Linux reuses human identity": ("src/synthe_init.py", 'if agent_user == approver:', 'if False:'),
    "root install reuses broker": ("deploy/linux/finish.sh", '[ ! -e "$STATE/broker.json" ]', 'true'),
    "unready broker ignored": ("deploy/linux/finish.sh", '[ "$BROKER_READY" = 1 ]', 'true'),
    "private verifier dependency": ("packaging/verify/pyproject.toml", 'dependencies = []', 'dependencies = ["synthe"]'),
}


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
@pytest.mark.parametrize("name", [None, *MUTATIONS])
def test_mutation_is_caught(tmp_path, name):
    for directory in ("src", "deploy", "integrations", "packaging", "scripts", "docs", ".github"):
        shutil.copytree(ROOT / directory, tmp_path / directory, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    shutil.copyfile(ROOT / "LICENSE", tmp_path / "LICENSE")
    (tmp_path / "tests").mkdir()
    for filename in ("test_any_agent.py", "test_claude_plugin.py", "test_release_packaging.py"):
        shutil.copyfile(ROOT / "tests" / filename, tmp_path / "tests" / filename)
    if name:
        filename, old, new = MUTATIONS[name]
        target = tmp_path / filename
        text = target.read_text()
        assert text.count(old) == 1, name
        target.write_text(text.replace(old, new))
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests"],
                         cwd=tmp_path, capture_output=True, text=True, timeout=90,
                         env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if name:
        assert run.returncode == 1 and "failed" in run.stdout, f"mutant did not cause an assertion failure: {name}\n{run.stdout[-2000:]}{run.stderr[-1000:]}"
    else:
        assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-1000:]
