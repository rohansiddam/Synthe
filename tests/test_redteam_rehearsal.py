"""Rehearse scripts/redteam_live.py against a dev broker and a local remote: every attack must be
refused and the control must go through, before anyone runs it against a real install. The OS-wall
checks need separate users, so they run only live (docs/REDTEAM.md)."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import redteam_live as rt  # noqa: E402
import synthe_approve as sa  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_task as st  # noqa: E402
from test_openclaw_flow import PASS, broker, git, world  # noqa: E402,F401


def test_every_attack_is_refused_and_the_control_goes_through(world, tmp_path):
    home, remote, clone = world["home"], world["remote"], world["clone"]
    # An existing agent branch, for the history-rewrite attack.
    seed = tmp_path / "seed2"
    subprocess.run(["git", "clone", "-q", str(remote), str(seed)], check=True, capture_output=True)
    git(seed, "checkout", "-q", "-b", "agent/hello3")
    (seed / "src" / "hello.md").write_text("hello\n")
    git(seed, "add", "-A")
    git(seed, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "hello")
    git(seed, "push", "-q", "origin", "agent/hello3")
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    index = {name: str(st.issue(home, f"red team {name}", branch, key)) for name, branch in rt.BRANCHES.items()}
    (inbox / rt.INDEX).write_text(json.dumps(index))
    broker_pub = json.loads((home / "broker" / "registry.json").read_text())["agents"]["synthe-broker"]["keys"][0]["public_key"]

    with broker(home) as url:
        human = scl.BrokerClient(url)
        seen = {}

        def approve(sid, detail=None):
            out = human.call("submit_approval", approval=sa.build_approval(detail or human.call("staged_detail", id=sid), key))
            return out

        callbacks = {"read_swap": lambda sid: seen.update(a=human.call("staged_detail", id=sid)),
                     "approve_swap": lambda sid: approve(sid, seen["a"]),
                     "approve": approve}
        args = rt.main.__wrapped__ if hasattr(rt.main, "__wrapped__") else None  # noqa: F841
        a = type("A", (), dict(broker=url, broker_pub=broker_pub, repo=str(clone), remote=str(remote),
                               receiver="openclaw", inbox=str(inbox), approver_home=str(home),
                               report=str(tmp_path / "report.json"), dev=True,
                               mcp=[sys.executable, str(ROOT / "src" / "synthe_mcp.py"), "--broker-url", url,
                                    "--as-receiver", "openclaw"]))
        code = rt.cmd_attack(a, human=callbacks)
    report = json.loads((tmp_path / "report.json").read_text())
    failed = [r for r in report["rows"] if r["result"] == "FAIL"]
    assert not failed, json.dumps(failed, indent=2)
    assert code == 0
    passed = {r["attack"] for r in report["rows"] if r["result"] == "PASS"}
    for must in ("the approved in-scope change", "swap the commit after the human read the diff",
                 "rewrite an existing branch's history (force push)", "approve its own push with its own key",
                 "verify the chain independently with the published broker key",
                 "rewrite a denial as 'executed' in a copy", "reuse the finished task"):
        assert must in passed, (must, report["rows"])
