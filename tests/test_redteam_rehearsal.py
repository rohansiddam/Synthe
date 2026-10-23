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


def test_every_attack_is_refused_and_the_control_goes_through(world, tmp_path, monkeypatch):
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
    import synthe_lane_templates as lanes
    monkeypatch.setenv("SYNTHE_REDTEAM_KEYS", str(home / "broker" / "keys"))   # dev: the agent can read them; use them

    with broker(home) as url:
        human = scl.BrokerClient(url)
        rt.sign_self_issue_lane(human, key, "openclaw", ["src/**"])       # step 1's self-issue lane
        seen = {}

        def approve(sid, detail=None):
            out = human.call("submit_approval", approval=sa.build_approval(detail or human.call("staged_detail", id=sid), key))
            return out

        callbacks = {"read_swap": lambda sid: seen.update(a=human.call("staged_detail", id=sid)),
                     "approve_swap": lambda sid: approve(sid, seen["a"]),
                     "approve": approve,
                     "revoke": lambda: human.call("revoke_lane_template", revocation=lanes.sign(
                         {"template_id": rt.SI_LANE}, key, revoke=True))}
        args = rt.main.__wrapped__ if hasattr(rt.main, "__wrapped__") else None  # noqa: F841
        a = type("A", (), dict(broker=url, broker_pub=broker_pub, repo=str(clone), remote=str(remote),
                               receiver="openclaw", inbox=str(inbox), approver_home=str(home),
                               report=str(tmp_path / "report.json"), dev=True,
                               registry=str(home / "broker" / "registry.json"),
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
                 "rewrite a denial as 'executed' in a copy", "reuse the finished task",
                 "SI-16 a self-issued routine push (control)", "SI-01 issue a task under no self-issue grant",
                 "SI-05 reuse a request_id for a different task", "SI-07 strip issued_under_grant from an issued task",
                 "SI-11 a purpose claiming the human's approval", "SI-10 approve its own self-issued push",
                 "SI-15 two self-issued tasks that depend on each other",
                 f"SI-04 open more tasks than the lane's max_open ({rt.SI_MAX_OPEN})",
                 "SI-13 claim an issued task after its lane was revoked",
                 "SI-13 a staged self-issued push after its lane was revoked",
                 "SI-14 present an issued task to a checker from before v0.7"):
        assert must in passed, (must, report["rows"])
