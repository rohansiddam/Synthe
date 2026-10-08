"""T2.2 crash tests: kill -9 the broker inside the fence.

The commit protocol runs the effect inside fenced_effect(): ledger lock
held, claim must be RESERVED for this token, the push happens, the effect
is recorded, the receipt is appended, and only then does the claim flip to
COMPLETED. These tests SIGKILL the broker process at three points:

  1. before the push   -> nothing happened; a retry must execute exactly once
  2. after the push    -> the push landed once; a retry must not push again
  3. before the receipt -> same observable state as (2)

In every case: no double effect, the receipt chain still verifies, and the
ledger never records the same effect twice. "Restart" is a fresh propose()
(the broker keeps all state on disk); "reconcile" is the retry.

Kill coordination: the broker runs in a forked child with a fault hook that
marks a file at the crash point and then stalls; the parent SIGKILLs on the
marker. fcntl locks die with the process, so the ledger is never wedged.
"""
import multiprocessing
import os
import signal
import time
import traceback

import pytest

from world import World, codes


def _child_main(config_path, packet, token, sha, agent_dir, hook_point, marker, errfile):
    """Run propose() in this (forked) process with a fault hook installed."""
    try:
        import synthe_commit as cm
        if hook_point == "before-push":
            orig = cm.GitPush.commit

            def crashing(self, prep, scope):
                with open(marker, "w") as fh:
                    fh.write("inside-fence-before-push")
                time.sleep(60)  # the parent SIGKILLs us here
                return orig(self, prep, scope)

            cm.GitPush.commit = crashing
        elif hook_point == "after-push":
            orig = cm.GitPush.commit

            def crashing(self, prep, scope):
                out = orig(self, prep, scope)  # the real push happens
                with open(marker, "w") as fh:
                    fh.write("push-done")
                time.sleep(60)
                return out

            cm.GitPush.commit = crashing
        elif hook_point == "before-receipt":
            orig = cm.append_receipt

            def crashing(cfg, key, receipt):
                with open(marker, "w") as fh:
                    fh.write("before-receipt")
                time.sleep(60)  # killed before the receipt is durably written
                return orig(cfg, key, receipt)

            cm.append_receipt = crashing
        else:
            raise AssertionError(f"unknown hook point {hook_point!r}")
        cfg = cm.BrokerConfig(config_path)
        proposal = {"packet": packet, "claim_token": token, "action": "push_branch",
                    "params": {"remote": "origin", "branch": "feature/x", "commit": sha},
                    "source": agent_dir}
        cm.propose(cfg, proposal)
    except BaseException:
        with open(errfile, "w") as fh:
            fh.write(traceback.format_exc())


def _kill_broker_at(hook_point, w, packet, token, sha, tmp_path, timeout=30):
    """Fork the broker, wait for it to reach the crash point, SIGKILL it."""
    marker = str(tmp_path / f"marker-{hook_point}")
    errfile = str(tmp_path / f"error-{hook_point}")
    ctx = multiprocessing.get_context("fork")
    proc = ctx.Process(target=_child_main,
                       args=(str(w.config_path), packet, token, sha,
                             str(w.agent), hook_point, marker, errfile))
    proc.start()
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(marker):
            break
        if not proc.is_alive():
            err = open(errfile).read() if os.path.exists(errfile) else "<no traceback>"
            pytest.fail(f"broker died before reaching '{hook_point}':\n{err}")
        time.sleep(0.05)
    else:
        proc.terminate()
        pytest.fail(f"broker never reached crash point '{hook_point}'")
    os.kill(proc.pid, signal.SIGKILL)  # the crash
    proc.join(timeout=10)
    assert not proc.is_alive(), "broker survived SIGKILL"
    return proc


@pytest.fixture
def crashed_world(tmp_path):
    """A World with a claimed packet and a committed change, ready to crash."""
    w = World(tmp_path)
    p = w.packet()
    token = w.claim(p)
    sha = w.commit({"src/app.py": "print('v2')\n"})
    return w, p, token, sha


def test_crash_before_push_retries_cleanly(tmp_path, crashed_world):
    w, p, token, sha = crashed_world
    _kill_broker_at("before-push", w, p, token, sha, tmp_path)
    # Nothing happened: no push, claim still RESERVED, no receipt, chain intact.
    assert w.remote_ref("feature/x") is None
    entry = w.ledger_entry()
    assert entry["state"] == "RESERVED" and not entry.get("effects")
    assert w.chain()["ok"] and w.chain()["count"] == 0
    # Restart + reconcile: the retry must execute exactly once.
    r = w.propose(p, token, sha)
    assert r["decision"] == "executed", r["reasons"]
    assert w.remote_ref("feature/x") == sha
    entry = w.ledger_entry()
    assert entry["state"] == "COMPLETED"
    assert entry["effects"]["push_branch"]["state"] == "EXECUTED"
    assert w.chain()["ok"]


def test_crash_after_push_never_pushes_twice(tmp_path, crashed_world):
    w, p, token, sha = crashed_world
    _kill_broker_at("after-push", w, p, token, sha, tmp_path)
    # The push landed exactly once, but nothing was recorded: unknown outcome.
    assert w.remote_ref("feature/x") == sha
    entry = w.ledger_entry()
    assert entry["state"] == "RESERVED" and not entry.get("effects")
    assert w.chain()["ok"] and w.chain()["count"] == 0
    # Reconcile: the retry must not push again. The branch is already at the
    # commit, so the broker refuses with no_change instead of double-pushing.
    r = w.propose(p, token, sha)
    assert r["decision"] == "denied" and codes(r) == {"no_change"}, r["reasons"]
    assert w.remote_ref("feature/x") == sha  # still exactly the one push
    assert w.ledger_entry()["state"] == "RESERVED"  # effect happened once, unrecorded
    assert w.chain()["ok"]


def test_crash_before_receipt_never_pushes_twice(tmp_path, crashed_world):
    w, p, token, sha = crashed_world
    _kill_broker_at("before-receipt", w, p, token, sha, tmp_path)
    # Observably identical to crash-after-push: push landed, nothing recorded,
    # no (partial) receipt.
    assert w.remote_ref("feature/x") == sha
    entry = w.ledger_entry()
    assert entry["state"] == "RESERVED" and not entry.get("effects")
    assert w.chain()["ok"] and w.chain()["count"] == 0
    r = w.propose(p, token, sha)
    assert r["decision"] == "denied" and codes(r) == {"no_change"}, r["reasons"]
    assert w.remote_ref("feature/x") == sha
    assert w.ledger_entry()["state"] == "RESERVED"
    assert w.chain()["ok"]
