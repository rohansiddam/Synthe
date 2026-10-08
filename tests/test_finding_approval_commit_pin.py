"""FINDING-D1: a human approval cannot be bound to the commit it was given for.

Step D approvals pin the target (remote, branch) but not the commit. A staged
proposal is replaced when the agent re-proposes (test_speculative.py::
test_restaging_supersedes_the_older_stage), so an approval given after reading
the diff of commit A also covers a commit B staged later. The broker already
honours an approval that pins `commit` (control test below), but such an
approval is never accepted because admission requires approval params to be a
subset of the sender's signed plan, and the plan cannot know the commit.

See findings/FINDING-D1-approval-commit-pin.md."""
import datetime as dt

import pytest
from test_speculative import PUSH, speculative_claim, staged_state
from world import World, cm, git, ss, ts


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def _pinned_approval(w, packet, commit):
    params = {**ss.planned_params(packet["handoff"], PUSH), "commit": commit}
    return ss.detached_approval(packet, w.keys["rishab"], PUSH, ts(dt.timedelta(days=1)), params)


def _stage(w):
    p = w.packet(idem="d1", branch="feature/x", approve=False)
    tok = speculative_claim(w, p)
    a = w.commit({"src/app.py": "print('A')\n"}, msg="A")
    r = w.propose(p, tok, a, branch="feature/x", wait_for_approval=True)
    assert r["decision"] == "staged", r
    return p, tok, a


def test_commit_pinned_approval_executes_the_commit_it_names(w):
    p, tok, a = _stage(w)
    out = cm.submit_approval(w.cfg, _pinned_approval(w, p, a))
    assert out["receipt"]["decision"] == "approval_accepted", out["receipt"]
    # today: approval stored, but nothing commits (the proposal stays staged)
    assert out["commits"], "approval was stored but the staged proposal never committed"
    [done] = out["commits"]
    assert done["decision"] == "executed" and w.remote_ref("feature/x") == a


def test_control_commit_pinned_approval_never_covers_a_different_commit(w):
    """The safe half works today: an approval that names A does not let B land."""
    p, tok, a = _stage(w)
    b = w.commit({"src/app.py": "print('B')\n"}, msg="B")
    r2 = w.propose(p, tok, b, branch="feature/x", wait_for_approval=True)
    assert r2["decision"] == "staged"
    out = cm.submit_approval(w.cfg, _pinned_approval(w, p, a))
    assert not any(c["decision"] == "executed" for c in out["commits"])
    assert w.remote_ref("feature/x") is None
    assert staged_state(w, "d1") == {PUSH: "STAGED"}


# -- FINDING-D2 (fixed): a corrupt staged store is refused, not read as empty ---

def test_corrupt_staged_store_is_refused_not_read_as_empty(w):
    _stage(w)
    w.cfg.staged_path.write_text("{ not json")
    with pytest.raises(Exception):
        cm.staged_view(w.cfg)


# -- FINDING-D1 (fixed): operator option so approvals must pin the commit -----

def _require_pin(w):
    w.cfg.effects["git_push"]["require_approval_commit_pin"] = True


def test_unpinned_approval_does_not_commit_when_the_pin_is_required(w):
    _require_pin(w)
    p, tok, a = _stage(w)
    unpinned = ss.detached_approval(p, w.keys["rishab"], PUSH, ts(dt.timedelta(days=1)),
                                    ss.planned_params(p["handoff"], PUSH))
    out = cm.submit_approval(w.cfg, unpinned)
    assert out["receipt"]["decision"] == "approval_accepted" and out["commits"] == []
    assert w.remote_ref("feature/x") is None and staged_state(w, "d1") == {PUSH: "STAGED"}


def test_swapped_commit_is_not_covered_when_the_pin_is_required(w):
    """The attack from FINDING-D1: approval read for A, agent restages B."""
    _require_pin(w)
    p, tok, a = _stage(w)
    b = w.commit({"src/app.py": "print('B')\n"}, msg="B")
    assert w.propose(p, tok, b, branch="feature/x", wait_for_approval=True)["decision"] == "staged"
    out = cm.submit_approval(w.cfg, _pinned_approval(w, p, a))
    assert not any(c["decision"] == "executed" for c in out["commits"])
    assert w.remote_ref("feature/x") is None
    # an approval for B does cover B
    [done] = cm.submit_approval(w.cfg, _pinned_approval(w, p, b))["commits"]
    assert done["decision"] == "executed" and w.remote_ref("feature/x") == b


def test_sign_cli_pins_the_commit(w, tmp_path):
    import json
    import subprocess
    import sys
    from world import ROOT
    p, tok, a = _stage(w)
    pk, kk, out = tmp_path / "p.json", tmp_path / "k.json", tmp_path / "a.json"
    pk.write_text(json.dumps(p))
    kk.write_text(json.dumps({k: v for k, v in w.keys["rishab"].items() if k != "_secret"}))
    r = subprocess.run([sys.executable, str(ROOT / "src/synthe_sign.py"), "approve", str(pk), "--key", str(kk),
                        "--action", PUSH, "--detached", "--commit", a, "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["params"]["commit"] == a
