"""v0.4 Synthe Commit: the broker holds the credentials, checks each proposed
effect at commit time, pushes with compare-and-swap, observes the result and
signs a hash-chained receipt for every allow and deny.

Everything runs against real git repos on disk (a bare repo stands in for
GitHub), so these tests need `git` but no network. The adversary groups
follow the four threats in "Delegation Without Trust" (arXiv:2609.00267):
confused deputy, token theft/replay, injection-driven privilege escalation,
compromised sub-agent."""
import datetime as dt
import json
import subprocess
import sys

import pytest

from world import ROOT, World, codes, git, ts
from world import cm, hc, ss  # noqa: F401  (modules under test)


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


# ---- the happy path ---------------------------------------------------------

def test_executes_observes_completes_and_signs(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "print('v2')\n"})
    r = w.propose(p, token, c)
    assert r["decision"] == "executed", r
    assert w.remote_ref("feature/x") == c
    assert r["effect"]["after"] == c and r["effect"]["before"] is None
    assert r["observed"]["paths"] == ["src/app.py"]
    assert r["approvals"][0]["approver"] == "rishab"
    assert r["approvals"][0]["params"] == {"remote": "origin", "branch": "feature/x"}
    e = w.ledger_entry()
    assert e["state"] == "COMPLETED" and e["effects"]["push_branch"]["state"] == "EXECUTED"
    chain = w.chain()
    assert chain["ok"] and chain["count"] == 1


def test_denial_does_not_consume_the_claim(w):
    p = w.packet()
    token = w.claim(p)
    bad = w.commit({"README.md": "# changed\n"})
    r = w.propose(p, token, bad)
    assert r["decision"] == "denied" and "path_outside_scope" in codes(r)
    assert w.remote_ref("feature/x") is None
    assert w.ledger_entry()["state"] == "RESERVED"
    git(w.agent, "reset", "-q", "--hard", "HEAD~1")
    good = w.commit({"src/app.py": "print('ok')\n"})
    assert w.propose(p, token, good)["decision"] == "executed"
    chain = w.chain()
    assert chain["ok"] and [x["decision"] for x in chain["receipts"]] == ["denied", "executed"]


# ---- adversary 1: confused deputy (agent steered to a target nobody approved) --

def test_confused_deputy_other_branch_than_planned(w):
    p = w.packet(branch="feature/x")
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(p, token, c, branch="main")
    assert r["decision"] == "denied" and "effect_params_mismatch" in codes(r)
    assert w.remote_ref("main") != c


def test_confused_deputy_sender_retargets_after_approval(w):
    # Rishab approved feature/x. The sender then edits its plan to main and
    # re-signs; the approval still verifies (same handoff) but pins feature/x.
    p = w.packet(branch="feature/x")
    p["handoff"]["planned_actions"][1]["params"]["branch"] = "main"
    p = ss.sign_packet(p, w.keys["planner"])
    admit = hc.check(p, registry=w.registry, ledger_path=w.tmp / "ledger.json",
                     workspace=w.tmp / "workspace")
    assert admit["decision"] == "REJECT"  # caught at admission...
    assert "approval_params_mismatch" in {x["code"] for x in admit["reasons"]}
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(p, "any", c, branch="main")  # ...and again at commit time
    assert r["decision"] == "denied" and "approval_params_mismatch" in codes(r)


def test_approval_must_pin_the_target(w):
    p = w.packet(pin_params=False)
    token = w.claim(p)
    r = w.propose(p, token, w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and "approval_params_missing" in codes(r)


def test_untrusted_approver(w):
    p = w.packet(approver="mallory")
    r = w.propose(p, "no-claim", w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and "approver_not_trusted" in codes(r)


# ---- adversary 2: token theft / replay --------------------------------------

def test_replay_of_executed_effect(w):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    first = w.propose(p, token, c)
    assert first["decision"] == "executed"
    r = w.propose(p, token, c)
    assert r == first
    assert w.chain()["count"] == 1
    assert w.chain()["ok"]


def test_approval_replayed_onto_another_handoff(w):
    p1 = w.packet(idem="k1")
    p2 = w.packet(idem="k2", approve=False)
    p2["handoff"]["authority"]["approvals"] = p1["handoff"]["authority"]["approvals"]
    p2 = ss.sign_packet(p2, w.keys["planner"])
    r = w.propose(p2, "x", w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and "approval_signature_invalid" in codes(r)


def test_expired_approval_is_refused_at_commit_time(w, monkeypatch):
    p = w.packet(approval_exp=ts(dt.timedelta(hours=1)))
    token = w.claim(p)  # valid at admission...
    c = w.commit({"src/app.py": "x\n"})
    later = hc.now_utc() + dt.timedelta(hours=2)
    monkeypatch.setattr(hc, "now_utc", lambda: later)
    r = w.propose(p, token, c)  # ...but not when the effect would happen
    assert r["decision"] == "denied" and "approval_expired" in codes(r)
    assert w.remote_ref("feature/x") is None


# ---- adversary 3: injection-driven privilege escalation ---------------------

def test_unplanned_effect(w):
    p = w.packet()
    token = w.claim(p)
    r = w.propose(p, token, w.commit({"src/app.py": "x\n"}), action="deploy")
    assert r["decision"] == "denied" and "effect_not_planned" in codes(r)


def test_sender_cannot_widen_paths_past_receiver_policy(w):
    p = w.packet(owned_paths=["**"])  # sender claims the whole repo
    token = w.claim(p)
    r = w.propose(p, token, w.commit({".github/workflows/ci.yml": "steal: secrets\n"}))
    assert r["decision"] == "denied" and "path_outside_receiver_policy" in codes(r)


def test_forbidden_path(w):
    p = w.packet()
    token = w.claim(p)
    r = w.propose(p, token, w.commit({"src/secrets/key.pem": "-----\n"}))
    assert r["decision"] == "denied" and "path_forbidden" in codes(r)


def test_secret_in_intermediate_commit_is_caught(w):
    p = w.packet()
    token = w.claim(p)
    w.commit({"leak.txt": "token=abc\n"}, msg="oops")
    c = w.commit({"src/app.py": "x\n"}, msg="clean up", delete=["leak.txt"])
    r = w.propose(p, token, c)  # the net diff is clean; the history is not
    assert r["decision"] == "denied" and "path_outside_scope" in codes(r)
    assert "leak.txt" in r["reasons"][0]["message"]


def test_branch_outside_broker_config(tmp_path):
    w = World(tmp_path, branches=("feature/*",))
    p = w.packet(branch="main")
    token = w.claim(p)
    r = w.propose(p, token, w.commit({"src/app.py": "x\n"}), branch="main")
    assert r["decision"] == "denied" and "branch_not_allowed" in codes(r)


def test_history_rewrite_is_refused(w):
    p1 = w.packet(idem="k1")
    t1 = w.claim(p1)
    a = w.commit({"src/app.py": "a\n"})
    assert w.propose(p1, t1, a)["decision"] == "executed"
    git(w.agent, "reset", "-q", "--hard", "HEAD~1")
    b = w.commit({"src/app.py": "b\n"})
    p2 = w.packet(idem="k2")
    t2 = w.claim(p2)
    r = w.propose(p2, t2, b)
    assert r["decision"] == "denied" and "non_fast_forward" in codes(r)
    assert w.remote_ref("feature/x") == a


def test_source_outside_roots(w, tmp_path):
    p = w.packet()
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(p, token, c, source=str(tmp_path))
    assert r["decision"] == "denied" and "source_not_allowed" in codes(r)


# ---- adversary 4: compromised sub-agent / stale holder ----------------------

def test_holder_of_packet_without_claim_token(w):
    p = w.packet()
    w.claim(p)
    r = w.propose(p, "stolen-or-guessed", w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and "claim_token_invalid" in codes(r)


def test_released_claim_old_holder_is_fenced_out(w):
    p = w.packet()
    old = w.claim(p)
    assert hc.release(p, w.tmp / "ledger.json", force=True)["decision"] == "RELEASED"
    new = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(p, old, c)
    assert r["decision"] == "denied" and "claim_token_invalid" in codes(r)
    ok = w.propose(p, new, c)
    assert ok["decision"] == "executed" and ok["claim"]["epoch"] == 2


# ---- check-to-effect races (TOCTOU) -----------------------------------------

def test_remote_moved_since_agent_looked(w):
    p = w.packet(branch="main")
    token = w.claim(p)
    c = w.commit({"src/app.py": "x\n"})
    r = w.propose(p, token, c, branch="main", params={"expected_old": "0" * 40})
    assert r["decision"] == "denied" and "remote_moved" in codes(r)


def test_race_between_check_and_push_is_caught_by_cas(w, monkeypatch):
    p = w.packet(branch="main")
    token = w.claim(p)
    ours = w.commit({"src/app.py": "ours\n"})
    # someone else lands a commit on main right after the broker's checks
    racer = w.tmp / "racer"
    git(w.tmp, "clone", "-q", str(w.remote), str(racer))
    (racer / "src" / "app.py").write_text("theirs\n")
    git(racer, "commit", "-qam", "theirs")
    real = cm.GitPush._is_ancestor

    def checks_then_race(self, a, b):
        result = real(self, a, b)
        git(racer, "push", "-q", "origin", "HEAD:main")
        return result

    monkeypatch.setattr(cm.GitPush, "_is_ancestor", checks_then_race)
    r = w.propose(p, token, ours, branch="main")
    assert r["decision"] == "denied" and "remote_moved_during_commit" in codes(r)
    assert w.remote_ref("main") == git(racer, "rev-parse", "HEAD")
    assert w.ledger_entry()["state"] == "RESERVED"


# ---- receipts --------------------------------------------------------------

def test_every_decision_is_a_verified_receipt_and_tampering_breaks_the_chain(w):
    p = w.packet()
    token = w.claim(p)
    w.propose(p, "wrong", w.commit({"src/app.py": "1\n"}))
    w.propose(p, token, w.commit({"src/app.py": "2\n"}))
    w.propose(p, token, w.commit({"src/app.py": "3\n"}))
    chain = w.chain()
    assert chain["ok"] and chain["count"] == 3
    lines = w.cfg.receipts_path.read_text().splitlines()
    forged = json.loads(lines[0])
    forged["decision"] = "executed"
    w.cfg.receipts_path.write_text("\n".join([json.dumps(forged), *lines[1:]]) + "\n")
    assert not w.chain()["ok"]
    w.cfg.receipts_path.write_text("\n".join(lines[1:]) + "\n")  # delete the first receipt
    assert not w.chain()["ok"]


def test_receipts_never_contain_credentials(tmp_path):
    w = World(tmp_path)
    remotes = w.cfg.effects["git_push"]["remotes"]
    remotes["origin"]["url"] = "https://x-access-token:SECRET123@example.invalid/r.git"
    assert "SECRET123" not in cm.redact_url(remotes["origin"]["url"])
    assert "SECRET123" not in json.dumps(w.cfg.public_view())


# ---- entry points ------------------------------------------------------------

def test_mcp_propose_effect_tool(w):
    import synthe_mcp as mcp
    server = mcp.SyntheServer(str(w.cfg.registry_path), str(w.cfg.ledger_path), str(w.cfg.workspace),
                              broker_config=str(w.config_path))
    names = {t["name"] for t in server.tools()}
    assert "synthe_propose_effect" in names
    p = w.packet()
    verdict = server.tool_validate({"packet": p})
    assert verdict["decision"] == "ACCEPT"
    c = w.commit({"src/app.py": "mcp\n"})
    out = server.tool_functions()["synthe_propose_effect"]({
        "packet": p, "claim_token": verdict["claim"]["token"], "action": "push_branch",
        "params": {"remote": "origin", "branch": "feature/x", "commit": c}, "source": str(w.agent)})
    assert out["decision"] == "executed" and w.remote_ref("feature/x") == c


def test_cli_push_and_receipts_verify(w):
    p = w.packet()
    token = w.claim(p)
    (w.tmp / "p.json").write_text(json.dumps(p))
    w.commit({"src/app.py": "cli\n"})
    run = subprocess.run([sys.executable, str(ROOT / "src" / "synthe_commit.py"), "push",
                          "--config", str(w.config_path), "--packet", str(w.tmp / "p.json"),
                          "--claim-token", token, "--action", "push_branch", "--remote", "origin",
                          "--branch", "feature/x", "--source", str(w.agent)],
                         capture_output=True, text=True)
    assert run.returncode == 0, (run.stdout, run.stderr)  # print the receipt if this ever flakes again
    assert json.loads(run.stdout)["decision"] == "executed", run.stdout
    v = subprocess.run([sys.executable, str(ROOT / "src" / "synthe_commit.py"), "receipts", "verify",
                        "--config", str(w.config_path)], capture_output=True, text=True)
    assert v.returncode == 0 and json.loads(v.stdout)["ok"]


def test_console_state_shows_chain_and_hides_token_hashes(w):
    p = w.packet()
    token = w.claim(p)
    w.propose(p, token, w.commit({"src/app.py": "ui\n"}))
    state = cm.console_state(w.cfg)
    assert state["chain"]["ok"] and state["chain"]["count"] == 1
    assert state["receipts"][0]["decision"] == "executed"
    assert state["claims"][0]["effects"]["push_branch"]["state"] == "EXECUTED"
    blob = json.dumps(state)
    assert "claim_token" not in blob and token not in blob
