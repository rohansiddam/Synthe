"""Step D: detached approvals and speculative commit.

An agent claims and proposes before the human has approved. The broker checks
everything it can, holds the proposal STAGED (pinned to the remote state it
saw), and commits it the moment a signed approval (or the upstream it waits
on) arrives, re-running every commit-time check. Every transition is a
signed receipt; anything that changed in between is a denial."""
import datetime as dt
import json
import os
import stat
import subprocess
import sys
import threading
import time

import pytest
from world import ROOT, World, cm, codes, git, hc, ss, ts

import synthe_broker as sb
import synthe_client as scl
import synthe_mcp
from test_isolation import daemon, lock_down

PUSH = "push_branch"


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def speculative_claim(w, packet):
    """Claim with the broker-mediated push's approval deferred (what the
    daemon's claim does with wait_for_approval)."""
    v = w.check(packet, defer_approvals={PUSH}, extra_approvals=cm.load_approvals(w.cfg, packet["handoff"]))
    assert v["decision"] == "ACCEPT", v
    return v["claim"]["token"]


def stage(w, idem="k1", branch="feature/x", **kw):
    p = w.packet(idem=idem, branch=branch, approve=False, **kw)
    tok = speculative_claim(w, p)
    sha = w.commit({"src/app.py": f"print('{idem}')\n"}, msg=idem)
    r = w.propose(p, tok, sha, branch=branch, wait_for_approval=True)
    return p, tok, sha, r


def detached(w, packet, approver="rishab", exp=None, params="planned"):
    if params == "planned":
        params = ss.planned_params(packet["handoff"], PUSH)
    return ss.detached_approval(packet, w.keys[approver], PUSH, exp or ts(dt.timedelta(days=1)), params)


def staged_state(w, idem="k1"):
    return {r["action"]: r["state"] for r in cm.staged_view(w.cfg, idem)}


def decisions(w):
    return [(r.get("kind", "effect"), r["decision"]) for r in w.chain()["receipts"]]


# -- the checker: detached approvals and deferral -----------------------------

def test_claim_without_approval_still_rejected_by_default(w):
    p = w.packet(approve=False)
    v = w.check(p)
    assert v["decision"] == "REJECT" and "approval_missing" in {r["code"] for r in v["reasons"]}


def test_deferred_claim_records_it_on_the_claim(w):
    p = w.packet(approve=False)
    speculative_claim(w, p)
    assert w.ledger_entry()["approvals_deferred"] == [PUSH]


def test_defer_never_excuses_a_bad_approval(w):
    p = w.packet(approval_exp=ts(dt.timedelta(seconds=-5)))  # embedded, expired
    v = w.check(p, defer_approvals={PUSH})
    assert v["decision"] == "REJECT" and "approval_expired" in {r["code"] for r in v["reasons"]}


def test_detached_approval_satisfies_the_checker(w):
    p = w.packet(approve=False)
    v = w.check(p, dry_run=True, extra_approvals=[detached(w, p)])
    assert v["decision"] == "ACCEPT", v


def test_unsigned_detached_approval_is_ignored(w):
    p = w.packet(approve=False)
    fake = {k: v for k, v in detached(w, p).items() if k != "sig"}
    v = w.check(p, dry_run=True, extra_approvals=[fake])
    assert v["decision"] == "REJECT" and "approval_missing" in {r["code"] for r in v["reasons"]}


def test_detached_cli_needs_out_and_writes_a_bound_approval(w, tmp_path):
    p = w.packet(approve=False)
    pk, kf = tmp_path / "p.json", tmp_path / "k.json"
    pk.write_text(json.dumps(p))
    kf.write_text(json.dumps({k: v for k, v in w.keys["rishab"].items() if k != "_secret"}))
    base = [sys.executable, str(ROOT / "src" / "synthe_sign.py"), "approve", str(pk), "--key", str(kf),
            "--action", PUSH, "--detached"]
    assert subprocess.run(base, capture_output=True, text=True).returncode == 2
    out = tmp_path / "a.json"
    assert subprocess.run(base + ["--out", str(out)], capture_output=True, text=True).returncode == 0
    a = json.loads(out.read_text())
    assert (a["idempotency_key"], a["from"], a["to"], a["action"]) == ("k1", "planner", "builder", PUSH)
    assert a["params"] == {"remote": "origin", "branch": "feature/x"} and a["sig"]
    assert p["handoff"]["authority"]["approvals"] == []  # the packet never changes


# -- speculative commit: the happy path --------------------------------------

def test_staged_then_approved_then_executed(w):
    p, tok, sha, r = stage(w)
    assert r["decision"] == "staged", r
    assert codes(r) >= {"approval_missing", "staged"}
    assert r["staged"]["waiting_for"] == ["approval"]
    assert r["plan"]["planned_actions"][1]["status"] == "staged"
    assert w.remote_ref("feature/x") is None  # nothing pushed yet
    assert staged_state(w) == {PUSH: "STAGED"}

    out = cm.submit_approval(w.cfg, detached(w, p))
    assert out["receipt"]["decision"] == "approval_accepted"
    [done] = out["commits"]
    assert done["decision"] == "executed", done
    assert done["triggered_by"]["kind"] == "approval"
    assert done["staged"]["receipt_seq"] == r["seq"]
    assert done["approvals"][0]["detached"] is True and done["approvals"][0]["approver"] == "rishab"
    assert done["commits_from"] == r["commits_from"]
    assert done["plan"]["remaining"] == [] and done["plan"]["claim_state"] == "COMPLETED"
    assert w.remote_ref("feature/x") == sha
    assert w.ledger_entry()["effects"][PUSH]["state"] == "EXECUTED"
    assert staged_state(w) == {PUSH: "EXECUTED"}
    assert decisions(w) == [("effect", "staged"), ("approval", "approval_accepted"), ("effect", "executed")]
    assert w.chain()["ok"]


def test_approval_before_the_proposal_executes_directly(w):
    p = w.packet(approve=False)
    tok = speculative_claim(w, p)
    assert cm.submit_approval(w.cfg, detached(w, p))["commits"] == []  # nothing staged yet
    sha = w.commit({"src/app.py": "print(2)\n"})
    r = w.propose(p, tok, sha)  # no wait_for_approval needed: the detached approval covers it
    assert r["decision"] == "executed", r
    assert r["approvals"][0]["detached"] is True


def test_without_wait_a_missing_approval_is_still_denied(w):
    p = w.packet(approve=False)
    tok = speculative_claim(w, p)
    r = w.propose(p, tok, w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and "approval_missing" in codes(r)
    assert cm.staged_view(w.cfg) == []


# -- what must never commit ---------------------------------------------------

def test_expired_approval_is_rejected_and_stays_staged(w):
    p, *_ = stage(w)
    out = cm.submit_approval(w.cfg, detached(w, p, exp=ts(dt.timedelta(seconds=-1))))
    assert out["receipt"]["decision"] == "approval_rejected"
    assert "approval_expired" in codes(out["receipt"]) and out["commits"] == []
    assert staged_state(w) == {PUSH: "STAGED"} and w.remote_ref("feature/x") is None


def test_approval_for_other_params_keeps_it_staged(w):
    p, *_ = stage(w)
    other = detached(w, p, params={"remote": "origin", "branch": "feature/elsewhere"})
    out = cm.submit_approval(w.cfg, other)
    assert out["receipt"]["decision"] == "approval_accepted"  # validly signed, just not for this push
    assert out["commits"] == []
    assert staged_state(w) == {PUSH: "STAGED"} and w.remote_ref("feature/x") is None


def test_untrusted_approver_is_rejected(w):
    p, *_ = stage(w)
    out = cm.submit_approval(w.cfg, detached(w, p, approver="mallory"))
    assert out["receipt"]["decision"] == "approval_rejected"
    assert "approver_not_trusted" in codes(out["receipt"])
    assert staged_state(w) == {PUSH: "STAGED"} and w.remote_ref("feature/x") is None


def test_agent_signed_approval_is_rejected(w):
    p, *_ = stage(w)
    out = cm.submit_approval(w.cfg, detached(w, p, approver="builder"))  # the agent approving itself
    assert out["receipt"]["decision"] == "approval_rejected" and w.remote_ref("feature/x") is None


@pytest.mark.parametrize("field,value", [("params", {"remote": "origin", "branch": "main"}),
                                         ("expires_at", "2099-01-01T00:00:00Z"),
                                         ("idempotency_key", "k-other"), ("approver", "rishab ")])
def test_tampered_approval_is_rejected(w, field, value):
    p, *_ = stage(w)
    a = {**detached(w, p), field: value}
    out = cm.submit_approval(w.cfg, a)
    assert out["receipt"]["decision"] == "approval_rejected", out["receipt"]
    assert out["commits"] == [] and w.remote_ref("feature/x") is None


def test_approval_for_another_handoff_cannot_be_rebound(w):
    p1, *_ = stage(w, idem="k1")
    p2 = w.packet(idem="k2", approve=False)
    a = {**detached(w, p2), "idempotency_key": "k1", "handoff_id": "h-k1"}  # re-addressed
    out = cm.submit_approval(w.cfg, a)
    assert "approval_signature_invalid" in codes(out["receipt"])
    assert staged_state(w, "k1") == {PUSH: "STAGED"}


@pytest.mark.parametrize("bad,code", [({}, "approval_malformed"), ("nope", "approval_malformed"),
                                      ({"params": "x"}, "approval_malformed"), ("unsigned", "approval_unsigned")])
def test_malformed_or_unsigned_approval(w, bad, code):
    p, *_ = stage(w)
    if bad == "unsigned":
        bad = {k: v for k, v in detached(w, p).items() if k != "sig"}
    elif isinstance(bad, dict) and bad:
        bad = {**detached(w, p), **bad}
    out = cm.submit_approval(w.cfg, bad)
    assert out["receipt"]["decision"] == "approval_rejected" and code in codes(out["receipt"])


def test_remote_moved_while_staged_is_denied(w):
    p, tok, sha, r = stage(w)
    # someone else creates the branch while the proposal waits
    git(w.agent, "push", "-q", "origin", f"{sha}~1:refs/heads/feature/x")
    out = cm.submit_approval(w.cfg, detached(w, p))
    [done] = out["commits"]
    assert done["decision"] == "denied" and "remote_moved" in codes(done)
    assert staged_state(w) == {PUSH: "DENIED"}
    assert w.remote_ref("feature/x") != sha


def test_handoff_expiring_while_staged_is_denied_by_the_sweep(w, monkeypatch):
    p, *_ = stage(w, expires=ts(dt.timedelta(hours=1)))
    real = hc.now_utc
    monkeypatch.setattr(hc, "now_utc", lambda: real() + dt.timedelta(hours=2))
    [done] = cm.retry_staged(w.cfg, sweep=True)
    assert done["decision"] == "denied" and "handoff_expired" in codes(done)
    assert staged_state(w) == {PUSH: "DENIED"} and w.remote_ref("feature/x") is None


def test_sweep_leaves_a_still_waiting_proposal_alone(w):
    stage(w)
    assert cm.retry_staged(w.cfg, sweep=True) == []
    assert staged_state(w) == {PUSH: "STAGED"}


# -- replays and duplicates ---------------------------------------------------

def test_same_approval_twice_is_a_duplicate(w):
    p, *_ = stage(w)
    a = detached(w, p)
    assert cm.submit_approval(w.cfg, a)["commits"][0]["decision"] == "executed"
    again = cm.submit_approval(w.cfg, a)
    assert again["receipt"]["decision"] == "approval_duplicate" and again["commits"] == []


def test_concurrent_identical_approvals_store_one(w):
    p, *_ = stage(w)
    a = detached(w, p)
    outs = []
    ts_ = [threading.Thread(target=lambda: outs.append(cm.submit_approval(w.cfg, a))) for _ in range(6)]
    for t in ts_:
        t.start()
    for t in ts_:
        t.join()
    got = sorted(o["receipt"]["decision"] for o in outs)
    assert got.count("approval_accepted") == 1 and got.count("approval_duplicate") == 5
    assert [d for _, d in decisions(w)].count("executed") == 1
    assert w.chain()["ok"]


def test_replaying_the_proposal_after_commit_is_a_duplicate(w):
    p, tok, sha, r = stage(w)
    cm.submit_approval(w.cfg, detached(w, p))
    again = w.propose(p, tok, sha, wait_for_approval=True)
    assert again["decision"] == "denied"
    assert codes(again) & {"duplicate_idempotency_key", "effect_already_executed"}


def test_restaging_supersedes_the_older_stage(w):
    p, tok, sha, r1 = stage(w)
    sha2 = w.commit({"src/app.py": "print('v2')\n"})
    r2 = w.propose(p, tok, sha2, wait_for_approval=True)
    assert r2["decision"] == "staged" and r2["staged"]["supersedes"] == r1["seq"]
    [done] = cm.submit_approval(w.cfg, detached(w, p))["commits"]
    assert done["decision"] == "executed" and w.remote_ref("feature/x") == sha2


def test_staging_needs_the_claim_token(w):
    p = w.packet(approve=False)
    speculative_claim(w, p)
    r = w.propose(p, "not-the-token", w.commit({"src/app.py": "x\n"}), wait_for_approval=True)
    assert r["decision"] == "denied" and cm.staged_view(w.cfg) == []


def test_staging_still_runs_the_path_checks(w):
    p = w.packet(approve=False)
    tok = speculative_claim(w, p)
    sha = w.commit({"src/secrets/key.txt": "x\n"})
    r = w.propose(p, tok, sha, wait_for_approval=True)
    assert r["decision"] == "denied" and cm.staged_view(w.cfg) == []


def test_crashed_commit_attempt_is_retried_through_the_fence(w):
    p, *_ = stage(w)
    with cm._staged_store(w.cfg) as box:  # the broker died between picking it and committing
        box["data"]["k1"][PUSH].update(state="COMMITTING", updated_at=ts(dt.timedelta(minutes=-11)))
        box["dirty"] = True
    cm.submit_approval(w.cfg, detached(w, p))
    assert staged_state(w) == {PUSH: "EXECUTED"} and w.remote_ref("feature/x") is not None


# -- waiting on an upstream (depends_on) -------------------------------------

def test_dependency_staged_then_committed_when_upstream_completes(w):
    up = w.packet(idem="up", branch="feature/up")
    up_tok = w.claim(up)
    down = w.packet(idem="down", branch="feature/down", depends_on=["up"])
    down_tok = w.claim(down)  # admission doesn't wait for the upstream
    down_sha = w.commit({"src/app.py": "print('down')\n"})
    r = w.propose(down, down_tok, down_sha, branch="feature/down", wait_for_approval=True)
    assert r["decision"] == "staged" and r["staged"]["waiting_for"] == ["dependency"], r
    assert "dependency_incomplete" in codes(r)

    up_sha = w.commit({"src/app.py": "print('up')\n"})
    done = w.propose(up, up_tok, up_sha, branch="feature/up")
    assert done["decision"] == "executed"
    assert w.remote_ref("feature/down") == down_sha  # committed by the upstream's completion
    [rec] = [x for x in w.chain()["receipts"] if x.get("triggered_by")]
    assert rec["triggered_by"] == {"kind": "upstream_completed", "idempotency_key": "up",
                                   "receipt_seq": done["seq"]}


# -- secrets and isolation ----------------------------------------------------

def test_claim_token_stays_in_the_broker(w):
    p, tok, sha, r = stage(w)
    cm.submit_approval(w.cfg, detached(w, p))
    assert tok not in w.cfg.receipts_path.read_text()
    assert tok not in json.dumps(cm.staged_view(w.cfg))
    assert tok in w.cfg.staged_path.read_text()  # the broker needs it to commit later
    assert stat.S_IMODE(w.cfg.staged_path.stat().st_mode) == 0o600


def test_isolation_check_flags_readable_staged_store(w):
    stage(w)
    lock_down(w)
    assert not [c for c, _ in sb.isolation_problems(w.cfg) if c == "broker_credentials_exposed"]
    os.chmod(w.cfg.staged_path, 0o644)
    assert "broker_credentials_exposed" in {c for c, _ in sb.isolation_problems(w.cfg)}


def test_in_process_submit_refused_unless_dev_mode(w):
    raw = json.loads(w.config_path.read_text())
    raw["isolation"] = {"mode": "user"}
    w.config_path.write_text(json.dumps(raw))
    with pytest.raises(cm.NotIsolated):
        cm.submit_approval(cm.BrokerConfig(w.config_path), {})


# -- through the daemon, the client and MCP -----------------------------------

def test_daemon_speculative_round_trip(w, tmp_path):
    p = w.packet(approve=False)
    (tmp_path / "p.json").write_text(json.dumps(p))
    with daemon(w.cfg) as url:
        client = scl.BrokerClient(url)
        assert client.call("claim", packet=p)["decision"] == "REJECT"  # dry by default: no deferral
        v = client.call("claim", packet=p, wait_for_approval=True)
        assert v["decision"] == "ACCEPT", v
        sha = w.commit({"src/app.py": "print('daemon')\n"})
        r = scl.push(client, p, v["claim"]["token"], PUSH, "origin", "feature/x", repo=w.agent, commit=sha,
                     wait_for_approval=True)
        assert r["decision"] == "staged" and r["commits_from"].startswith("bundle sha256:"), r
        assert r["via"] == "unix"
        view = client.call("staged", idempotency_key="k1")["staged"]
        assert [x["state"] for x in view] == ["STAGED"] and "claim_token" not in json.dumps(view)

        a = tmp_path / "a.json"
        a.write_text(json.dumps(detached(w, p)))
        rc = scl.main(["--broker", url, "approve-submit", str(a)])
        assert rc == 0
    assert w.remote_ref("feature/x") == sha
    done = w.chain()["receipts"][-1]
    assert done["decision"] == "executed" and done["commits_from"] == r["commits_from"]
    assert done["via"] == "unix"  # the staged proposal keeps the proposer's origin


def test_client_push_exit_code_for_staged(w, tmp_path, capsys):
    p = w.packet(approve=False)
    with daemon(w.cfg) as url:
        v = scl.BrokerClient(url).call("claim", packet=p, wait_for_approval=True)
        (tmp_path / "p.json").write_text(json.dumps(p))
        (tmp_path / "c.json").write_text(json.dumps(v))
        w.commit({"src/app.py": "x\n"})
        rc = scl.main(["--broker", url, "push", "--packet", str(tmp_path / "p.json"), "--claim-token-file",
                       str(tmp_path / "c.json"), "--action", PUSH, "--remote", "origin", "--branch", "feature/x",
                       "--repo", str(w.agent), "--wait-for-approval"])
        assert rc == 3
        assert scl.main(["--broker", url, "staged"]) == 0
    assert '"STAGED"' in capsys.readouterr().out


def test_daemon_sweeper_denies_an_expired_staged_proposal(w, monkeypatch):
    stage(w, expires=ts(dt.timedelta(hours=1)))
    real = hc.now_utc
    monkeypatch.setattr(hc, "now_utc", lambda: real() + dt.timedelta(hours=2))
    stop = threading.Event()
    t = threading.Thread(target=sb.sweep_staged, args=(w.cfg, stop, 0.05), daemon=True)
    t.start()
    try:
        for _ in range(100):
            if staged_state(w) == {PUSH: "DENIED"}:
                break
            time.sleep(0.05)
    finally:
        stop.set()
        t.join(2)
    assert staged_state(w) == {PUSH: "DENIED"}


def test_daemon_complete_triggers_dependents(w):
    up = w.packet(idem="up", branch="feature/up", extra_actions=())
    # an upstream with no mediated effect: the agent completes it by hand
    up["handoff"]["planned_actions"] = [{"name": "edit", "tool": "edit_files"}]
    up["handoff"]["authority"]["approval_required_for"] = []
    up["handoff"]["authority"]["approvals"] = []
    up = ss.sign_packet({"handoff": up["handoff"]}, w.keys["planner"])
    down = w.packet(idem="down", branch="feature/down", depends_on=["up"])
    with daemon(w.cfg) as url:
        client = scl.BrokerClient(url)
        up_v = client.call("claim", packet=up)
        assert up_v["decision"] == "ACCEPT", up_v
        down_v = client.call("claim", packet=down)
        sha = w.commit({"src/app.py": "print('down')\n"})
        r = scl.push(client, down, down_v["claim"]["token"], PUSH, "origin", "feature/down", repo=w.agent,
                     commit=sha, wait_for_approval=True)
        assert r["decision"] == "staged", r
        out = client.call("complete", packet=up, claim_token=up_v["claim"]["token"])
        assert out["decision"] == "COMPLETED"
        assert [c["decision"] for c in out["staged_commits"]] == ["executed"]
    assert w.remote_ref("feature/down") == sha


def test_mcp_advertises_submit_approval_with_a_broker(w):
    with daemon(w.cfg) as url:
        srv = synthe_mcp.SyntheServer(None, None, None, broker_url=url)
        names = {t["name"] for t in srv.tools()}
        assert {"synthe_propose_effect", "synthe_submit_approval"} <= names
        p, *_ = stage(w)
        out = srv.tool_functions()["synthe_submit_approval"]({"approval": detached(w, p)})
        assert out["receipt"]["decision"] == "approval_accepted"
        assert out["commits"][0]["decision"] == "executed"
    plain = synthe_mcp.SyntheServer(str(w.tmp / "registry.json"), str(w.tmp / "ledger.json"), None)
    assert "synthe_submit_approval" not in {t["name"] for t in plain.tools()}


def test_lab_does_not_advertise_speculative_claims_yet():
    sys.path.insert(0, str(ROOT / "lab"))
    synthe_lab = pytest.importorskip("synthe_lab")  # the Lab is proprietary: absent in the public repo
    tools = synthe_lab.LabMCP.tools(type("L", (), {"lab": type("X", (), {"broker_url": None})()})())
    validate = next(t for t in tools if t["name"] == "synthe_validate_handoff")
    assert "wait_for_approval" not in validate["inputSchema"]["properties"]
    assert "synthe_submit_approval" not in {t["name"] for t in tools}
    # and the shared definition was not mutated by the Lab's copy
    shared = next(t for t in synthe_mcp.TOOLS if t["name"] == "synthe_validate_handoff")
    assert "wait_for_approval" in shared["inputSchema"]["properties"]
