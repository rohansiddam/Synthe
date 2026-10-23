"""synthe-task grant / grants / revoke-grant, and the "how hands-off?" question at the end of setup.

A real dev broker (the same fixture as the OpenClaw flow) and the real signing code; only the person is
stood in for: the passphrase key is unlocked with the test passphrase, and the yes/no is a function.

- the plain-English summary says what is being allowed, and what is not;
- main/master/'*' branches, paths outside the policy and forbidden paths are refused before anything is signed;
- --uses and --until are optional (no limit, no expiry), and parsed when given;
- a signed grant reaches the broker, lets a push inside it go out with no approval, and leaves other pushes asking;
- grants are listed with uses left and expiry, flagged for renewal, and revoked;
- setup's question changes nothing without a person at a terminal, and opens a lane only on "2".
"""
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_openclaw_flow import ENV, PASS, ROOT, Mcp, _commit, broker, git
import synthe_client as scl
import synthe_grant as sg
import synthe_init as si
import synthe_sign as ss
import synthe_task as st
import synthe_touchid as touchid

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 23, 12, 0, tzinfo=UTC)   # a Friday
PATHS = ["src/**", "tests/**"]


@pytest.fixture
def lane(tmp_path):
    """A dev setup like synthe-init's: you are rohan, the agent is openclaw, agent/* and src/**,tests/**."""
    remote, seed, clone, home = (tmp_path / n for n in ("remote.git", "seed", "clone", "home"))
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], env=ENV, check=True)
    subprocess.run(["git", "clone", "-q", str(remote), str(seed)], env=ENV, check=True, capture_output=True)
    (seed / "src").mkdir()
    (seed / "src" / "app.py").write_text("print('hi')\n")
    git(seed, "add", "-A")
    git(seed, "commit", "-q", "-m", "init")
    git(seed, "push", "-q", "origin", "main")
    subprocess.run(["git", "clone", "-q", str(remote), str(clone)], env=ENV, check=True, capture_output=True)
    home.mkdir()
    pub = si.approver_public_key(home, "rohan", passphrase=PASS)
    si.write_broker(home, repo_url=str(remote), branches=["agent/*"], allowed_paths=PATHS, approver="rohan",
                    approver_pub=pub, agent="openclaw", token_file=None)
    key = ss.load_key(str(home / "approver.key.json"), passphrase=PASS, require_encrypted=True)
    return {"remote": remote, "clone": clone, "home": home, "key": key}


@pytest.fixture
def live(lane):
    """The dev broker, serving, with setup.json pointing at it (so the CLI finds it)."""
    with broker(lane["home"]) as url:
        si.write_setup(lane["home"], {**si.read_setup(lane["home"]), "broker": url})
        lane["url"], lane["client"] = url, scl.BrokerClient(url)
        yield lane


def spec(**over):
    return {"branch": "agent/*", "paths": ["src/**"], "uses": 3, "until": "7d", "now": NOW, "tz": UTC, **over}


def open_lane(lane, **over):
    """What `synthe-task grant` does once you said yes, with the test passphrase standing in for yours."""
    return sg.issue(lane["home"], **{"client": lane["client"], "key": lane["key"], "confirm": lambda q: True,
                                     "out": lambda *_: None, **spec(), "now": None, **over})


def propose(lane, branch, files, mcp_url=None):
    """The agent's side: claim a task, commit in its clone, propose the push. Returns the broker's decision."""
    home = lane["home"]
    packet, _ = st.build_task(home, f"Work on {branch}", branch)
    packet = ss.sign_packet(packet, lane["key"])
    mcp = Mcp(lane["url"])
    try:
        v = mcp.tool("synthe_validate_handoff", packet=packet, wait_for_approval=True)
        sha = _commit(lane["clone"], branch, files)
        return mcp.tool("synthe_propose_effect", packet=packet, claim_token=v["claim"]["token"], action="push_branch",
                        params={"remote": "origin", "branch": branch, "commit": sha},
                        source=str(lane["clone"]), wait_for_approval=True)
    finally:
        mcp.close()


# ---- what you are shown ------------------------------------------------------------------------

def test_the_summary_says_what_is_allowed_and_what_is_not(live):
    s = st.setup_of(live["home"])
    body, text = sg.plan(s, client=live["client"], **spec(paths=PATHS, uses=50))
    assert text.splitlines()[0] == ("Agent openclaw may push to agent/* changing src/** and tests/**, "
                                    "up to 50 times, until Fri Oct 30 12:00 UTC.")
    assert "Pushes to other branches still ask you." in text
    assert ("High-risk pushes (CI workflows, key and secret files, 400+ changed lines, mass deletions, 30+ commits, "
            "per the broker's rules) and pushes outside these paths still ask you.") in text
    assert "reads paths and sizes, not code" in text
    assert "refused" not in text and "not asked about" not in text
    assert "nobody reviews each push" in text and "signs a receipt for every push" in text
    assert "Never, whatever this says: .github/**" in text
    draft = live["client"].call("lane_template_draft", receiver="openclaw", auto_approve=["routine", "review"])
    assert body["lineage"] == draft["lineage"] and "risk_rules_digest" in body["lineage"]   # a risk-aware lineage
    assert body["auto_approve"] == draft["auto_approve"] == ["routine", "review"]
    assert (body["max_uses"], body["expires_at"], body["tool"]) == (50, "2026-10-30T12:00:00Z", "git_push")
    assert body["params"] == {"remote": "origin", "branch_pattern": "agent/*"} and body["path_scope"] == PATHS


def test_the_default_lane_has_no_limit_and_no_expiry_and_the_summary_says_it_is_standing(live):
    body, text = sg.plan(st.setup_of(live["home"]), client=live["client"], now=NOW, tz=UTC, branch="agent/*",
                         paths=PATHS)
    assert "max_uses" not in body and "expires_at" not in body       # omitted, not a huge number: there is no limit
    assert text.splitlines()[0] == ("Agent openclaw may push to agent/* changing src/** and tests/**, "
                                    "with no limit on pushes, with no expiry.")
    assert f"standing permission: it stays open until you close it (synthe-task revoke-grant {body['template_id']})" in text
    _, only_uses = sg.plan(st.setup_of(live["home"]), client=live["client"], now=NOW, tz=UTC, branch="agent/*",
                           paths=PATHS, uses=5)
    assert "up to 5 times, with no expiry." in only_uses and "standing permission" not in only_uses
    _, only_time = sg.plan(st.setup_of(live["home"]), client=live["client"], now=NOW, tz=UTC, branch="agent/*",
                           paths=PATHS, until="2d")
    assert "with no limit on pushes, until Sun Oct 25 12:00 UTC." in only_time and "standing permission" not in only_time


def test_summary_wording_for_one_use_one_path_a_reviewer_and_another_remote():
    body = {"receiver": "openclaw", "params": {"remote": "fork", "branch_pattern": "agent/fix-*"}, "path_scope": ["src/**"],
            "max_uses": 1, "expires_at": "2026-10-23T18:30:00Z", "delegate": "claude-reviewer"}
    text = sg.summary(body, tz=UTC)
    assert text.splitlines()[0] == ("Agent openclaw may push to agent/fix-* on fork changing src/**, once, "
                                    "until Fri Oct 23 18:30 UTC.")
    assert "reviewed by claude-reviewer instead of you" in text and "nobody reviews" not in text
    assert sg._join(["a", "b", "c"]) == "a, b and c"


def test_the_summary_says_which_pushes_still_interrupt_you_for_each_set_of_tiers():
    base = {"receiver": "openclaw", "params": {"remote": "origin", "branch_pattern": "agent/*"}, "path_scope": ["src/**"],
            "template_id": "lane-1"}
    both = sg.summary({**base, "auto_approve": ["routine", "review"]}).splitlines()[1]
    assert both.startswith("Pushes to other branches still ask you. High-risk pushes (CI workflows, ")
    # the default lane lets review-level changes go out; the text says so and says how to make them ask
    assert "Review-level changes (dependency manifests and lockfiles, Dockerfiles, build scripts, " in both
    assert "200+ changed lines, any deletion, per the broker's rules) go out without asking you" in both
    assert "synthe-notify digest lists them afterwards); --auto-approve routine makes them ask too." in both
    assert "Review-level pushes" not in both and both.count("still ask you") == 2
    assert "dependency" not in both.split("Review-level changes")[0]       # dependencies are not among the things that ask
    routine = sg.summary({**base, "auto_approve": ["routine"]}).splitlines()[1]
    assert "Review-level pushes (dependency manifests and lockfiles, Dockerfiles, build scripts" in routine and "and high-risk pushes (CI workflows" in routine
    assert "any deletion" in routine
    everything = sg.summary({**base, "auto_approve": ["routine", "review", "high"]}).splitlines()[1]
    assert "lets every risk level through. Only pushes outside these paths still ask you." in everything
    old = sg.summary(base).splitlines()[1]
    assert "not risk-aware" in old and "high-risk ones included" in old       # a grant signed before risk tiers
    # the words follow the broker's own rules, an operator's custom lists included
    rules = {"high_paths": [".github/workflows/*", "infra/*", "deploy/*.tf"], "high_lines": 100, "high_commits": 5,
             "review_paths": ["package.json"], "review_lines": 50}
    custom = sg.summary({**base, "auto_approve": ["routine"]}, rules=rules).splitlines()[1]
    assert "(CI workflows, infra/*, deploy/*.tf, 100+ changed lines, mass deletions, 5+ commits, per the broker's rules)" in custom
    assert "(dependency manifests and lockfiles, 50+ changed lines, any deletion, per the broker's rules)" in custom
    hostile = {"high_paths": ["x\x1b[2Jy"]}
    assert "\x1b" not in sg.summary({**base, "auto_approve": ["routine", "review"]}, rules=hostile)


@pytest.mark.parametrize("value, tiers", [("routine", ["routine"]), ("routine,review", ["routine", "review"]),
                                          (" Review , routine ", ["routine", "review"]), ("high,routine,review,high",
                                                                                          ["routine", "review", "high"]),
                                          (["review"], ["review"])])
def test_auto_approve_tiers_are_read_into_the_brokers_order(value, tiers):
    assert sg.parse_tiers(value) == tiers


@pytest.mark.parametrize("value", ["", " , ", "critical", "routine,medium", "all", "none", "routine;review", []])
def test_unknown_or_empty_tiers_are_refused_before_asking_the_broker(value):
    with pytest.raises(SystemExit, match="--auto-approve"):
        sg.parse_tiers(value)


def test_the_tiers_are_the_brokers_default_unless_you_name_them(live):
    s = st.setup_of(live["home"])
    default = live["client"].call("lane_template_draft", receiver="openclaw")["auto_approve_default"]
    body, _ = sg.plan(s, client=live["client"], **spec())
    assert body["auto_approve"] == default == ["routine", "review"]
    for given, wanted in (("routine", ["routine"]), ("routine,review,high", ["routine", "review", "high"])):
        body, text = sg.plan(s, client=live["client"], **spec(auto_approve=given))
        assert body["auto_approve"] == wanted
        assert body["lineage"] == live["client"].call("lane_template_draft", receiver="openclaw",
                                                      auto_approve=wanted)["lineage"]
    with pytest.raises(SystemExit, match="unknown tier 'critical'"):
        sg.plan(s, client=live["client"], **spec(auto_approve="routine,critical"))


def test_the_default_tiers_follow_what_the_broker_says(live):
    class Draft:
        def __init__(self, inner):
            self.inner, self.calls = inner, []

        def call(self, op, **kw):
            self.calls.append((op, kw))
            out = self.inner.call(op, **kw)
            return {**out, "auto_approve_default": ["routine"]} if op == "lane_template_draft" else out
    client = Draft(live["client"])
    body, text = sg.plan(st.setup_of(live["home"]), client=client, **spec())
    assert body["auto_approve"] == ["routine"] and "Review-level pushes" in text
    drafts = [kw for op, kw in client.calls if op == "lane_template_draft"]
    assert drafts[-1]["auto_approve"] == ["routine"]           # the lineage it signs is for the tiers it lists


# ---- what is refused before anything is signed -----------------------------------------------------

@pytest.mark.parametrize("branch", ["main", "master", "*", "**", "ma*", "?ain", "**/*"])
def test_a_lane_never_covers_main_or_a_pattern_that_reaches_it(live, branch):
    with pytest.raises(SystemExit, match="never main or master"):
        sg.plan(st.setup_of(live["home"]), client=live["client"], **spec(branch=branch))


def test_a_branch_the_broker_may_not_push_is_refused(live):
    with pytest.raises(SystemExit, match="outside the branches the broker may push"):
        sg.plan(st.setup_of(live["home"]), client=live["client"], **spec(branch="release/*"))
    with pytest.raises(SystemExit, match="outside the branches"):
        sg.plan(st.setup_of(live["home"]), client=live["client"], **spec(branch="agent/**"))   # reaches agent/a/b
    sg.plan(st.setup_of(live["home"]), client=live["client"], **spec(branch="agent/login-*"))   # narrower is fine


@pytest.mark.parametrize("paths, message", [
    (["docs/**"], "outside what the agent's policy allows"),
    (["**"], "outside what the agent's policy allows"),
    (["**/*.py"], "outside what the agent's policy allows"),
    ([".github/**"], "forbidden list"),
    (["src/**", ".github/workflows/**"], "forbidden list"),
    (["/etc/**"], "relative to the repo root"),
    (["src/../.github/**"], "relative to the repo root"),
    ([], "at least one glob"),
])
def test_paths_outside_the_policy_or_on_its_forbidden_list_are_refused(live, paths, message):
    with pytest.raises(SystemExit, match=message):
        sg.plan(st.setup_of(live["home"]), client=live["client"], **spec(paths=paths))


def test_paths_inside_the_policy_pass_even_when_narrower(live):
    body, _ = sg.plan(st.setup_of(live["home"]), client=live["client"], **spec(paths=["src/api/**", "tests/*.py"]))
    assert body["path_scope"] == ["src/api/**", "tests/*.py"]


def test_uses_brief_agent_and_remote_are_checked(live):
    s = st.setup_of(live["home"])
    for uses in (0, -1, sg.MAX_USES + 1):
        with pytest.raises(SystemExit, match="--uses"):
            sg.plan(s, client=live["client"], **spec(uses=uses))
    with pytest.raises(SystemExit, match="--brief"):
        sg.plan(s, client=live["client"], **spec(brief="  "))
    with pytest.raises(SystemExit, match="one agent"):
        sg.plan(s, client=live["client"], **spec(receiver="someone-else"))
    with pytest.raises(SystemExit, match="no such remote"):
        sg.plan(s, client=live["client"], **spec(remote="upstream"))
    body, _ = sg.plan(s, client=live["client"], **spec(brief="small src/ changes only", delegate="claude-reviewer"))
    assert body["brief"] == "small src/ changes only" and body["delegate"] == "claude-reviewer"


def test_a_broker_without_lane_grants_switched_on_says_how(live, tmp_path):
    cfg = json.loads((live["home"] / "broker" / "broker.json").read_text())
    assert cfg["lane_templates"]["receivers"] == ["openclaw"]     # setup switches it on (and names its issuer)
    s = {**st.setup_of(live["home"]), "receiver": "builder"}
    with pytest.raises(SystemExit, match="aren't switched on for builder"):
        sg.plan(s, client=live["client"], **spec())


# ---- --until -------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, delta", [
    ("90m", dt.timedelta(minutes=90)), ("12h", dt.timedelta(hours=12)), ("7d", dt.timedelta(days=7)),
    ("2w", dt.timedelta(days=14)), (" 7D ", dt.timedelta(days=7)), ("30d", dt.timedelta(days=30)),
    ("5m", dt.timedelta(minutes=5)),
])
def test_until_takes_a_length(text, delta):
    assert sg.parse_until(text, NOW) == NOW + delta


def test_until_takes_a_date_or_a_time():
    assert sg.parse_until("2026-10-30", NOW, UTC) == dt.datetime(2026, 10, 30, 23, 59, 59, tzinfo=UTC)
    assert sg.parse_until("2026-10-25T17:00", NOW, UTC) == dt.datetime(2026, 10, 25, 17, 0, tzinfo=UTC)
    assert sg.parse_until("2026-10-25T17:00+02:00", NOW, UTC) == dt.datetime(2026, 10, 25, 15, 0, tzinfo=UTC)


@pytest.mark.parametrize("text, year", [("31d", 2026), ("5w", 2026), ("2026-12-25", 2026), ("3650d", 2036),
                                        ("99999d", 2300), ("99999w", 3943)])
def test_until_has_no_upper_bound_but_the_format_is_checked(text, year):
    assert sg.parse_until(text, NOW, UTC).year == year


def test_until_far_enough_out_is_no_expiry():
    assert sg.parse_until("9999-12-31", NOW, UTC) == sg.NO_EXPIRY
    assert sg.no_expiry(sg.parse_until("9999-12-31", NOW, UTC))
    with pytest.raises(SystemExit, match="past the year 9999"):
        sg.parse_until("9999-12-31T23:59:59-14:00", NOW, UTC)


@pytest.mark.parametrize("text", ["", "soon", "7", "d7", "-3d", "1.5d", "4m", "0h", "2026-10-22", "2026-13-01"])
def test_until_refuses_nonsense_and_the_past(text):
    with pytest.raises(SystemExit, match="--until"):
        sg.parse_until(text, NOW, UTC)


# ---- signing and submitting: the round trip --------------------------------------------------------

def test_a_signed_grant_lets_a_push_inside_it_go_without_asking_and_others_still_ask(live):
    out = open_lane(live, branch="agent/lane-*", uses=2)
    assert out["status"] == "accepted"
    [g] = sg.list_grants(live["client"])
    assert (g["status"], g["uses_left"], g["max_uses"], g["approver"]) == ("active", 2, 2, "rohan")
    assert g["params"]["branch_pattern"] == "agent/lane-*" and g["path_scope"] == ["src/**"]
    # inside the lane: no approval, one use spent, the receipt names the grant
    r = propose(live, "agent/lane-one", {"src/one.py": "x = 1\n"})
    assert r["decision"] == "executed" and r["lane_template"]["template_id"] == g["template_id"], r
    assert git(live["remote"], "branch", "--list", "agent/lane-one")
    assert sg.list_grants(live["client"])[0]["uses_left"] == 1
    # another branch is not in the lane: it waits for you, as before
    r = propose(live, "agent/other", {"src/two.py": "x = 2\n"})
    assert r["decision"] == "staged", r
    assert git(live["remote"], "branch", "--list", "agent/other") == ""


def test_a_push_on_the_lanes_branch_but_outside_its_paths_asks_you_first(live):
    open_lane(live, branch="agent/*", paths=["src/**"])
    r = propose(live, "agent/wide", {"tests/new_test.py": "def test_x(): pass\n"})
    codes = {x["code"] for x in r["reasons"]}
    assert r["decision"] == "staged" and "outside_lane_paths" in codes and "template_scope" not in codes, r
    assert r["lane_scope"]["outside_paths"] == ["tests/new_test.py"] and r["lane_scope"]["outside_count"] == 1
    assert r["staged"]["waiting_for"] == ["approval", "scope"]
    assert sg.list_grants(live["client"])[0]["status"] == "active"
    assert propose(live, "agent/narrow", {"src/ok.py": "ok = 1\n"})["decision"] == "executed"     # in paths: fine
    assert git(live["remote"], "branch", "--list", "agent/wide") == ""                               # nothing went out
    assert sg.list_grants(live["client"])[0]["uses_left"] == 2       # only the push inside the paths spent a use


def test_a_high_risk_push_in_the_default_lane_asks_you_and_with_every_tier_it_does_not(live):
    big = "".join(f"line_{i} = {i}\n" for i in range(450))          # 450 changed lines: high-risk on size alone
    open_lane(live, branch="agent/std-*", paths=["src/**"], uses=None, until=None)
    r = propose(live, "agent/std-big", {"src/big.py": big})
    assert r["decision"] == "staged" and "risk_escalated" in {x["code"] for x in r["reasons"]}, r
    assert r["risk"]["tier"] == "high" and r["risk"]["auto_approve"] == ["routine", "review"]
    assert git(live["remote"], "branch", "--list", "agent/std-big") == ""
    assert propose(live, "agent/std-small", {"src/small.py": "x = 1\n"})["decision"] == "executed"
    assert propose(live, "agent/std-deps", {"src/setup.py": "from setuptools import setup\n"})["decision"] == "executed"   # review
    open_lane(live, branch="agent/free-*", paths=["src/**"], uses=None, until=None, auto_approve="routine,review,high")
    assert propose(live, "agent/free-big", {"src/big2.py": big})["decision"] == "executed"
    open_lane(live, branch="agent/careful-*", paths=["src/**"], uses=None, until=None, auto_approve="routine")
    assert propose(live, "agent/careful-deps", {"src/setup.py": "from setuptools import setup\n"})["decision"] == "staged"


def test_a_grant_signed_by_someone_else_or_tampered_with_is_refused_by_the_broker(live, tmp_path):
    other = {**live["key"], "agent": "mallory"}
    with pytest.raises(SystemExit, match="refused the grant"):
        open_lane(live, key=other)
    assert sg.list_grants(live["client"]) == []
    body, _ = sg.plan(st.setup_of(live["home"]), client=live["client"], **spec())
    signed_by_rohan = sg.lanes.sign(body, live["key"])
    signed_by_rohan["max_uses"] = 900                                  # edited after signing
    with pytest.raises(scl.BrokerError, match="template_signature_invalid"):
        live["client"].call("submit_lane_template", template=signed_by_rohan)


def test_saying_no_signs_nothing(live):
    lines = []
    assert sg.issue(live["home"], client=live["client"], key=live["key"], confirm=lambda q: False,
                    out=lines.append, **spec()) is None
    assert sg.list_grants(live["client"]) == [] and "Nothing signed" in lines[-1]
    assert "Agent openclaw may push" in lines[0]                     # it was shown before it asked


def test_revoking_closes_the_lane(live):
    open_lane(live, uses=5)
    [g] = sg.list_grants(live["client"])
    lines = []
    sg.revoke(live["client"], live["home"], g["template_id"], key=live["key"], out=lines.append)
    assert "Lane closed" in lines[0]
    [g2] = sg.list_grants(live["client"])
    assert g2["status"] == "template_revoked"
    assert propose(live, "agent/after-revoke", {"src/a.py": "a = 1\n"})["decision"] == "staged"
    with pytest.raises(SystemExit, match="no grant 'nope'"):
        sg.revoke(live["client"], live["home"], "nope", key=live["key"])


def test_the_key_is_unlocked_the_way_synthe_approve_does(live, monkeypatch):
    home = live["home"]
    seen = {}
    monkeypatch.setattr(ss, "load_key", lambda path, **kw: seen.setdefault("pass", live["key"]))
    assert sg.unlock_key(home, "rohan", "reason") is live["key"] and "pass" in seen
    (home / touchid.KEY_NAME).write_text("{}")                        # a Touch ID key is enrolled
    tid = {"agent": "rohan", "kid": "rohan-touchid", "_sign": lambda m: b""}
    monkeypatch.setattr(touchid, "signing_key", lambda path, reason: seen.update(reason=reason) or tid)
    assert sg.unlock_key(home, "rohan", "Agent openclaw may push") is tid and seen["reason"] == "Agent openclaw may push"
    seen.clear()
    assert sg.unlock_key(home, "rohan", "r", passphrase=True) is live["key"] and "pass" in seen    # --passphrase
    monkeypatch.setattr(touchid, "signing_key", lambda path, reason: (_ for _ in ()).throw(touchid.TouchIDError("cancelled")))
    with pytest.raises(SystemExit, match="not signed: cancelled"):
        sg.unlock_key(home, "rohan", "r")
    monkeypatch.setattr(ss, "load_key", lambda path, **kw: {**live["key"], "agent": "someone"})
    with pytest.raises(SystemExit, match="belongs to 'someone'"):
        sg.unlock_key(home, "rohan", "r", passphrase=True)


# ---- listing and renewing -----------------------------------------------------------------------------

class Listing:
    """What the broker's lane_templates op returns, for the renewal thresholds."""
    def __init__(self, *grants):
        self.grants = grants

    def call(self, op, **_):
        assert op == "lane_templates"
        return {"templates": list(self.grants), "enabled_receivers": ["openclaw"]}


def grant_row(tid="lane-1", left=50, uses=50, hours=100, status="active", **over):
    return {"template_id": tid, "receiver": "openclaw", "approver": "rohan", "status": status, "uses_left": left,
            "max_uses": uses, "params": {"remote": "origin", "branch_pattern": "agent/*"},
            "path_scope": ["src/**", "tests/**"],
            "expires_at": (NOW + dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"), **over}


@pytest.mark.parametrize("kwargs, hint", [
    ({"hours": 100}, None), ({"hours": 25}, None), ({"hours": 24}, "expires in 1d 0h"), ({"hours": 5}, "expires in 5h 0m"),
    ({"left": 5}, None), ({"left": 4}, "only 4 of 50 uses left"), ({"left": 1}, "only 1 of 50 uses left"),
    ({"left": 0, "status": "template_exhausted"}, None),             # not open: nothing to renew
    ({"hours": 2, "status": "template_expired"}, None),
    ({"uses": 10000, "left": 3}, None),                              # no use limit: nothing to run out of
    ({"expires_at": "9999-01-01T00:00:00Z"}, None),                              # no expiry: nothing to renew
])
def test_grants_are_flagged_inside_24_hours_or_under_ten_percent_of_uses(kwargs, hint):
    [row] = sg.list_grants(Listing(grant_row(**kwargs)), NOW)
    assert row["hints"] == ([hint] if hint else [])


def test_the_listing_shows_uses_left_expiry_and_the_command_to_renew():
    rows = sg.list_grants(Listing(grant_row("a", left=3, hours=30), grant_row("b", hours=200),
                                  grant_row("c", status="template_revoked", hours=50)), NOW)
    assert [r["template_id"] for r in rows] == ["b", "c", "a"]       # longest-lived first
    text = sg.render_grants(rows, ui=sui_plain(), tz=UTC)
    assert "b  open" in text and "50 of 50 uses left, until Fri Oct 30 12:00 UTC" not in text
    assert "3 of 50 uses left, until Sat Oct 24 18:00 UTC (in 1d 6h)" in text
    assert "renew soon: only 3 of 50 uses left" in text
    assert "renew: synthe-task grant --branch 'agent/*' --paths 'src/**,tests/**' --uses 50 --until 7d" in text
    assert "1 more not open" in text and "lane-1" not in text and "  c  " not in text
    assert "c  revoked" in sg.render_grants(rows, show_all=True, ui=sui_plain(), tz=UTC)
    assert "No open lanes" in sg.render_grants([], ui=sui_plain())


def sui_plain():
    import synthe_ui
    return synthe_ui.UI(stream=open("/dev/null", "w"))


def standing_row(tid="open-1", **over):
    """A lane as the broker lists it when the signed grant omits both limits: no max_uses, no expires_at."""
    row = grant_row(tid, left=None, **over)
    del row["max_uses"], row["expires_at"]
    return row


@pytest.mark.parametrize("forever", [
    standing_row(auto_approve=["routine", "review"]),
    grant_row("open-1", left=9990, uses=10000, expires_at="9999-01-01T00:00:00Z"),      # opened before limits were optional
], ids=["omitted", "legacy-sentinels"])
def test_a_lane_with_no_limits_is_listed_as_standing_and_never_flagged(forever):
    [row] = sg.list_grants(Listing(forever), NOW)
    assert row["hints"] == []
    text = sg.render_grants([row], ui=sui_plain(), tz=UTC)
    assert "open-1  open" in text and "no use limit, no expiry (open until you revoke it)" in text
    assert "renew" not in text
    assert sg.renew_command(forever) == "synthe-task grant --branch 'agent/*' --paths 'src/**,tests/**'"
    capped = sg.renew_command(grant_row())
    assert "--uses 50 --until 7d" in capped


def test_a_standing_lane_sorts_first_and_a_capped_one_still_shows_its_numbers():
    rows = sg.list_grants(Listing(grant_row("capped", hours=500), standing_row("standing"), grant_row("short", hours=30)), NOW)
    assert [r["template_id"] for r in rows] == ["standing", "capped", "short"]
    assert rows[0]["left"] is None
    text = sg.render_grants(rows, ui=sui_plain(), tz=UTC)
    assert "standing  open" in text and "capped  open" in text and "50 of 50 uses left, until" in text


def test_the_listing_says_which_pushes_go_out_alone_and_which_still_ask_you():
    rows = sg.list_grants(Listing(standing_row("a", auto_approve=["routine", "review"]),
                                  standing_row("b", auto_approve=["routine"]),
                                  standing_row("c", auto_approve=["routine", "review", "high"]),
                                  standing_row("d")), NOW)
    text = {r["template_id"]: sg.alone(r) for r in rows}
    assert text["a"] == "goes out on its own: routine and review-level; high-risk pushes and pushes outside its paths ask you"
    assert text["b"] == ("goes out on its own: routine; review-level and high-risk pushes and pushes outside its paths "
                         "ask you")
    assert text["c"] == "goes out on its own: routine, review-level and high-risk; pushes outside its paths ask you"
    assert text["d"].startswith("not risk-aware: every kind of push goes out, high-risk ones too")
    shown = sg.render_grants(rows, ui=sui_plain(), tz=UTC)
    assert "  goes out on its own: routine and review-level; high-risk pushes and pushes outside its paths ask you" in shown


def test_the_renew_command_keeps_tiers_that_are_not_the_default():
    assert "--auto-approve" not in sg.renew_command(grant_row(auto_approve=["routine", "review"]))
    assert "--auto-approve routine " in sg.renew_command(grant_row(auto_approve=["routine"])) + " "
    assert "--auto-approve routine,review,high" in sg.renew_command(grant_row(auto_approve=["routine", "review", "high"]))


def test_the_renew_command_keeps_the_remote_the_reviewer_and_a_short_brief():
    t = grant_row(delegate="claude-reviewer", brief="src only", params={"remote": "fork", "branch_pattern": "agent/*"})
    cmd = sg.renew_command(t)
    assert "--remote fork" in cmd and "--delegate claude-reviewer" in cmd and "--brief 'src only'" in cmd
    assert "add your --brief again" in sg.renew_command({**t, "brief": "x" * 300})


def test_a_stale_grant_says_why(live):
    open_lane(live)
    reg = Path(live["home"] / "broker" / "registry.json")
    registry = json.loads(reg.read_text())
    registry["agents"]["openclaw"]["policy"]["forbidden_paths"].append("src/vendor/**")   # the policy moved
    reg.write_text(json.dumps(registry))
    [g] = sg.list_grants(live["client"])
    assert g["status"] == "template_stale" and g["hints"] == []
    text = sg.render_grants([g], show_all=True, ui=sui_plain())
    assert "stale (the policy, approvers or config changed" in text


# ---- the command line -------------------------------------------------------------------------------

def test_the_cli_lists_grants_but_signs_only_at_a_terminal(live, capsys, monkeypatch):
    open_lane(live)
    assert st.main(["grants", "--home", str(live["home"])]) == 0
    assert "3 of 3 uses left" in capsys.readouterr().out
    for argv in (["grant", "--branch", "agent/*"], ["revoke-grant", "lane-x"]):
        assert st.main([*argv, "--home", str(live["home"])]) == 2          # no terminal: nothing to sign with
        assert "run it in your own terminal" in capsys.readouterr().err
    assert len(sg.list_grants(live["client"])) == 1


def test_the_cli_defaults_come_from_setup(live, capsys, monkeypatch):
    monkeypatch.setattr(sg, "_terminal", lambda: True)
    monkeypatch.setattr(sg, "_yes", lambda q: True)
    monkeypatch.setattr(sg, "unlock_key", lambda *a, **kw: live["key"])
    assert st.main(["grant", "--home", str(live["home"])]) == 0
    out = capsys.readouterr().out
    assert "Agent openclaw may push to agent/* changing src/** and tests/**, with no limit on pushes, with no expiry" in out
    assert "Lane open: lane-" in out and "no use limit, no expiry" in out
    assert "High-risk pushes (CI workflows" in out and "and pushes outside these paths still ask you." in out
    [g] = sg.list_grants(live["client"])
    assert "max_uses" not in g and "expires_at" not in g and g["uses_left"] is None     # nothing was signed to limit it
    assert (g["path_scope"], g["auto_approve"]) == (PATHS, ["routine", "review"])
    with pytest.raises(SystemExit, match="--until 'whenever'"):
        st.main(["grant", "--until", "whenever", "--home", str(live["home"])])
    assert st.main(["grant", "--until", "45d", "--uses", "20", "--paths", "src/**", "--home", str(live["home"])]) == 0
    capped = [x for x in sg.list_grants(live["client"]) if x.get("max_uses") == 20]
    assert len(capped) == 1 and capped[0]["path_scope"] == ["src/**"] and capped[0]["expires_at"] < "2026-13"
    assert not sg.no_expiry(dt.datetime.strptime(capped[0]["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC))
    with pytest.raises(SystemExit, match="never main or master"):
        st.main(["grant", "--branch", "main", "--home", str(live["home"])])
    assert len(sg.list_grants(live["client"])) == 2                    # the refusals signed nothing


def test_the_cli_passes_auto_approve_through_and_refuses_unknown_tiers(live, capsys, monkeypatch):
    monkeypatch.setattr(sg, "_terminal", lambda: True)
    monkeypatch.setattr(sg, "_yes", lambda q: True)
    monkeypatch.setattr(sg, "unlock_key", lambda *a, **kw: live["key"])
    with pytest.raises(SystemExit, match="unknown tier 'severe'"):
        st.main(["grant", "--auto-approve", "routine,severe", "--home", str(live["home"])])
    assert sg.list_grants(live["client"]) == []                        # refused before anything was signed
    assert st.main(["grant", "--auto-approve", "routine", "--home", str(live["home"])]) == 0
    out = capsys.readouterr().out
    assert "Review-level pushes (" in out and "and high-risk pushes (" in out
    [g] = sg.list_grants(live["client"])
    assert g["auto_approve"] == ["routine"]
    assert st.main(["grants", "--home", str(live["home"])]) == 0
    assert "goes out on its own: routine; review-level and high-risk pushes and pushes outside its paths ask you" in capsys.readouterr().out


def test_the_cli_asks_for_a_branch_when_setup_has_several(live, monkeypatch):
    monkeypatch.setattr(sg, "_terminal", lambda: True)
    setup = si.read_setup(live["home"])
    si.write_setup(live["home"], {**setup, "remote": {**setup["remote"], "branches": ["agent/*", "bot/*"]}})
    with pytest.raises(SystemExit, match="say which branch pattern"):
        st.main(["grant", "--home", str(live["home"])])


# ---- setup: "how hands-off?" ------------------------------------------------------------------------------

def test_the_question_changes_nothing_without_a_person(live):
    lines = []
    assert sg.offer_lane(live["home"], interactive=False, out=lines.append, ask=pytest.fail) == "ask"
    assert "Every push will ask you" in lines[0] and sg.list_grants(live["client"]) == []


def test_finish_setup_runs_the_question_and_a_script_gets_todays_behaviour(live):
    run = subprocess.run([sys.executable, str(ROOT / "src" / "synthe_init.py"), "lane-offer", "--home", str(live["home"])],
                         stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert "Every push will ask you" in run.stdout and sg.list_grants(live["client"]) == []


@pytest.mark.parametrize("answer", ["1", "  1 ", "3", "yes", "no"])
def test_anything_but_2_keeps_asking_before_every_push(live, answer):
    lines = []
    assert sg.offer_lane(live["home"], interactive=True, out=lines.append, ask=lambda q: answer, client=live["client"],
                         key=live["key"], confirm=lambda q: pytest.fail("must not get as far as signing")) == "ask"
    assert lines[0].startswith("\nHow hands-off?") and "[1] Ask me before every push" in lines[0]
    assert ("[2] Agents push without asking; Synthe only interrupts for what it blocks or flags as high-risk "
            "(recommended)") in lines[0]
    assert sg.list_grants(live["client"]) == []


@pytest.mark.parametrize("answer", ["2", "", "  2 "])                  # Return alone takes the recommended choice
def test_the_autonomous_lane_is_the_recommended_default_at_a_terminal(live, answer):
    lines = []
    asked = []
    prompts = []
    assert sg.offer_lane(live["home"], interactive=True, out=lines.append, client=live["client"], key=live["key"],
                         ask=lambda q: prompts.append(q) or answer,
                         confirm=lambda q: asked.append(q) or True) == "lane"
    [g] = sg.list_grants(live["client"])
    assert prompts == ["Choose 1 or 2 [2]: "]
    assert (g["status"], g["path_scope"], g["params"]["branch_pattern"]) == ("active", PATHS, "agent/*")
    assert "max_uses" not in g and "expires_at" not in g and g["hints"] == []         # no limits are signed, none exist
    assert g["auto_approve"] == ["routine", "review"]                # the broker's default: high-risk still asks
    assert asked == ["Sign it with your key? [Y/n] "]                # it still shows the terms and asks
    assert any("with no limit on pushes, with no expiry" in x and "standing permission" in x for x in lines)
    assert any("High-risk pushes (CI workflows" in x and "outside these paths still ask you" in x for x in lines)
    assert propose(live, "agent/default-lane", {"tests/test_new.py": "def test_ok(): pass\n"})["decision"] == "executed"
    assert propose(live, "agent/second", {"src/s.py": "s = 1\n"})["decision"] == "executed"     # no asking, no counting down
    big = "".join(f"line_{i} = {i}\n" for i in range(450))
    assert propose(live, "agent/third", {"src/big.py": big})["decision"] == "staged"            # high-risk: it asks you


def test_choosing_2_then_declining_the_terms_keeps_asking(live):
    assert sg.offer_lane(live["home"], interactive=True, out=lambda *_: None, ask=lambda q: "2", client=live["client"],
                         key=live["key"], confirm=lambda q: False) == "ask"
    assert sg.list_grants(live["client"]) == []


def test_choosing_2_with_no_broker_running_says_so_and_keeps_asking(lane):
    lines = []
    si.write_setup(lane["home"], {**si.read_setup(lane["home"]), "broker": f"unix://{lane['home']}/nobody.sock"})
    naps = []
    assert sg.offer_lane(lane["home"], interactive=True, out=lines.append, ask=lambda q: "2", key=lane["key"],
                         tries=3, sleep=naps.append) == "ask"
    assert naps == [1, 1] and "Couldn't open a lane" in lines[-1] and "Every push will ask you" in lines[-1]


def test_finish_setup_ends_with_the_question(tmp_path, monkeypatch):
    monkeypatch.setattr(si.sys, "platform", "darwin")
    monkeypatch.setattr(si.os, "geteuid", lambda: 501)
    monkeypatch.setattr(si, "source_root", lambda: ROOT)
    node = tmp_path / "node"
    node.write_text("")
    finish = si.prepare(tmp_path / "home", repo_url="https://github.com/acme/app.git", branches=["agent/*"],
                        allowed_paths=["src/**"], agent_account="openclaw", approver="rohan", python="/usr/bin/python3",
                        script_path=ROOT / "src" / "synthe_init.py", node=node)
    lines = finish.read_text().splitlines()
    enforce = next(i for i, x in enumerate(lines) if x.startswith("sudo bash"))
    assert "lane-offer --home" in lines[enforce + 2]                  # after the broker is up, never before
    assert lines[enforce + 2].endswith("|| true")                     # declining or failing never fails setup


def test_setup_switches_lane_grants_on_for_the_agent_in_both_modes(lane, tmp_path):
    cfg = json.loads((lane["home"] / "broker" / "broker.json").read_text())
    assert cfg["lane_templates"] == {"receivers": ["openclaw"]}
    state = tmp_path / "state"
    (state / "keys").mkdir(parents=True)
    (state / "keys" / "synthe-broker.key.json").write_text(json.dumps(
        {"agent": "synthe-broker", "kid": "b-1", "alg": "Ed25519", "private_key": "A" * 43}))
    (state / "broker.json").write_text(json.dumps({"isolation": {"mode": "user"}}))
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "registry.json").write_text(json.dumps({"agents": {}}))
    (stage / "config-patch.json").write_text(json.dumps({"workspace": "/w", "receiver": "openclaw",
                                                         "remote": {"url": "u", "branches": ["agent/*"]}}))
    si.apply_config(state, stage)
    assert json.loads((state / "broker.json").read_text())["lane_templates"] == {"receivers": ["openclaw"]}
    cfg = json.loads((state / "broker.json").read_text())
    cfg["lane_templates"] = {"receivers": ["openclaw", "other"]}        # an operator's own choice survives a re-apply
    (state / "broker.json").write_text(json.dumps(cfg))
    si.apply_config(state, stage)
    assert json.loads((state / "broker.json").read_text())["lane_templates"]["receivers"] == ["openclaw", "other"]
