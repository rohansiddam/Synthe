"""v0.5 wait-for dependencies (`handoff.depends_on`) and conflict detection
(`exclusive_paths`). The ICML 2026 concurrency position paper attributes
37.2% of multi-agent failures to submitting before upstream work is done and
29.9% to concurrent changes to shared state; these are the two gates for it.

Dependencies never block a claim (the receiver may work ahead); they block
the commit, inside the fence. Exclusive paths block the second live claim."""
import copy
import json
import random

import pytest

from world import ROOT, World, codes, git, hc, ss


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


@pytest.fixture
def wx(tmp_path):
    return World(tmp_path, policy={"exclusive_paths": True})


def reject_codes(verdict):
    return {r["code"] for r in verdict.get("reasons", [])}


# ---- depends_on: the commit waits, the claim does not -----------------------

def test_commit_blocked_until_upstream_completes_then_executes(w):
    up = w.packet(idem="up", branch="feature/up")
    down = w.packet(idem="down", branch="feature/down", depends_on=["up"])
    t_up = w.claim(up)
    t_down = w.claim(down)  # admission does not wait: the agent can work ahead
    git(w.agent, "checkout", "-q", "-b", "down")
    c_down = w.commit({"src/down.py": "down\n"})
    r = w.propose(down, t_down, c_down, branch="feature/down")
    assert r["decision"] == "denied" and codes(r) == {"dependency_incomplete"}
    assert r["reasons"][0]["state"] == "blocked" and "up (RESERVED)" in r["reasons"][0]["message"]
    assert w.remote_ref("feature/down") is None
    assert w.ledger_entry("down")["state"] == "RESERVED"  # a denial never consumes the claim
    git(w.agent, "checkout", "-q", "main")
    c_up = w.commit({"src/up.py": "up\n"})
    assert w.propose(up, t_up, c_up, branch="feature/up")["decision"] == "executed"
    assert w.ledger_entry("up")["state"] == "COMPLETED"
    git(w.agent, "checkout", "-q", "down")
    r = w.propose(down, t_down, c_down, branch="feature/down")
    assert r["decision"] == "executed", r
    assert w.remote_ref("feature/down") == c_down
    chain = w.chain()
    assert chain["ok"] and [x["decision"] for x in chain["receipts"]] == ["denied", "executed", "executed"]


def test_unknown_dependency_is_denied_at_commit(w):
    down = w.packet(idem="down", depends_on=["never-claimed"])
    token = w.claim(down)
    r = w.propose(down, token, w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and codes(r) == {"dependency_unknown"}
    assert w.remote_ref("feature/x") is None


def test_released_upstream_does_not_count_as_done(w):
    up = w.packet(idem="up", branch="feature/up")
    down = w.packet(idem="down", depends_on=["up"])
    w.claim(up)
    token = w.claim(down)
    assert hc.release(up, w.tmp / "ledger.json", force=True)["decision"] == "RELEASED"
    r = w.propose(down, token, w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and "dependency_incomplete" in codes(r)
    assert "up (RELEASED)" in r["reasons"][0]["message"]


def test_complete_and_fenced_wait_for_dependencies(w):
    up = w.packet(idem="up", branch="feature/up")
    down = w.packet(idem="down", depends_on=["up"])
    t_up, t_down = w.claim(up), w.claim(down)
    ledger = w.tmp / "ledger.json"
    out = hc.complete(down, ledger, claim_token=t_down)
    assert out["decision"] == "REJECT" and out["state"] == "blocked"
    assert reject_codes(out) == {"dependency_incomplete"}
    ran = []
    with pytest.raises(hc.FenceError) as fence:
        with hc.fenced(down, ledger, t_down):
            ran.append("effect")
    assert ran == [] and fence.value.verdict["reasons"][0]["code"] == "dependency_incomplete"
    assert hc.complete(up, ledger, claim_token=t_up)["decision"] == "COMPLETED"
    with hc.fenced(down, ledger, t_down):
        ran.append("effect")
    assert ran == ["effect"] and w.ledger_entry("down")["state"] == "COMPLETED"


def test_dependency_cycles_are_refused_at_claim(w):
    a = w.packet(idem="a", depends_on=["b"])
    b = w.packet(idem="b", branch="feature/b", depends_on=["a"])
    assert w.check(a)["decision"] == "ACCEPT"
    v = w.check(b)
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert reject_codes(v) == {"dependency_cycle"} and "b -> a -> b" in v["reasons"][0]["message"]
    selfish = w.check(w.packet(idem="c", depends_on=["c"]))
    assert reject_codes(selfish) == {"dependency_cycle"}


def test_depends_on_is_a_signed_sender_fact(w):
    down = w.packet(idem="down", depends_on=["up"])
    tampered = copy.deepcopy(down)
    tampered["handoff"]["depends_on"] = []  # drop the dependency in transit
    assert "signature_invalid" in reject_codes(w.check(tampered, dry_run=True))
    token = w.claim(down)
    # the claimant re-signs a copy without the dependency: the claim is bound to
    # the packet digest, so the fence refuses the swapped packet
    stripped = copy.deepcopy(down)
    stripped["handoff"].pop("depends_on")
    stripped = ss.sign_packet(stripped, w.keys["planner"])
    r = w.propose(stripped, token, w.commit({"src/app.py": "x\n"}))
    assert r["decision"] == "denied" and "completion_packet_mismatch" in codes(r)
    assert w.remote_ref("feature/x") is None


@pytest.mark.parametrize("bad", ["up", [""], [1], [None], {"up": True}])
def test_malformed_depends_on_is_invalid(w, bad):
    v = w.check(w.packet(idem="down", depends_on=bad), dry_run=True)
    assert v["decision"] == "REJECT" and "malformed:depends_on" in reject_codes(v)


def test_schema_declares_every_field_a_signed_packet_uses(w):
    """schema/handoff.schema.json is additionalProperties:false, so a field the
    checker accepts but the schema omits (v0.4 params, v0.5 depends_on) makes
    schema-validating senders reject good packets. Walk real packets."""
    schema = json.loads((ROOT / "schema" / "handoff.schema.json").read_text())

    def walk(node, value, path):
        if isinstance(value, dict) and "properties" in node:
            for k, v in value.items():
                assert k in node["properties"] or node.get("additionalProperties") is not False, path + k
                if k in node["properties"]:
                    walk(node["properties"][k], v, f"{path}{k}.")
        elif isinstance(value, list) and "items" in node:
            for i, v in enumerate(value):
                walk(node["items"], v, f"{path}[{i}].")

    walk(schema, w.packet(idem="down", depends_on=["up"]), "")
    assert "depends_on" in schema["properties"]["handoff"]["properties"]


def test_claim_records_paths_and_dependencies(w):
    w.claim(w.packet(idem="down", depends_on=["up", "up2"]))
    entry = w.ledger_entry("down")
    assert entry["depends_on"] == ["up", "up2"]
    assert entry["owned_paths"] == ["src/**", "tests/**"]  # receiver defaults applied


# ---- exclusive_paths: no two live claims on the same files ------------------

def test_overlapping_live_claims_are_rejected_under_the_flag(wx):
    a = wx.packet(idem="a", owned_paths=["src/**"])
    b = wx.packet(idem="b", owned_paths=["src/app.py"])
    c = wx.packet(idem="c", owned_paths=["tests/**"])
    t_a = wx.claim(a)
    v = wx.check(b)
    assert v["decision"] == "REJECT" and v["state"] == "blocked"
    assert reject_codes(v) == {"claim_conflict"} and "h-a" in v["reasons"][0]["message"]
    assert wx.check(c)["decision"] == "ACCEPT"  # disjoint paths are fine
    assert "b" not in wx.ledger()
    # once the first claim completes, the overlapping one may proceed
    assert hc.complete(a, wx.tmp / "ledger.json", claim_token=t_a)["decision"] == "COMPLETED"
    assert wx.check(b)["decision"] == "ACCEPT"


def test_overlapping_claims_are_allowed_without_the_flag(w):
    w.claim(w.packet(idem="a", owned_paths=["src/**"]))
    assert w.check(w.packet(idem="b", owned_paths=["src/app.py"]))["decision"] == "ACCEPT"


def test_released_claim_frees_its_paths(wx):
    a = wx.packet(idem="a", owned_paths=["src/**"])
    wx.claim(a)
    assert "claim_conflict" in reject_codes(wx.check(wx.packet(idem="b", owned_paths=["src/x.py"])))
    assert hc.release(a, wx.tmp / "ledger.json", force=True)["decision"] == "RELEASED"
    assert wx.check(wx.packet(idem="b", owned_paths=["src/x.py"]))["decision"] == "ACCEPT"


def test_defaulted_owned_paths_count(wx):
    wx.claim(wx.packet(idem="a"))  # owned_paths from receiver defaults: src/**, tests/**
    v = wx.check(wx.packet(idem="b", owned_paths=["tests/test_x.py"]))
    assert "claim_conflict" in reject_codes(v)


def test_other_receivers_and_unrecorded_claims(wx):
    led = wx.tmp / "ledger.json"
    led.write_text(json.dumps({
        "other": {"state": "RESERVED", "handoff_id": "h-o", "to": "someone-else",
                  "reserved_at": hc.now_utc().isoformat(), "owned_paths": ["**"]}}))
    assert wx.check(wx.packet(idem="a", owned_paths=["src/**"]))["decision"] == "ACCEPT"
    # a live claim written before v0.5 (no owned_paths) is assumed to overlap
    data = json.loads(led.read_text())
    data["legacy"] = {"state": "RESERVED", "handoff_id": "h-l", "to": "builder",
                      "reserved_at": hc.now_utc().isoformat()}
    led.write_text(json.dumps(data))
    v = wx.check(wx.packet(idem="b", owned_paths=["docs/**"]))
    assert "claim_conflict" in reject_codes(v) and "not recorded" in v["reasons"][0]["message"]


def test_empty_owned_paths_never_conflict(wx):
    wx.claim(wx.packet(idem="a", owned_paths=["**"]))
    assert wx.check(wx.packet(idem="b", owned_paths=[]))["decision"] == "ACCEPT"


# ---- glob intersection: conservative, never misses a shared path ------------

@pytest.mark.parametrize("a,b,want", [
    ("src/**", "src/app.py", True),
    ("src/**", "tests/**", False),
    ("src/a/*.py", "src/b/*.py", False),
    ("**/*.py", "**/*.md", False),
    ("**/README.md", "README.md", True),
    ("src/*.py", "src/**", True),
    ("src/app.py", "src/app.py", True),
    ("src/app.py", "src/util.py", False),
    ("src/app.py", "src/*.md", False),
    ("Docs/**", "docs/x.md", True),  # case-insensitive filesystems collide
    ("**", "anything/at/all", True),
])
def test_globs_may_overlap_examples(a, b, want):
    assert hc.globs_may_overlap(a, b) is want
    assert hc.globs_may_overlap(b, a) is want


def test_globs_may_overlap_never_misses_a_shared_path():
    """Soundness: whenever some path matches both globs, the check says
    'overlap'. Random globs and paths from a small alphabet, fixed seed."""
    rng = random.Random(20261001)
    segs = ["src", "tests", "a", "b", "x.py", "y.md", "a.py", "ab"]
    wild = ["*", "**", "?", "*.py", "*.md", "a*", "?b", "**/"]

    def pattern():
        parts = [rng.choice(segs + wild) for _ in range(rng.randint(1, 4))]
        out = ""
        for part in parts:
            out += part if (not out or out.endswith("/")) else "/" + part
        return out

    def path():
        return "/".join(rng.choice(segs) for _ in range(rng.randint(1, 4)))

    patterns = {pattern() for _ in range(300)}
    paths = [path() for _ in range(400)]
    matches = {p: {x for x in paths if hc.glob_match(p, x)} for p in patterns}
    checked = 0
    for a in patterns:
        for b in patterns:
            if matches[a] & matches[b]:
                checked += 1
                assert hc.globs_may_overlap(a, b), (a, b, sorted(matches[a] & matches[b])[:3])
    assert checked > 1000  # the property was actually exercised
