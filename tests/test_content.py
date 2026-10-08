"""Content proposals: chat agents ship without git.

The agent sends the full text of each file it changes and cites the blob each
edit was based on. The broker builds the commit in its own mirror and then
runs every usual check on it. If the branch moved meanwhile, the commit is
rebuilt on the new tip only when every cited blob is still current.
Also: read-only file access for agents without a repo."""
import datetime as dt
import json

import pytest
from world import World, cm, codes, git, ss, ts

import synthe_client as scl
import synthe_mcp
from test_isolation import daemon

PUSH = "push_branch"


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def configure(w, **git_push):
    raw = json.loads(w.config_path.read_text())
    raw["effects"]["git_push"].update(git_push)
    w.config_path.write_text(json.dumps(raw))
    w.cfg = cm.BrokerConfig(w.config_path)


def readable(w, **extra):
    raw = json.loads(w.config_path.read_text())
    raw["effects"]["git_push"]["remotes"]["origin"].update({"readable": True, **extra})
    w.config_path.write_text(json.dumps(raw))
    w.cfg = cm.BrokerConfig(w.config_path)


def blob(w, ref, path):
    return git(w.remote, "rev-parse", f"{ref}:{path}")


def show(w, ref, path):
    return git(w.remote, "show", f"{ref}:{path}")


def propose(w, packet, token, files=None, delete=None, base_blobs=None, branch="feature/x", **extra):
    params = {"remote": "origin", "branch": branch}
    if files is not None:
        params["files"] = files
    if delete is not None:
        params["delete"] = delete
    params["base_blobs"] = base_blobs if base_blobs is not None else {p: None for p in (files or {})}
    params.update(extra.pop("params", {}))
    return cm.propose(w.cfg, {"packet": packet, "claim_token": token, "action": PUSH, "params": params, **extra})


def speculative(w, idem):
    p = w.packet(idem=idem, approve=False)
    v = w.check(p, defer_approvals={PUSH})
    assert v["decision"] == "ACCEPT", v
    return p, v["claim"]["token"]


def approve(w, packet):
    a = ss.detached_approval(packet, w.keys["rishab"], PUSH, ts(dt.timedelta(hours=1)),
                             ss.planned_params(packet["handoff"], PUSH))
    return cm.submit_approval(w.cfg, a)


# -- the happy paths ------------------------------------------------------------

def test_new_file_becomes_a_commit_authored_by_the_agent(w):
    p = w.packet()
    r = propose(w, p, w.claim(p), files={"src/new.py": "print('hi')\n"}, params={"message": "T1: add new.py"})
    assert r["decision"] == "executed", r
    assert show(w, "feature/x", "src/new.py") == "print('hi')"
    assert show(w, "feature/x", "src/app.py") == "print('v1')"  # built on main: nothing else changed
    assert git(w.remote, "log", "-1", "--format=%an <%ae>", "feature/x") == "builder via Synthe <builder@synthe.invalid>"
    body = git(w.remote, "log", "-1", "--format=%B", "feature/x")
    assert body.startswith("T1: add new.py") and "Synthe-Key: k1" in body and "Synthe-Agent: builder" in body
    assert r["commits_from"].startswith("content sha256:")
    assert r["content"]["files"] == 1 and r["content"]["paths"] == ["src/new.py"]
    assert r["effect"]["content"]["digest"] == r["content"]["digest"]
    assert w.ledger_entry()["effects"][PUSH]["commit"] == r["effect"]["commit"]
    assert w.chain()["ok"]


def test_edit_cites_the_current_blob(w):
    p = w.packet()
    tok = w.claim(p)
    cur = blob(w, "main", "src/app.py")
    r = propose(w, p, tok, files={"src/app.py": "print('v2')\n"}, base_blobs={"src/app.py": cur})
    assert r["decision"] == "executed", r
    assert show(w, "feature/x", "src/app.py") == "print('v2')"


def test_missing_or_wrong_citation_is_refused(w):
    p = w.packet()
    tok = w.claim(p)
    r = propose(w, p, tok, files={"src/app.py": "x\n"}, base_blobs={})
    assert r["decision"] == "denied" and "content_base_missing" in codes(r)
    r = propose(w, p, tok, files={"src/app.py": "x\n"}, base_blobs={"src/app.py": None})  # "new", but it exists
    assert "content_conflict" in codes(r)
    r = propose(w, p, tok, files={"src/app.py": "x\n"}, base_blobs={"src/app.py": "0" * 40})
    assert "content_conflict" in codes(r)
    r = propose(w, p, tok, files={"src/app.py": "x\n"}, base_blobs={"src/app.py": "nope"})
    assert "content_malformed" in codes(r)
    assert w.remote_ref("feature/x") is None
    assert w.ledger_entry()["state"] == "RESERVED"  # a denial never consumes the claim


def test_delete_a_file(w):
    p = w.packet()
    r = propose(w, p, w.claim(p), delete=["src/app.py"], base_blobs={"src/app.py": blob(w, "main", "src/app.py")})
    assert r["decision"] == "executed", r
    assert "src/app.py" not in git(w.remote, "ls-tree", "-r", "--name-only", "feature/x").split()


def test_deleting_a_missing_file_is_a_conflict(w):
    p = w.packet()
    r = propose(w, p, w.claim(p), delete=["src/gone.py"], base_blobs={"src/gone.py": "1" * 40})
    assert r["decision"] == "denied" and "content_conflict" in codes(r)


def test_identical_content_is_no_change(w):
    p = w.packet()
    r = propose(w, p, w.claim(p), files={"src/app.py": "print('v1')\n"},
                base_blobs={"src/app.py": blob(w, "main", "src/app.py")})
    assert r["decision"] == "denied" and "no_change" in codes(r)


# -- paths git itself would accept --------------------------------------------

@pytest.mark.parametrize("path", [".git/config", "src/../README.md", "/src/x.py", "src//x.py", "src/./x.py",
                                  "src/.GIT/x", "src/git~1/x", "src/x.", "src/x ", "src\\x.py", "src/\x01x.py",
                                  "src/‌.git/x", "src/é.py", "src/", ""])
def test_bad_content_paths_are_refused(w, path):
    p = w.packet()
    r = propose(w, p, w.claim(p), files={path: "x\n"})
    assert r["decision"] == "denied" and codes(r) & {"path_invalid", "content_malformed"}, r
    assert w.remote_ref("feature/x") is None


def test_good_paths_pass_the_validator():
    for path in ("src/a.py", "docs/research/standards/x.md", "src/é.py", "tests/ledger/test_x.py", ".github2/x"):
        assert cm.GitPush.content_path_problem(path) is None, path


def test_case_collisions_and_overlaps_are_refused(w):
    p = w.packet()
    tok = w.claim(p)
    r = propose(w, p, tok, files={"src/A.py": "a\n", "src/a.py": "b\n"})
    assert "path_invalid" in codes(r)
    r = propose(w, p, tok, files={"src/a.py": "a\n"}, delete=["src/a.py"], base_blobs={"src/a.py": None})
    assert "content_malformed" in codes(r)


def test_nothing_under_a_file(w):
    p = w.packet()
    r = propose(w, p, w.claim(p), files={"src/app.py/x.py": "x\n"})
    assert r["decision"] == "denied" and "path_invalid" in codes(r)


# -- limits and shapes ----------------------------------------------------------

def test_size_limits(w):
    configure(w, max_content_files=1)
    p = w.packet()
    tok = w.claim(p)
    r = propose(w, p, tok, files={"src/a.py": "a\n", "src/b.py": "b\n"})
    assert "content_too_large" in codes(r)
    configure(w, max_content_files=100, max_content_mb=0.00001)  # about 10 bytes
    r = propose(w, p, tok, files={"src/a.py": "x" * 64})
    assert "content_too_large" in codes(r)


@pytest.mark.parametrize("files", [["src/a.py"], {"src/a.py": 1}, {}, {"src/a.py": "nul\x00byte"}])
def test_malformed_content(w, files):
    p = w.packet()
    r = propose(w, p, w.claim(p), files=files, base_blobs={"src/a.py": None})
    assert r["decision"] == "denied" and "content_malformed" in codes(r), r


def test_content_with_a_commit_or_source_is_malformed(w):
    p = w.packet()
    tok = w.claim(p)
    sha = w.commit({"src/x.py": "x\n"})
    r = propose(w, p, tok, files={"src/a.py": "a\n"}, params={"commit": sha})
    assert "proposal_malformed" in codes(r)
    r = propose(w, p, tok, files={"src/a.py": "a\n"}, source=str(w.agent))
    assert "proposal_malformed" in codes(r)


# -- the lane still decides ------------------------------------------------------

def test_forbidden_and_out_of_scope_paths_are_denied(w):
    p = w.packet()
    tok = w.claim(p)
    r = propose(w, p, tok, files={"src/secrets/key.txt": "k\n"})
    assert r["decision"] == "denied" and "path_forbidden" in codes(r)
    r = propose(w, p, tok, files={"README.md": "# hi\n"}, base_blobs={"README.md": blob(w, "main", "README.md")})
    assert r["decision"] == "denied" and "path_outside_scope" in codes(r)
    assert w.remote_ref("feature/x") is None


def test_replayed_content_is_a_duplicate(w):
    p = w.packet()
    tok = w.claim(p)
    assert propose(w, p, tok, files={"src/new.py": "x\n"})["decision"] == "executed"
    for files in ({"src/new.py": "x\n"}, {"src/other.py": "y\n"}):  # same or different text: one key, one effect
        r = propose(w, p, tok, files=files)
        assert r["decision"] == "denied" and "duplicate_idempotency_key" in codes(r), r
    assert show(w, "feature/x", "src/new.py") == "x"
    assert "src/other.py" not in git(w.remote, "ls-tree", "-r", "--name-only", "feature/x").split()
    assert w.chain()["ok"]


def test_receipts_hold_no_claim_token_and_no_file_text(w):
    secret = "SENTINEL-" + "f" * 24
    p = w.packet()
    tok = w.claim(p)
    assert propose(w, p, tok, files={"src/new.py": f"KEY = '{secret}'\n"})["decision"] == "executed"
    p2, tok2 = speculative(w, "k2")
    assert propose(w, p2, tok2, files={"src/b.py": f"# {secret}\n"}, wait_for_approval=True)["decision"] == "staged"
    raw = w.cfg.receipts_path.read_text()
    assert secret not in raw and tok not in raw and tok2 not in raw  # only the digest and paths
    assert '"digest": "sha256:' in raw or '"digest":"sha256:' in raw


def test_without_approval_it_is_still_denied(w):
    p, tok = speculative(w, "k1")
    r = propose(w, p, tok, files={"src/a.py": "a\n"})
    assert r["decision"] == "denied" and "approval_missing" in codes(r)


# -- concurrency: per-path rebase -------------------------------------------------

def _seed_branch(w):
    """feature/x with src/a.py, through Synthe."""
    p = w.packet(idem="seed")
    r = propose(w, p, w.claim(p), files={"src/a.py": "a1\n"})
    assert r["decision"] == "executed", r
    return r


def test_staged_content_rebases_onto_an_unrelated_change(w):
    _seed_branch(w)
    p2, tok2 = speculative(w, "k2")
    staged = propose(w, p2, tok2, files={"src/b.py": "b1\n"}, wait_for_approval=True)
    assert staged["decision"] == "staged", staged
    assert staged["staged"]["expected_old"] == "cited-blobs"
    p3 = w.packet(idem="k3")
    moved = propose(w, p3, w.claim(p3), files={"src/a.py": "a2\n"},
                    base_blobs={"src/a.py": blob(w, "feature/x", "src/a.py")})
    assert moved["decision"] == "executed", moved
    [done] = approve(w, p2)["commits"]
    assert done["decision"] == "executed", done
    assert done["effect"]["rebased_onto"] == moved["effect"]["commit"]
    assert show(w, "feature/x", "src/a.py") == "a2" and show(w, "feature/x", "src/b.py") == "b1"
    assert w.chain()["ok"]


def test_rebase_refused_when_a_cited_blob_changed(w):
    _seed_branch(w)
    old = blob(w, "feature/x", "src/a.py")
    p2, tok2 = speculative(w, "k2")
    staged = propose(w, p2, tok2, files={"src/a.py": "mine\n"}, base_blobs={"src/a.py": old}, wait_for_approval=True)
    assert staged["decision"] == "staged", staged
    p3 = w.packet(idem="k3")
    assert propose(w, p3, w.claim(p3), files={"src/a.py": "theirs\n"},
                   base_blobs={"src/a.py": old})["decision"] == "executed"
    [done] = approve(w, p2)["commits"]
    assert done["decision"] == "denied" and "content_conflict" in codes(done)
    assert show(w, "feature/x", "src/a.py") == "theirs"  # nobody's work was overwritten


def _race(w, monkeypatch, files):
    """Another writer pushes `files` to feature/x after prepare built the
    content commit, just before the fenced push (the window _rebase_content
    guards). Returns a getter for the racing commit."""
    orig, fired = cm.GitPush.commit, {}

    def racing(self, prep, scope, dry_run=False):
        if not dry_run and not fired:
            git(w.agent, "fetch", "-q", "origin", "feature/x")
            git(w.agent, "checkout", "-q", "-B", "other", "FETCH_HEAD")
            fired["commit"] = w.commit(files, msg="another writer")
            git(w.agent, "push", "-q", "origin", "HEAD:feature/x")
        return orig(self, prep, scope, dry_run)

    monkeypatch.setattr(cm.GitPush, "commit", racing)
    return lambda: fired["commit"]


def test_race_on_an_unrelated_path_rebases(w, monkeypatch):
    _seed_branch(w)
    other = _race(w, monkeypatch, {"src/a.py": "theirs\n"})
    p = w.packet(idem="k2")
    r = propose(w, p, w.claim(p), files={"src/b.py": "b\n"})
    assert r["decision"] == "executed", r
    assert r["effect"]["rebased_onto"] == other()
    assert git(w.remote, "rev-parse", "feature/x^") == other()
    assert show(w, "feature/x", "src/a.py") == "theirs" and show(w, "feature/x", "src/b.py") == "b"


def test_race_on_a_cited_path_is_a_conflict(w, monkeypatch):
    _seed_branch(w)
    cited = blob(w, "feature/x", "src/a.py")
    other = _race(w, monkeypatch, {"src/a.py": "theirs\n"})
    p = w.packet(idem="k2")
    r = propose(w, p, w.claim(p), files={"src/a.py": "mine\n"}, base_blobs={"src/a.py": cited})
    assert r["decision"] == "denied" and "content_conflict" in codes(r), r
    assert w.remote_ref("feature/x") == other() and show(w, "feature/x", "src/a.py") == "theirs"
    assert w.ledger_entry("k2")["state"] == "RESERVED"  # nothing ran: the agent can re-read and retry


def test_explicit_expected_old_is_strict(w):
    _seed_branch(w)
    p = w.packet(idem="k2")
    r = propose(w, p, w.claim(p), files={"src/b.py": "b\n"}, params={"expected_old": "1" * 40})
    assert r["decision"] == "denied" and "remote_moved" in codes(r)


# -- reading the repository ------------------------------------------------------

def test_read_file_and_list_files(w):
    readable(w)
    eff = cm.GitPush(w.cfg)
    f = eff.read_file(None, None, "src/app.py")  # the only readable remote, its first plain branch (main)
    assert f["text"] == "print('v1')\n" and f["blob"] == blob(w, "main", "src/app.py") and f["ref"] == "main"
    listing = eff.list_files("origin", "main", "src")
    assert [x["path"] for x in listing["files"]] == ["src/app.py"] and not listing["truncated"]
    assert {x["path"] for x in eff.list_files(None, None)["files"]} == {"README.md", "src/app.py"}


def test_read_errors(w):
    eff = cm.GitPush(w.cfg)
    with pytest.raises(cm.Deny) as e:
        eff.read_file("origin", "main", "src/app.py")
    assert e.value.reason["code"] == "read_not_allowed"  # not marked readable
    readable(w)
    eff = cm.GitPush(w.cfg)
    for args, code in [(("origin", "main", "src/nope.py"), "file_not_found"),
                       (("origin", "main", "../etc/passwd"), "path_invalid"),
                       (("origin", "release", "src/app.py"), "read_not_allowed"),
                       (("other", "main", "src/app.py"), "read_not_allowed")]:
        with pytest.raises(cm.Deny) as e:
            eff.read_file(*args)
        assert e.value.reason["code"] == code, args
    (w.agent / "src" / "blob.bin").write_bytes(b"\x00\x01\x02")
    git(w.agent, "add", "-A")
    git(w.agent, "commit", "-qm", "binary")
    git(w.agent, "push", "-q", "origin", "HEAD:main")
    with pytest.raises(cm.Deny) as e:
        eff.read_file("origin", "main", "src/blob.bin")
    assert e.value.reason["code"] == "file_not_text"


def test_read_then_propose_round_trip_through_the_daemon(w, tmp_path):
    readable(w)
    p = w.packet()
    with daemon(w.cfg) as url:
        client = scl.BrokerClient(url)
        f = client.call("read_file", path="src/app.py")
        assert f["text"] == "print('v1')\n"
        assert client.call("list_files", prefix="src")["files"][0]["path"] == "src/app.py"
        v = client.call("claim", packet=p)
        r = client.call("propose", packet=p, claim_token=v["claim"]["token"], action=PUSH,
                        params={"remote": "origin", "branch": "feature/x",
                                "files": {"src/app.py": f["text"] + "print('v2')\n"},
                                "base_blobs": {"src/app.py": f["blob"]}, "message": "edit via daemon"})
        assert r["decision"] == "executed" and r["via"] == "unix", r
        with pytest.raises(scl.BrokerError) as e:
            client.call("read_file", path="src/nope.py")
        assert e.value.code == "file_not_found"
        assert scl.main(["--broker", url, "read", "src/app.py", "--ref", "feature/x"]) == 0
        assert scl.main(["--broker", url, "ls", "src"]) == 0
    assert show(w, "feature/x", "src/app.py") == "print('v1')\nprint('v2')"


def test_mcp_exposes_read_tools_with_a_broker(w):
    readable(w)
    with daemon(w.cfg) as url:
        srv = synthe_mcp.SyntheServer(None, None, None, broker_url=url)
        assert {"synthe_read_file", "synthe_list_files"} <= {t["name"] for t in srv.tools()}
        out = srv.tool_functions()["synthe_read_file"]({"path": "src/app.py"})
        assert out["text"] == "print('v1')\n"
        bad = srv.tool_functions()["synthe_read_file"]({"path": "src/nope.py"})
        assert bad["error"]["code"] == "file_not_found"
    plain = synthe_mcp.SyntheServer(str(w.tmp / "registry.json"), str(w.tmp / "ledger.json"), None)
    assert "synthe_read_file" not in {t["name"] for t in plain.tools()}
