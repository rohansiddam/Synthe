"""Broker isolation (Rohan's ask #3): the process that holds the keys is not
the agent's process. The broker daemon serves a socket; the kernel names
each client's uid; agents send commits as git bundles and never load the
broker's key, token, registry or ledger.

These tests run as one OS user, so they cover everything except the real
two-user wall: that is scripts/isolation_selftest.sh (Linux, as root),
whose output is in docs/ISOLATION.md."""
import base64
import contextlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading

import pytest

from world import ROOT, World, cm, codes, git, hc
import synthe_broker as sb
import synthe_client as scl
import synthe_mcp


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def reconfigure(w, **changes):
    raw = json.loads(w.config_path.read_text())
    raw.update(changes)
    w.config_path.write_text(json.dumps(raw))
    w.cfg = cm.BrokerConfig(w.config_path)
    return w.cfg


def lock_down(w):
    """What an operator does before serving: key 0600, nothing writable by others."""
    os.chmod(w.tmp, 0o755)
    os.chmod(w.cfg.key_path, 0o600)
    for p in (w.config_path, w.tmp / "registry.json"):
        os.chmod(p, 0o644)


@contextlib.contextmanager
def daemon(cfg, listen=False, token=None):
    """Serve the broker in a thread. The socket goes in a short /tmp dir:
    unix socket paths are capped at 104 bytes on macOS."""
    d = tempfile.mkdtemp(prefix="sy", dir="/tmp")
    try:
        if listen:
            srv = sb.make_server(cfg, listen="127.0.0.1:0", token=token)
            url = f"tcp://127.0.0.1:{srv.server_address[1]}"
        else:
            srv = sb.make_server(cfg, socket_path=os.path.join(d, "broker.sock"))
            url = f"unix://{d}/broker.sock"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            yield url
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def raw_call(url, data: bytes) -> dict:
    """One raw request line, for malformed input the client would never send."""
    path = url[len("unix://"):]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        s.sendall(data)
        with s.makefile("rb") as fh:
            return json.loads(fh.readline())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def chain_decisions(w):
    chain = w.chain()
    assert chain["ok"], chain["errors"]
    return [r["decision"] for r in chain["receipts"]]


# ---- mode user: the broker refuses clients that could read its keys ----------

def test_user_mode_refuses_a_client_running_as_the_broker_user(w):
    lock_down(w)
    reconfigure(w, isolation={"mode": "user"})
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        for op, args in (("hello", {}), ("claim", {"packet": w.packet()})):
            with pytest.raises(scl.BrokerError) as e:
                c.call(op, **args)
            assert e.value.code == "broker_not_isolated"
    assert not (w.tmp / "ledger.json").exists()  # the refused claim wrote nothing


def test_admit_names_the_client_from_the_kernel_uid(w):
    lock_down(w)
    me = os.geteuid()
    cfg = reconfigure(w, isolation={"mode": "user", "clients": [me + 4242]})
    b = sb.Broker(cfg, "unix")
    ok = b.admit({"uid": me + 4242}, None)
    assert ok == {"mode": "separate-user", "verified": True, "broker_uid": me, "peer_uid": me + 4242}
    for peer, code in (({"uid": me}, "broker_not_isolated"), ({"uid": 0}, "broker_not_isolated"),
                       (None, "broker_not_isolated"), ({"uid": me + 4343}, "client_not_allowed")):
        with pytest.raises(sb.Refused) as e:
            b.admit(peer, None)
        assert e.value.code == code, peer


def test_clients_allowlist_with_unknown_users_refuses_to_start(w):
    lock_down(w)
    reconfigure(w, isolation={"mode": "user", "clients": ["no-such-user-synthe-test"]})
    with pytest.raises(SystemExit) as e:
        with daemon(w.cfg):
            pass
    assert "not users on this machine" in str(e.value)


# ---- mode none over a unix socket: the full path, receipted as dev ------------

def test_dev_mode_socket_claim_bundle_push_executes(w):
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        hello = c.call("hello")
        assert hello["isolation"]["mode"] == "none" and hello["isolation"]["verified"] is False
        assert hello["isolation"]["peer_uid"] == os.geteuid()
        assert c.server_creds["uid"] == os.geteuid()  # the kernel's answer, on the client side
        p = w.packet()
        v = c.call("claim", packet=p)
        assert v["decision"] == "ACCEPT"
        sha = w.commit({"src/app.py": "print('v2')\n"})
        r = scl.push(c, p, v["claim"]["token"], "push_branch", "origin", "feature/x", repo=w.agent)
        assert r["decision"] == "executed", r
        assert r["via"] == "unix"
        assert r["isolation"]["mode"] == "none" and r["isolation"]["verified"] is False
        assert r["commits_from"].startswith("bundle sha256:")
        assert str(w.agent) not in json.dumps(r)  # the receipt never names the agent's disk
        assert w.remote_ref("feature/x") == sha
        assert w.ledger_entry()["state"] == "COMPLETED"
        rec = c.call("receipts")
        assert rec["ok"] and rec["count"] == 1 and rec["receipts"][0]["decision"] == "executed"
        done = c.call("complete", packet=p, claim_token=v["claim"]["token"])
        assert done["decision"] == "COMPLETED"
    assert chain_decisions(w) == ["executed"]


def test_path_source_refused_in_daemon_mode_unless_allowed(w):
    p = w.packet()
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        token = c.call("claim", packet=p)["claim"]["token"]
        sha = w.commit({"src/app.py": "print('v2')\n"})
        args = dict(packet=p, claim_token=token, action="push_branch",
                    params={"remote": "origin", "branch": "feature/x", "commit": sha}, source=str(w.agent))
        r = c.call("propose", **args)
        assert r["decision"] == "denied" and codes(r) == {"source_path_not_allowed"}
    assert w.remote_ref("feature/x") is None
    assert w.ledger_entry()["state"] == "RESERVED"  # a denial never consumes the claim
    reconfigure(w, allow_path_sources=True)
    with daemon(w.cfg) as url:
        r = scl.BrokerClient(url).call("propose", **args)
        assert r["decision"] == "executed", r
        assert r["commits_from"] == "local path"
    assert chain_decisions(w) == ["denied", "executed"]


# ---- bundles are untrusted input ----------------------------------------------

def _claimed(w, c):
    p = w.packet()
    return p, c.call("claim", packet=p)["claim"]["token"]


def _propose_bundle(c, p, token, sha, data):
    return c.call("propose", packet=p, claim_token=token, action="push_branch",
                  params={"remote": "origin", "branch": "feature/x", "commit": sha}, bundle=b64(data))


def test_garbage_bundle_is_commit_unavailable(w):
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        p, token = _claimed(w, c)
        sha = w.commit({"src/app.py": "x\n"})
        r = _propose_bundle(c, p, token, sha, b"# v2 git bundle\nthis is not a bundle\n")
        assert r["decision"] == "denied" and codes(r) == {"commit_unavailable"}
    assert w.remote_ref("feature/x") is None


def test_bundle_that_is_not_base64_is_request_malformed(w):
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        p, token = _claimed(w, c)
        with pytest.raises(scl.BrokerError) as e:
            c.call("propose", packet=p, claim_token=token, action="push_branch",
                   params={"remote": "origin", "branch": "feature/x", "commit": "a" * 40}, bundle="%%%")
        assert e.value.code == "request_malformed"


def test_bundle_without_the_proposed_commit_is_commit_unavailable(w):
    init = git(w.agent, "rev-parse", "HEAD")
    other = scl.make_bundle(w.agent, init)  # a valid bundle, of the wrong commit
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        p, token = _claimed(w, c)
        sha = w.commit({"src/app.py": "x\n"})
        r = _propose_bundle(c, p, token, sha, other)
        assert r["decision"] == "denied" and codes(r) == {"commit_unavailable"}
    assert w.remote_ref("feature/x") is None


def test_bundle_over_the_cap_is_bundle_too_large(w):
    reconfigure(w, max_bundle_mb=0.0001)  # ~100 bytes
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        p, token = _claimed(w, c)
        sha = w.commit({"src/app.py": "x\n"})
        r = scl.push(c, p, token, "push_branch", "origin", "feature/x", repo=w.agent)
        assert r["decision"] == "denied" and codes(r) == {"bundle_too_large"}
        assert r["effect"]["commit"] == sha
    assert w.remote_ref("feature/x") is None


def test_thin_bundle_prerequisites_are_fetched_from_the_remote(w):
    main = git(w.agent, "rev-parse", "HEAD")
    w.commit({"src/a.py": "a\n"})
    sha = w.commit({"src/b.py": "b\n"})
    thin = scl.make_bundle(w.agent, sha, [main])
    header = thin.split(b"\n\n", 1)[0].decode()
    assert f"-{main}" in header  # it needs main, which only the remote has
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        p, token = _claimed(w, c)
        r = _propose_bundle(c, p, token, sha, thin)
        assert r["decision"] == "executed", r
        assert r["observed"]["commits"] == 2 and r["observed"]["paths"] == ["src/a.py", "src/b.py"]
    assert w.remote_ref("feature/x") == sha


def test_bundle_with_a_malformed_tree_is_refused(w):
    # A tree entry named ".git" must never reach the path checks or the remote.
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    h = subprocess.run(["git", "-C", str(w.agent), "hash-object", "-w", "--stdin"], input="x\n",
                       capture_output=True, text=True, env=env, check=True).stdout.strip()
    tree = subprocess.run(["git", "-C", str(w.agent), "mktree", "--missing"], input=f"100644 blob {h}\t.git\n",
                          capture_output=True, text=True, env=env, check=True).stdout.strip()
    parent = git(w.agent, "rev-parse", "HEAD")
    bad = git(w.agent, "commit-tree", tree, "-p", parent, "-m", "evil")
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        p, token = _claimed(w, c)
        r = _propose_bundle(c, p, token, bad, scl.make_bundle(w.agent, bad))
        assert r["decision"] == "denied" and codes(r) == {"commit_unavailable"}, r
    assert w.remote_ref("feature/x") is None


# ---- the wire: malformed requests, unknown ops, size limits ---------------------

def test_malformed_and_unknown_requests(w):
    with daemon(w.cfg) as url:
        assert raw_call(url, b"not json\n")["error"]["code"] == "request_malformed"
        assert raw_call(url, b'{"op": "claim", "args": []}\n')["error"]["code"] == "request_malformed"
        # release is operator-only: run it as the broker's user, never over the socket
        r = raw_call(url, json.dumps({"op": "release", "args": {}}).encode() + b"\n")
        assert r["error"]["code"] == "unknown_op"
        c = scl.BrokerClient(url)
        with pytest.raises(scl.BrokerError) as e:
            c.call("bundle_bases", remote="nope", branch="feature/x")
        assert e.value.code == "remote_unknown"


def test_request_too_large(w):
    reconfigure(w, max_bundle_mb=0.0001)
    with daemon(w.cfg) as url:
        b = sb.Broker(w.cfg, "unix")
        r = raw_call(url, b"x" * (b.max_request + 10) + b"\n")
        assert r["error"]["code"] == "request_too_large"


# ---- TCP (container mode): a bearer token, and the right transport per mode ------

def test_tcp_needs_the_right_token(w):
    lock_down(w)
    cfg = reconfigure(w, isolation={"mode": "container"})
    tok = "broker-token-for-tests-0123456789"
    with daemon(cfg, listen=True, token=tok) as url:
        for given in ("", "wrong-token-0123456789"):
            with pytest.raises(scl.BrokerError) as e:
                scl.BrokerClient(url, token=given).call("hello")
            assert e.value.code == "unauthorized"
        hello = scl.BrokerClient(url, token=tok).call("hello")
        assert hello["isolation"]["mode"] == "container" and hello["isolation"]["verified"] is False


def test_tcp_dev_mode_push_executes(w):
    tok = "broker-token-for-tests-0123456789"
    with daemon(w.cfg, listen=True, token=tok) as url:
        c = scl.BrokerClient(url, token=tok)
        p, token = _claimed(w, c)
        sha = w.commit({"src/app.py": "x\n"})
        r = scl.push(c, p, token, "push_branch", "origin", "feature/x", repo=w.agent)
        assert r["decision"] == "executed" and r["via"] == "tcp" and r["isolation"]["mode"] == "none"
    assert w.remote_ref("feature/x") == sha


def test_transport_must_fit_the_mode(w):
    lock_down(w)
    reconfigure(w, isolation={"mode": "user"})
    with pytest.raises(SystemExit, match="unix socket"):
        sb.make_server(w.cfg, listen="127.0.0.1:0", token="t" * 32)
    reconfigure(w, isolation={"mode": "container"})
    with pytest.raises(SystemExit, match="TCP"):
        sb.make_server(w.cfg, socket_path="/tmp/synthe-never.sock")
    with pytest.raises(SystemExit, match="token"):
        sb.make_server(w.cfg, listen="127.0.0.1:0", token=None)
    reconfigure(w, isolation={"mode": "sideways"})
    with pytest.raises(SystemExit, match="isolation mode"):
        sb.make_server(w.cfg, socket_path="/tmp/synthe-never.sock")


# ---- startup checks: the broker's own files ----------------------------------------

def _problem_codes(cfg):
    return {c for c, _ in sb.isolation_problems(cfg)}


def test_exposed_key_refuses_to_serve(w, capsys):
    lock_down(w)
    os.chmod(w.cfg.key_path, 0o644)
    reconfigure(w, isolation={"mode": "user"})
    assert _problem_codes(w.cfg) == {"broker_key_exposed"}
    with pytest.raises(SystemExit, match="not starting"):
        with daemon(w.cfg):
            pass
    assert "REFUSING broker_key_exposed" in capsys.readouterr().err
    assert sb.doctor(w.cfg) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and out["problems"][0]["code"] == "broker_key_exposed"


def test_writable_ledger_dir_is_broker_state_writable(w):
    lock_down(w)
    (w.tmp / "led").mkdir()
    os.chmod(w.tmp / "led", 0o770)
    reconfigure(w, ledger="led/ledger.json", isolation={"mode": "user"})
    problems = sb.isolation_problems(w.cfg)
    assert {c for c, _ in problems} == {"broker_state_writable"}
    assert "ledger" in problems[0][1]
    with pytest.raises(SystemExit):
        with daemon(w.cfg):
            pass


def test_exposed_token_file_is_broker_credentials_exposed(w):
    lock_down(w)
    (w.tmp / "gh.token").write_text("tok-0123456789abcdef\n")
    os.chmod(w.tmp / "gh.token", 0o644)
    raw = json.loads(w.config_path.read_text())
    raw["effects"]["git_push"]["remotes"]["origin"]["token_file"] = "gh.token"
    reconfigure(w, effects=raw["effects"], isolation={"mode": "user"})
    assert _problem_codes(w.cfg) == {"broker_credentials_exposed"}
    os.chmod(w.tmp / "gh.token", 0o600)
    assert _problem_codes(w.cfg) == set()


def test_writable_socket_dir_refuses_to_serve(w, capsys):
    lock_down(w)
    reconfigure(w, isolation={"mode": "user"})
    d = tempfile.mkdtemp(prefix="sy", dir="/tmp")
    try:
        os.chmod(d, 0o777)
        with pytest.raises(SystemExit):
            sb.make_server(w.cfg, socket_path=os.path.join(d, "b.sock"))
        assert "impersonate the broker" in capsys.readouterr().err
        assert not os.path.exists(os.path.join(d, "b.sock"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_dev_mode_only_warns(w, capsys):
    os.chmod(w.cfg.key_path, 0o644)
    assert "broker_key_exposed" in _problem_codes(w.cfg)
    with daemon(w.cfg) as url:
        assert scl.BrokerClient(url).call("hello")["isolation"]["mode"] == "none"
    err = capsys.readouterr().err
    assert "WARNING broker_key_exposed" in err and "isolation mode 'none'" in err


# ---- scrub: no credential leaves the broker ------------------------------------------

def test_scrub_removes_userinfo_and_token_values():
    t = "ghp_" + "Z" * 30
    assert t not in cm.scrub(f"fatal: https://x-access-token:{t}@github.com/o/r.git failed")
    assert cm.scrub("see https://user:pw@host/x") == "see https://<redacted>@host/x"
    out = cm.scrub_obj({"a": [f"x{t}y", {"k": t}], f"key-{t}": 1, "n": 3}, values=[t])
    assert t not in json.dumps(out) and out["n"] == 3


def test_no_token_in_any_receipt_response_or_error(w):
    tok = "tok-SECRET-abcdef012345"
    userinfo = "SEKRET-USERINFO-6789"
    (w.tmp / "gh.token").write_text(tok + "\n")
    os.chmod(w.tmp / "gh.token", 0o600)
    raw = json.loads(w.config_path.read_text())
    # Unreachable on purpose, with secrets both as userinfo and (contrived) in the
    # path, so git's own error messages carry them.
    raw["effects"]["git_push"]["remotes"]["origin"].update(
        url=f"https://u:{userinfo}@127.0.0.1:9/{tok}.git", token_file="gh.token")
    reconfigure(w, effects=raw["effects"])
    seen = []
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        seen.append(c.call("hello"))
        with pytest.raises(scl.BrokerError) as e:
            c.call("bundle_bases", remote="origin", branch="feature/x")
        assert e.value.code == "remote_unreachable"
        seen.append(e.value.message)
        p, token = _claimed(w, c)
        w.commit({"src/app.py": "x\n"})
        r = scl.push(c, p, token, "push_branch", "origin", "feature/x", repo=w.agent)
        assert r["decision"] == "errored" and codes(r) == {"remote_unreachable"}, r
        seen += [r, c.call("receipts")]
    seen.append((w.tmp / "receipts.jsonl").read_text())
    blob = json.dumps(seen)
    assert "<redacted>" in blob
    assert tok not in blob and userinfo not in blob
    assert w.chain()["ok"]


# ---- in-process brokers are dev-only ---------------------------------------------------

def test_in_process_propose_and_push_refused_unless_dev(w, capsys):
    lock_down(w)
    reconfigure(w, isolation={"mode": "user"})
    prop = w.tmp / "proposal.json"
    prop.write_text(json.dumps({"packet": w.packet(), "claim_token": "t", "action": "push_branch",
                                "params": {}, "source": str(w.agent)}))
    assert cm.main(["propose", str(prop), "--config", str(w.config_path)]) == 2
    pkt = w.tmp / "packet.json"
    pkt.write_text(json.dumps(w.packet(idem="k2")))
    assert cm.main(["push", "--config", str(w.config_path), "--packet", str(pkt), "--claim-token", "t",
                    "--action", "push_branch", "--remote", "origin", "--branch", "feature/x",
                    "--source", str(w.agent)]) == 2
    err = capsys.readouterr().err
    assert err.count("refused") == 2 and "synthe_commit.py serve" in err
    with pytest.raises(cm.NotIsolated, match="isolation mode 'user'"):  # the library, not just the CLI
        w.propose(w.packet(idem="k3"), "t", "a" * 40)
    assert not w.cfg.receipts_path.exists()  # refused before the key was ever loaded
    with pytest.raises(SystemExit, match="not isolation"):
        synthe_mcp.SyntheServer(None, None, None, broker_config=str(w.config_path))


def test_init_writes_the_requested_isolation_mode(tmp_path):
    assert cm.main(["init", "--dir", str(tmp_path / "c"), "--isolation", "container"]) == 0
    cfg = cm.BrokerConfig(tmp_path / "c" / "broker.json")
    assert cfg.isolation["mode"] == "container"
    assert stat.S_IMODE(os.stat(cfg.key_path).st_mode) == 0o600
    assert cm.main(["init", "--dir", str(tmp_path / "u")]) == 0
    assert cm.BrokerConfig(tmp_path / "u" / "broker.json").isolation["mode"] == "user"


def test_client_cli_reads_the_claim_token_from_a_file(w, capsys):
    p = w.packet()
    (w.tmp / "packet.json").write_text(json.dumps(p))
    with daemon(w.cfg) as url:
        assert scl.main(["--broker", url, "claim", str(w.tmp / "packet.json")]) == 0
        (w.tmp / "claim.json").write_text(capsys.readouterr().out)  # what `claim` printed, as-is
        w.commit({"src/app.py": "print('cli')\n"})
        rc = scl.main(["--broker", url, "push", "--packet", str(w.tmp / "packet.json"),
                       "--claim-token-file", str(w.tmp / "claim.json"), "--action", "push_branch",
                       "--remote", "origin", "--branch", "feature/x", "--repo", str(w.agent)])
        out = json.loads(capsys.readouterr().out)
        assert rc == 0 and out["decision"] == "executed", out
        token = json.loads((w.tmp / "claim.json").read_text())["claim"]["token"]
        (w.tmp / "token.txt").write_text(token + "\n")  # a bare token works too
        assert scl.main(["--broker", url, "complete", str(w.tmp / "packet.json"),
                         "--claim-token-file", str(w.tmp / "token.txt")]) == 0
    assert token not in json.dumps(out)  # the receipt never carries the claim token


# ---- MCP --broker-url: the MCP server holds no secrets, it forwards ----------------------

def _mcp(server, name, args):
    out = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": name, "arguments": args}})
    return out["result"]["structuredContent"]


def test_mcp_broker_url_forwards_and_bundles_client_side(w):
    with daemon(w.cfg) as url:  # allow_path_sources is off: only a bundle can work
        server = synthe_mcp.SyntheServer(None, None, None, broker_url=url)
        names = {t["name"] for t in server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                 ["result"]["tools"]}
        assert "synthe_propose_effect" in names
        assert _mcp(server, "synthe_receiver_policy", {"receiver": "builder"})["known"] is True
        p = w.packet()
        v = _mcp(server, "synthe_validate_handoff", {"packet": p})
        assert v["decision"] == "ACCEPT"
        sha = w.commit({"src/app.py": "print('mcp')\n"})
        r = _mcp(server, "synthe_propose_effect", {
            "packet": p, "claim_token": v["claim"]["token"], "action": "push_branch",
            "params": {"remote": "origin", "branch": "feature/x", "commit": sha}, "source": str(w.agent)})
        assert r["decision"] == "executed", r
        assert r["commits_from"].startswith("bundle sha256:") and r["via"] == "unix"
        done = _mcp(server, "synthe_complete_handoff", {"packet": p, "claim_token": v["claim"]["token"]})
        assert done["decision"] == "COMPLETED"
    assert w.remote_ref("feature/x") == sha
    # the broker gone: tools report it, they don't crash
    v = _mcp(server, "synthe_validate_handoff", {"packet": p})
    assert v["decision"] == "ERROR" and v["error"]["code"] == "broker_unreachable"


# ---- client doctor: the agent's-eye view --------------------------------------------------

def test_doctor_fails_dev_mode_and_detects_direct_push(w, capsys):
    git(w.agent, "remote", "add", "nowhere", str(w.tmp / "no-such-remote.git"))
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        checks = {x["check"]: x for x in scl.doctor(c, repo=w.agent, git_remote="origin")}
        assert checks["broker isolation"]["status"] == "FAIL"
        assert "kernel" in checks["broker isolation"]["detail"]
        assert checks["direct push"]["status"] == "FAIL"  # the agent can still push itself
        checks = {x["check"]: x for x in scl.doctor(c, repo=w.agent, git_remote="nowhere")}
        assert checks["direct push"]["status"] == "PASS"
        assert scl.main(["--broker", url, "doctor"]) == 2
    assert "FAIL  broker isolation" in capsys.readouterr().out
    assert w.remote_ref("synthe-doctor-probe") is None  # the probe is a dry run


def test_doctor_direct_push_asks_the_filesystem_for_local_remotes(w):
    # `git push --dry-run` to a local path succeeds with read access alone (it
    # never writes), so for local remotes doctor checks write access instead.
    assert scl._local_repo("https://github.com/o/r.git", w.agent) is None
    assert scl._local_repo("git@github.com:o/r.git", w.agent) is None
    assert scl._local_repo("file:///srv/r.git", w.agent) == scl.Path("/srv/r.git")
    assert scl._local_repo(str(w.remote), w.agent) == w.remote.resolve()
    assert scl._local_repo("../remote.git", w.agent) == w.remote.resolve()
    if os.geteuid() == 0:
        pytest.skip("root can write anything; the read-only case needs an ordinary user")
    objects = w.remote / "objects"
    os.chmod(objects, 0o555)
    try:
        with daemon(w.cfg) as url:
            checks = {x["check"]: x for x in scl.doctor(scl.BrokerClient(url), repo=w.agent, git_remote="origin")}
    finally:
        os.chmod(objects, 0o755)
    assert checks["direct push"]["status"] == "PASS", checks["direct push"]


def test_doctor_reports_a_refused_connection(w):
    lock_down(w)
    reconfigure(w, isolation={"mode": "user"})
    with daemon(w.cfg) as url:
        checks = {x["check"]: x for x in scl.doctor(scl.BrokerClient(url))}
    assert checks["broker isolation"]["status"] == "FAIL"
    assert "refused this user" in checks["broker isolation"]["detail"]


# ---- scripts: the daemon demo and the selftests' world builder --------------------------

def test_daemon_demo_runs_end_to_end(tmp_path):
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "demo_commit.py"), "--dir", str(tmp_path / "d")],
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    decisions = [line.split()[1] for line in out.stdout.splitlines() if line.strip().startswith("-> ")
                 and line.split()[1] in ("EXECUTED", "DENIED")]
    assert decisions == ["EXECUTED", "DENIED", "DENIED", "DENIED", "DENIED", "DENIED", "EXECUTED"], out.stdout
    assert "chain VERIFIED: 7 signed receipts" in out.stdout


def test_selftest_world_builds_a_handoff_the_broker_accepts(tmp_path):
    b = tmp_path / "broker"
    b.mkdir()
    rc = subprocess.run([sys.executable, str(ROOT / "scripts" / "selftest_world.py"), "--broker-dir", str(b),
                         "--remote-url", str(tmp_path / "remote.git"), "--packet", str(tmp_path / "p.json"),
                         "--new-broker-key", "--clients", "agent1"], capture_output=True, text=True)
    assert rc.returncode == 0, rc.stderr
    cfg = cm.BrokerConfig(b / "broker.json")
    assert cfg.isolation == {"mode": "user", "clients": ["agent1"]}
    registry = json.loads((b / "registry.json").read_text())
    v = hc.check(json.loads((tmp_path / "p.json").read_text()), registry=registry, ledger_path=None,
                 workspace=cfg.workspace)
    assert v["decision"] == "ACCEPT", v
    assert "approver" in registry["agents"] and "rishab" not in json.dumps(registry)  # throwaway approver only


# ---- Step B: per-phase timings (scripts/bench_commit.py) -------------------------------

def test_timings_are_reported_per_phase_and_stay_out_of_the_receipt(w):
    with daemon(w.cfg) as url:
        c = scl.BrokerClient(url)
        p, token = _claimed(w, c)
        sha = w.commit({"src/app.py": "timed\n"})
        data = scl.make_bundle(w.agent, sha)
        resp = c.call_full("propose", packet=p, claim_token=token, action="push_branch",
                           params={"remote": "origin", "branch": "feature/x", "commit": sha},
                           bundle=b64(data), timings=True)
    assert resp["result"]["decision"] == "executed"
    assert set(resp["timings"]) == {"validate", "prepare", "fence", "live_check", "inspect", "push",
                                    "confirm", "receipt"}
    assert all(0 <= v < 60 for v in resp["timings"].values())
    assert "timings" not in resp["result"] and w.chain()["ok"]  # the signed receipt is unchanged


def test_bench_script_runs(tmp_path):
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "bench_commit.py"), "--runs", "2",
                          "--warmup", "0", "--json", str(tmp_path / "r.json")],
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    r = json.loads((tmp_path / "r.json").read_text())
    assert set(r["paths"]) == {"isolated", "in-process"}
    assert r["paths"]["isolated"]["summary"]["total"]["p50_ms"] > 0
