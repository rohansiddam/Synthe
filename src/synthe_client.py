#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthe client: the agent's side of the commit broker. Holds no secrets.

The broker (`synthe_commit.py serve`) runs as its own OS user, or in a
container, and is the only thing holding the keys and the GitHub token. This
client talks to its socket, and ships commits as git bundles so the broker
never reads the agent's disk.

  export SYNTHE_BROKER=unix:///var/run/synthe/broker.sock
         (or tcp://127.0.0.1:8791 with SYNTHE_BROKER_TOKEN, for a container)

  synthe_client.py hello
  synthe_client.py claim PACKET.json [--dry-run] [--wait-for-approval]
                        validate + claim (keep claim.token)
  synthe_client.py push --packet P --claim-token-file CLAIM.json --action A --remote R --branch B
                        [--repo .] [--commit HEAD] [--expected-old SHA|new] [--base main]
                        [--wait-for-approval]
  synthe_client.py approve-submit APPROVAL.json        deliver a human's detached approval
  synthe_client.py staged [--key IDEMPOTENCY_KEY]      proposals the broker holds
  synthe_client.py read PATH [--remote R] [--ref BRANCH] a file's text + blob id (readable remotes)
  synthe_client.py ls [PREFIX] [--remote R] [--ref BRANCH]
  synthe_client.py complete PACKET.json --claim-token-file CLAIM.json
                        (--claim-token T works too, but argv is visible to every user via ps)
  synthe_client.py receipts [--limit 20]
  synthe_client.py doctor [--repo . --git-remote origin]
                        can this agent really not touch the keys, or push on its own?

Speculative commit (v0.5): with --wait-for-approval an agent may claim a
handoff and propose its push before the human has approved it. The broker
checks everything it can now and holds the proposal STAGED (exit code 3);
when the signed approval arrives (approve-submit), it re-runs every check
and commits it, or denies it if anything changed.

Stdlib only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


class BrokerError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _git(args, check=True, env=None):
    full = {**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})}
    proc = subprocess.run(["git", *args], capture_output=True, text=True, env=full, timeout=300)
    if check and proc.returncode != 0:
        raise BrokerError("git_failed", f"git {' '.join(args[:3])}: {proc.stderr.strip()[-300:]}")
    return proc


def peer_creds(sock) -> dict | None:
    """uid/gid (and pid on Linux) of the process on the other end of a unix
    socket, as the kernel reports it (SO_PEERCRED / macOS LOCAL_PEERCRED).
    The broker uses it to name its clients; the client uses it to check
    that the broker really runs as another user."""
    try:
        if hasattr(socket, "SO_PEERCRED"):  # Linux
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", raw)
            return {"pid": pid, "uid": uid, "gid": gid}
        if sys.platform == "darwin":  # struct xucred via LOCAL_PEERCRED (SOL_LOCAL = 0)
            raw = sock.getsockopt(0, getattr(socket, "LOCAL_PEERCRED", 0x001), struct.calcsize("IIh2x16I"))
            _, uid, ngroups, *groups = struct.unpack("IIh2x16I", raw)
            return {"uid": uid, "gid": groups[0] if ngroups else None}
    except OSError:
        return None
    return None


def configured_broker() -> str | None:
    """The broker address `synthe-init` wrote to ~/.synthe/setup.json, for an agent shell that never set
    SYNTHE_BROKER (a clean-Mac run: OpenClaw's exec tool doesn't load the user's profile, so
    `synthe-client sync` failed with broker_unset). It only says where to connect; the broker's uid is
    still checked when SYNTHE_BROKER_UID or a clone's pin asks for it."""
    try:
        broker = json.loads((Path.home() / ".synthe" / "setup.json").read_text()).get("broker")
    except (OSError, ValueError, AttributeError):
        return None
    return broker if isinstance(broker, str) else None   # BrokerClient refuses anything not unix:// or tcp://


class BrokerClient:
    """One request per connection: a JSON line out, a JSON line back."""

    def __init__(self, url: str | None = None, token: str | None = None, timeout: float = 600.0,
                 expected_broker_uid: int | None = None):
        url = url or os.environ.get("SYNTHE_BROKER") or configured_broker()
        if not url:
            raise BrokerError("broker_unset", "no broker address: pass --broker or set SYNTHE_BROKER "
                                              "(unix:///path/to/broker.sock or tcp://host:port)")
        parts = urlsplit(url)
        if parts.scheme == "unix":
            self.family, self.addr = socket.AF_UNIX, parts.path or parts.netloc
        elif parts.scheme == "tcp" and parts.hostname and parts.port:
            self.family, self.addr = socket.AF_INET, (parts.hostname, parts.port)
        else:
            raise BrokerError("broker_unset", f"broker address must be unix:///path or tcp://host:port, not {url!r}")
        self.url, self.timeout = url, timeout
        self.token = token if token is not None else os.environ.get("SYNTHE_BROKER_TOKEN")
        self.server_creds = None  # the broker's uid, from the kernel (unix sockets only)
        # Pin the broker: the kernel names the process behind a unix socket, so a swapped
        # socket (a fake broker) is refused BEFORE any packet, claim token or bundle is sent.
        # Set by the operator (SYNTHE_BROKER_UID, written by the installer's "next steps").
        if expected_broker_uid is None:
            expected_broker_uid = os.environ.get("SYNTHE_BROKER_UID") or None
        try:
            self.expected_broker_uid = int(expected_broker_uid) if expected_broker_uid is not None else None
        except (TypeError, ValueError):
            raise BrokerError("broker_unset", f"expected broker uid must be a uid, not {expected_broker_uid!r}")
        if self.expected_broker_uid is not None and self.family != socket.AF_UNIX:
            raise BrokerError("broker_unset", "an expected broker uid can only be checked on a unix socket "
                                              "(tcp:// has no kernel peer credentials); unset SYNTHE_BROKER_UID "
                                              "or use unix://")

    def call(self, op: str, **args):
        return self.call_full(op, **args)["result"]

    def _verify_broker_uid(self) -> None:
        """Refuse to talk to a process that is not the expected broker (FINDING-T42-1 / FINDING-2)."""
        if self.expected_broker_uid is None:
            return
        uid = (self.server_creds or {}).get("uid")
        if uid is None:
            raise BrokerError("broker_not_isolated", "cannot read the broker's uid from the kernel; refusing")
        if uid != self.expected_broker_uid:
            raise BrokerError("broker_not_isolated",
                              f"the process on the socket runs as uid {uid}, not the expected broker uid "
                              f"{self.expected_broker_uid}: refusing a possible fake broker")

    def call_full(self, op: str, **args) -> dict:
        """The whole response, e.g. {"ok", "result", "timings"}; raises
        BrokerError when the broker refused the request."""
        req = {"op": op, "args": args}
        if self.family == socket.AF_INET and self.token:
            req["auth"] = self.token
        with socket.socket(self.family, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            try:
                s.connect(self.addr)
            except OSError as exc:
                raise BrokerError("broker_unreachable", f"cannot reach the broker at {self.url}: {exc}")
            if self.family == socket.AF_UNIX:
                self.server_creds = peer_creds(s)
                self._verify_broker_uid()  # before anything is sent
            s.sendall(json.dumps(req).encode() + b"\n")
            with s.makefile("rb") as fh:
                line = fh.readline()
        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            raise BrokerError("broker_error", "the broker closed the connection without an answer")
        if not resp.get("ok"):
            err = resp.get("error") or {}
            raise BrokerError(err.get("code", "broker_error"), err.get("message", ""))
        return resp


# --------------------------------------------------------------------------
# commits travel as a git bundle

def make_bundle(repo, commit: str, exclude=()) -> bytes:
    """A git bundle holding `commit` and its history, minus whatever is
    reachable from `exclude` (tips the broker can fetch from the remote
    itself). Uses a temporary ref under refs/synthe/ in the agent's repo."""
    repo = str(Path(repo).expanduser())
    ref = f"refs/synthe/outgoing/{commit}"
    _git(["-C", repo, "update-ref", ref, commit])
    try:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "proposal.bundle")
            have = [b for b in dict.fromkeys(exclude) if b and
                    _git(["-C", repo, "cat-file", "-e", f"{b}^{{commit}}"], check=False).returncode == 0]
            made = _git(["-C", repo, "bundle", "create", "-q", out, ref, *[f"^{b}" for b in have]], check=False)
            if made.returncode != 0 and have:  # nothing new (the commit is already there): send it whole
                made = _git(["-C", repo, "bundle", "create", "-q", out, ref], check=False)
            if made.returncode != 0:
                raise BrokerError("bundle_failed", made.stderr.strip()[-300:])
            return Path(out).read_bytes()
    finally:
        _git(["-C", repo, "update-ref", "-d", ref], check=False)


def push(client: BrokerClient, packet: dict, claim_token: str, action: str, remote: str, branch: str,
         repo=".", commit: str = "HEAD", expected_old: str | None = None, base: str | None = None,
         wait_for_approval: bool = False) -> dict:
    """Propose a git_push: resolve the commit, bundle it, send the proposal.
    Returns the broker's signed receipt (executed / denied / staged / ...)."""
    sha = _git(["-C", str(repo), "rev-parse", "--verify", f"{commit}^{{commit}}"]).stdout.strip()
    try:
        tips = client.call("bundle_bases", remote=remote, branch=branch, base=base or "main")
    except BrokerError:
        tips = {}  # send the whole history; the broker will still decide (and receipt) the proposal
    bundle = make_bundle(repo, sha, [tips.get("branch"), tips.get("base")])
    params = {"remote": remote, "branch": branch, "commit": sha}
    if expected_old:
        params["expected_old"] = expected_old
    if base:
        params["base"] = base
    extra = {"wait_for_approval": True} if wait_for_approval else {}
    return client.call("propose", packet=packet, claim_token=claim_token, action=action, params=params,
                       bundle=base64.b64encode(bundle).decode("ascii"), **extra)


def propose_from_args(client: BrokerClient, args: dict) -> dict:
    """MCP synthe_propose_effect in client mode: `source` is the agent's repo
    (read here, on the agent's side); the broker gets a bundle."""
    params = dict(args.get("params") or {})
    source = args.get("source")
    if source and params.get("commit") and params.get("remote") and params.get("branch"):
        return push(client, args.get("packet"), args.get("claim_token"), args.get("action"),
                    params["remote"], params["branch"], repo=source, commit=params["commit"],
                    expected_old=params.get("expected_old"), base=params.get("base"),
                    wait_for_approval=args.get("wait_for_approval") is True)
    return client.call("propose", **{k: args.get(k) for k in ("packet", "claim_token", "action", "params",
                                                               "wait_for_approval") if k in args})


# --------------------------------------------------------------------------
# doctor: the agent's-eye view of isolation

def _local_repo(url: str, repo) -> Path | None:
    """The path behind a local git remote (a path or file:// URL), or None
    for a network remote (scheme://... or scp-like host:path)."""
    if url.startswith("file://"):
        return Path(urlsplit(url).path)
    if "://" in url or ":" in url.split("/", 1)[0]:
        return None
    return (Path(repo).expanduser() / url).resolve()


def doctor(client: BrokerClient, repo=None, git_remote=None) -> list:
    """Checks, from the agent's side, that the broker is a wall and not a
    seatbelt: [{status: PASS|WARN|FAIL, check, detail}]."""
    out = []

    def add(status, check, detail):
        out.append({"status": status, "check": check, "detail": detail})

    try:
        iso = client.call("hello")["isolation"]
        mode = iso.get("mode")
        kernel_uid = (client.server_creds or {}).get("uid")
        if kernel_uid is not None and kernel_uid == os.geteuid():
            add("FAIL", "broker isolation", f"the kernel says the broker process runs as this agent's own user "
                                            f"(uid {kernel_uid}): this user can read its keys")
        elif kernel_uid is not None and iso.get("broker_uid") not in (None, kernel_uid):
            add("FAIL", "broker isolation", f"the process on this socket runs as uid {kernel_uid} but claims "
                                            f"{iso.get('broker_uid')}: it may not be the broker")
        elif mode == "separate-user" and iso.get("verified"):
            add("PASS", "broker isolation",
                f"the broker runs as uid {iso.get('broker_uid')} (kernel-checked); this agent is uid "
                f"{iso.get('peer_uid')}")
        elif mode == "container":
            add("WARN", "broker isolation", "declared container isolation: make sure this user cannot run "
                                            "docker/podman, or it can enter the container")
        else:
            add("FAIL", "broker isolation", f"isolation '{mode}': this user could read the broker's keys")
    except BrokerError as exc:
        add("FAIL", "broker isolation", exc.message if exc.code != "broker_not_isolated" else
            f"the broker refused this user: {exc.message}")
    if shutil.which("sudo"):
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            add("FAIL", "privilege", "passwordless sudo: this user can become the broker's user (or root) "
                                     "and read its keys")
        else:
            add("PASS", "privilege", "no passwordless sudo")
    if os.geteuid() == 0:
        add("FAIL", "privilege", "running as root: every file on this machine is readable")
    socks = ("/var/run/docker.sock", os.path.expanduser("~/.docker/run/docker.sock"), "/run/podman/podman.sock")
    for sock in dict.fromkeys(os.path.realpath(s) for s in socks):  # /var/run/docker.sock is often a symlink
        if os.path.exists(sock) and os.access(sock, os.R_OK | os.W_OK):
            add("WARN", "container runtime", f"this user can control {sock}: a broker container is not a "
                                             f"wall against it (a separate OS user still is)")
    for var in ("GITHUB_TOKEN", "GH_TOKEN", "GIT_ASKPASS", "SYNTHE_GIT_TOKEN"):
        if os.environ.get(var):
            add("WARN", "credentials in env", f"${var} is set in this agent's environment")
    if repo and git_remote:
        url = _git(["-C", str(repo), "remote", "get-url", "--push", git_remote], check=False).stdout.strip()
        target = git_remote
        if not url or url.startswith("synthe::"):
            # A clone made through the broker has no remote, or Synthe itself as `origin` (a push there
            # is a proposal). Either way pushing to it says nothing about the real remote, so probe the
            # broker's real URL instead of passing on nothing.
            url = ""
            try:
                url = ((client.call("hello").get("remotes") or {}).get(git_remote) or {}).get("url") or ""
            except BrokerError:
                url = ""
            if not url:
                add("WARN", "direct push", f"'{git_remote}' is not a remote of {repo}, and the broker names no "
                                           f"such remote: the direct-push test didn't run")
                return out
            target = url
        local = _local_repo(url or git_remote, repo)
        if local is not None:
            # A dry run never writes, and a local remote checks permissions only
            # when it writes: ask the filesystem instead.
            objects = next((p for p in (local / "objects", local / ".git" / "objects") if p.is_dir()), None)
            if objects is not None and os.access(objects, os.W_OK):
                add("FAIL", "direct push", f"this user can write the repository at {local} ('{git_remote}') "
                                           f"directly: only the broker's user should")
            else:
                add("PASS", "direct push", f"this user cannot write the repository behind '{git_remote}'")
            return out
        probe = _git(["-C", str(repo), "push", "--dry-run", "--porcelain", target,
                      "HEAD:refs/heads/synthe-doctor-probe"], check=False,
                     env={"GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o ConnectTimeout=10"})
        if probe.returncode == 0:
            add("FAIL", "direct push", f"this user can push to '{git_remote}' on its own: remove its "
                                       f"credentials (gh auth logout, keychain entry, SSH key) so the "
                                       f"broker is the only way")
        else:
            add("PASS", "direct push", f"this user cannot push to '{git_remote}' on its own")
    return out


# --------------------------------------------------------------------------
# CLI

def _load(path):
    return json.loads(Path(path).read_text())


def _claim_token(a) -> str:
    """--claim-token, or --claim-token-file: a file holding the token, or the
    claim verdict JSON that `claim` printed. A file keeps the token out of
    argv, which every user on the machine can read with ps."""
    if a.claim_token:
        return a.claim_token
    text = Path(a.claim_token_file).read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text.strip()
    if isinstance(data, dict) and isinstance(data.get("claim"), dict) and data["claim"].get("token"):
        return data["claim"]["token"]
    if isinstance(data, str):
        return data.strip()
    raise BrokerError("claim_token_required", f"{a.claim_token_file} holds no claim token")


def _apply_bundle(repo: Path, reply: dict) -> str:
    """Unpack the broker's bundle into refs/remotes/synthe/<ref> and return the tip."""
    import base64
    import tempfile
    if reply.get("up_to_date"):
        return reply["tip"]
    fd, tmp = tempfile.mkstemp(suffix=".bundle")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(base64.b64decode(reply["bundle"]))
        _git(["-C", str(repo), "-c", "transfer.fsckObjects=true", "fetch", "-q", "--no-tags", tmp,
              f"+{reply['bundle_ref']}:refs/remotes/synthe/{reply['ref']}"])
    finally:
        os.unlink(tmp)
    return reply["tip"]


def clone(client, directory: str, remote=None, ref=None) -> dict:
    """A working clone through the broker: no GitHub credential in this account, not even to read."""
    repo = Path(directory).expanduser()
    if repo.exists() and any(repo.iterdir()):
        raise BrokerError("clone_target_not_empty", f"{repo} exists and is not empty")
    reply = client.call("fetch_bundle", remote=remote, ref=ref)
    repo.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q", str(repo)])
    tip = _apply_bundle(repo, reply)
    branch = reply["ref"]
    _git(["-C", str(repo), "checkout", "-q", "-B", branch, f"refs/remotes/synthe/{branch}"])
    _git(["-C", str(repo), "config", "synthe.remote", reply["remote"]])
    _git(["-C", str(repo), "config", "synthe.ref", branch])
    # `origin` is Synthe itself (git-remote-synthe): a plain `git push` becomes a proposal and `git pull`
    # reads through the broker. Only this branch is tracked, so a proposed push never moves a remote-
    # tracking ref as if it had reached GitHub.
    _git(["-C", str(repo), "remote", "add", "-t", branch, "origin", f"synthe::{client.url}"])
    _git(["-C", str(repo), "update-ref", f"refs/remotes/origin/{branch}", tip])
    _git(["-C", str(repo), "branch", "-q", f"--set-upstream-to=origin/{branch}", branch])
    _git(["-C", str(repo), "config", "push.default", "current"])
    uid = (client.server_creds or {}).get("uid")
    if uid is not None:  # pin the helper to the broker this clone came from, as SYNTHE_BROKER_UID does
        _git(["-C", str(repo), "config", "synthe.brokerUid", str(uid)])
    return {"cloned": str(repo), "remote": reply["remote"], "ref": branch, "tip": tip, "bytes": reply.get("bytes")}


def sync(client, directory: str = ".", ref=None) -> dict:
    """Bring refs/remotes/synthe/<ref> up to date through the broker. It never touches your branches
    or working tree: merge or rebase onto it yourself."""
    repo = Path(directory).expanduser()
    remote = _git(["-C", str(repo), "config", "--get", "synthe.remote"], check=False).stdout.strip() or None
    ref = ref or _git(["-C", str(repo), "config", "--get", "synthe.ref"], check=False).stdout.strip() or None
    have = _git(["-C", str(repo), "rev-parse", "-q", "--verify", f"refs/remotes/synthe/{ref}"],
                check=False).stdout.strip() if ref else ""
    reply = client.call("fetch_bundle", remote=remote, ref=ref, **({"have": have} if have else {}))
    tip = _apply_bundle(repo, reply)
    return {"ref": reply["ref"], "tip": tip, "updated": not reply.get("up_to_date"),
            "use": f"git rebase refs/remotes/synthe/{reply['ref']}"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Synthe client: talk to the commit broker (holds no secrets)")
    ap.add_argument("--broker", help="unix:///path/to/broker.sock or tcp://host:port (default $SYNTHE_BROKER)")
    ap.add_argument("--broker-uid", type=int, default=None,
                    help="refuse to talk to a broker whose kernel uid differs (default $SYNTHE_BROKER_UID)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hello", help="who is the broker, and how isolated is this connection")
    c = sub.add_parser("claim", help="validate and claim a handoff (keep claim.token)")
    c.add_argument("packet")
    c.add_argument("--dry-run", action="store_true")
    c.add_argument("--wait-for-approval", action="store_true",
                   help="claim now even if the approval of a broker-mediated push is still missing")
    m = sub.add_parser("complete", help="complete a claimed handoff whose effects are done")
    m.add_argument("packet")
    p = sub.add_parser("push", help="propose a git_push; the commits travel as a bundle")
    p.add_argument("--packet", required=True)
    for sp in (m, p):
        tok = sp.add_mutually_exclusive_group(required=True)
        tok.add_argument("--claim-token")
        tok.add_argument("--claim-token-file", help="file with the token, or the JSON `claim` printed")
    p.add_argument("--action", required=True)
    p.add_argument("--remote", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--repo", default=".")
    p.add_argument("--commit", default="HEAD")
    p.add_argument("--expected-old", help="SHA the branch must be at, or 'new'")
    p.add_argument("--base", help="base branch for a new branch (default main)")
    p.add_argument("--wait-for-approval", action="store_true",
                   help="if only the approval (or an upstream) is missing, stage it; the broker commits "
                        "it when covered")
    ap_ = sub.add_parser("approve-submit", help="deliver a detached approval (synthe_sign.py approve --detached)")
    ap_.add_argument("approval")
    st = sub.add_parser("staged", help="proposals the broker holds until their approval or upstream arrives")
    st.add_argument("--key", help="only this idempotency key")
    rd = sub.add_parser("read", help="a file's text and blob id from a readable branch")
    rd.add_argument("path")
    ls = sub.add_parser("ls", help="files (path, blob, size) on a readable branch")
    ls.add_argument("prefix", nargs="?", default="")
    for sp_ in (rd, ls):
        sp_.add_argument("--remote")
        sp_.add_argument("--ref", help="branch (default: the remote's first plain branch)")
    cl = sub.add_parser("clone", help="clone a readable branch through the broker (no GitHub credential needed)")
    cl.add_argument("directory")
    cl.add_argument("--remote")
    cl.add_argument("--ref", help="branch (default: the remote's first plain readable branch)")
    sy = sub.add_parser("sync", help="update refs/remotes/synthe/<branch> through the broker")
    sy.add_argument("directory", nargs="?", default=".")
    sy.add_argument("--ref")
    r = sub.add_parser("receipts", help="the receipt chain's status and latest receipts")
    r.add_argument("--limit", type=int, default=20)
    d = sub.add_parser("doctor", help="can this agent touch the keys or push on its own?")
    d.add_argument("--repo")
    d.add_argument("--git-remote")
    a = ap.parse_args(argv)
    try:
        client = BrokerClient(a.broker, expected_broker_uid=a.broker_uid)
        if a.cmd == "hello":
            out = client.call("hello")
        elif a.cmd == "claim":
            extra = {"wait_for_approval": True} if a.wait_for_approval else {}
            out = client.call("claim", packet=_load(a.packet), dry_run=a.dry_run, **extra)
        elif a.cmd == "complete":
            out = client.call("complete", packet=_load(a.packet), claim_token=_claim_token(a))
        elif a.cmd == "push":
            out = push(client, _load(a.packet), _claim_token(a), a.action, a.remote, a.branch, a.repo,
                       a.commit, a.expected_old, a.base, wait_for_approval=a.wait_for_approval)
        elif a.cmd == "approve-submit":
            out = client.call("submit_approval", approval=_load(a.approval))
        elif a.cmd == "staged":
            out = client.call("staged", **({"idempotency_key": a.key} if a.key else {}))
        elif a.cmd == "read":
            out = client.call("read_file", path=a.path, remote=a.remote, ref=a.ref)
        elif a.cmd == "ls":
            out = client.call("list_files", prefix=a.prefix, remote=a.remote, ref=a.ref)
        elif a.cmd == "clone":
            out = clone(client, a.directory, a.remote, a.ref)
        elif a.cmd == "sync":
            out = sync(client, a.directory, a.ref)
        elif a.cmd == "receipts":
            out = client.call("receipts", limit=a.limit)
        else:
            checks = doctor(client, a.repo, a.git_remote)
            for x in checks:
                print(f"{x['status']:5} {x['check']}: {x['detail']}")
            return 2 if any(x["status"] == "FAIL" for x in checks) else 0
    except BrokerError as exc:
        print(json.dumps({"ok": False, "error": {"code": exc.code, "message": exc.message}}, indent=2))
        return 2
    print(json.dumps(out, indent=2))
    if a.cmd == "push":
        return {"executed": 0, "staged": 3}.get(out.get("decision"), 2)
    if a.cmd == "approve-submit":
        return 0 if (out.get("receipt") or {}).get("decision") == "approval_accepted" else 2
    if a.cmd in ("claim", "complete"):
        return 0 if out.get("decision") in ("ACCEPT", "COMPLETED") else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
