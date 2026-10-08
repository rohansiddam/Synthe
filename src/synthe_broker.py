#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
"""Synthe Commit broker daemon: the only process that holds the keys.

    agent (its own OS user) --unix socket--> broker (separate user / container)
                                             signing key, GitHub token, registry,
                                             ledger, receipts, git mirror

If an agent can run the broker's code in its own process, it can read the
broker's key and credentials, and the commit barrier is a seatbelt, not a
wall. So the broker runs as its own OS user (or in a container) and agents
reach it only through a socket: they can propose, never touch a secret.

Isolation modes (broker.json "isolation": {"mode": ...}):

  user       (default) unix socket. Every client's uid is read from the
             kernel (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS); a client
             running as the broker's own user, or as root, is refused
             (`broker_not_isolated`): it could read the keys. Optional
             "clients": [user or uid, ...] allowlist.
  container  TCP with a bearer token. The container boundary is the wall;
             it is declared by the operator and cannot be verified from inside.
  none       dev only. Same-user clients are allowed and every receipt says so.

Before serving in `user` or `container` mode the broker checks its own
files and refuses to start if the key or a token file is readable by others,
or if its registry, ledger or receipts are writable by others.

Protocol: one JSON request line, one JSON response line, per connection.
  request  {"op": "...", "args": {...}, "auth": "<token, tcp only>"}
  response {"ok": true, "result": ...} | {"ok": false, "error": {"code", "message"}}
Ops: hello, claim, complete, policy, bundle_bases, propose, receipts, and
(v0.5) submit_approval, staged, read_file, list_files; (v0.7) submit_task.

Speculative commit (v0.5): `claim` and `propose` take "wait_for_approval":
true. The claim then succeeds while the approval of a broker-mediated effect
is still missing, and a proposal that lacks only that approval (or waits
only on a `depends_on` upstream) is checked against the live remote and held
STAGED. A sweeper thread, a `submit_approval` and an upstream completing
commit it the moment it is covered, re-running every commit-time check.

Run it:  synthe_commit.py serve --config broker.json --socket /var/run/synthe/broker.sock
Talk to it: synthe_client.py (agent side; holds no secrets).
"""
from __future__ import annotations

import base64
import binascii
import grp
import hashlib
import hmac
import json
import os
import pwd
import re
import signal
import socket
import socketserver
import stat
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc   # noqa: E402
import synthe_commit as cm   # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_plan as sp     # noqa: E402

PROTOCOL = 1
MODES = ("user", "container", "none")
MAX_TASK_BYTES = 64 * 1024
TASK_PATH = re.compile(r"tasks/[a-z0-9][a-z0-9.-]{0,127}\.md")


class Reply:
    """An op result plus extra response fields (e.g. timings) that sit next to
    "result" in the response, outside the signed receipt."""

    def __init__(self, result, **meta):
        self.result, self.meta = result, meta


class Refused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


# --------------------------------------------------------------------------
# who is on the other end of the socket (from the kernel, not the client)

peer_creds = scl.peer_creds


def _uid_of(who) -> int | None:
    if isinstance(who, int):
        return who
    try:
        return int(who)
    except (TypeError, ValueError):
        pass
    try:
        return pwd.getpwnam(str(who)).pw_uid
    except KeyError:
        return None


# --------------------------------------------------------------------------
# the broker's own files must not be readable/writable by the agents

def isolation_problems(cfg: cm.BrokerConfig) -> list:
    """[(code, message)] for every broker file an agent could read (secrets)
    or rewrite (registry, ledger, receipts, config). Empty = OK to serve."""
    me = os.geteuid()
    out = []

    def secret(path: Path, what: str, code: str):
        try:
            st = path.stat()
        except OSError:
            out.append((code, f"{what} {path} is missing or unreadable"))
            return
        if st.st_uid != me:
            out.append((code, f"{what} {path} is owned by uid {st.st_uid}, not the broker (uid {me})"))
        if st.st_mode & 0o077:
            out.append((code, f"{what} {path} is readable by others (mode {stat.filemode(st.st_mode)}); "
                              f"chmod 600 it"))

    def guarded(path: Path, what: str):
        for p in (path, path.parent):
            try:
                st = p.stat()
            except OSError:
                continue
            if st.st_mode & 0o022:  # no sticky-bit exception: predictable temp names
                out.append(("broker_state_writable",
                            f"{what}: {p} is writable by others (mode {stat.filemode(st.st_mode)}); an agent "
                            f"could rewrite it"))
                return

    secret(cfg.key_path, "broker key", "broker_key_exposed")
    for name, remote in ((cfg.effects.get("git_push") or {}).get("remotes") or {}).items():
        for label, r in ((f"remote '{name}'", remote), (f"the fetch_from source of '{name}'", remote.get("fetch_from"))):
            if isinstance(r, dict) and r.get("token_file"):
                secret(cfg.rel(r["token_file"]), f"token file for {label}", "broker_credentials_exposed")
    guarded(cfg.path, "broker config")
    guarded(cfg.registry_path, "registry")
    guarded(cfg.ledger_path, "ledger")
    guarded(cfg.receipts_path, "receipts")
    guarded(cfg.state_dir, "state dir")
    guarded(cfg.approvals_path, "detached approvals")
    if cfg.staged_path.exists():  # holds the claim tokens of staged proposals
        secret(cfg.staged_path, "staged proposals", "broker_credentials_exposed")
    return out


# --------------------------------------------------------------------------
# the daemon

class Broker:
    def __init__(self, cfg: cm.BrokerConfig, transport: str, token: str | None = None):
        self.cfg = cfg
        self.mode = cfg.isolation["mode"]
        self.transport = transport  # "unix" | "tcp"
        self.token = token
        self.uid = os.geteuid()
        self.task_lock = threading.Lock()
        # An allowlist that names nobody resolvable admits nobody (fail closed);
        # make_server refuses to start with one anyway.
        listed = cfg.isolation.get("clients") or []
        self.clients = {u for u in (_uid_of(c) for c in listed) if u is not None} if listed else None
        self.max_request = cfg.max_bundle_bytes * 4 // 3 + 4 * 1024 * 1024  # base64 bundle + packet

    # -- access ----------------------------------------------------------------
    def admit(self, peer: dict | None, auth) -> dict:
        """Decide whether this connection may talk to the broker; return the
        isolation record that goes into every receipt it causes."""
        if self.transport == "tcp":
            if not self.token or not isinstance(auth, str) or \
                    not hmac.compare_digest(auth.encode(), self.token.encode()):
                raise Refused("unauthorized", "missing or wrong broker token")
            if self.mode == "container":
                return {"mode": "container", "verified": False,
                        "note": "declared by the operator: the broker runs in a container the agent "
                                "cannot enter"}
            return {"mode": "none", "verified": False, "note": "dev mode over tcp: not isolated"}
        uid = (peer or {}).get("uid")
        if self.mode == "none":
            return {"mode": "none", "verified": False, "broker_uid": self.uid, "peer_uid": uid,
                    "note": "dev mode: the client may run as the broker's user and read its keys"}
        if uid is None:
            raise Refused("broker_not_isolated", "cannot read the client's uid from the kernel; refusing")
        if uid == self.uid:
            raise Refused("broker_not_isolated",
                          f"the client runs as the broker's own user (uid {uid}) and could read its keys; "
                          f"run the agent as a different OS user")
        if uid == 0:
            raise Refused("broker_not_isolated",
                          "the client runs as root, which can read any file; run the agent unprivileged")
        if self.clients is not None and uid not in self.clients:
            raise Refused("client_not_allowed", f"uid {uid} is not in this broker's clients list")
        return {"mode": "separate-user", "verified": True, "broker_uid": self.uid, "peer_uid": uid}

    # -- ops -------------------------------------------------------------------
    def dispatch(self, req, peer: dict | None) -> dict:
        try:
            if not isinstance(req, dict) or not isinstance(req.get("op"), str):
                raise Refused("request_malformed", "request must be {\"op\": ..., \"args\": {...}}")
            isolation = self.admit(peer, req.get("auth"))
            args = req.get("args", {})
            if args is None:
                args = {}
            if not isinstance(args, dict):
                raise Refused("request_malformed", "args must be an object")
            fn = getattr(self, f"op_{req['op']}", None)
            if fn is None:
                raise Refused("unknown_op", f"unknown op '{req['op']}'")
            out = fn(args, isolation)
            if isinstance(out, Reply):
                return {"ok": True, "result": out.result, **out.meta}
            return {"ok": True, "result": out}
        except Refused as r:
            return {"ok": False, "error": {"code": r.code, "message": r.message}}
        except cm.Deny as d:  # e.g. bundle_bases for a remote the broker doesn't have
            return {"ok": False, "error": {"code": d.reason["code"], "message": d.reason["message"]}}
        except Exception as exc:  # never crash the daemon on one bad request
            return {"ok": False, "error": {"code": "broker_error", "message": f"{type(exc).__name__}: {exc}"}}

    def _registry(self):
        registry, err = hc.load_registry(str(self.cfg.registry_path))
        if err:
            raise Refused(err["reasons"][0]["code"], err["reasons"][0]["message"])
        return registry

    def op_hello(self, args, isolation):
        view = self.cfg.public_view()
        return {"broker_id": self.cfg.broker_id, "version": cm.VERSION, "protocol": PROTOCOL,
                "isolation": isolation, "effects": view["effects"], "remotes": view["remotes"]}

    def op_claim(self, args, isolation):
        registry = self._registry()
        packet = args.get("packet")
        h = packet.get("handoff") if isinstance(packet, dict) else None
        extra, defer = (), None
        if isinstance(h, dict):
            extra = cm.load_approvals(self.cfg, h)
            if args.get("wait_for_approval") is True:
                # Work ahead: an approval this broker checks at commit may still be missing.
                defer = {a.get("name") for a in h.get("planned_actions") or []
                         if isinstance(a, dict) and a.get("tool") in self.cfg.effects}
        verdict = hc.check(packet, registry=registry, ledger_path=self.cfg.ledger_path,
                           workspace=self.cfg.workspace, dry_run=bool(args.get("dry_run", False)),
                           verify_evidence=self.cfg.verify_evidence, extra_approvals=extra,
                           defer_approvals=defer, as_receiver=self.cfg.receiver_id)
        if not isinstance(verdict, dict) or verdict.get("decision") != "ACCEPT":
            return verdict
        ledger = hc.load_ledger(self.cfg.ledger_path)
        plan = sp.plan_for(packet, registry, ledger, tuple(self.cfg.effects), extra_approvals=extra,
                           staged_actions=cm._staged_actions(self.cfg, (h or {}).get("idempotency_key")))
        return {**verdict, "plan": plan} if plan else verdict

    def op_complete(self, args, isolation):
        out = hc.complete(args.get("packet"), self.cfg.ledger_path,
                          claim_token=args.get("claim_token"), require_token=True)
        if isinstance(out, dict) and out.get("decision") == "COMPLETED":
            h = args["packet"]["handoff"]
            out["staged_commits"] = cm.retry_staged(
                self.cfg, depends_on=h["idempotency_key"],
                trigger={"kind": "upstream_completed", "idempotency_key": h["idempotency_key"]})
        return out

    def op_policy(self, args, isolation):
        registry = self._registry()
        who = args.get("receiver")
        agents = registry.get("agents", {})
        if who not in agents:
            return {"receiver": who, "known": False}
        return {"receiver": who, "known": True, "policy": hc.receiver_policy(registry, who) or {}}

    def op_bundle_bases(self, args, isolation):
        """Remote tips the agent may leave out of its bundle (the broker can
        fetch them itself). Read-only; credentials stay here."""
        return cm.GitPush(self.cfg).remote_tips(args.get("remote"), args.get("branch"), args.get("base") or "main")

    def op_propose(self, args, isolation):
        proposal = {k: args.get(k) for k in ("packet", "claim_token", "action", "params", "source",
                                             "wait_for_approval")}
        bundle = None
        if args.get("bundle") is not None:
            if not isinstance(args["bundle"], str):
                raise Refused("request_malformed", "bundle must be base64 text")
            try:
                bundle = base64.b64decode(args["bundle"], validate=True)
            except (binascii.Error, ValueError):
                raise Refused("request_malformed", "bundle is not valid base64")
        origin = {"isolation": isolation, "via": self.transport}
        timings = {} if args.get("timings") is True else None
        receipt = cm.propose(self.cfg, proposal, origin=origin, bundle=bundle,
                             allow_path_source=self.cfg.allow_path_sources, timings=timings)
        return Reply(receipt, timings=timings) if timings is not None else receipt

    def op_submit_approval(self, args, isolation):
        """A human's detached approval (synthe_sign.py approve --detached). It is
        verified like an embedded one, receipted either way, and commits every
        staged proposal it now covers. Anyone may deliver it: only the
        approver's signature makes it count."""
        return cm.submit_approval(self.cfg, args.get("approval"), origin={"isolation": isolation,
                                                                         "via": self.transport})

    def op_submit_task(self, args, isolation):
        with self.task_lock:
            return self._submit_task(args, isolation)

    def _submit_task(self, args, isolation):
        """Install one human-signed, hash-pinned task in the broker's workspace.

        The caller chooses neither an arbitrary destination nor arbitrary extra
        artifacts. A later claim revalidates the same packet and file; this
        operation only crosses the separate-user filesystem boundary.
        """
        packet, content = args.get("packet"), args.get("content")
        h = packet.get("handoff") if isinstance(packet, dict) else None
        if not isinstance(h, dict) or not isinstance(content, str):
            raise Refused("request_malformed", "submit_task needs a handoff packet and text content")
        raw = content.encode("utf-8")
        if len(raw) > MAX_TASK_BYTES:
            raise Refused("task_too_large", f"task content exceeds {MAX_TASK_BYTES} bytes")
        refs = (h.get("inputs") or {}).get("artifact_refs") if isinstance(h.get("inputs"), dict) else None
        if not isinstance(refs, list) or len(refs) != 1 or not isinstance(refs[0], dict):
            raise Refused("task_artifact_invalid", "a submitted task must pin exactly one artifact")
        rel, expected = refs[0].get("path"), refs[0].get("sha256")
        if not isinstance(rel, str) or TASK_PATH.fullmatch(rel) is None:
            raise Refused("task_path_invalid", "task artifact path must be tasks/<safe-name>.md")
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise Refused("task_artifact_invalid", "task artifact needs a lowercase SHA-256 digest")
        actual = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual, expected):
            raise Refused("task_hash_mismatch", "task content does not match the signed artifact hash")

        registry = self._registry()
        sender = (registry.get("agents") or {}).get(h.get("from"))
        if not isinstance(sender, dict) or sender.get("kind") != "human":
            raise Refused("task_sender_not_human", "submitted tasks must be signed by a registered human")

        tasks = self.cfg.workspace / "tasks"
        if tasks.is_symlink():
            raise Refused("task_path_invalid", "the workspace tasks directory must not be a symlink")
        tasks.mkdir(parents=True, exist_ok=True)
        # The broker runs with umask 077 (the LaunchDaemon's), so set the modes: the agent must read its task.
        if tasks.stat().st_uid == self.uid:
            os.chmod(tasks, 0o755)
        target = hc.resolve_in_workspace(self.cfg.workspace, rel)
        if target is None or target.parent != tasks.resolve() or target.is_symlink():
            raise Refused("task_path_invalid", "task artifact path escapes the broker workspace")

        created = False
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(target, flags, 0o644)
            except FileExistsError:
                if target.is_symlink() or not target.is_file():
                    raise Refused("task_conflict", "the task path exists but is not a regular file")
                st = target.stat()
                if st.st_uid != self.uid or st.st_mode & 0o022:
                    raise Refused("task_conflict", "the existing task is not broker-owned and read-only to clients")
                if not hmac.compare_digest(target.read_bytes(), raw):
                    raise Refused("task_conflict", "the task path already holds different content")
            else:
                created = True
                os.fchmod(fd, 0o644)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(raw)
                    fh.flush()
                    os.fsync(fh.fileno())

            extra = cm.load_approvals(self.cfg, h)
            defer = {a.get("name") for a in h.get("planned_actions") or []
                     if isinstance(a, dict) and a.get("tool") in self.cfg.effects}
            verdict = hc.check(packet, registry=registry, ledger_path=None, workspace=self.cfg.workspace,
                               dry_run=True, verify_evidence=self.cfg.verify_evidence,
                               extra_approvals=extra, defer_approvals=defer,
                               as_receiver=self.cfg.receiver_id)
            if not isinstance(verdict, dict) or verdict.get("decision") != "ACCEPT":
                if created:
                    target.unlink(missing_ok=True)
                    created = False
                return verdict
            return {**verdict, "task": {"path": rel, "sha256": actual, "created": created}}
        except BaseException:
            if created:
                target.unlink(missing_ok=True)
            raise

    def op_read_file(self, args, isolation):
        """Read-only: one file's text and blob id at the live tip of a branch the
        operator marked readable, so agents without git can see what they edit
        (and cite the blob in a content proposal)."""
        return cm.GitPush(self.cfg).read_file(args.get("remote"), args.get("ref"), args.get("path"))

    def op_fetch_bundle(self, args, isolation):
        """Read-only: a readable branch as a git bundle (clone or update without a GitHub credential)."""
        return cm.GitPush(self.cfg).bundle_ref(args.get("remote"), args.get("ref"), args.get("have"))

    def op_list_files(self, args, isolation):
        """Read-only: regular files (path, blob, size) under a prefix."""
        return cm.GitPush(self.cfg).list_files(args.get("remote"), args.get("ref"), args.get("prefix") or "")

    def op_staged(self, args, isolation):
        """Staged proposals (never their claim tokens)."""
        key = args.get("idempotency_key")
        return {"staged": cm.staged_view(self.cfg, key if isinstance(key, str) else None)}

    def op_staged_detail(self, args, isolation):
        """Read-only: one staged proposal as its approver should see it, built from the broker's
        record and mirror (the diff it would push), never from the agent's text; the agent's own
        words come back separately under `agent_says`. Never the claim token."""
        sid = args.get("id")
        if not isinstance(sid, str) or "/" not in sid:
            raise Refused("request_malformed", "id must be a staged proposal id (idempotency_key/action)")
        max_patch = args.get("max_patch", 200_000)
        if not isinstance(max_patch, int) or isinstance(max_patch, bool) or not 0 < max_patch <= 2_000_000:
            raise Refused("request_malformed", "max_patch must be a whole number of bytes up to 2000000")
        detail = cm.staged_detail(self.cfg, sid, max_patch=max_patch)
        if detail is None:
            raise Refused("staged_unknown", f"no staged proposal {sid!r}")
        return detail

    def op_receipts(self, args, isolation):
        limit = args.get("limit", 20)
        limit = limit if isinstance(limit, int) and 0 < limit <= 1000 else 20
        chain = cm.verify_receipts(self.cfg.receipts_path, self._registry())
        return {k: chain[k] for k in ("ok", "count", "head", "errors")} | {
            "receipts": chain["receipts"][-limit:]}


class _Handler(socketserver.StreamRequestHandler):
    timeout = 60  # seconds per socket read/write: an idle client can't pin a thread forever

    def handle(self):
        broker: Broker = self.server.broker
        peer = peer_creds(self.request) if broker.transport == "unix" else None
        try:
            line = self.rfile.readline(broker.max_request + 1)
        except (TimeoutError, OSError):
            return
        req = None
        if len(line) > broker.max_request:
            resp = {"ok": False, "error": {"code": "request_too_large",
                                           "message": f"request exceeds {broker.max_request} bytes"}}
        else:
            resp = None
            try:
                req = hc.strict_loads(line or b"null")
            except hc.StrictJSONError as exc:  # duplicate keys, NaN/Infinity: refuse, never guess
                resp = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
            except ValueError:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
                pass
            if resp is None:
                resp = broker.dispatch(req, peer)
        resp = cm.scrub_obj(resp, broker.cfg)  # no credential ever leaves the broker
        op = req.get("op") if isinstance(req, dict) else "?"
        status = "ok" if resp.get("ok") else resp["error"]["code"]
        if resp.get("ok") and isinstance(resp.get("result"), dict) and resp["result"].get("decision"):
            status = str(resp["result"]["decision"])
        sys.stderr.write(f"synthe-broker: {op} from uid {(peer or {}).get('uid', '-')}: {status}\n")
        self.wfile.write(json.dumps(resp).encode() + b"\n")


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(cfg: cm.BrokerConfig, socket_path: str | None = None, listen: str | None = None,
                token: str | None = None):
    """Build (but don't run) the server after the isolation checks. Raises
    SystemExit with the reasons when the broker must not start."""
    mode = cfg.isolation["mode"]
    if mode not in MODES:
        raise SystemExit(f"isolation mode must be one of {MODES}, not {mode!r}")
    if bool(socket_path) == bool(listen):
        raise SystemExit("give exactly one of --socket PATH or --listen HOST:PORT")
    if socket_path and mode == "container":
        raise SystemExit("isolation mode 'container' serves TCP (--listen) with a token")
    if listen and mode == "user":
        raise SystemExit("isolation mode 'user' needs a unix socket (--socket) so the kernel can name each "
                         "client's uid; use mode 'container' for TCP")
    problems = isolation_problems(cfg)
    unknown = [c for c in cfg.isolation.get("clients") or [] if _uid_of(c) is None]
    if unknown:
        raise SystemExit(f"isolation clients {unknown} are not users on this machine; fix the list "
                         f"(an allowlist that names nobody would admit nobody)")
    if socket_path:
        # Whoever can write the socket's directory can swap in their own
        # socket and impersonate the broker to every agent.
        sock_dir = Path(socket_path).parent
        sock_dir.mkdir(parents=True, exist_ok=True)
        st = sock_dir.stat()
        if st.st_mode & 0o022:
            problems.append(("broker_state_writable",
                             f"socket directory {sock_dir} is writable by others (mode {stat.filemode(st.st_mode)}); "
                             f"an agent could replace the socket and impersonate the broker"))
    for code, msg in problems:
        sys.stderr.write(f"synthe-broker: {'WARNING' if mode == 'none' else 'REFUSING'} {code}: {msg}\n")
    if problems and mode != "none":
        raise SystemExit("synthe-broker: not starting; fix the problems above (or set isolation mode 'none' "
                         "for local development only)")
    if mode == "none":
        sys.stderr.write("synthe-broker: WARNING isolation mode 'none' (dev): agents running as this user can "
                         "read the broker's keys; receipts will say so\n")
    if listen:
        if not token:
            raise SystemExit("serving TCP needs a bearer token (set it in the --token-env variable)")
        host, _, port = listen.rpartition(":")
        server = _TCPServer((host or "127.0.0.1", int(port)), _Handler)
        server.broker = Broker(cfg, "tcp", token)
        return server
    path = Path(socket_path)
    if path.exists() or path.is_symlink():
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(str(path))
            raise SystemExit(f"another broker is already serving on {path}")
        except (ConnectionRefusedError, FileNotFoundError):
            path.unlink()
        finally:
            probe.close()
    server = _UnixServer(str(path), _Handler)
    group = cfg.isolation.get("socket_group")
    if group:
        os.chown(path, -1, grp.getgrnam(group).gr_gid)
        os.chmod(path, 0o660)
    else:
        os.chmod(path, 0o666)  # the kernel-checked uid (and "clients") decide, not the file mode
    server.broker = Broker(cfg, "unix")
    return server


def sweep_staged(cfg: cm.BrokerConfig, stop: threading.Event, every: float) -> None:
    """Every `every` seconds: commit staged proposals that became covered
    without a direct trigger (an upstream completed elsewhere, a backoff
    elapsed) and deny the ones whose handoff expired or changed."""
    while not stop.wait(every):
        try:
            for r in cm.retry_staged(cfg, sweep=True):
                sys.stderr.write(f"synthe-broker: sweeper: staged {r.get('staged', {}).get('id')}: "
                                 f"{r.get('decision')}\n")
        except Exception as exc:  # the sweeper must never take the daemon down
            sys.stderr.write(f"synthe-broker: sweeper error: {type(exc).__name__}: {cm.scrub(str(exc), cfg)}\n")


def serve(cfg: cm.BrokerConfig, socket_path=None, listen=None, token=None) -> int:
    server = make_server(cfg, socket_path, listen, token)
    where = socket_path or listen
    sys.stderr.write(f"synthe-broker {cm.VERSION}: serving on {where} (isolation: {cfg.isolation['mode']}, "
                     f"broker uid {os.geteuid()})\n")
    halt = threading.Event()
    every = cfg.staged_sweep_seconds
    if every > 0:
        threading.Thread(target=sweep_staged, args=(cfg, halt, every), daemon=True,
                         name="synthe-staged-sweeper").start()

    def stop(*_):
        halt.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if socket_path:
            try:
                Path(socket_path).unlink()
            except OSError:
                pass
    return 0


def doctor(cfg: cm.BrokerConfig) -> int:
    """Broker-side self-check: the files an agent must not read or rewrite."""
    problems = isolation_problems(cfg)
    print(json.dumps({"broker_uid": os.geteuid(), "isolation": cfg.isolation["mode"],
                      "ok": not problems,
                      "problems": [{"code": c, "message": m} for c, m in problems]}, indent=2))
    return 0 if not problems else 2
