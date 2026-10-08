#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""git-remote-synthe: a plain `git push` becomes a Synthe proposal.

Any agent, or person, already knows `git push`. In an agent's clone made through the broker
(`synthe-client clone`), `origin` is `synthe::<broker address>`, so git hands the push to this
helper instead of to GitHub. The helper finds the signed task for the branch, claims it (once; the
claim token is kept under .git/synthe/), bundles the commit and proposes it to the broker. Nothing
reaches GitHub until a person approves; then the broker pushes exactly that commit and signs a
receipt. `git fetch` / `git pull` on the clone's branch read through the broker the same way.

The helper holds no credential and adds no authority: everything it does, the agent could do with
synthe-client. The broker still decides, and receipts, every proposal.

  git remote add origin synthe::unix:///var/db/synthe-run/broker.sock     (clone does this)
  git push origin agent/my-branch            -> proposed; the approver runs synthe-approve

Which task: $SYNTHE_TASK or `git config synthe.task` (a packet path) if set; otherwise the newest
unexpired packet in the inbox ($SYNTHE_INBOX, `git config synthe.inbox`, or the macOS installer's
/Users/Shared/Synthe/inbox) that plans a git_push of this branch.

Stdlib only. Protocol: gitremote-helpers(7) (capabilities, list, fetch, push).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_client as scl  # noqa: E402

DEFAULT_BROKER = "unix:///var/db/synthe-run/broker.sock"   # the macOS installer's (synthe_init.MACOS_SOCKET)
DEFAULT_INBOX = "/Users/Shared/Synthe/inbox"                 # where synthe-task leaves signed tasks there
HEADS = "refs/heads/"


def _git(*args, check=True) -> subprocess.CompletedProcess:
    # GIT_DIR is set by git for its helpers, so these act on the repository being pushed from.
    proc = subprocess.run(["git", *args], capture_output=True, text=True,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, timeout=300)
    if check and proc.returncode != 0:
        raise scl.BrokerError("git_failed", f"git {args[0]}: {proc.stderr.strip()[-300:]}")
    return proc


def _config(key: str) -> str:
    return _git("config", "--get", key, check=False).stdout.strip()


def _say(line: str = "") -> None:
    """Messages for the person or agent at the terminal (git shows a helper's stderr as is)."""
    print(f"synthe: {line}" if line else "synthe:", file=sys.stderr, flush=True)


def _git_dir() -> Path:
    return Path(os.environ.get("GIT_DIR") or _git("rev-parse", "--git-dir").stdout.strip()).resolve()


# --------------------------------------------------------------------------
# the task for a branch

def _push_action(packet: dict, branch: str) -> dict | None:
    h = packet.get("handoff") if isinstance(packet, dict) else None
    for a in (h or {}).get("planned_actions") or []:
        if isinstance(a, dict) and a.get("tool") == "git_push" and (a.get("params") or {}).get("branch") == branch:
            return a
    return None


def _expired(packet: dict, now: dt.datetime) -> bool:
    exp = ((packet.get("handoff") or {}).get("acceptance") or {}).get("expires_at")
    try:
        return dt.datetime.fromisoformat(str(exp).replace("Z", "+00:00")) <= now
    except ValueError:
        return True


def find_task(branch: str, inbox: Path | None = None, explicit: str | None = None,
              now: dt.datetime | None = None) -> tuple[dict, dict, Path]:
    """(packet, planned push action, path) for the branch, or BrokerError saying what to do."""
    now = now or dt.datetime.now(dt.timezone.utc)
    if explicit:
        path = Path(explicit).expanduser()
        try:
            packet = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise scl.BrokerError("task_unreadable", f"cannot read the task {path}: {exc}")
        action = _push_action(packet, branch)
        if action is None:
            raise scl.BrokerError("task_branch_mismatch", f"the task {path.name} plans no push of {branch}")
        return packet, action, path
    inbox = inbox or Path(DEFAULT_INBOX)
    found = []
    for path in sorted(inbox.glob("*.json")) if inbox.is_dir() else []:
        try:
            packet = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        action = _push_action(packet, branch)
        if action is not None and not _expired(packet, now):
            found.append((path.stat().st_mtime, path.name, packet, action, path))
    if not found:
        raise scl.BrokerError("no_task_for_branch",
                              f"no signed task in {inbox} plans a push of {branch}. Ask the approver for one "
                              f"(synthe-task new \"...\" --branch {branch}), or push the branch a task names")
    _, _, packet, action, path = max(found, key=lambda f: (f[0], f[1]))   # the newest
    return packet, action, path


# --------------------------------------------------------------------------
# the claim, kept in the clone (the token is the agent's own; it's no secret from the agent)

def _claim_file(packet: dict) -> Path:
    key = (packet.get("handoff") or {}).get("idempotency_key", "")
    return _git_dir() / "synthe" / "claims" / f"{hashlib.sha256(key.encode()).hexdigest()[:32]}.json"


def claim_token(client: scl.BrokerClient, packet: dict) -> str:
    h = packet.get("handoff") or {}
    path = _claim_file(packet)
    try:
        saved = json.loads(path.read_text())
        if saved.get("handoff_id") == h.get("id") and saved.get("token"):
            return saved["token"]
    except (OSError, ValueError):
        pass
    verdict = client.call("claim", packet=packet, wait_for_approval=True)
    if not isinstance(verdict, dict) or verdict.get("decision") != "ACCEPT":
        codes = [r.get("code", "?") for r in (verdict or {}).get("reasons", []) if isinstance(r, dict)]
        if "idempotency_key_reserved" in codes:
            raise scl.BrokerError("task_claimed_elsewhere",
                                  "this task is already claimed in another session (the synthe tools, most "
                                  "likely). Finish it there with synthe_propose_effect, or ask for a new task")
        raise scl.BrokerError(codes[0] if codes else "claim_refused",
                              f"the broker refused the task: {', '.join(codes) or 'no reason given'}")
    token = verdict["claim"]["token"]
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"handoff_id": h.get("id"), "token": token}, fh)
    return token


# --------------------------------------------------------------------------
# the remote helper

class Helper:
    def __init__(self, remote_name: str, address: str, out=None):
        address = (address or "").strip()
        if address in ("", "default"):
            address = os.environ.get("SYNTHE_BROKER") or DEFAULT_BROKER
        uid = os.environ.get("SYNTHE_BROKER_UID") or _config("synthe.brokerUid") or None
        self.client = scl.BrokerClient(address, expected_broker_uid=uid)
        self.remote_name, self.out = remote_name, out or sys.stdout
        self.fetched: dict | None = None

    def send(self, *lines: str) -> None:
        for line in lines:
            self.out.write(line + "\n")
        self.out.flush()

    # list ---------------------------------------------------------------
    def list_refs(self, for_push: bool) -> None:
        if for_push:
            # The broker, not git, compares with the remote; every push is a proposal for it to check.
            self.send("")
            return
        remote = _config("synthe.remote") or None
        ref = _config("synthe.ref") or None
        have = _git("rev-parse", "-q", "--verify", f"refs/remotes/{self.remote_name}/{ref}",
                    check=False).stdout.strip() if ref else ""
        self.fetched = self.client.call("fetch_bundle", remote=remote, ref=ref, **({"have": have} if have else {}))
        branch = self.fetched["ref"]
        self.send(f"{self.fetched['tip']} {HEADS}{branch}", f"@{HEADS}{branch} HEAD", "")

    # fetch --------------------------------------------------------------
    def fetch(self) -> None:
        reply = self.fetched or {}
        if reply.get("bundle"):
            fd, tmp = tempfile.mkstemp(suffix=".bundle")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(base64.b64decode(reply["bundle"]))
                _git("bundle", "unbundle", tmp)           # the objects land; git updates the refs itself
            finally:
                os.unlink(tmp)
        self.send("")

    # push ---------------------------------------------------------------
    def push_one(self, spec: str) -> str:
        src, _, dst = spec.lstrip("+").partition(":")
        if not dst.startswith(HEADS):
            return f"error {dst} synthe proposes branches only"
        branch = dst[len(HEADS):]
        if not src:
            _say(f"{branch}: deleting a branch isn't something Synthe proposes. Nothing was changed.")
            return f"error {dst} deletion is not a proposal"
        try:
            sha = _git("rev-parse", "--verify", f"{src}^{{commit}}").stdout.strip()
            explicit = os.environ.get("SYNTHE_TASK") or _config("synthe.task") or None
            inbox = os.environ.get("SYNTHE_INBOX") or _config("synthe.inbox") or None
            packet, action, path = find_task(branch, Path(inbox) if inbox else None, explicit)
            token = claim_token(self.client, packet)
            params = action.get("params") or {}
            receipt = scl.push(self.client, packet, token, action["name"], params.get("remote", "origin"),
                               branch, repo=".", commit=sha, base=params.get("base"), wait_for_approval=True)
        except scl.BrokerError as exc:
            _say(f"{branch}: not proposed ({exc.code}). {exc.message}")
            return f"error {dst} {exc.code}"
        decision, seq = receipt.get("decision"), receipt.get("seq")
        short = sha[:12]
        if decision == "staged":
            _say(f"{branch} at {short} is proposed for approval, not pushed yet (task {path.name}, receipt #{seq}).")
            _say("A person reviews the diff and approves it with synthe-approve; then Synthe pushes exactly this")
            _say("commit and signs a receipt. Don't push it another way, and don't approve it yourself.")
            return f"ok {dst}"
        if decision == "executed":
            _say(f"{branch} at {short} was pushed by Synthe (receipt #{seq}).")
            return f"ok {dst}"
        codes = [r.get("code", "?") for r in receipt.get("reasons") or [] if isinstance(r, dict)]
        _say(f"{branch}: Synthe refused this push ({', '.join(codes) or decision}; receipt #{seq}). Nothing was pushed.")
        for r in (receipt.get("reasons") or [])[:3]:
            if isinstance(r, dict) and r.get("message"):
                _say(f"  {r.get('code')}: {r['message']}")
        _say("Report this to the person you work for; don't try another way to push.")
        return f"error {dst} {codes[0] if codes else decision}"

    # the protocol loop -------------------------------------------------
    def run(self, stdin=None) -> int:
        stdin = stdin or sys.stdin
        batch: list[str] = []
        for raw in stdin:
            line = raw.rstrip("\n")
            if line == "capabilities":
                self.send("fetch", "push", "")
            elif line in ("list", "list for-push"):
                self.list_refs(line == "list for-push")
            elif line.startswith("fetch "):
                batch.append(line)
            elif line.startswith("push "):
                batch.append(line)
            elif line == "":
                if not batch:
                    return 0                                  # the end of the conversation
                if batch[0].startswith("fetch "):
                    self.fetch()
                else:
                    self.send(*[self.push_one(b[len("push "):]) for b in batch], "")
                batch = []
            else:
                _say(f"unsupported request from git: {line!r}")
                return 1
        return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 1 or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    try:
        return Helper(argv[0], argv[1] if len(argv) > 1 else "").run()
    except scl.BrokerError as exc:
        _say(f"{exc.code}: {exc.message}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
