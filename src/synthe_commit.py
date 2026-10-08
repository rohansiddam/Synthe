#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
"""Synthe Commit (v0.4): the commit authority for agent effects.

    Agents propose. Synthe commits. Anyone can verify.

The v0.3 gate is an admission check the receiving agent *chooses* to call,
and it never sees what the agent then does. Here the receiving agent holds
no credentials for the effect. It sends a *proposal* ("push commit C to
branch B of remote R"), and the broker, which alone holds the credentials:

  1. re-validates the signed handoff now (signature, receiver policy, expiry,
     approvals): authority at commit time, not just at admission;
  2. checks the effect was planned by the sender with these exact params,
     and that a trusted human approval pins the same params;
  3. inside the claim fence (the model-checked exactly-once ledger), checks
     the effect's precondition against live state and inspects what the
     effect would change (every commit's paths vs scope and receiver policy);
  4. performs the effect with a compare-and-swap on the remote, so a race
     cannot slip between check and effect;
  5. observes the result and records EXECUTED only when it is confirmed;
  6. appends a signed, hash-chained receipt for every proposal: executed,
     denied or errored. A denial is evidence the gate worked.

Supported effects: git_push. (send_email is next; see docs/COMMIT.md.)

Commands:
  init       --dir DIR [--broker-id ID]    broker key + config skeleton
  serve      --config CFG --socket PATH    the broker daemon, run as its own OS
             (or --listen HOST:PORT)       user; agents use synthe_client.py
  doctor     --config CFG                  are the key, tokens and state private?
  propose    PROPOSAL.json --config CFG    dev only (isolation "none"): in-process
  push       --config CFG --packet P ...   dev only (isolation "none"): in-process
  receipts   verify|show --config CFG      offline chain + signature check
  ui         --config CFG [--port 8790]    read-only console on 127.0.0.1

Isolation (synthe_broker.py): by default the broker refuses to run inside an
agent's process. It serves a socket as its own OS user and refuses clients
running as that user or as root, because they could read its keys.

Stdlib only (uses `cryptography` for Ed25519 when installed).
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc  # noqa: E402
import synthe_crypto as sc  # noqa: E402
import synthe_plan as sp    # noqa: E402
import synthe_sign as ss    # noqa: E402

VERSION = "0.6.0"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# Plan params the sender must commit to for each effect type: the broker
# never executes an effect whose target the sender did not sign.
REQUIRED_PLAN_PARAMS = {"git_push": ("remote", "branch")}
EFFECT_FINGERPRINT_DOMAIN = b"synthe/prepared-effect/v1\n"


class Deny(Exception):
    """The proposal is refused; nothing was done."""

    def __init__(self, state: str, code: str, message: str, decision: str = "denied"):
        super().__init__(message)
        self.reason = {"state": state, "code": code, "message": message}
        self.decision = decision


class _Laps:
    """Wall-clock seconds per commit phase, for scripts/bench_commit.py. A
    no-op unless the caller passed a dict to fill."""

    def __init__(self, out: dict | None):
        self.out, self.t = out, time.perf_counter()

    def lap(self, name: str):
        if self.out is not None:
            now = time.perf_counter()
            self.out[name] = self.out.get(name, 0.0) + now - self.t
            self.t = now


# --------------------------------------------------------------------------
# config

class BrokerConfig:
    """Operator-owned config. Paths are relative to the config file."""

    def __init__(self, path):
        self.path = Path(path).expanduser().resolve()
        raw = json.loads(self.path.read_text())
        base = self.path.parent

        def rel(p):
            return (base / Path(p).expanduser()).resolve() if p else None

        self.raw = raw
        self.rel = rel
        self.broker_id = raw.get("broker_id", "synthe-broker")
        self.receiver_id = raw.get("receiver")
        self.key_path = rel(raw["key"])
        self.registry_path = rel(raw["registry"])
        self.ledger_path = rel(raw["ledger"])
        self.receipts_path = rel(raw.get("receipts", "receipts.jsonl"))
        # v0.5: detached approvals (append-only) and staged proposals (0600:
        # they hold the claim tokens the broker commits with later).
        self.approvals_path = rel(raw.get("approvals", "approvals.jsonl"))
        self.workspace = rel(raw.get("workspace"))
        self.state_dir = rel(raw.get("state_dir", ".synthe-broker"))
        self.staged_path = self.state_dir / "staged.json"
        self.source_roots = [rel(p) for p in raw.get("source_roots", [])]
        self.verify_evidence = bool(raw.get("verify_evidence", False))
        self.effects = raw.get("effects") or {}
        # Isolation (synthe_broker.py): who may talk to the broker, and how.
        # Default "user": the broker runs as its own OS user and refuses
        # clients running as that user or as root. "none" = dev only.
        iso = raw.get("isolation") or {}
        iso = {"mode": iso} if isinstance(iso, str) else dict(iso)
        iso.setdefault("mode", "user")
        self.isolation = iso
        # Daemon proposals carry the commits as a git bundle; reading a path on
        # the agent's disk is a dev convenience the operator must opt into.
        self.allow_path_sources = bool(raw.get("allow_path_sources", False))
        self.max_bundle_bytes = int(float(raw.get("max_bundle_mb", 50)) * 1024 * 1024)
        # v0.5: how often the daemon's sweeper revisits staged proposals (0 = never)
        self.staged_sweep_seconds = float(raw.get("staged_sweep_seconds", 30))

    def secrets(self) -> list:
        """Credential values this broker holds, so they can be scrubbed from
        anything that leaves it (messages, receipts, responses)."""
        out = []
        remotes = list(((self.effects.get("git_push") or {}).get("remotes") or {}).values())
        remotes += [r["fetch_from"] for r in remotes if isinstance(r.get("fetch_from"), dict)]
        for remote in remotes:
            if remote.get("token_env") and os.environ.get(remote["token_env"]):
                out.append(os.environ[remote["token_env"]])
            if remote.get("token_file"):
                try:
                    out.append(self.rel(remote["token_file"]).read_text().strip())
                except OSError:
                    pass
        return [s for s in out if len(s) >= 6]

    def public_view(self) -> dict:
        remotes = ((self.effects.get("git_push") or {}).get("remotes") or {})
        return {
            "broker_id": self.broker_id,
            "effects": sorted(self.effects),
            "isolation": self.isolation.get("mode"),
            "remotes": {n: {"url": redact_url(r.get("url", "")), "branches": r.get("branches", [])}
                        for n, r in remotes.items()},
            "source_roots": [str(p) for p in self.source_roots],
            "ledger": str(self.ledger_path),
            "receipts": str(self.receipts_path),
        }


_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@'\"]+@")


def scrub(text: str, cfg: "BrokerConfig | None" = None, values: list | None = None) -> str:
    """Remove credentials from text that leaves the broker: URL userinfo
    (https://user:token@host) and any token value the broker holds."""
    text = _USERINFO.sub(r"\1<redacted>@", text)
    for secret in (values if values is not None else cfg.secrets() if cfg else []):
        text = text.replace(secret, "<redacted>")
    return text


def scrub_obj(obj, cfg: "BrokerConfig | None" = None, values: list | None = None):
    """scrub() every string (and key) in a JSON-like value. Works on the
    decoded value, so a secret can't slip through in JSON-escaped form."""
    if values is None:
        values = cfg.secrets() if cfg else []
    if isinstance(obj, str):
        return scrub(obj, values=values)
    if isinstance(obj, dict):
        return {scrub(str(k), values=values): scrub_obj(v, values=values) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_obj(v, values=values) for v in obj]
    return obj


def git_username(url: str, token: str) -> str:
    """The HTTPS username to send with a token. `x-access-token` is GitHub's name for App installation
    tokens; with a personal access token (github_pat_…, ghp_…) GitHub authenticated the first real
    push but then failed it with an internal error (2026-10-07), so a PAT goes with the repo's owner."""
    if token.startswith(("github_pat_", "ghp_")):
        try:
            parts = urlsplit(url)
        except ValueError:
            parts = None
        if parts and parts.hostname == "github.com":
            owner = parts.path.strip("/").split("/")[0]
            if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner or ""):
                return owner
    return "x-access-token"


def redact_url(url: str) -> str:
    """Drop any userinfo (tokens) from a URL before it goes in a receipt."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable>"
    if parts.username or parts.password:
        host = parts.hostname or ""
        if parts.port:
            host += f":{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    return url


glob_match = hc.glob_match  # `**` crosses directories; `*` and `?` stay within one segment


def any_match(patterns, path: str) -> bool:
    return any(glob_match(p, path) for p in patterns or [])


# --------------------------------------------------------------------------
# receipts: signed, hash-chained, append-only

@contextlib.contextmanager
def _file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+")
    try:
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except ImportError:  # pragma: no cover - Windows: best effort
            pass
        yield
    finally:
        fh.close()


def receipt_digest(receipt: dict) -> str:
    return hashlib.sha256(sc.canonical_json(receipt)).hexdigest()


def _read_receipts(path: Path) -> list:
    if not path.exists():
        return []
    out = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"_unparseable": True, "_line": n})
    return out


def _receipt_tip_path(path: Path) -> Path:
    return path.with_name(path.name + ".tip.json")


def _write_receipt_tip(path: Path, tip: dict) -> None:
    """Crash-safe derived index. The signed receipt stream remains authority."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(tip, fh, sort_keys=True, separators=(",", ":"))
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def _tail_receipt(path: Path) -> dict | None:
    """Read only the final non-empty JSONL record."""
    if not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as fh:
        pos, data = fh.seek(0, os.SEEK_END), b""
        while pos > 0:
            take = min(8192, pos)
            pos -= take
            fh.seek(pos)
            data = fh.read(take) + data
            lines = [line for line in data.splitlines() if line.strip()]
            if len(lines) >= 2 or (pos == 0 and lines):
                return json.loads(lines[-1])
    return None


def _rebuild_receipt_tip(path: Path) -> dict:
    receipts = _read_receipts(path)
    prev = None
    for i, receipt in enumerate(receipts, 1):
        if receipt.get("_unparseable") or receipt.get("seq") != i:
            raise ValueError("receipt stream is corrupt; refusing to append")
        if receipt.get("prev") != (receipt_digest(prev) if prev is not None else None):
            raise ValueError("receipt chain is broken; refusing to append")
        prev = receipt
    tip = {"v": 1, "seq": len(receipts), "head": receipt_digest(prev) if prev else None,
           "bytes": path.stat().st_size if path.exists() else 0}
    _write_receipt_tip(_receipt_tip_path(path), tip)
    return tip


def _receipt_tip(path: Path) -> dict:
    tip_path, size = _receipt_tip_path(path), path.stat().st_size if path.exists() else 0
    try:
        tip = json.loads(tip_path.read_text())
    except (OSError, ValueError):
        return _rebuild_receipt_tip(path)
    shaped = isinstance(tip, dict) and tip.get("v") == 1 and isinstance(tip.get("seq"), int) \
        and tip.get("seq") >= 0 and isinstance(tip.get("bytes"), int)
    if not shaped or tip.get("bytes") != size:
        return _rebuild_receipt_tip(path)  # absent/stale after a crash: derive it again
    try:
        last = _tail_receipt(path)
    except (OSError, ValueError, json.JSONDecodeError):
        raise ValueError("receipt stream tail is corrupt; refusing to append") from None
    valid = tip.get("seq") == 0 and tip.get("head") is None and last is None if size == 0 else \
        isinstance(last, dict) and last.get("seq") == tip.get("seq") and receipt_digest(last) == tip.get("head")
    if not valid:
        # Same byte count but different content is not a recoverable stale
        # index: it means the append-only stream or its tip was rewritten.
        raise ValueError("receipt stream does not match its trusted tip; refusing to append")
    return tip


def append_receipt(cfg: BrokerConfig, key: dict, receipt: dict) -> dict:
    """Assign seq/prev, sign, append (fsync), then atomically advance the derived tip."""
    lock = cfg.receipts_path.with_name(cfg.receipts_path.name + ".lock")
    with _file_lock(lock):
        tip = _receipt_tip(cfg.receipts_path)
        receipt["seq"] = tip["seq"] + 1
        receipt["prev"] = tip["head"]
        receipt["broker"], receipt["kid"] = key["agent"], key["kid"]
        receipt["sig"] = sc.b64u(sc.sign_bytes(key["_secret"], sc.receipt_signing_input(receipt)))
        cfg.receipts_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        with open(cfg.receipts_path, "a") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        _write_receipt_tip(_receipt_tip_path(cfg.receipts_path),
                           {"v": 1, "seq": receipt["seq"], "head": receipt_digest(receipt),
                            "bytes": tip["bytes"] + len(line.encode())})
    return receipt


def verify_receipts(path: Path, registry: dict | None, broker_id: str | None = None) -> dict:
    """Offline verification: every signature against the broker's registered
    key, seq continuity, and each `prev` equal to the digest of the receipt
    before it. Any edit, deletion or reordering breaks the chain.
    `broker_id` pins the signer: without it, any agent in the registry could
    sign a chain as itself and it would verify. Callers with a BrokerConfig
    pass `cfg.broker_id`. The standalone, stricter check is synthe_verify.py."""
    receipts = _read_receipts(Path(path))
    errors, prev, report = [], None, []
    for i, r in enumerate(receipts):
        ok = True
        if r.get("_unparseable"):
            errors.append({"index": i, "error": f"line {r['_line']} is not JSON"})
            report.append({**r, "verified": False})
            prev = None
            continue
        if r.get("seq") != i + 1:
            errors.append({"index": i, "seq": r.get("seq"), "error": f"expected seq {i + 1}"})
            ok = False
        want_prev = receipt_digest(prev) if prev is not None else None
        if r.get("prev") != want_prev:
            errors.append({"index": i, "seq": r.get("seq"), "error": "prev does not match the previous receipt"})
            ok = False
        if broker_id is not None and r.get("broker") != broker_id:
            errors.append({"index": i, "seq": r.get("seq"),
                           "error": f"signed as {r.get('broker')!r}, not by this broker ({broker_id})"})
            ok = False
        key = sc.find_key(registry, r.get("broker"), r.get("kid"))
        try:
            good = key is not None and sc.verify_bytes(key, sc.receipt_signing_input(r),
                                                      sc.unb64u(r.get("sig", "")))
        except Exception:
            good = False
        if not good:
            errors.append({"index": i, "seq": r.get("seq"),
                           "error": "signature does not verify against the broker's registered key"})
            ok = False
        report.append({**r, "verified": ok})
        prev = r
    return {"ok": not errors, "count": len(receipts),
            "head": receipt_digest(receipts[-1]) if receipts and not receipts[-1].get("_unparseable") else None,
            "errors": errors, "receipts": report}


def effect_fingerprint(action: str, effect_type: str, params: dict) -> str:
    """Bind replay to the complete proposed effect, not just its operation id.

    The transport (source path / bundle) is deliberately outside the binding:
    for a git push the commit hash already binds the bytes and history. Defaults
    that prepare() applies are made explicit so omission and an explicit default
    describe the same effect. Unknown params remain in the digest and therefore
    fail closed if their value changes or a later release gives them meaning.
    """
    if not isinstance(action, str) or not isinstance(effect_type, str) or not isinstance(params, dict):
        raise Deny("invalid", "proposal_malformed", "the effect fingerprint needs action, type and params")
    normalized = copy.deepcopy(params)
    if effect_type == "git_push":
        normalized.setdefault("base", "main")
        normalized.setdefault("expected_old", None)
        normalized.pop("fetch_from", None)  # proposal transport, not an external-effect input
        if "files" in normalized or "delete" in normalized:
            normalized.setdefault("files", {})
            normalized["delete"] = sorted(normalized.get("delete") or [])
            normalized.setdefault("base_blobs", {})
            normalized.setdefault("message", "content proposal via Synthe")
    body = {"action": action, "effect_type": effect_type, "params": normalized}
    try:
        encoded = sc.canonical_json(body)
    except (TypeError, ValueError) as exc:
        raise Deny("invalid", "proposal_malformed", f"effect params are not canonical JSON: {exc}") from None
    return "sha256:" + hashlib.sha256(EFFECT_FINGERPRINT_DOMAIN + encoded).hexdigest()


def _completed_replay(cfg: BrokerConfig, registry: dict, h: dict, token: str,
                      action: str, fingerprint: str) -> tuple[dict | None, dict | None]:
    """Return (original receipt, problem) for a completed proposal replay.

    A ledger pointer is not enough. The append-only receipt stream must verify,
    and the pointed receipt must bind the exact claim, epoch, action and complete
    effect fingerprint. Any missing legacy field or mismatch blocks replay; it
    never becomes permission to execute again.
    """
    entry = hc.load_ledger(cfg.ledger_path).get(h.get("idempotency_key"))
    if not isinstance(entry, dict) or hc.entry_state(entry) != "COMPLETED":
        return None, None
    problem = hc._claim_problem(entry, h, token, require_token=True)
    if problem:
        return None, problem
    prior = (entry.get("effects") or {}).get(action)
    if not isinstance(prior, dict) or prior.get("state") != "EXECUTED":
        return None, hc._reject(
            "duplicate", "replay_result_unavailable",
            f"idempotency_key '{h.get('idempotency_key')}' is completed but has no replayable result for '{action}'; "
            "do not re-execute it")
    prior_fp = prior.get("effect_fingerprint")
    if not isinstance(prior_fp, str):
        return None, hc._reject(
            "duplicate", "replay_result_unavailable",
            "the completed effect predates effect fingerprints; it cannot be proved equivalent and will not run again")
    if not hmac.compare_digest(prior_fp, fingerprint):
        return None, hc._reject(
            "conflicting", "effect_fingerprint_mismatch",
            "the idempotency key is completed, but the prepared effect differs from the recorded effect; "
            "changed semantics never re-execute under the same identity")
    seq = prior.get("receipt_seq")
    chain = verify_receipts(cfg.receipts_path, registry, cfg.broker_id)
    if not chain["ok"]:
        return None, hc._reject(
            "unknown", "replay_receipt_unverified",
            "the stored receipt chain does not verify; the result is not replayed and the effect remains blocked")
    if not isinstance(seq, int) or seq < 1 or seq > len(chain["receipts"]):
        return None, hc._reject(
            "unknown", "replay_receipt_mismatch",
            "the completed effect does not point to an exact stored receipt; the effect remains blocked")
    receipt = chain["receipts"][seq - 1]
    rh, reffect = receipt.get("handoff") or {}, receipt.get("effect") or {}
    exact = (
        receipt.get("verified") is True
        and receipt.get("seq") == seq
        and receipt.get("decision") == "executed"
        and rh.get("idempotency_key") == h.get("idempotency_key")
        and rh.get("id") == h.get("id")
        and rh.get("packet_sha256") == entry.get("packet_sha256")
        and (receipt.get("claim") or {}).get("epoch") == entry.get("epoch")
        and reffect.get("action") == action
        and reffect.get("fingerprint") == fingerprint
        and isinstance(receipt.get("observed"), dict)
    )
    if not exact:
        return None, hc._reject(
            "unknown", "replay_receipt_mismatch",
            "the stored receipt does not exactly match the completed claim and prepared effect; "
            "the result is not replayed and the effect remains blocked")
    # verify_receipts adds only a display flag. Remove it from the already
    # verified object instead of re-reading the file after verification (which
    # would create a time-of-check/time-of-use gap).
    return {k: v for k, v in receipt.items() if k != "verified"}, None


# --------------------------------------------------------------------------
# git

def _git(args, cwd=None, env=None, timeout=180, check=True, input=None):
    full_env = dict(os.environ)
    full_env["GIT_TERMINAL_PROMPT"] = "0"
    full_env.update(env or {})
    # UTF-8 whatever the locale (a service's C locale must not crash on a path).
    proc = subprocess.run(["git", *args], cwd=cwd, env=full_env, capture_output=True, text=True,
                          encoding="utf-8", errors="surrogateescape", timeout=timeout, input=input)
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, ["git", *args], proc.stdout, proc.stderr)
    return proc


def _git_bytes(args, data: bytes | None = None, env=None, timeout=180) -> bytes:
    """git with raw bytes in and out (blob contents are not text until checked)."""
    full_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})}
    proc = subprocess.run(["git", *args], env=full_env, input=data, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, ["git", *args], proc.stdout, proc.stderr)
    return proc.stdout


class GitPush:
    """git_push effect. The broker keeps a private bare mirror (no hooks, its
    own config); the agent's repo is only ever *read* (fetch by SHA), never
    run git commands with the broker's credentials in it."""

    def __init__(self, cfg: BrokerConfig):
        self.cfg = cfg
        self.conf = cfg.effects.get("git_push") or {}
        self.mirror = cfg.state_dir / "mirror.git"
        self.laps = _Laps(None)

    # -- helpers -------------------------------------------------------------
    def _mirror(self) -> Path:
        if not (self.mirror / "HEAD").exists():
            self.mirror.parent.mkdir(parents=True, exist_ok=True)
            _git(["init", "-q", "--bare", str(self.mirror)])
            _git(["-C", str(self.mirror), "config", "core.hooksPath", "/dev/null"])
            _git(["-C", str(self.mirror), "config", "gc.auto", "0"])
        return self.mirror

    def _remote_env(self, remote: dict) -> tuple[list, dict]:
        """Credentials stay in the broker: the broker user's own git
        credential setup, a token file only the broker user can read
        (`token_file`, chmod 600), or an env var only the broker has."""
        token_env, token_file = remote.get("token_env"), remote.get("token_file")
        if not token_env and not token_file:
            return [], {}
        if token_file:
            try:
                token = self.cfg.rel(token_file).read_text().strip()
            except OSError:
                token = None
            where = f"token file {token_file}"
        else:
            token, where = os.environ.get(token_env), f"${token_env}"
        if not token:
            raise Deny("retryable", "broker_credentials_missing",
                       f"broker has no credentials: {where} is missing or empty", "errored")
        askpass = self.cfg.state_dir / "askpass.sh"
        if not askpass.exists():
            askpass.parent.mkdir(parents=True, exist_ok=True)
            askpass.write_text('#!/bin/sh\ncase "$1" in Username*) echo "${SYNTHE_GIT_USER:-x-access-token}";; '
                               '*) echo "$SYNTHE_GIT_TOKEN";; esac\n')
            os.chmod(askpass, 0o700)
        return (["-c", "credential.helper="],
                {"GIT_ASKPASS": str(askpass), "SYNTHE_GIT_TOKEN": token,
                 "SYNTHE_GIT_USER": remote.get("username") or git_username(remote.get("url", ""), token)})

    def _ls_remote(self, url, branch, pre, env):
        try:
            out = _git([*pre, "ls-remote", url, f"refs/heads/{branch}"], env=env, timeout=60).stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise Deny("retryable", "remote_unreachable",
                       f"cannot read remote: {getattr(exc, 'stderr', '') or exc}".strip(), "errored")
        for line in out.splitlines():
            sha, _, ref = line.partition("\t")
            if ref == f"refs/heads/{branch}":
                return sha
        return None

    def _fetch_remote_ref(self, url, branch, local, pre, env):
        try:
            _git([*pre, "-C", str(self.mirror), "fetch", "-q", "--no-tags", url,
                  f"+refs/heads/{branch}:{local}"], env=env)
        except subprocess.CalledProcessError as exc:
            raise Deny("retryable", "remote_unreachable", f"cannot fetch {branch}: {exc.stderr.strip()}",
                       "errored")

    def _is_ancestor(self, a, b) -> bool:
        return _git(["-C", str(self.mirror), "merge-base", "--is-ancestor", a, b], check=False).returncode == 0

    @staticmethod
    def _branch_ok(branch) -> bool:
        return isinstance(branch, str) and _git(["check-ref-format", f"refs/heads/{branch}"],
                                                check=False).returncode == 0

    def remote_tips(self, name, branch, base) -> dict:
        """Where `branch` and `base` stand on the remote (read-only), so an
        agent can leave history the broker can fetch itself out of its bundle."""
        remotes = self.conf.get("remotes") or {}
        if name not in remotes:
            raise Deny("blocked", "remote_unknown", f"broker has no remote named '{name}'")
        if not self._branch_ok(branch) or not self._branch_ok(base):
            raise Deny("invalid", "bad_branch", f"not valid branch names: {branch!r}, {base!r}")
        remote = remotes[name]
        pre, env = self._remote_env(remote)
        return {"branch": self._ls_remote(remote["url"], branch, pre, env),
                "base": self._ls_remote(remote["url"], base, pre, env)}

    def _fetch_proposal(self, name: str, remote: dict, ref, commit: str) -> str:
        """Fetch the proposed commit from an agent's sandbox branch: a branch of
        the remote's `fetch_from` source that matches its allowlist (`refs`).
        Read-only, objects fsck'd; the commit must be on that branch. This is how
        agents that only have their own git access (no local socket) propose."""
        src = remote.get("fetch_from")
        if not isinstance(src, dict) or not src.get("url"):
            raise Deny("blocked", "source_not_allowed",
                       f"remote '{name}' takes no fetch_from proposals (no fetch_from source configured)")
        if not isinstance(ref, str) or not self._branch_ok(ref) or not any_match(src.get("refs") or [], ref):
            raise Deny("blocked", "source_not_allowed",
                       f"fetch_from {ref!r} is not an allowed source branch (allowed: {src.get('refs') or []})")
        pre, env = self._remote_env(src)
        tag = re.sub(r"[^A-Za-z0-9._/-]", "_", name)
        local = f"refs/synthe/sources/{tag}/{ref}"
        fetch = _git([*pre, "-c", "transfer.fsckObjects=true", "-C", str(self.mirror), "fetch", "-q", "--no-tags",
                      src["url"], f"+refs/heads/{ref}:{local}"], env=env, check=False)
        if fetch.returncode != 0:
            raise Deny("incomplete", "commit_unavailable",
                       f"cannot fetch {ref} from the source: {fetch.stderr.strip()[-300:]}")
        if not self._is_ancestor(commit, local):
            raise Deny("incomplete", "commit_unavailable", f"commit {commit} is not on source branch {ref}")
        return f"fetch_from {ref}"

    def _load_bundle(self, data, commit: str, name: str, remote: dict, branch: str, base: str) -> str:
        """Unpack an agent's git bundle into the private mirror. The broker
        never reads the agent's disk or runs git in its repo; the bundle is
        untrusted input with a size cap, and only the content-addressed
        commit it is asked to push matters."""
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise Deny("invalid", "proposal_malformed", "the bundle is empty")
        if len(data) > self.cfg.max_bundle_bytes:
            raise Deny("invalid", "bundle_too_large",
                       f"the bundle is {len(data)} bytes; this broker accepts up to {self.cfg.max_bundle_bytes}")
        digest = hashlib.sha256(data).hexdigest()
        inbox = self.cfg.state_dir / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=inbox, suffix=".bundle")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        # A namespace of its own per request: the daemon serves proposals in
        # parallel threads of one process.
        mirror, ns = str(self.mirror), f"refs/synthe/incoming/{digest[:16]}-{secrets.token_hex(4)}"
        try:
            check = _git(["-C", mirror, "bundle", "verify", "-q", tmp], check=False)
            if check.returncode != 0:
                # The agent left out history the remote already has: fetch the
                # target branch and its base (read-only), then verify again.
                pre, env = self._remote_env(remote)
                tag = re.sub(r"[^A-Za-z0-9._/-]", "_", name)
                for ref in dict.fromkeys((branch, base)):
                    _git([*pre, "-C", mirror, "fetch", "-q", "--no-tags", remote["url"],
                          f"+refs/heads/{ref}:refs/synthe/remotes/{tag}/{ref}"], env=env, check=False)
                check = _git(["-C", mirror, "bundle", "verify", "-q", tmp], check=False)
                if check.returncode != 0:
                    raise Deny("incomplete", "commit_unavailable",
                               f"the bundle cannot be unpacked here: {check.stderr.strip()[-300:]}")
            # Untrusted objects: fsck them on the way in (malformed trees, e.g.
            # a ".git" entry, must never reach the path checks or the remote).
            fetch = _git(["-c", "transfer.fsckObjects=true", "-C", mirror, "fetch", "-q", "--no-tags", tmp,
                          f"+refs/*:{ns}/*"], check=False)
            if fetch.returncode != 0 or _git(["-C", mirror, "cat-file", "-t", commit],
                                             check=False).stdout.strip() != "commit":
                raise Deny("incomplete", "commit_unavailable", f"the bundle does not contain commit {commit}")
        finally:
            os.unlink(tmp)
            for ref in _git(["-C", mirror, "for-each-ref", "--format=%(refname)", ns],
                            check=False).stdout.split():
                _git(["-C", mirror, "update-ref", "-d", ref], check=False)
        return f"bundle sha256:{digest}"

    # -- content proposals (v0.5): chat agents send files, not commits ---------
    # The agent has no git. It sends the full text of each file it changes and
    # cites the blob each edit was based on (PlanFence: cite the exact records
    # the plan used; re-check exactly those at commit). The broker builds the
    # commit in its own mirror; then every usual check applies to that commit.
    READ_MAX_BYTES = 200 * 1024
    LIST_MAX = 2000

    @staticmethod
    def content_path_problem(p) -> str | None:
        """Why `p` can't be a path in a content proposal, or None. Strict on
        purpose: git's own plumbing accepts '.git/config', '..' and '/abs'."""
        if not isinstance(p, str) or not p:
            return "must be a non-empty string"
        if unicodedata.normalize("NFC", p) != p:
            return "is not NFC-normalized"
        if len(p.encode("utf-8", "surrogatepass")) > 1024:
            return "is longer than 1024 bytes"
        if "\\" in p or any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn") for ch in p):
            return "contains a backslash, a control or format character, or an unassigned code point"
        if p.startswith("/") or p.endswith("/"):
            return "must be relative, without a leading or trailing slash"
        for part in p.split("/"):
            if part in ("", ".", ".."):
                return "has an empty, '.' or '..' component"
            if len(part.encode("utf-8")) > 255:
                return "has a component longer than 255 bytes"
            if part != part.rstrip(". "):
                return "has a component ending in a dot or a space"
            if part.lower() == ".git" or re.fullmatch(r"git~\d+", part.lower()):
                return "names a .git directory"
        return None

    def _entries(self, commit: str, paths) -> dict:
        """{path: (mode, type, sha)} for each of `paths` (and nothing else)
        present in `commit`'s tree."""
        paths = sorted(set(paths))
        if not paths:
            return {}
        out = _git(["-C", str(self.mirror), "ls-tree", "-z", "--full-tree", commit, "--", *paths]).stdout
        found = {}
        for rec in out.split("\0"):
            if not rec:
                continue
            meta, _, name = rec.partition("\t")
            mode, typ, sha = meta.split()
            if name in paths:
                found[name] = (mode, typ, sha)
        return found

    def _content_base_problem(self, commit: str, files: dict, delete: list, cited: dict):
        """Deny if any cited blob is not what `commit` holds now (or the path
        can't take the change); returns {path: mode} for files kept as-is."""
        touched = list(files) + list(delete)
        prefixes = {"/".join(p.split("/")[:i]) for p in touched for i in range(1, p.count("/") + 1)}
        here = self._entries(commit, list(touched) + list(prefixes))
        for pre in sorted(prefixes):
            if pre in here and here[pre][1] != "tree":
                raise Deny("invalid", "path_invalid", f"'{pre}' is a file in the target, so nothing can live under it")
        modes = {}
        for p in touched:
            cur = here.get(p)
            if cur is not None and (cur[1] != "blob" or cur[0] not in ("100644", "100755")):
                raise Deny("invalid", "content_malformed",
                           f"'{p}' is not a regular file in the target ({cur[1]} {cur[0]}); content proposals "
                           f"change regular files only")
            want = cited[p]
            have = cur[2] if cur is not None else None
            if p in delete and cur is None:
                raise Deny("stale", "content_conflict", f"'{p}' is not in the target any more; nothing to delete")
            if want != have:
                raise Deny("stale", "content_conflict",
                           f"'{p}' is {'at blob ' + have[:12] if have else 'absent'} in the target, but your edit "
                           f"cites {'blob ' + want[:12] if want else 'a new file'}: re-read it and re-apply your change")
            if cur is not None:
                modes[p] = cur[0]
        return modes

    def _build_content_commit(self, parent: str, c: dict) -> str:
        """Parent's tree + files - delete, as one commit authored by the agent."""
        mirror = str(self.mirror)
        modes = self._content_base_problem(parent, c["files"], c["delete"], c["base_blobs"])
        fd, idx = tempfile.mkstemp(dir=self.cfg.state_dir, prefix=".content-", suffix=".idx")
        os.close(fd)
        os.unlink(idx)  # git creates the index itself
        env = {"GIT_INDEX_FILE": idx}
        try:
            _git(["-C", mirror, "read-tree", parent], env=env)
            records = []
            for p, text in c["files"].items():
                blob = _git_bytes(["-C", mirror, "hash-object", "-w", "--stdin"],
                                  text.encode("utf-8")).decode().strip()
                records.append(f"{modes.get(p, '100644')} {blob}\t{p}")
            for p in c["delete"]:
                records.append(f"0 {'0' * 40}\t{p}")
            _git(["-C", mirror, "update-index", "-z", "--index-info"], env=env,
                 input="".join(r + "\0" for r in records))
            tree = _git(["-C", mirror, "write-tree"], env=env).stdout.strip()
        finally:
            with contextlib.suppress(OSError):
                os.unlink(idx)
        if tree == _git(["-C", mirror, "rev-parse", f"{parent}^{{tree}}"]).stdout.strip():
            raise Deny("invalid", "no_change", "the proposed files are identical to what the branch already holds")
        when = f"{c['built_at']} +0000"
        meta = c["meta"]
        agent = re.sub(r"[^A-Za-z0-9._-]", "_", str(meta.get("agent") or "agent"))[:64]
        clean = lambda v: re.sub(r"[\x00-\x1f\x7f]", " ", str(v or ""))[:200]  # noqa: E731
        message = (f"{c['message']}\n\nSynthe-Handoff: {clean(meta.get('handoff_id'))}\n"
                   f"Synthe-Key: {clean(meta.get('key'))}\nSynthe-Agent: {agent}\n")
        commit_env = {"GIT_AUTHOR_NAME": f"{agent} via Synthe", "GIT_AUTHOR_EMAIL": f"{agent}@synthe.invalid",
                      "GIT_COMMITTER_NAME": f"Synthe broker ({clean(self.cfg.broker_id)})",
                      "GIT_COMMITTER_EMAIL": "broker@synthe.invalid",
                      "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
        commit = _git(["-C", mirror, "commit-tree", tree, "-p", parent, "-F", "-"], env=commit_env,
                      input=message).stdout.strip()
        _git(["-C", mirror, "update-ref", f"refs/synthe/proposals/{commit}", commit])
        return commit

    def _content(self, params: dict, meta: dict | None) -> dict:
        """Validate a content proposal; return its normalized form (no git yet)."""
        files, delete = params.get("files", {}), params.get("delete", [])
        if files is None:
            files = {}
        if delete is None:
            delete = []
        if not isinstance(files, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                                  for k, v in files.items()):
            raise Deny("invalid", "content_malformed", "params.files must be an object of path -> full UTF-8 text")
        if not isinstance(delete, list) or not all(isinstance(x, str) for x in delete):
            raise Deny("invalid", "content_malformed", "params.delete must be a list of paths")
        if not files and not delete:
            raise Deny("invalid", "content_malformed", "a content proposal needs files or delete")
        max_files = int(self.conf.get("max_content_files", 100))
        max_bytes = int(float(self.conf.get("max_content_mb", 2)) * 1024 * 1024)
        size = sum(len(t.encode("utf-8", "surrogatepass")) for t in files.values())
        if len(files) + len(delete) > max_files or size > max_bytes:
            raise Deny("invalid", "content_too_large",
                       f"{len(files) + len(delete)} paths and {size} bytes; this broker takes up to {max_files} "
                       f"paths and {max_bytes} bytes per proposal")
        if len(set(delete)) != len(delete) or set(files) & set(delete):
            raise Deny("invalid", "content_malformed", "a path appears twice (in files and delete, or twice in delete)")
        folded = {}
        for p in list(files) + list(delete):
            why = self.content_path_problem(p)
            if why:
                raise Deny("invalid", "path_invalid", f"content path {p!r} {why}")
            if p.casefold() in folded and folded[p.casefold()] != p:
                raise Deny("invalid", "path_invalid", f"{p!r} and {folded[p.casefold()]!r} differ only in case")
            folded[p.casefold()] = p
        for p, text in files.items():
            if "\x00" in text:
                raise Deny("invalid", "content_malformed", f"'{p}' contains a NUL byte; content proposals carry text only")
            try:
                text.encode("utf-8")
            except UnicodeEncodeError:
                raise Deny("invalid", "content_malformed", f"'{p}' is not valid UTF-8 text")
        cited = params.get("base_blobs") or {}
        if not isinstance(cited, dict):
            raise Deny("invalid", "content_malformed", "params.base_blobs must be an object of path -> blob id or null")
        missing = [p for p in list(files) + list(delete) if p not in cited]
        if missing:
            raise Deny("blocked", "content_base_missing",
                       f"cite the blob each change is based on (synthe_read_file returns it; null for a new file): "
                       f"missing for {missing[:10]}")
        for p in list(files) + list(delete):
            v = cited[p]
            if not (v is None or (isinstance(v, str) and SHA_RE.match(v))):
                raise Deny("invalid", "content_malformed", f"base_blobs[{p!r}] must be a 40-hex blob id or null")
        first = str(params.get("message") or "").splitlines()[0] if params.get("message") else ""
        message = re.sub(r"[\x00-\x1f\x7f]", " ", first).strip()[:200] or "content proposal via Synthe"
        canon = json.dumps({"files": files, "delete": sorted(delete)}, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"))
        digest = hashlib.sha256(canon.encode("utf-8", "surrogatepass")).hexdigest()
        return {"files": dict(files), "delete": list(delete), "base_blobs": {p: cited[p] for p in list(files) + delete},
                "message": message, "meta": dict(meta or {}), "built_at": int(time.time()),
                "summary": {"files": len(files), "deletes": len(delete), "bytes": size,
                            "digest": f"sha256:{digest}", "paths": sorted(list(files) + list(delete))}}

    def _fetch_tip(self, name: str, remote: dict, ref: str, pre, env) -> str | None:
        tip = self._ls_remote(remote["url"], ref, pre, env)
        if tip is not None:
            tag = re.sub(r"[^A-Za-z0-9._/-]", "_", name)
            self._fetch_remote_ref(remote["url"], ref, f"refs/synthe/remotes/{tag}/{ref}", pre, env)
        return tip

    # -- reading the repo (v0.5): agents without git read through the broker ---
    def _read_target(self, name, ref) -> tuple:
        remotes = self.conf.get("remotes") or {}
        readable = sorted(n for n, r in remotes.items() if isinstance(r, dict) and r.get("readable"))
        if name is None and len(readable) == 1:
            name = readable[0]
        remote = remotes.get(name) if isinstance(name, str) else None
        if not isinstance(remote, dict) or not remote.get("readable"):
            raise Deny("blocked", "read_not_allowed",
                       f"remote {name!r} is not readable through this broker (readable: {readable})")
        allowed = remote.get("readable_refs") or remote.get("branches") or []
        if ref is None:
            plain = [b for b in allowed if not any(ch in b for ch in "*?[")]
            if not plain:
                raise Deny("invalid", "read_not_allowed", "name the branch to read (ref)")
            ref = plain[0]
        if not self._branch_ok(ref) or not any_match(allowed, ref):
            raise Deny("blocked", "read_not_allowed", f"branch {ref!r} is not readable (allowed: {allowed})")
        self._mirror()
        pre, env = self._remote_env(remote)
        tip = self._fetch_tip(name, remote, ref, pre, env)
        if tip is None:
            raise Deny("invalid", "file_not_found", f"branch {ref!r} does not exist on {name!r}")
        return name, ref, tip

    EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

    def describe(self, commit: str, base: str | None = None, max_patch: int = 200_000) -> dict:
        """What pushing `commit` changes, read from the broker's own mirror (where the agent's
        bundle was unpacked and checked): the commits, the files, and the patch against `base`
        (the branch tip it is pinned to). With no base (a new branch), the base is the parent of
        the oldest commit no ref in the mirror reaches. Commit subjects, file names and the patch
        are the agent's bytes: callers that print them must neutralize terminal control codes."""
        mirror = str(self._mirror())
        if _git(["-C", mirror, "cat-file", "-t", commit], check=False).stdout.strip() != "commit":
            return {"available": False, "note": "the broker's mirror no longer holds this commit"}
        if base is None:
            new = _git(["-C", mirror, "rev-list", "--reverse", commit, "--not", "--all"],
                       check=False).stdout.split()
            first = new[0] if new else commit
            parent = _git(["-C", mirror, "rev-parse", "--verify", "-q", f"{first}^"], check=False).stdout.strip()
            base = parent or self.EMPTY_TREE
        span = [f"{base}..{commit}"] if base != self.EMPTY_TREE else [commit]
        log = _git(["-C", mirror, "log", "--max-count=50", "--format=%H%x1f%an%x1f%s", *span],
                   check=False).stdout
        commits = [dict(zip(("sha", "author", "subject"), line.split("\x1f", 2)))
                   for line in log.splitlines() if line.count("\x1f") == 2]
        diff = ["-C", mirror, "diff", "--no-color", "--no-ext-diff", "--no-textconv", base, commit]
        fields = _git(diff[:3] + ["-z", "--name-status", "--no-renames", base, commit], check=False).stdout.split("\0")
        files = [{"status": s, "path": p} for s, p in zip(fields[0::2], fields[1::2]) if s and p]
        stat = _git(diff[:3] + ["--shortstat", base, commit], check=False).stdout.strip()
        patch = _git(diff, check=False).stdout
        truncated = len(patch.encode("utf-8", "surrogateescape")) > max_patch
        if truncated:
            patch = patch.encode("utf-8", "surrogateescape")[:max_patch].decode("utf-8", "replace")
        return {"available": True, "base": base, "commit": commit, "commits": commits, "files": files,
                "stat": stat, "patch": patch, "patch_truncated": truncated}

    def bundle_ref(self, name, ref, have: str | None = None) -> dict:
        """A git bundle of one readable branch, so an agent whose account holds no GitHub credential
        (not even read-only) can clone and update a private repo through the broker. `have`: a commit
        the agent already has, for a smaller update. Same allowlist as read_file; read-only."""
        name, ref, tip = self._read_target(name, ref)
        tag = re.sub(r"[^A-Za-z0-9._/-]", "_", name)
        local = f"refs/synthe/remotes/{tag}/{ref}"
        mirror = str(self.mirror)
        span = [local]
        if isinstance(have, str) and re.fullmatch(r"[0-9a-f]{40}", have):
            if have == tip:
                return {"remote": name, "ref": ref, "tip": tip, "bundle": None, "up_to_date": True}
            if _git(["-C", mirror, "merge-base", "--is-ancestor", have, tip], check=False).returncode == 0:
                span = [local, f"^{have}"]
        fd, tmp = tempfile.mkstemp(dir=str(self.cfg.state_dir), suffix=".bundle")
        os.close(fd)
        try:
            made = _git(["-C", mirror, "bundle", "create", "-q", tmp, *span], check=False)
            if made.returncode != 0:
                raise Deny("invalid", "bundle_failed", f"could not bundle {ref}: {made.stderr.strip()[-200:]}")
            data = Path(tmp).read_bytes()
        finally:
            Path(tmp).unlink(missing_ok=True)
        if len(data) > self.cfg.max_bundle_bytes:
            raise Deny("blocked", "bundle_too_large",
                       f"{ref} is {len(data)} bytes as a bundle; this broker serves up to {self.cfg.max_bundle_bytes}")
        return {"remote": name, "ref": ref, "tip": tip, "bundle_ref": local,
                "bundle": base64.b64encode(data).decode(), "bytes": len(data), "up_to_date": False}

    def read_file(self, name, ref, path) -> dict:
        """One file's text and blob id at the live tip of a readable branch."""
        why = self.content_path_problem(path)
        if why:
            raise Deny("invalid", "path_invalid", f"path {path!r} {why}")
        name, ref, tip = self._read_target(name, ref)
        entry = self._entries(tip, [path]).get(path)
        if entry is None:
            raise Deny("invalid", "file_not_found", f"'{path}' is not on {ref}")
        mode, typ, blob = entry
        if typ != "blob" or mode not in ("100644", "100755"):
            raise Deny("invalid", "file_not_text", f"'{path}' is a {typ} ({mode}), not a regular file")
        size = int(_git(["-C", str(self.mirror), "cat-file", "-s", blob]).stdout.strip())
        if size > self.READ_MAX_BYTES:
            raise Deny("invalid", "file_too_large", f"'{path}' is {size} bytes; reads stop at {self.READ_MAX_BYTES}")
        data = _git_bytes(["-C", str(self.mirror), "cat-file", "blob", blob])
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise Deny("invalid", "file_not_text", f"'{path}' is not UTF-8 text")
        if "\x00" in text:
            raise Deny("invalid", "file_not_text", f"'{path}' is binary")
        return {"remote": name, "ref": ref, "commit": tip, "path": path, "blob": blob, "size": size, "text": text}

    def list_files(self, name, ref, prefix="") -> dict:
        """Regular files (path, blob, size) at the live tip, under `prefix`."""
        prefix = (prefix or "").strip("/")
        if prefix:
            why = self.content_path_problem(prefix)
            if why:
                raise Deny("invalid", "path_invalid", f"prefix {prefix!r} {why}")
        name, ref, tip = self._read_target(name, ref)
        args = ["-C", str(self.mirror), "ls-tree", "-r", "-l", "-z", "--full-tree", tip]
        out = _git(args + (["--", prefix] if prefix else [])).stdout
        files = []
        for rec in out.split("\0"):
            if not rec:
                continue
            meta, _, path = rec.partition("\t")
            mode, typ, blob, size = meta.split()
            if typ == "blob" and mode in ("100644", "100755"):
                files.append({"path": path, "blob": blob, "size": int(size)})
        return {"remote": name, "ref": ref, "commit": tip, "files": files[:self.LIST_MAX],
                "truncated": len(files) > self.LIST_MAX}

    # -- phases --------------------------------------------------------------
    def prepare(self, params: dict, source=None, bundle=None, allow_path_source=True, preloaded=False,
                meta: dict | None = None) -> dict:
        """Outside the fence: static checks + copy the proposed commit into
        the mirror, from a git bundle (the isolated path) or, in dev setups
        that allow it, by reading the agent's repo. Nothing here changes the
        remote or the claim."""
        remotes = self.conf.get("remotes") or {}
        name, branch = params.get("remote"), params.get("branch")
        if name not in remotes:
            raise Deny("blocked", "remote_unknown", f"broker has no remote named '{name}'")
        remote = remotes[name]
        if not self._branch_ok(branch):
            raise Deny("invalid", "bad_branch", f"not a valid branch name: {branch!r}")
        if not any_match(remote.get("branches") or [], branch):
            raise Deny("blocked", "branch_not_allowed",
                       f"broker config does not allow pushes to '{branch}' on '{name}' "
                       f"(allowed: {remote.get('branches') or []})")
        if "files" in params or "delete" in params:
            return self._prepare_content(name, remote, branch, params, bundle, source, meta)
        commit = params.get("commit")
        if not isinstance(commit, str) or not SHA_RE.match(commit):
            raise Deny("invalid", "proposal_malformed", "params.commit must be a full 40-hex commit SHA")
        exp = params.get("expected_old")
        if exp not in (None, "new") and not (isinstance(exp, str) and SHA_RE.match(exp)):
            raise Deny("invalid", "proposal_malformed", "params.expected_old must be a 40-hex SHA or 'new'")
        base = params.get("base") or "main"
        if not self._branch_ok(base):
            raise Deny("invalid", "bad_branch", f"not a valid base branch name: {base!r}")
        mirror = self._mirror()
        fetch_from = params.get("fetch_from")
        if sum(x is not None for x in (bundle, fetch_from)) + bool(source) > 1:
            raise Deny("invalid", "proposal_malformed",
                       "send the commits one way: a bundle, fetch_from (a sandbox branch), or a source path")
        if preloaded:  # a staged proposal: its commit was copied into the mirror when it was staged
            if _git(["-C", str(mirror), "cat-file", "-t", commit], check=False).stdout.strip() != "commit":
                raise Deny("incomplete", "commit_unavailable", f"staged commit {commit} is no longer in the mirror")
            label = "staged"
        elif fetch_from is not None:
            label = self._fetch_proposal(name, remote, fetch_from, commit)
        elif bundle is not None:
            label = self._load_bundle(bundle, commit, name, remote, branch, base)
        else:
            if not allow_path_source:
                raise Deny("blocked", "source_path_not_allowed",
                           "this broker takes commits only as a git bundle (synthe_client.py push makes one); "
                           "it never reads an agent's disk")
            if not isinstance(source, str) or not source:
                raise Deny("invalid", "proposal_malformed",
                           "the proposal needs the commits: a git bundle, or a source repo path in dev setups")
            src = Path(source).expanduser().resolve()
            if not any(src == r or r in src.parents for r in self.cfg.source_roots):
                raise Deny("blocked", "source_not_allowed",
                           f"source repo {src} is outside the broker's source_roots")
            if not src.is_dir():
                raise Deny("invalid", "source_not_allowed", f"source repo {src} does not exist")
            fetch = _git(["-C", str(mirror), "fetch", "-q", "--no-tags", str(src), commit], check=False)
            if fetch.returncode != 0 or _git(["-C", str(mirror), "cat-file", "-t", commit],
                                             check=False).stdout.strip() != "commit":
                raise Deny("incomplete", "commit_unavailable",
                           f"commit {commit} could not be read from {src}: {fetch.stderr.strip()[:200]}")
            label = "local path"
        _git(["-C", str(mirror), "update-ref", f"refs/synthe/proposals/{commit}", commit])
        return {"remote_name": name, "remote": remote, "branch": branch, "commit": commit,
                "expected_old": exp, "base": base, "source": label}

    def _prepare_content(self, name, remote, branch, params, bundle, source, meta) -> dict:
        if bundle is not None or source or params.get("fetch_from") is not None or params.get("commit") is not None:
            raise Deny("invalid", "proposal_malformed",
                       "a content proposal (files/delete) carries no commit, bundle, fetch_from or source path")
        exp = params.get("expected_old")
        if exp not in (None, "new") and not (isinstance(exp, str) and SHA_RE.match(exp)):
            raise Deny("invalid", "proposal_malformed", "params.expected_old must be a 40-hex SHA or 'new'")
        base = params.get("base") or "main"
        if not self._branch_ok(base):
            raise Deny("invalid", "bad_branch", f"not a valid base branch name: {base!r}")
        c = self._content(params, meta)
        self._mirror()
        pre, env = self._remote_env(remote)
        parent = self._fetch_tip(name, remote, branch, pre, env) or self._fetch_tip(name, remote, base, pre, env)
        if parent is None:
            raise Deny("invalid", "base_missing", f"neither '{branch}' nor its base '{base}' exists on the remote")
        commit = self._build_content_commit(parent, c)
        return {"remote_name": name, "remote": remote, "branch": branch, "commit": commit, "expected_old": exp,
                "base": base, "source": f"content {c['summary']['digest']}", "content": c, "parent": parent}

    def _rebase_content(self, prep: dict, before, pre, env) -> None:
        """Inside the fence: if the branch moved since the content commit was
        built, rebuild it on the live tip, but only if every blob the agent
        cited is still current there (else content_conflict, nothing pushed).
        An explicit expected_old means strict compare-and-swap instead."""
        c = prep.get("content")
        if not c or prep["expected_old"] is not None:
            return
        target = before
        if target is None:
            target = self._fetch_tip(prep["remote_name"], prep["remote"], prep["base"], pre, env)
            if target is None:
                raise Deny("invalid", "base_missing", f"new branch base '{prep['base']}' does not exist on the remote "
                                                            f"(base names a branch there, e.g. main, not a commit)")
        else:
            tag = re.sub(r"[^A-Za-z0-9._/-]", "_", prep["remote_name"])
            self._fetch_remote_ref(prep["remote"]["url"], prep["branch"],
                                   f"refs/synthe/remotes/{tag}/{prep['branch']}", pre, env)
        if target == prep["parent"]:
            return
        prep["commit"] = self._build_content_commit(target, c)
        prep["parent"] = prep["rebased_onto"] = target

    def commit(self, prep: dict, scope: dict, dry_run: bool = False) -> dict:
        """Inside the fence: live precondition, effect inspection, push with
        compare-and-swap, then observe. Raises Deny when nothing happened.
        dry_run: every check, then stop before the push (staging a proposal);
        returns {"before", "observed"}."""
        remote, branch = prep["remote"], prep["branch"]
        url = remote["url"]
        pre, env = self._remote_env(remote)
        before = self._ls_remote(url, branch, pre, env)
        self._rebase_content(prep, before, pre, env)
        commit = prep["commit"]
        exp = prep["expected_old"]
        if exp == "new" and before is not None:
            raise Deny("stale", "remote_moved", f"'{branch}' was expected not to exist; it is at {before}")
        if exp not in (None, "new") and before != exp:
            raise Deny("stale", "remote_moved",
                       f"'{branch}' is at {before or '(missing)'}, not the expected {exp}; rebase and re-propose")
        if before == commit:
            raise Deny("invalid", "no_change", f"'{branch}' is already at {commit}")
        tag = re.sub(r"[^A-Za-z0-9._/-]", "_", prep["remote_name"])
        if before is not None:
            self._fetch_remote_ref(url, branch, f"refs/synthe/remotes/{tag}/{branch}", pre, env)
            if not self._is_ancestor(before, commit):
                raise Deny("blocked", "non_fast_forward",
                           f"{commit[:12]} does not descend from {branch}@{before[:12]}; "
                           f"rewriting history is never mediated")
            base_sha = before
        else:
            base_branch = prep["base"]
            base_sha = self._ls_remote(url, base_branch, pre, env)
            if base_sha is None:
                raise Deny("invalid", "base_missing", f"new branch base '{base_branch}' does not exist on the remote "
                                                         f"(base names a branch there, e.g. main, not a commit)")
            self._fetch_remote_ref(url, base_branch, f"refs/synthe/remotes/{tag}/{base_branch}", pre, env)
            if not self._is_ancestor(base_sha, commit):
                raise Deny("blocked", "unrelated_history",
                           f"{commit[:12]} does not descend from {base_branch}@{base_sha[:12]}")
        self.laps.lap("live_check")
        rng = f"{base_sha}..{commit}"
        commits = _git(["-C", str(self.mirror), "rev-list", rng]).stdout.split()
        limit = int(self.conf.get("max_commits", 200))
        if len(commits) > limit:
            raise Deny("blocked", "too_many_commits", f"{len(commits)} commits exceed the broker limit {limit}")
        # Every path any pushed commit touches (not just the net diff): the
        # remote receives every intermediate commit, secrets included.
        log = _git(["-C", str(self.mirror), "log", "--format=", "--name-only", "--no-renames", "-m", rng]).stdout
        net = _git(["-C", str(self.mirror), "diff", "--name-only", "--no-renames", base_sha, commit]).stdout
        paths = sorted({p for p in (log + "\n" + net).splitlines() if p.strip()})
        # A tree entry named .git is a malformed tree whatever git's fsck says
        # (2.43 accepts it): refuse it here, before the scope checks, so the
        # outcome never depends on one git version's fsck behaviour.
        dotgit = [p for p in paths if any(seg.lower() == ".git" for seg in p.split("/"))]
        if dotgit:
            raise Deny("incomplete", "commit_unavailable",
                       f"malformed tree: {len(dotgit)} entr{'y' if len(dotgit) == 1 else 'ies'} named .git "
                       f"({', '.join(dotgit[:3])}); such objects are never accepted")
        bad = []
        for p in paths:
            if not any_match(scope["owned_paths"], p):
                bad.append(("path_outside_scope", p))
            elif any(not any_match(layer, p) for layer in scope["allowed_layers"]):
                bad.append(("path_outside_receiver_policy", p))
            elif any_match(scope["forbidden_paths"], p):
                bad.append(("path_forbidden", p))
        if bad:
            codes = sorted({c for c, _ in bad})
            shown = ", ".join(f"{p} ({c})" for c, p in bad[:10]) + (" ..." if len(bad) > 10 else "")
            raise Deny("blocked", codes[0], f"{len(bad)} path(s) not allowed: {shown}")
        self.laps.lap("inspect")
        if dry_run:
            return {"before": before, "observed": {"commits": len(commits), "paths": paths, "base": base_sha}}
        if getattr(self, "authorize_dispatch", None):
            self.authorize_dispatch(paths)
        lease = f"--force-with-lease=refs/heads/{branch}:{before or ''}"
        push = _git([*pre, "-C", str(self.mirror), "push", "--porcelain", "--no-verify", lease, url,
                     f"{commit}:refs/heads/{branch}"], env=env, check=False)
        self.laps.lap("push")
        try:
            after = self._ls_remote(url, branch, pre, env)
        except Deny:
            after = "<unobservable>"
        self.laps.lap("confirm")
        effect = {"type": "git_push", "remote": prep["remote_name"], "remote_url": redact_url(url),
                  "branch": branch, "commit": commit, "before": before, "after": after}
        if prep.get("content"):
            effect["content"] = prep["content"]["summary"]
            if prep.get("rebased_onto"):
                effect["rebased_onto"] = prep["rebased_onto"]
        observed = {"commits": len(commits), "paths": paths, "base": base_sha}
        if after == commit:
            return {"state": "EXECUTED", "effect": effect, "observed": observed}
        msg = (push.stdout + push.stderr).strip()
        if push.returncode != 0:
            # A per-ref rejection is definitive: the remote did not change.
            if any(s in msg for s in ("stale info", "fetch first", "non-fast-forward",
                                      "cannot lock ref", "failed to update ref")):
                raise Deny("stale", "remote_moved_during_commit",
                           f"the remote changed between check and push (compare-and-swap refused); "
                           f"nothing was pushed: {msg[-300:]}")
            # The server failing is not the server refusing: nothing changed, so try again later.
            if after == before and any(s in msg for s in ("Internal Server Error", "fatal error in commit_refs",
                                                          "(failure)", "HTTP 50", "error: 50")):
                raise Deny("retryable", "push_failed", f"the remote failed (a server error, not a refusal); "
                           f"nothing was pushed: {msg[-300:]}", "errored")
            if "[remote rejected]" in msg or "[rejected]" in msg:
                raise Deny("blocked", "push_rejected", f"the remote refused the push: {msg[-300:]}")
            if after == before:
                raise Deny("retryable", "push_failed", f"push failed; nothing was pushed: {msg[-300:]}",
                           "errored")
        return {"state": "UNCONFIRMED", "effect": effect, "observed": observed,
                "note": f"push exit {push.returncode}; remote is at {after}, not {commit}"}


EFFECTS = {"git_push": GitPush}


# --------------------------------------------------------------------------
# the commit protocol

def _scope(registry: dict, h: dict) -> dict:
    """Paths the effect may touch: the packet's owned_paths (receiver
    defaults applied), every policy layer's allowed_paths (each layer is a
    ceiling on its own), minus every layer's forbidden_paths."""
    policy = hc.receiver_policy(registry, h.get("to")) or {}
    h2 = copy.deepcopy(h)
    hc.apply_receiver_defaults(h2, policy)
    layers = []
    for layer in (registry.get("policy"), (registry.get("agents", {}).get(h.get("to")) or {}).get("policy")):
        if isinstance(layer, dict) and isinstance(layer.get("allowed_paths"), list):
            layers.append(layer["allowed_paths"])
    return {"owned_paths": (h2.get("scope") or {}).get("owned_paths") or [],
            "allowed_layers": layers, "forbidden_paths": policy.get("forbidden_paths") or []}


def _needs_commit_pin(cfg: BrokerConfig, etype) -> bool:
    """Operator opt-in per effect: {"effects": {"git_push": {"require_approval_commit_pin": true}}}."""
    return bool((cfg.effects.get(etype) or {}).get("require_approval_commit_pin"))


def _approvals_for(h: dict, registry: dict, action: str, etype: str, params: dict, at, extra=(),
                   require_commit_pin: bool = False) -> list:
    """The signed approvals (in the packet, or detached: `extra`) that cover
    this exact effect, or Deny."""
    policy = hc.receiver_policy(registry, h.get("to")) or {}
    auth = h.get("authority") or {}
    needs = set(auth.get("approval_required_for") or []) | set(policy.get("approval_required_for") or [])
    if action not in needs and etype not in needs:
        return []
    cands = [a for a in list(auth.get("approvals") or []) + [x for x in extra if x.get("sig")]
             if isinstance(a, dict) and a.get("action") in (action, etype)]
    pinned = [a for a in cands if isinstance(a.get("params"), dict)
              and all(k in a["params"] for k in REQUIRED_PLAN_PARAMS.get(etype, ()))]
    if not pinned:
        raise Deny("blocked", "approval_params_missing",
                   f"'{action}' needs an approval that pins its params "
                   f"({', '.join(REQUIRED_PLAN_PARAMS.get(etype, ()))}); an approval for the bare action "
                   f"name could be reused after the sender changes the target")
    matching = [a for a in pinned if all(params.get(k) == v for k, v in a["params"].items())]
    if not matching:
        raise Deny("blocked", "approval_params_mismatch",
                   f"no approval for '{action}' covers these params: "
                   f"{json.dumps({k: params.get(k) for k in pinned[0]['params']})}")
    if require_commit_pin:
        # the human signed which commit they read, not just where it goes
        matching = [a for a in matching if a["params"].get("commit") == params.get("commit")]
        if not matching:
            raise Deny("blocked", "approval_commit_missing",
                       "this broker requires the approval to pin the commit it covers "
                       "(synthe_sign.py approve --commit <sha>); none does for this commit")
    problems = hc._approval_ok(action, matching, h, registry, policy, at)
    if problems:
        code, msg = problems[0]
        raise Deny("blocked", code, msg)
    return [{"approver": a.get("approver"), "kid": a.get("kid"), "action": a.get("action"),
             "params": a.get("params"), **({"detached": True} if "idempotency_key" in a else {})}
            for a in matching]


class NotIsolated(Exception):
    """In-process use of a broker whose config does not say isolation mode
    "none": the caller's own process would load the broker's key."""


def in_process_refusal(cfg: BrokerConfig, what: str) -> str | None:
    """Why `what` may not run the broker inside the caller's process, or None.
    That only works where the caller can read the broker's key, which is not
    isolation, so it is allowed only when the operator set mode "none" (dev)."""
    mode = cfg.isolation.get("mode")
    if mode == "none":
        return None
    return (f"{what}: refused. This broker is configured for isolation mode '{mode}': it runs as its own OS "
            f"user (or in a container) and agents never load its key. Start it with\n"
            f"  synthe_commit.py serve --config {cfg.path} --socket <path>\n"
            f"as the broker's user, and propose from the agent with\n"
            f"  synthe_client.py --broker unix://<path> push ...\n"
            f"(or set \"isolation\": {{\"mode\": \"none\"}} in {cfg.path.name} for local development only).")


APPROVAL_CODES = {"approval_missing", "approval_expired", "approval_expires_invalid", "approval_params_missing",
                  "approval_params_mismatch", "approver_not_trusted", "approval_unsigned",
                  "approval_signature_invalid", "approval_commit_missing"}
DEPENDENCY_CODES = {"dependency_incomplete", "dependency_unknown"}
# A push under a grant with a delegate waits for that delegate (or a human); escalated waits for a human.
DELEGATE_WAIT_CODES = {"delegate_approval_missing", "delegate_approval_expired", "delegate_approval_stale",
                       "delegate_escalated"}


# --------------------------------------------------------------------------
# detached approvals (v0.5): signed apart from the packet, stored append-only

def _public_approval(a: dict) -> dict:
    return {k: a.get(k) for k in ("action", "approver", "kid", "expires_at", "params", "idempotency_key",
                                  "from", "to", "handoff_id") if a.get(k) is not None}


def load_approvals(cfg: BrokerConfig, handoff: dict | None = None) -> list:
    """Accepted detached approvals, optionally only those bound to this
    handoff (same idempotency key, sender and receiver). Each is re-verified
    wherever it is used; this file is only where they wait."""
    out = []
    if not cfg.approvals_path.exists():
        return out
    for line in cfg.approvals_path.read_text().splitlines():
        try:
            a = json.loads(line).get("approval")
        except (json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(a, dict):
            continue
        if handoff is None or all(a.get(k) == handoff.get(k) for k in ("idempotency_key", "from", "to")):
            out.append(a)
    return out


def _approvals_lock(cfg: BrokerConfig):
    return _file_lock(cfg.approvals_path.with_name(cfg.approvals_path.name + ".lock"))


def _store_approval(cfg: BrokerConfig, record: dict) -> None:
    """Append one accepted approval. Caller holds _approvals_lock."""
    with open(cfg.approvals_path, "a") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


# --------------------------------------------------------------------------
# staged proposals (v0.5): prepared and checked, waiting for an approval or
# an upstream handoff; committed by the broker the moment they're covered

class StagedStoreCorrupt(RuntimeError):
    """staged.json exists but is not valid JSON. Reading it as empty would
    silently drop every staged proposal and its claim token."""


@contextlib.contextmanager
def _staged_store(cfg: BrokerConfig, strict: bool = True):
    """{idempotency_key: {action: record}} under a lock. The file holds claim
    tokens (the broker commits staged proposals later, on the claimant's
    behalf), so it is created 0600 and never leaves the broker."""
    path = cfg.staged_path
    with _file_lock(path.with_name(path.name + ".lock")):
        try:
            data = json.loads(path.read_text()) if path.exists() else {}
        except json.JSONDecodeError:
            if strict:
                raise StagedStoreCorrupt(f"{path} is not valid JSON; refusing to treat it as empty "
                                         f"(move it aside to discard the staged proposals)")
            data = {}
        box = {"data": data, "dirty": False}
        yield box
        if box["dirty"]:
            tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)


def staged_view(cfg: BrokerConfig, idempotency_key: str | None = None) -> list:
    """Staged proposals as anyone may see them: never the claim token."""
    out = []
    with _staged_store(cfg) as box:
        for key, actions in sorted(box["data"].items()):
            if idempotency_key and key != idempotency_key:
                continue
            for action, rec in sorted(actions.items()):
                out.append({"idempotency_key": key, "action": action, "handoff_id": rec.get("handoff_id"),
                            **{k: rec.get(k) for k in ("state", "params", "waiting_for", "commits_from",
                                                       "staged_at", "receipt_seq", "last_receipt_seq",
                                                       "attempts", "updated_at")}})
    return out


_SHA1 = re.compile(r"[0-9a-f]{40}")


def staged_detail(cfg: BrokerConfig, staged_id: str, max_patch: int = 200_000) -> dict | None:
    """One staged proposal as its approver should see it: what the broker will do, built from the
    broker's own record and its private mirror, never from text the agent wrote (study F03,
    Verifiable Action Card). The agent's own words come back separately, under `agent_says`, for
    the caller to label as unverified. Never the claim token. None if there is no such proposal."""
    if not isinstance(staged_id, str) or "/" not in staged_id:
        return None
    key, _, action = staged_id.rpartition("/")
    with _staged_store(cfg) as box:
        rec = copy.deepcopy((box["data"].get(key) or {}).get(action))
    if rec is None:
        return None
    packet = rec.get("packet") or {}
    h = packet.get("handoff") or {}
    params = rec.get("params") or {}
    out = {"id": rec.get("id"), "state": rec.get("state"), "waiting_for": rec.get("waiting_for"),
           "idempotency_key": key, "action": action, "handoff_id": rec.get("handoff_id"),
           "from": h.get("from"), "to": h.get("to"), "staged_at": rec.get("staged_at"),
           "receipt_seq": rec.get("receipt_seq"),
           "handoff_expires_at": (h.get("acceptance") or {}).get("expires_at"),
           "effect": {k: params.get(k) for k in ("remote", "branch", "commit", "expected_old")},
           "packet": {k: v for k, v in packet.items() if k in ("handoff", "signature")},
           "agent_says": {"purpose": h.get("purpose")}}
    commit, base = params.get("commit"), params.get("expected_old")
    if isinstance(commit, str) and _SHA1.fullmatch(commit):
        out["changes"] = GitPush(cfg).describe(
            commit, base if isinstance(base, str) and _SHA1.fullmatch(base) else None, max_patch)
    else:
        out["changes"] = {"available": False,
                          "note": "a content proposal: the broker builds its commit when it lands"}
    return out


def _staged_actions(cfg: BrokerConfig, key: str | None) -> set:
    if not key or not cfg.staged_path.exists():
        return set()
    with _staged_store(cfg, strict=False) as box:  # read-only: never blocks a receipt
        return {a for a, r in (box["data"].get(key) or {}).items() if r.get("state") in ("STAGED", "COMMITTING")}


def _set_staged(cfg: BrokerConfig, key: str, action: str, only_from=None, **fields) -> None:
    with _staged_store(cfg) as box:
        rec = (box["data"].get(key) or {}).get(action)
        if rec is None or (only_from and rec.get("state") not in only_from):
            return
        rec.update(fields, updated_at=hc.now_utc().isoformat())
        box["dirty"] = True


def _approval_only(reasons: list, info: dict, action: str) -> bool:
    """True when the only thing wrong is the approval of `action` (it may still arrive)."""
    problems = info.get("approval_problems") or {}
    return bool(reasons) and set(problems) == {action} and all(r["code"] in APPROVAL_CODES for r in reasons)


IN_PROCESS = {"via": "in-process",
              "isolation": {"mode": "in-process", "verified": False,
                            "note": "the broker ran inside the caller's process, so the caller could "
                                    "read its keys: not isolated"}}


def propose(cfg: BrokerConfig, proposal, origin: dict | None = None, bundle: bytes | None = None,
            allow_path_source: bool = True, timings: dict | None = None, _staged: dict | None = None) -> dict:
    """Run one proposal through the commit protocol. Always returns the
    signed receipt (executed / denied / errored / unconfirmed / staged).

    `origin` says how the proposal arrived and how isolated the caller was
    (synthe_broker.py passes what the kernel told it; a direct call is
    `in-process`); it is recorded in the receipt. `bundle` carries the
    commits as a git bundle, so the broker never reads the agent's disk.

    v0.5 speculative commit: with `"wait_for_approval": true`, a proposal that
    lacks only its approval (or waits only on an upstream `depends_on`) is
    prepared, checked against the live remote without pushing, pinned to the
    remote state it saw, and stored STAGED (receipt decision `staged`). The
    broker commits it when it is covered (submit_approval / retry_staged),
    re-running every commit-time check; if anything changed it is denied.

    Called without `origin` (in the caller's own process) it raises
    NotIsolated unless the config says isolation mode "none". `timings`, if
    given, is filled with seconds per phase (scripts/bench_commit.py)."""
    laps = _Laps(timings)
    if origin is None:
        refusal = in_process_refusal(cfg, "synthe_commit.propose()")
        if refusal:
            raise NotIsolated(refusal)
    key = ss.load_key(str(cfg.key_path))
    origin = origin or IN_PROCESS
    receipt: dict = {"v": 1, "time": hc.now_utc().isoformat(), "decision": None, "reasons": [],
                     "effect": None, "observed": None, "handoff": None, "claim": None, "approvals": [],
                     "via": origin.get("via"), "isolation": origin.get("isolation")}
    if _staged is not None:
        receipt["staged"] = {"id": _staged.get("id"), "receipt_seq": _staged.get("receipt_seq")}
        if _staged.get("trigger"):
            receipt["triggered_by"] = _staged["trigger"]

    ctx: dict = {}  # the handoff and registry once known: every receipt carries the plan anchor

    def finish(decision, reasons=None, **fields):
        reasons = [{**r, "message": str(r.get("message", ""))} for r in reasons or []]
        receipt.update(decision=decision, reasons=reasons, **fields)
        if ctx.get("registry") is not None:
            receipt["plan"] = sp.plan_for(ctx["packet"], ctx["registry"], hc.load_ledger(cfg.ledger_path),
                                          tuple(cfg.effects), current=(ctx["action"], decision),
                                          extra_approvals=ctx.get("extra", ()),
                                          staged_actions=_staged_actions(cfg, ctx.get("key")))
        receipt.update(scrub_obj(receipt, cfg))  # no credential is ever signed into the chain
        return append_receipt(cfg, key, receipt)

    try:
        if not isinstance(proposal, dict):
            raise Deny("invalid", "proposal_malformed", "proposal must be a JSON object")
        packet, token = proposal.get("packet"), proposal.get("claim_token")
        action, params, source = proposal.get("action"), proposal.get("params"), proposal.get("source")
        wait = proposal.get("wait_for_approval") is True or _staged is not None
        h = packet.get("handoff") if isinstance(packet, dict) else None
        if not isinstance(h, dict):
            raise Deny("invalid", "proposal_malformed", "proposal.packet must contain a 'handoff' object")
        receipt["handoff"] = {"id": h.get("id"), "idempotency_key": h.get("idempotency_key"),
                              "trace_id": h.get("trace_id"), "from": h.get("from"), "to": h.get("to"),
                              "packet_sha256": hc.handoff_digest(h)}
        if not isinstance(action, str) or not isinstance(params, dict):
            raise Deny("invalid", "proposal_malformed", "proposal needs 'action' (string) and 'params' (object)")
        if not isinstance(token, str) or not token:
            raise Deny("invalid", "claim_token_required",
                       "proposal needs the claim token returned with the handoff's ACCEPT")
        receipt["effect"] = {"action": action, **{k: params.get(k) for k in ("remote", "branch", "commit")}}

        registry, err = hc.load_registry(str(cfg.registry_path))
        if err:
            raise Deny("invalid", err["reasons"][0]["code"], err["reasons"][0]["message"])
        extra = load_approvals(cfg, h)
        ctx.update(packet=packet, registry=registry, action=action, extra=extra, key=h.get("idempotency_key"))

        # 1. the sender planned this effect, with these params
        plan = [a for a in h.get("planned_actions") or [] if isinstance(a, dict) and a.get("name") == action]
        if not plan:
            raise Deny("blocked", "effect_not_planned", f"'{action}' is not a planned action of this handoff")
        etype = plan[0].get("tool")
        receipt["effect"]["type"] = etype
        if etype not in EFFECTS or etype not in cfg.effects:
            raise Deny("blocked", "effect_type_unsupported",
                       f"tool '{etype}' is not an effect this broker mediates ({sorted(cfg.effects)})")
        planned = plan[0].get("params") if isinstance(plan[0].get("params"), dict) else {}
        missing = [k for k in REQUIRED_PLAN_PARAMS.get(etype, ()) if k not in planned]
        if missing:
            raise Deny("blocked", "effect_params_unplanned",
                       f"planned action '{action}' does not pin {missing}; the sender must sign the target")
        diff = {k: (v, params.get(k)) for k, v in planned.items() if params.get(k) != v}
        if diff:
            raise Deny("blocked", "effect_params_mismatch",
                       "proposal differs from the signed plan: " +
                       ", ".join(f"{k}: planned {a!r}, proposed {b!r}" for k, (a, b) in diff.items()))

        # 2. authority at commit time: the whole handoff re-validated now. The
        #    other mediated effects' approvals are checked when they commit.
        import synthe_lane_templates as lanes
        lane = lanes.select(cfg, registry, h.get("to"), params) if etype == "git_push" else None
        at = hc.now_utc()
        info: dict = {}
        mediated = [a.get("name") for a in h.get("planned_actions") or []
                    if isinstance(a, dict) and a.get("tool") in cfg.effects]
        ok, reasons = hc.validate(packet, registry=registry, ledger={}, workspace=cfg.workspace,
                                  at=at, info=info, verify_evidence=cfg.verify_evidence,
                                  extra_approvals=extra, defer_approvals={m for m in mediated if m != action or lane},
                                  as_receiver=cfg.receiver_id)
        pending: list = []  # what a staged proposal waits for
        if not ok:
            if not _approval_only(reasons, info, action):
                raise _DenyMany(reasons)
            pending = list(reasons)

        # 3. a trusted human approved exactly this effect (in the packet, or detached); under a grant that
        #    names a delegate, otherwise the delegate approved this exact commit. A grant without a delegate
        #    stands in for the approval itself (checked again, and a use reserved, at dispatch).
        if not pending and (not lane or lane.get("delegate")):
            try:
                receipt["approvals"] = _approvals_for(h, registry, action, etype, params, at, extra,
                                                      require_commit_pin=_needs_commit_pin(cfg, etype))
                lane = None  # a human's approval never spends a grant use
            except Deny as d:
                if d.reason["code"] not in APPROVAL_CODES:
                    raise
                if not lane:
                    pending = [d.reason]
                else:
                    try:
                        receipt["approvals"] = [lanes.delegate_approval(cfg, registry, h, action, params, lane)]
                    except Deny as dd:
                        if dd.reason["code"] not in DELEGATE_WAIT_CODES:
                            raise
                        pending = [d.reason, dd.reason]
        if wait:  # an unfinished upstream stages the proposal instead of failing in the fence
            ledger = hc.load_ledger(cfg.ledger_path)
            dep = hc._dependency_problem(ledger, h, ledger.get(h.get("idempotency_key")))
            if dep and all(r["code"] in DEPENDENCY_CODES for r in dep["reasons"]):
                pending += dep["reasons"]
        if pending and not wait:
            raise _DenyMany(pending)

        # A completed replay is decided from the complete proposed effect, not
        # merely the idempotency key. Matching proposals return the original
        # signed receipt byte-for-byte; changed semantics conflict and never
        # reach prepare() or the external-effect adapter.
        # A staged proposal may carry an internally-added expected_old pin on
        # retry.  That pin protects the commit race but is not a caller change
        # to the prepared effect.  Preserve the fingerprint computed from the
        # original proposal; explicit caller-supplied expected_old values were
        # already included in it.
        fingerprint = ((_staged or {}).get("effect_fingerprint")
                       if isinstance((_staged or {}).get("effect_fingerprint"), str)
                       else effect_fingerprint(action, etype, params))
        replayed, replay_problem = _completed_replay(
            cfg, registry, h, token, action, fingerprint)
        if replayed is not None:
            return replayed
        if replay_problem is not None:
            raise _DenyMany(replay_problem["reasons"])

        # A previously executed action on a still-RESERVED multi-effect claim
        # is not a completed result replay. Keep the existing fail-closed path.
        replay = _replay_problem(cfg, h, token, action)
        if replay:
            raise _DenyMany(replay["reasons"])

        # 4. effect-specific static checks, outside the fence
        laps.lap("validate")
        eff = EFFECTS[etype](cfg)
        eff.laps = laps
        prep = eff.prepare(params, source, bundle=bundle, allow_path_source=allow_path_source,
                           preloaded=_staged is not None,
                           meta={"agent": h.get("to"), "handoff_id": h.get("id"), "key": h.get("idempotency_key")})
        receipt["commits_from"] = (_staged or {}).get("commits_from") or prep["source"]
        if prep.get("content"):
            receipt["content"] = prep["content"]["summary"]
            # A staged content proposal is rebuilt on today's tip (gated by the
            # blobs it cites): record that it landed somewhere else than staged.
            if _staged and _staged.get("content_parent") not in (None, prep["parent"]):
                prep["rebased_onto"] = prep["parent"]
        scope = _scope(registry, h)
        if pending:
            return _stage(cfg, finish, packet, h, token, action, params, prep, eff, scope, pending, origin,
                          receipt["commits_from"], fingerprint, _staged)

        # 5. inside the claim fence: live check, effect, observe, receipt
        try:
            laps.lap("prepare")
            with hc.fenced_effect(packet, cfg.ledger_path, token, action, mediated) as record:
                laps.lap("fence")  # the ledger lock, the claim and dependency checks
                receipt["claim"] = {"epoch": record["epoch"]}
                # Revalidate and reserve under the shared lane lock at dispatch.
                # Revocation cannot race a push after returning successfully.
                if lane:
                    def authorize(paths):
                        current_registry, error = hc.load_registry(str(cfg.registry_path))
                        if error:
                            raise Deny("invalid", "registry_unreadable", "registry unavailable at dispatch")
                        valid, why = hc.validate(packet, registry=current_registry, ledger={}, workspace=cfg.workspace,
                                                  at=hc.now_utc(), extra_approvals=load_approvals(cfg, h),
                                                  defer_approvals=set(mediated), verify_evidence=cfg.verify_evidence,
                                                  as_receiver=cfg.receiver_id)
                        if not valid:
                            raise _DenyMany(why)
                        if lane.get("delegate"):  # escalated or expired since: nothing is pushed, no use spent
                            receipt["approvals"] = [lanes.delegate_approval(cfg, current_registry, h, action, params, lane)]
                        receipt["lane_template"] = lanes.reserve(cfg, h.get("to"), params, paths, lane["template_id"])
                    eff.authorize_dispatch = authorize
                    with lanes.locked(cfg):
                        result = eff.commit(prep, scope)
                else:
                    result = eff.commit(prep, scope)
                record.update(state=result["state"], commit=prep["commit"], branch=prep["branch"],
                              effect_fingerprint=fingerprint)
                decision = "executed" if result["state"] == "EXECUTED" else "unconfirmed"
                reasons = [] if decision == "executed" else [
                    {"state": "unknown", "code": "effect_unconfirmed", "message": result.get("note", "")}]
                try:
                    out = finish(decision, reasons,
                                 effect={"action": action, **result["effect"],
                                         "fingerprint": fingerprint},
                                 observed=result["observed"])
                    record["receipt_seq"] = out["seq"]
                except Exception as exc:
                    # The effect happened: it must still be recorded on the
                    # claim (so it can never run twice) even if the receipt
                    # could not be written. Surface the failure loudly.
                    record["receipt_error"] = str(exc)
                    out = {**receipt, "decision": decision, "receipt_error": str(exc)}
                laps.lap("receipt")
            laps.lap("fence")  # recording the effect on the claim, under the lock
        except hc.FenceError as exc:
            # A concurrent identical proposal may have completed while this
            # one waited for the fence. Re-read the exact stored result before
            # turning that race into a duplicate rejection.
            replayed, replay_problem = _completed_replay(
                cfg, registry, h, token, action, fingerprint)
            if replayed is not None:
                return replayed
            return finish("denied", (replay_problem or exc.verdict)["reasons"])
        if _staged is None:  # proposed directly: a staged copy of this action is now moot
            _set_staged(cfg, h["idempotency_key"], action, only_from=("STAGED",), state="SUPERSEDED",
                        last_receipt_seq=out.get("seq"))
        if hc.entry_state(hc.load_ledger(cfg.ledger_path).get(h["idempotency_key"]) or {}) == "COMPLETED":
            retry_staged(cfg, depends_on=h["idempotency_key"],
                         trigger={"kind": "upstream_completed", "idempotency_key": h["idempotency_key"],
                                  "receipt_seq": out.get("seq")})
        return out
    except _DenyMany as many:
        return finish("denied", many.reasons)
    except Deny as d:
        return finish(d.decision, [d.reason])


def _replay_problem(cfg, h, token, action) -> dict | None:
    """The fence's duplicate verdict, read without the lock: only for this
    claim's own token holder, and only when the key or this action is done."""
    entry = hc.load_ledger(cfg.ledger_path).get(h.get("idempotency_key"))
    if entry is None or hc._claim_problem(entry, h, token, require_token=True):
        return None
    if hc.entry_state(entry) != "RESERVED":
        return hc._reject("duplicate", "duplicate_idempotency_key",
                          f"idempotency_key '{h['idempotency_key']}' is already {hc.entry_state(entry)}")
    prior = (entry.get("effects") or {}).get(action)
    if prior is not None and prior.get("state") == "EXECUTED":
        return hc._reject("duplicate", "effect_already_executed",
                          f"effect '{action}' already executed for this handoff (receipt {prior.get('receipt_seq')})")
    return None


def _stage(cfg, finish, packet, h, token, action, params, prep, eff, scope, pending, origin, commits_from,
           effect_fingerprint, staged) -> dict:
    """Hold a proposal that waits only for its approval or an upstream. It must
    be this claim's (token, RESERVED, effect not yet run) and pass every live
    check now; it is pinned to the remote state it saw, so any later move is
    caught (remote_moved) when it commits."""
    key = h["idempotency_key"]
    with hc.LockedLedger(cfg.ledger_path) as locked:
        entry = locked.ledger.get(key)
        problem = hc._claim_problem(entry, h, token, require_token=True)
        if problem is None and hc.entry_state(entry) != "RESERVED":
            problem = hc._reject("duplicate", "duplicate_idempotency_key",
                                 f"idempotency_key '{key}' is already {hc.entry_state(entry)}")
        prior = (entry.get("effects") or {}).get(action) if problem is None else None
        if prior is not None:
            problem = hc._reject("duplicate" if prior.get("state") == "EXECUTED" else "unknown",
                                 "effect_already_executed" if prior.get("state") == "EXECUTED"
                                 else "effect_outcome_unknown",
                                 f"effect '{action}' was already attempted (state {prior.get('state')})")
    if problem:
        return finish("denied", problem["reasons"])
    preview = eff.commit(prep, scope, dry_run=True)  # Deny -> denied now, not later
    # Content proposals are re-checked by the blobs they cite (and rebased when
    # those are unchanged), so they aren't pinned to the tip seen now.
    pinned = prep["expected_old"] or ("cited-blobs" if prep.get("content") else preview["before"] or "new")
    waiting = sorted({"approval" if r["code"] in APPROVAL_CODES else "escalated" if r["code"] == "delegate_escalated"
                      else "review" if r["code"] in DELEGATE_WAIT_CODES else "dependency" for r in pending})
    sid = f"{key}/{action}"
    with _staged_store(cfg) as box:
        prev = (box["data"].get(key) or {}).get(action)
    supersedes = prev.get("receipt_seq") if prev and prev.get("state") == "STAGED" and not staged else None
    note = {"state": "blocked", "code": "staged",
            "message": f"staged: waiting for {' and '.join(waiting)}; the broker commits it when covered, "
                       f"if nothing has changed ("
                       + ("re-checked against the blobs it cites" if pinned == "cited-blobs"
                          else f"pinned to {pinned[:12] if pinned != 'new' else 'a new branch'}") + ")"}
    out = finish("staged", list(pending) + [note],
                 staged={"id": sid, "waiting_for": waiting, "expected_old": pinned,
                         **({"supersedes": supersedes} if supersedes else {})},
                 observed=preview["observed"])
    now = hc.now_utc().isoformat()
    with _staged_store(cfg) as box:
        box["data"].setdefault(key, {})[action] = {
            "id": sid, "state": "STAGED", "handoff_id": h.get("id"), "packet": packet, "claim_token": token,
            "action": action, "commits_from": commits_from,
            "params": params if prep.get("content") and not prep["expected_old"] else {**params, "expected_old": pinned},
            "effect_fingerprint": effect_fingerprint,
            "origin": origin, "waiting_for": waiting, "receipt_seq": out.get("seq"),
            "staged_at": (staged or {}).get("staged_at") or now, "updated_at": now,
            "content_parent": (staged or {}).get("content_parent") or prep.get("parent"),
            "attempts": (staged or {}).get("attempts", 0)}
        box["dirty"] = True
    return out


def _staged_ready(cfg: BrokerConfig, rec: dict) -> bool:
    """True when a staged proposal is covered now, or something it relied on
    changed (then committing it produces the denial and its reason). False
    while it still waits for its approval or its upstream."""
    packet, action = rec["packet"], rec["action"]
    h = packet["handoff"]
    registry, err = hc.load_registry(str(cfg.registry_path))
    if err:
        return True
    plan = [a for a in h.get("planned_actions") or [] if isinstance(a, dict) and a.get("name") == action]
    etype = plan[0].get("tool") if plan else None
    extra = load_approvals(cfg, h)
    mediated = {a.get("name") for a in h.get("planned_actions") or []
                if isinstance(a, dict) and a.get("tool") in cfg.effects}
    import synthe_lane_templates as lanes
    lane = lanes.select(cfg, registry, h.get("to"), rec["params"]) if etype == "git_push" else None
    info: dict = {}
    at = hc.now_utc()
    ok, reasons = hc.validate(packet, registry=registry, ledger={}, workspace=cfg.workspace, at=at, info=info,
                              verify_evidence=cfg.verify_evidence, extra_approvals=extra,
                              defer_approvals=mediated if lane else mediated - {action}, as_receiver=cfg.receiver_id)
    if not ok:
        return not _approval_only(reasons, info, action)
    if not lane or lane.get("delegate"):
        try:
            _approvals_for(h, registry, action, etype, rec["params"], at, extra,
                           require_commit_pin=_needs_commit_pin(cfg, etype))
        except Deny as d:
            if d.reason["code"] not in APPROVAL_CODES:
                return True
            if not lane:
                return False
            try:
                lanes.delegate_approval(cfg, registry, h, action, rec["params"], lane)
            except Deny as dd:
                return dd.reason["code"] not in DELEGATE_WAIT_CODES
    ledger = hc.load_ledger(cfg.ledger_path)
    dep = hc._dependency_problem(ledger, h, ledger.get(h.get("idempotency_key")))
    return not (dep and all(r["code"] in DEPENDENCY_CODES for r in dep["reasons"]))


def retry_staged(cfg: BrokerConfig, idempotency_key: str | None = None, depends_on: str | None = None,
                 trigger: dict | None = None, sweep: bool = False) -> list:
    """Commit every STAGED proposal (of one handoff, or waiting on the upstream
    `depends_on`, or all of them when sweeping) that is covered now or whose
    handoff changed underneath it. Returns the receipts written."""
    now = hc.now_utc()
    picked = []
    if not cfg.staged_path.exists():
        return []
    with _staged_store(cfg) as box:
        for key, actions in box["data"].items():
            if idempotency_key and key != idempotency_key:
                continue
            for action, rec in actions.items():
                if rec.get("state") == "COMMITTING":
                    since = hc.parse_ts(rec.get("updated_at") or "")
                    if since is None or (now - since).total_seconds() < 600:
                        continue
                    rec["state"] = "STAGED"  # a commit attempt died with the broker: the fence decides again
                if rec.get("state") != "STAGED":
                    continue
                if depends_on and depends_on not in (rec["packet"]["handoff"].get("depends_on") or []):
                    continue
                due = hc.parse_ts(rec.get("next_attempt_at") or "")
                if sweep and due is not None and now < due:
                    continue
                if not _staged_ready(cfg, rec):
                    continue
                rec.update(state="COMMITTING", updated_at=now.isoformat())
                box["dirty"] = True
                picked.append(json.loads(json.dumps(rec)))
    out = []
    for rec in picked:
        r = propose(cfg, {"packet": rec["packet"], "claim_token": rec["claim_token"], "action": rec["action"],
                          "params": rec["params"]},
                    origin=rec.get("origin") or IN_PROCESS, _staged={**rec, "trigger": trigger})
        key, action = rec["packet"]["handoff"]["idempotency_key"], rec["action"]
        if r.get("decision") == "staged":  # still waiting (raced with an expiry or a revocation)
            pass
        elif r.get("decision") == "errored":  # transient: try again later, with backoff
            attempts = rec.get("attempts", 0) + 1
            nxt = now + dt.timedelta(seconds=min(3600, 60 * 2 ** (attempts - 1)))
            _set_staged(cfg, key, action, state="STAGED", attempts=attempts, next_attempt_at=nxt.isoformat(),
                        last_receipt_seq=r.get("seq"))
        else:
            _set_staged(cfg, key, action, only_from=("COMMITTING",),
                        state={"executed": "EXECUTED", "unconfirmed": "UNCONFIRMED"}.get(r.get("decision"), "DENIED"),
                        last_receipt_seq=r.get("seq"))
        out.append(r)
    return out


def submit_approval(cfg: BrokerConfig, approval, origin: dict | None = None) -> dict:
    """Receive a detached approval. It is verified like an embedded one (a
    registered approver's signature over the handoff's key, sender and
    receiver; trusted by the receiver; not expired), receipted either way,
    stored if good, and then every staged proposal it now covers is committed
    (re-running every check). Returns {"receipt", "commits": [receipts]}.
    A bad approval never touches a staged proposal: it stays staged."""
    if origin is None:
        refusal = in_process_refusal(cfg, "synthe_commit.submit_approval()")
        if refusal:
            raise NotIsolated(refusal)
    key = ss.load_key(str(cfg.key_path))
    origin = origin or IN_PROCESS
    receipt: dict = {"v": 1, "kind": "approval", "time": hc.now_utc().isoformat(), "decision": None,
                     "reasons": [], "approval": None, "handoff": None,
                     "via": origin.get("via"), "isolation": origin.get("isolation")}

    def finish(decision, reasons):
        receipt.update(decision=decision, reasons=[{**r, "message": str(r.get("message", ""))} for r in reasons])
        receipt.update(scrub_obj(receipt, cfg))
        return append_receipt(cfg, key, receipt)

    a = approval if isinstance(approval, dict) else {}
    if not all(isinstance(a.get(k), str) and a.get(k) for k in ("action", "approver", "idempotency_key", "from", "to")) \
            or (a.get("params") is not None and not isinstance(a.get("params"), dict)):
        return {"receipt": finish("approval_rejected", [{
            "state": "invalid", "code": "approval_malformed",
            "message": "a detached approval needs action, approver, idempotency_key, from, to (strings), kid, "
                       "sig, and optional params (an object): make it with synthe_sign.py approve --detached"}]),
            "commits": []}
    receipt["approval"] = _public_approval(a)
    receipt["handoff"] = {"id": a.get("handoff_id"), "idempotency_key": a["idempotency_key"],
                          "from": a["from"], "to": a["to"]}
    if not a.get("sig") or not a.get("kid"):
        return {"receipt": finish("approval_rejected", [{
            "state": "blocked", "code": "approval_unsigned",
            "message": "a detached approval must carry the approver's signature (anyone could write an unsigned one)"}]),
            "commits": []}
    registry, err = hc.load_registry(str(cfg.registry_path))
    if err:
        return {"receipt": finish("approval_rejected", err["reasons"]), "commits": []}
    if a["to"] not in (registry.get("agents") or {}):
        return {"receipt": finish("approval_rejected", [{
            "state": "invalid", "code": "unknown_agent:to", "message": f"no receiver '{a['to']}' in the registry"}]),
            "commits": []}
    stub = {"idempotency_key": a["idempotency_key"], "from": a["from"], "to": a["to"]}
    policy = hc.receiver_policy(registry, a["to"]) or {}
    problems = hc._approval_ok(a["action"], [a], stub, registry, policy, hc.now_utc())
    if problems:
        return {"receipt": finish("approval_rejected", [{"state": "blocked", "code": c, "message": m}
                                                         for c, m in problems]), "commits": []}
    with _approvals_lock(cfg):  # check and store as one step: a concurrent copy is a duplicate
        if any(x.get("sig") == a["sig"] for x in load_approvals(cfg, stub)):
            return {"receipt": finish("approval_duplicate", [{
                "state": "duplicate", "code": "approval_duplicate",
                "message": "this exact approval was already received"}]), "commits": []}
        out = finish("approval_accepted", [])
        _store_approval(cfg, {"received_at": receipt["time"], "receipt_seq": out.get("seq"), "approval": a})
    commits = retry_staged(cfg, idempotency_key=a["idempotency_key"],
                           trigger={"kind": "approval", "approver": a["approver"], "receipt_seq": out.get("seq")})
    return {"receipt": out, "commits": commits}


def submit_delegate(cfg: BrokerConfig, doc, origin: dict | None = None, escalate: bool = False) -> dict:
    """A grant delegate's signed approval of one staged push, or its escalation of that push to a human
    (synthe_lane_templates). Receipted either way; an approval then retries the staged proposal, which re-runs
    every check. Returns {"receipt", "commits": [receipts]}. A bad document never touches a staged proposal."""
    import synthe_lane_templates as lanes
    what = "synthe_commit.submit_delegate()"
    if origin is None:
        refusal = in_process_refusal(cfg, what)
        if refusal:
            raise NotIsolated(refusal)
    key = ss.load_key(str(cfg.key_path))
    origin = origin or IN_PROCESS
    kind = "delegate_escalation" if escalate else "delegate_approval"
    receipt: dict = {"v": 1, "kind": kind, "time": hc.now_utc().isoformat(), "decision": None, "reasons": [],
                     "delegate": None, "handoff": None, "via": origin.get("via"), "isolation": origin.get("isolation")}

    def finish(decision, reasons):
        receipt.update(decision=decision, reasons=[{**r, "message": str(r.get("message", ""))} for r in reasons])
        receipt.update(scrub_obj(receipt, cfg))
        return append_receipt(cfg, key, receipt)

    x = doc if isinstance(doc, dict) else {}
    receipt["delegate"] = {k: x.get(k) for k in ("template_id", "approver", "kid", "action", "params", "expires_at",
                                                 "recommendation", "note") if x.get(k) is not None}
    if isinstance(receipt["delegate"].get("note"), str):
        receipt["delegate"]["note"] = receipt["delegate"]["note"][:500]
    receipt["handoff"] = {k: x.get(k) for k in ("idempotency_key", "from", "to") if isinstance(x.get(k), str)}
    rejected = "escalation_rejected" if escalate else "delegate_approval_rejected"
    registry, err = hc.load_registry(str(cfg.registry_path))
    if err:
        return {"receipt": finish(rejected, err["reasons"]), "commits": []}
    staged = None
    if not escalate and isinstance(x.get("idempotency_key"), str) and isinstance(x.get("action"), str):
        with _staged_store(cfg) as box:  # a snapshot, released before the lane lock (no lock is ever nested)
            staged = copy.deepcopy((box["data"].get(x["idempotency_key"]) or {}).get(x["action"]))
    try:
        with lanes.locked(cfg):
            out = lanes.escalate(cfg, registry, x) if escalate else lanes.submit_delegate(cfg, registry, x, staged)
    except Deny as d:
        return {"receipt": finish(rejected, [d.reason]), "commits": []}
    r = finish("escalated" if escalate else "delegate_approval_accepted", [])
    if escalate:  # what the staged proposal waits for now: a human (shown to approvers and Studio)
        with _staged_store(cfg) as box:
            rec = (box["data"].get(x["idempotency_key"]) or {}).get(x["action"])
            if rec and rec.get("state") == "STAGED":
                rec["waiting_for"] = sorted((set(rec.get("waiting_for") or []) - {"review"}) | {"approval", "escalated"})
                box["dirty"] = True
        return {"receipt": r, "commits": [], **out}
    commits = retry_staged(cfg, idempotency_key=x["idempotency_key"],
                           trigger={"kind": "delegate_approval", "approver": x["approver"], "receipt_seq": r.get("seq")})
    return {"receipt": r, "commits": commits, **out}


def delegate_grant(cfg: BrokerConfig, staged_id) -> dict:
    """Which grant (and delegate) covers a staged push right now, so an approver cites the right one."""
    import synthe_lane_templates as lanes
    if not isinstance(staged_id, str) or "/" not in staged_id:
        raise Deny("invalid", "request_malformed", "id must be a staged proposal id (idempotency_key/action)")
    key, _, action = staged_id.rpartition("/")
    with _staged_store(cfg) as box:
        rec = copy.deepcopy((box["data"].get(key) or {}).get(action))
    if rec is None:
        raise Deny("invalid", "staged_unknown", f"no staged proposal {staged_id!r}")
    registry, err = hc.load_registry(str(cfg.registry_path))
    if err:
        raise Deny("invalid", err["reasons"][0]["code"], err["reasons"][0]["message"])
    h = rec["packet"]["handoff"]
    plan = [a for a in h.get("planned_actions") or [] if isinstance(a, dict) and a.get("name") == action]
    t = lanes.select(cfg, registry, h.get("to"), rec.get("params") or {}) \
        if plan and plan[0].get("tool") == "git_push" else None
    t = t or {}
    return {"id": staged_id, "state": rec.get("state"), "template_id": t.get("template_id"),
            "delegate": t.get("delegate"), "granted_by": t.get("approver"),
            # the human's own words to the reviewer, signed with the grant, and the limits it signed
            "brief": t.get("brief"), "limits": {k: t.get(k) for k in ("params", "path_scope", "max_uses", "expires_at")}
            if t else None, "decisions": lanes.delegate_view(cfg, staged_id)}


class _DenyMany(Exception):
    def __init__(self, reasons):
        super().__init__(reasons[0]["message"] if reasons else "denied")
        self.reasons = reasons


def summarize(receipt: dict) -> str:
    e = receipt.get("effect") or {}
    tgt = f"{e.get('remote')}:{e.get('branch')}" if e.get("branch") else ""
    head = f"#{receipt.get('seq')} {receipt.get('decision', '?').upper()} {e.get('type') or ''} {tgt}".strip()
    if e.get("commit"):
        head += f" @ {str(e['commit'])[:12]}"
    if receipt.get("reasons"):
        head += "  " + ", ".join(r["code"] for r in receipt["reasons"])
    return head


# --------------------------------------------------------------------------
# console (read-only, loopback)

def _ui_file() -> Path:
    """Next to this module in a checkout; under <prefix>/share/synthe when pip-installed."""
    here = Path(__file__).resolve().parent / "synthe_commit_ui.html"
    installed = Path(sys.prefix) / "share" / "synthe" / "synthe_commit_ui.html"
    return here if here.exists() or not installed.exists() else installed


UI_FILE = _ui_file()


def console_state(cfg: BrokerConfig) -> dict:
    registry, _ = hc.load_registry(str(cfg.registry_path))
    chain = verify_receipts(cfg.receipts_path, registry, cfg.broker_id)
    ledger = hc.load_ledger(cfg.ledger_path) if cfg.ledger_path else {}
    claims = []
    for k, e in (ledger or {}).items():
        if not isinstance(e, dict) or k.startswith("_"):
            continue
        claims.append({"idempotency_key": k, "state": hc.entry_state(e), "handoff_id": e.get("handoff_id"),
                       "from": e.get("from"), "to": e.get("to"), "epoch": e.get("epoch"),
                       "reserved_at": e.get("reserved_at"), "completed_at": e.get("completed_at"),
                       "effects": {a: {"state": r.get("state"), "receipt_seq": r.get("receipt_seq"),
                                       "branch": r.get("branch"), "commit": r.get("commit")}
                                   for a, r in (e.get("effects") or {}).items()}})
    claims.sort(key=lambda c: c.get("reserved_at") or "", reverse=True)
    return {"version": VERSION, "config": cfg.public_view(),
            "chain": {k: chain[k] for k in ("ok", "count", "head", "errors")},
            "receipts": list(reversed(chain["receipts"])), "claims": claims}


def serve_ui(cfg: BrokerConfig, host: str, port: int):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            pass

        def _send(self, status, body: bytes, ctype):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                if not UI_FILE.exists():
                    return self._send(200, b"<!doctype html><title>Synthe Commit</title>"
                                      b"<p>Console page not installed; state is at <a href=/api/state>"
                                      b"/api/state</a>.</p>", "text/html; charset=utf-8")
                return self._send(200, UI_FILE.read_bytes(), "text/html; charset=utf-8")
            if path == "/api/state":
                try:
                    body = json.dumps(console_state(cfg)).encode()
                except Exception as exc:  # keep the console up; show the error
                    body = json.dumps({"error": str(exc)}).encode()
                return self._send(200, body, "application/json")
            return self._send(404, b"not found", "text/plain")

    httpd = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write(f"synthe-commit console: http://{host}:{port}/  (read-only; Ctrl-C to stop)\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


# --------------------------------------------------------------------------
# CLI

def cmd_init(a) -> int:
    d = Path(a.dir).expanduser().resolve()
    (d / "keys").mkdir(parents=True, exist_ok=True)
    keyfile = d / "keys" / f"{a.broker_id}.key.json"
    if keyfile.exists():
        key = json.loads(keyfile.read_text())
        pub = {"kid": key["kid"], "alg": sc.ALG,
               "public_key": sc.b64u(sc.public_key(sc.unb64u(key["private_key"])))}
    else:
        secret = sc.generate_secret()
        kid = f"{a.broker_id}-1"
        keyfile.write_text(json.dumps({"agent": a.broker_id, "kid": kid, "alg": sc.ALG,
                                       "private_key": sc.b64u(secret)}, indent=2) + "\n")
        os.chmod(keyfile, 0o600)
        pub = {"kid": kid, "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}
    cfg_path = d / "broker.json"
    if not cfg_path.exists():
        cfg_path.write_text(json.dumps({
            "broker_id": a.broker_id, "key": f"keys/{a.broker_id}.key.json",
            "registry": "registry.json", "ledger": "ledger.sqlite3", "receipts": "receipts.jsonl",
            "workspace": "workspace", "state_dir": ".synthe-broker", "source_roots": [],
            "isolation": {"mode": a.isolation, "clients": []},
            "effects": {"git_push": {"max_commits": 200, "remotes": {}}}}, indent=2) + "\n")
    reg_path = d / "registry.json"
    if a.add_to_registry and reg_path.exists():
        reg = json.loads(reg_path.read_text())
        entry = reg.setdefault("agents", {}).setdefault(a.broker_id, {"role": "commit broker", "kind": "service"})
        keys = entry.setdefault("keys", [])
        if not any(k.get("kid") == pub["kid"] for k in keys):
            keys.append(pub)
        reg_path.write_text(json.dumps(reg, indent=2) + "\n")
        print(f"added {a.broker_id} ({pub['kid']}) to {reg_path}", file=sys.stderr)
    else:
        print(f"# add under agents.{a.broker_id}.keys in your registry:", file=sys.stderr)
    print(json.dumps(pub, indent=2))
    print(f"# broker config: {cfg_path}", file=sys.stderr)
    return 0


def _print_result(receipt: dict) -> int:
    print(json.dumps(receipt, indent=2))
    sys.stderr.write(summarize(receipt) + "\n")
    return 0 if receipt.get("decision") == "executed" else 2


def _in_process_allowed(cfg: BrokerConfig, what: str) -> bool:
    refusal = in_process_refusal(cfg, f"synthe-commit {what}")
    if refusal:
        sys.stderr.write(refusal + "\n")
    return refusal is None


def cmd_propose(a) -> int:
    cfg = BrokerConfig(a.config)
    if not _in_process_allowed(cfg, "propose"):
        return 2
    try:
        proposal = json.loads(Path(a.proposal).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        proposal = {"_unreadable": str(exc)}
    return _print_result(propose(cfg, proposal))


def cmd_push(a) -> int:
    cfg = BrokerConfig(a.config)
    if not _in_process_allowed(cfg, "push"):
        return 2
    commit = a.commit
    if not SHA_RE.match(commit or ""):
        commit = _git(["-C", a.source, "rev-parse", "--verify", f"{commit or 'HEAD'}^{{commit}}"]).stdout.strip()
    params = {"remote": a.remote, "branch": a.branch, "commit": commit}
    if a.expected_old:
        params["expected_old"] = a.expected_old
    if a.base:
        params["base"] = a.base
    proposal = {"packet": json.loads(Path(a.packet).read_text()), "claim_token": a.claim_token,
                "action": a.action, "params": params, "source": a.source}
    return _print_result(propose(cfg, proposal))


def cmd_receipts(a) -> int:
    cfg = BrokerConfig(a.config)
    registry, err = hc.load_registry(str(cfg.registry_path))
    if err:
        print(json.dumps(err, indent=2))
        return 2
    report = verify_receipts(cfg.receipts_path, registry, cfg.broker_id)
    if a.op == "show":
        for r in report["receipts"]:
            print(("ok  " if r.get("verified") else "BAD ") + summarize(r))
    print(json.dumps({k: report[k] for k in ("ok", "count", "head", "errors")}, indent=2))
    return 0 if report["ok"] else 2


def cmd_ui(a) -> int:
    serve_ui(BrokerConfig(a.config), "127.0.0.1", a.port)
    return 0


def cmd_serve(a) -> int:
    import synthe_broker as sb
    token = os.environ.get(a.token_env) if a.listen else None
    return sb.serve(BrokerConfig(a.config), a.socket, a.listen, token)


def cmd_doctor(a) -> int:
    import synthe_broker as sb
    return sb.doctor(BrokerConfig(a.config))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=f"Synthe Commit {VERSION}: agents propose, Synthe commits")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="create a broker key and config skeleton")
    i.add_argument("--dir", required=True)
    i.add_argument("--broker-id", default="synthe-broker")
    i.add_argument("--add-to-registry", action="store_true",
                   help="add the broker's public key to DIR/registry.json")
    i.add_argument("--isolation", choices=["user", "container", "none"], default="user",
                   help="isolation mode written into a new broker.json (default user)")
    v = sub.add_parser("serve", help="run the broker daemon (as the broker's own OS user)")
    v.add_argument("--config", required=True)
    v.add_argument("--socket", help="unix socket path (isolation mode 'user' or 'none')")
    v.add_argument("--listen", metavar="HOST:PORT", help="TCP with a bearer token (mode 'container' or 'none')")
    v.add_argument("--token-env", default="SYNTHE_BROKER_TOKEN",
                   help="env var holding the bearer token for --listen (default SYNTHE_BROKER_TOKEN)")
    d = sub.add_parser("doctor", help="check that no broker secret or state is exposed to other users")
    d.add_argument("--config", required=True)
    p = sub.add_parser("propose", help="dev only (isolation mode none): run a proposal JSON in-process")
    p.add_argument("proposal")
    p.add_argument("--config", required=True)
    g = sub.add_parser("push", help="dev only (isolation mode none): propose a git_push in-process")
    g.add_argument("--config", required=True)
    g.add_argument("--packet", required=True)
    g.add_argument("--claim-token", required=True)
    g.add_argument("--action", required=True)
    g.add_argument("--remote", required=True)
    g.add_argument("--branch", required=True)
    g.add_argument("--source", required=True, help="the agent's git repo")
    g.add_argument("--commit", default="HEAD")
    g.add_argument("--expected-old", help="SHA the branch must be at, or 'new'")
    g.add_argument("--base", help="base branch for a new branch (default main)")
    r = sub.add_parser("receipts", help="verify or list the receipt chain")
    r.add_argument("op", choices=["verify", "show"])
    r.add_argument("--config", required=True)
    u = sub.add_parser("ui", help="read-only web console on 127.0.0.1")
    u.add_argument("--config", required=True)
    u.add_argument("--port", type=int, default=8790)
    a = ap.parse_args(argv)
    return {"init": cmd_init, "propose": cmd_propose, "push": cmd_push, "serve": cmd_serve,
            "doctor": cmd_doctor, "receipts": cmd_receipts, "ui": cmd_ui}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
