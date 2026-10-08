#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Handoff Contract validator (packet wire format v0.1; stdlib only).

Validates one handoff packet before a receiver executes. Returns ACCEPT or a
failure state (invalid / incomplete / stale / conflicting / blocked /
retryable / duplicate / unknown) with reason codes. Exit codes: 0 = ACCEPT,
2 = reject.

v0.2 ledger semantics: an ACCEPT records the idempotency key as RESERVED;
once the receiver has actually performed the effect it flips the entry to
COMPLETED (`--complete`). Re-presenting a COMPLETED key is a duplicate.
Re-presenting a RESERVED key within `--reserve-ttl-hours` is a duplicate
(still claimed; reconcile before redispatch); a RESERVED claim older than
the TTL is `unknown`: the receiver may have crashed before or after the
effect, so reconcile against its effect receipt before redispatch. Ledger
writes are atomic: an flock-serialized read-check-write critical section and
a temp-file + os.replace save, so concurrent invocations cannot both pass.

v0.5 wait-for: `handoff.depends_on` lists idempotency keys that must be
COMPLETED before this handoff's effect may commit (checked inside fenced(),
fenced_effect() and complete(), under the ledger lock). A receiver policy
with `exclusive_paths` refuses a second live claim whose owned_paths may
overlap one already held on that receiver (`claim_conflict`).
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import sys
from pathlib import Path

REQUIRED = [
    "id", "idempotency_key", "trace_id", "schema_version", "from", "to",
    "purpose", "inputs", "scope", "authority", "acceptance", "on_failure",
]
FAILURE_STATES = {"invalid", "incomplete", "stale", "conflicting", "blocked", "retryable", "duplicate", "unknown"}
# Evidence kinds that must be verbatim-fidelity by default (rule/code text).
VERBATIM_KINDS = {"code_text", "verbatim_quote", "legal_text"}


class StrictJSONError(ValueError):
    """JSON that parses differently across parsers. `code` is the reason code to report."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _strict_pairs(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            name = k if len(k) <= 64 else k[:61] + "..."
            raise StrictJSONError(f"duplicate_field:{name}",
                                  f"the JSON object has the key {name!r} twice; parsers disagree on "
                                  f"which copy counts, so it is refused")
        obj[k] = v
    return obj


def _strict_constant(name):
    raise StrictJSONError("malformed:non_finite_number", f"{name} is not a JSON number")


def _strict_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise StrictJSONError("malformed:non_finite_number", f"the number {text[:32]} overflows to infinity")
    return value


def strict_loads(text):
    """json.loads for anything an agent or a peer sent. It refuses what parsers
    disagree on: a duplicate key (Python keeps the last copy, other parsers the
    first, so a signer and a checker could see different packets) and NaN,
    Infinity or a number that overflows to infinity (not JSON, and not
    canonicalizable for a signature). Raises StrictJSONError(code, message)."""
    return json.loads(text, object_pairs_hook=_strict_pairs, parse_constant=_strict_constant,
                      parse_float=_strict_float)


def non_finite_path(obj, root: str = "packet") -> str | None:
    """Where the first NaN or Infinity sits in an already-parsed object, or None.
    The defense for callers that hand check() a dict parsed leniently."""
    stack = [(root, obj)]
    while stack:
        path, value = stack.pop()
        if isinstance(value, float) and not math.isfinite(value):
            return path
        if isinstance(value, dict):
            stack.extend((f"{path}.{k}", v) for k, v in value.items())
        elif isinstance(value, list):
            stack.extend((f"{path}[{i}]", v) for i, v in enumerate(value))
    return None


def _non_finite_reject(packet) -> dict | None:
    where = non_finite_path(packet)
    if where is None:
        return None
    return _reject("invalid", "malformed:non_finite_number",
                   f"{where} is NaN or Infinity, which is not a JSON number")


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_ts(value: str) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


SQLITE_LEDGER_SUFFIXES = (".sqlite", ".sqlite3")


def sqlite_ledger(path: Path | None) -> bool:
    return bool(path) and str(path).lower().endswith(SQLITE_LEDGER_SUFFIXES)


def _sqlite_connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("CREATE TABLE IF NOT EXISTS claims "
                     "(key TEXT PRIMARY KEY, value TEXT NOT NULL CHECK(json_valid(value)))")
        conn.commit()
        return conn
    except BaseException:
        conn.close()
        raise


class SQLiteLedger(dict):
    """Lazy dict-compatible view over ledger-v2 rows.

    Normal claim paths touch one key. Cross-key semantics (`depends_on`,
    `exclusive_paths`) intentionally call items() and load the hot set.
    """

    def __init__(self, path: Path, conn: sqlite3.Connection | None = None):
        super().__init__()
        self.path, self.conn = Path(path), conn
        self.dirty_keys: set[str] = set()
        self.loaded_all = False

    def _rows(self, sql, params=()):
        if self.conn is not None:
            return self.conn.execute(sql, params).fetchall()
        conn = _sqlite_connect(self.path)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def _load_one(self, key):
        row = self._rows("SELECT value FROM claims WHERE key = ?", (key,))
        if not row:
            return None
        value = json.loads(row[0][0])
        dict.__setitem__(self, key, value)
        return value

    def _load_all(self):
        if not self.loaded_all:
            for key, value in self._rows("SELECT key, value FROM claims"):
                if not dict.__contains__(self, key):
                    dict.__setitem__(self, key, json.loads(value))
            self.loaded_all = True

    def get(self, key, default=None):
        if dict.__contains__(self, key):
            return dict.get(self, key, default)
        value = self._load_one(key)
        return default if value is None else value

    def __getitem__(self, key):
        value = self.get(key, None)
        if value is None and not dict.__contains__(self, key):
            raise KeyError(key)
        return value

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.dirty_keys.add(key)

    def __contains__(self, key):
        return self.get(key, None) is not None

    def items(self):
        self._load_all()
        return dict.items(self)

    def values(self):
        self._load_all()
        return dict.values(self)

    def keys(self):
        self._load_all()
        return dict.keys(self)

    def __iter__(self):
        self._load_all()
        return dict.__iter__(self)

    def __len__(self):
        self._load_all()
        return dict.__len__(self)

    def __eq__(self, other):
        self._load_all()
        return dict.__eq__(self, other)

    def flush(self):
        if self.conn is None:
            raise RuntimeError("SQLite ledger writes need a locked transaction")
        # Existing entries are mutable dicts. LockedLedger.dirty tells us an
        # operation changed one, so persist every row this transaction
        # actually loaded (normally only the claim key and its dependencies).
        for key in list(dict.keys(self)):
            self.conn.execute("INSERT INTO claims(key, value) VALUES (?, ?) "
                              "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                              (key, json.dumps(dict.__getitem__(self, key), sort_keys=True, separators=(",", ":"))))
        self.dirty_keys.clear()


def load_ledger(path: Path) -> dict:
    if sqlite_ledger(path):
        if not path or not Path(path).exists():
            return {}
        try:
            conn = _sqlite_connect(Path(path))
            conn.execute("SELECT key FROM claims LIMIT 1").fetchone()
            conn.close()
            return SQLiteLedger(Path(path))
        except (OSError, sqlite3.DatabaseError):
            return {"_corrupt": True}
    if path and path.exists():
        try:
            return json.loads(path.read_text()) or {}
        except json.JSONDecodeError:
            return {"_corrupt": True}
    return {}


def save_ledger(path: Path, ledger: dict) -> None:
    """Write the ledger atomically: temp file in the same dir + os.replace,
    so a concurrent reader never observes a torn file."""
    if path and sqlite_ledger(path):
        try:
            conn = _sqlite_connect(Path(path))
            with conn:
                conn.execute("DELETE FROM claims")
                conn.executemany("INSERT INTO claims(key, value) VALUES (?, ?)",
                                 [(str(k), json.dumps(v, sort_keys=True, separators=(",", ":")))
                                  for k, v in ledger.items()])
            conn.close()
        except sqlite3.DatabaseError:
            raise ValueError("ledger database is corrupt") from None
    elif path:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, path)


def migrate_ledger(source: Path, destination: Path) -> dict:
    """Copy a legacy JSON ledger into a new SQLite/WAL ledger. Never changes
    or deletes the source and refuses to overwrite a destination."""
    source, destination = Path(source), Path(destination)
    if sqlite_ledger(source) or not sqlite_ledger(destination):
        raise ValueError("source must be JSON and destination must end in .sqlite or .sqlite3")
    if destination.exists():
        raise FileExistsError(destination)
    ledger = load_ledger(source)
    if ledger.get("_corrupt"):
        raise ValueError("source ledger is corrupt")
    save_ledger(destination, ledger)
    copied = load_ledger(destination)
    if copied.get("_corrupt") or dict(copied.items()) != ledger:
        raise ValueError("ledger migration verification failed")
    return {"source": str(source), "destination": str(destination), "entries": len(ledger)}


def entry_state(entry: dict) -> str:
    """Ledger entry state. Pre-v0.2 entries (no 'state' field) were written
    only after acceptance in the old claim-on-accept model and count as
    COMPLETED."""
    return entry.get("state") or "COMPLETED"


def handoff_digest(h: dict) -> str:
    """SHA-256 of the canonical handoff object: the exact claim a ledger
    entry is bound to."""
    try:
        import synthe_crypto as sc
        data = sc.canonical_json(h)
    except ImportError:  # pragma: no cover - synthe_crypto ships alongside
        data = json.dumps(h, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(data).hexdigest()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class LockedLedger:
    """Exclusive, crash-safe handle on the ledger file.

    The whole read-check-write cycle runs under an flock so concurrent
    checker invocations serialize and two presentations of the same key
    cannot both pass. Saves go through save_ledger's temp-file + os.replace.
    On platforms without fcntl (Windows) the lock is best-effort.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.ledger: dict = {}
        self.dirty = False
        self._fh = None
        self._conn = None

    def __enter__(self) -> "LockedLedger":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if sqlite_ledger(self.path):
            try:
                self._conn = _sqlite_connect(self.path)
                self._conn.execute("BEGIN IMMEDIATE")
                self.ledger = SQLiteLedger(self.path, self._conn)
            except (OSError, sqlite3.DatabaseError):
                if self._conn is not None:
                    self._conn.close()
                    self._conn = None
                self.ledger = {"_corrupt": True}
            return self
        self._fh = open(self.path.with_name(self.path.name + ".lock"), "a+")
        try:
            import fcntl
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass  # Windows: best-effort, atomic replace still applies
        self.ledger = load_ledger(self.path)
        return self

    def __exit__(self, *exc) -> bool:
        try:
            if self._conn is not None:
                if self.dirty:
                    self.ledger.flush()
                self._conn.commit()
            elif self.dirty:
                save_ledger(self.path, self.ledger)
        finally:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            if self._fh is not None:
                try:
                    import fcntl
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
                except ImportError:
                    pass
                self._fh.close()
                self._fh = None
        return False


def fail(state: str, code: str, msg: str, reasons: list) -> None:
    assert state in FAILURE_STATES, state
    reasons.append({"state": state, "code": code, "message": msg})


def resolve_in_workspace(workspace: Path, rel: str) -> Path | None:
    """Resolve rel under workspace; None if it is absolute or escapes the root
    (via '..' or a symlink). The checker must never become a file-existence or
    hash oracle for paths outside the workspace it was given."""
    if not isinstance(rel, str) or not rel or os.path.isabs(rel) or rel.startswith("~"):
        return None
    base = workspace.resolve()
    target = (base / rel).resolve()
    if target != base and base not in target.parents:
        return None
    return target


def glob_match(pattern: str, path: str) -> bool:
    """`**` crosses directories; `*` and `?` stay within one segment."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.fullmatch(out, path) is not None


def _glob_tokens(pattern: str) -> list:
    """(is_wildcard, text) tokens, read exactly the way glob_match reads them."""
    out, i = [], 0
    while i < len(pattern):
        for wild in ("**/", "**", "*", "?"):
            if pattern.startswith(wild, i):
                out.append((True, wild))
                i += len(wild)
                break
        else:
            out.append((False, pattern[i]))
            i += 1
    return out


def globs_may_overlap(a: str, b: str) -> bool:
    """Could one path match both globs? Conservative: False only when no path
    can. Any path matching a glob starts with its literal prefix (the text
    before its first wildcard) and ends with its literal suffix (the text
    after its last), so two globs whose prefixes, or whose suffixes, are not
    compatible cannot share a path; everything else counts as overlapping.
    A wildcard-free glob is one path and is matched exactly. Compared
    case-insensitively, because a case-insensitive filesystem would collide."""
    a, b = a.casefold(), b.casefold()
    ta, tb = _glob_tokens(a), _glob_tokens(b)
    wild_a, wild_b = any(w for w, _ in ta), any(w for w, _ in tb)
    if not wild_a and not wild_b:
        return a == b
    if not wild_a:
        return glob_match(b, a)
    if not wild_b:
        return glob_match(a, b)

    def ends(tokens):
        head, tail = [], []
        for wild, text in tokens:
            if wild:
                break
            head.append(text)
        for wild, text in reversed(tokens):
            if wild:
                break
            tail.append(text)
        return "".join(head), "".join(reversed(tail))

    (pa, sa), (pb, sb) = ends(ta), ends(tb)
    return (pa.startswith(pb) or pb.startswith(pa)) and (sa.endswith(sb) or sb.endswith(sa))


def parse_utc(value) -> tuple[dt.datetime | None, str | None]:
    """Parse an ISO 8601 timestamp that carries an explicit UTC offset.
    Returns (datetime, None) or (None, problem). Naive timestamps are rejected
    rather than guessed, so they can never crash the comparison."""
    ts = parse_ts(value) if isinstance(value, str) else None
    if ts is None:
        return None, "not a valid ISO 8601 timestamp"
    if ts.tzinfo is None:
        return None, "timestamp has no UTC offset (use e.g. 2026-10-01T00:00:00Z)"
    return ts, None


_LIST_SETS = ("forbidden", "approval_required_for", "forbidden_paths")  # restrictions: union
_LIST_CEILINGS = ("allowed_tools", "trusted_approvers")    # grants: intersection
_FLAGS = ("require_signatures", "require_signed_approvals", "verify_evidence",
          "require_planned_actions", "exclusive_paths")
_MINIMUMS = ("max_ttl_hours",)                              # ceilings on time: the smallest wins


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def receiver_policy(registry: dict | None, receiver: str) -> dict | None:
    """Merge the registry-wide `policy` with the receiver's own `policy`.

    Policy is the receiver's (operator's) statement of what it will ever
    accept. A packet may only narrow it: restrictions union, grants
    intersect, budgets take the minimum, flags OR together."""
    if not isinstance(registry, dict):
        return None
    layers = []
    if isinstance(registry.get("policy"), dict):
        layers.append(registry["policy"])
    agent = registry.get("agents", {}).get(receiver)
    if isinstance(agent, dict) and isinstance(agent.get("policy"), dict):
        layers.append(agent["policy"])
    if not layers:
        return None
    merged: dict = {}
    for layer in layers:
        for k, v in layer.items():
            if k in _LIST_SETS:
                merged[k] = sorted(set(merged.get(k, [])) | set(v or []))
            elif k in _LIST_CEILINGS:
                merged[k] = sorted(set(merged[k]) & set(v or [])) if k in merged else sorted(set(v or []))
            elif k == "budget" and isinstance(v, dict):
                cur = merged.get("budget", {})
                merged["budget"] = {kk: min(x for x in (cur.get(kk), v.get(kk)) if x is not None)
                                    for kk in set(cur) | set(v)}
            elif k == "defaults" and isinstance(v, dict):
                merged["defaults"] = {**merged.get("defaults", {}), **v}
            elif k in _FLAGS:
                merged[k] = bool(merged.get(k)) or bool(v)
            elif k in _MINIMUMS:
                if k not in merged:
                    merged[k] = v
                elif _is_number(merged[k]) and _is_number(v):
                    merged[k] = min(merged[k], v)
                elif _is_number(merged[k]):
                    merged[k] = v  # a malformed layer is kept, so validation refuses it (fail closed)
            else:
                merged[k] = v
    return merged


_DEFAULT_SLOTS = {
    "owned_paths": ("scope", "owned_paths"),
    "forbidden": ("scope", "forbidden"),
    "allowed_tools": ("authority", "allowed_tools"),
    "approval_required_for": ("authority", "approval_required_for"),
    "output_schema": ("acceptance", "output_schema"),
    "required_evidence": ("acceptance", "required_evidence"),
    "expires_at": ("acceptance", "expires_at"),
}


def apply_receiver_defaults(h: dict, policy: dict | None) -> list:
    """Fill fields the sender left out from the receiver's declared defaults.

    This is not inventing facts: the receiver's own policy is a legitimate
    source for *its* constraints (where it may write, what it must output,
    its budget). It never fills sender-side facts: identity, artifacts,
    evidence, approvals, idempotency key. Every fill is reported."""
    applied: list = []
    defaults = (policy or {}).get("defaults") or {}
    if not isinstance(defaults, dict):
        return applied
    for key, value in defaults.items():
        if key == "budget" and isinstance(value, dict):
            auth = h.setdefault("authority", {})
            if not isinstance(auth, dict):
                continue
            budget = auth.get("budget")
            if budget is None:
                budget = auth["budget"] = {}
            if not isinstance(budget, dict):
                continue
            for dim, amount in value.items():
                if dim not in budget:
                    budget[dim] = amount
                    applied.append(f"authority.budget.{dim}")
        elif key == "on_failure":
            if h.get("on_failure") in (None, ""):
                h["on_failure"] = value
                applied.append("on_failure")
        elif key in _DEFAULT_SLOTS:
            section, field = _DEFAULT_SLOTS[key]
            sec = h.setdefault(section, {})
            if isinstance(sec, dict) and sec.get(field) in (None, ""):
                sec[field] = copy.deepcopy(value)
                applied.append(f"{section}.{field}")
    return applied


def _shape_errors(h: dict) -> list:
    """Element-level shape checks so malformed entries yield `invalid`
    instead of a KeyError/TypeError traceback (fail closed with a verdict)."""
    errs: list = []

    def str_list(value, name):
        if value is None:
            return
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            errs.append((f"malformed:{name}", f"{name} must be a list of strings"))

    def obj_list(value, name, required):
        if value is None:
            return []
        if not isinstance(value, list):
            errs.append((f"malformed:{name}", f"{name} must be a list"))
            return []
        good = []
        for i, item in enumerate(value):
            if not isinstance(item, dict) or any(
                    not isinstance(item.get(r), str) or not item.get(r) for r in required):
                errs.append((f"malformed:{name}[{i}]",
                             f"{name}[{i}] must be an object with non-empty {', '.join(required)}"))
            else:
                good.append(item)
        return good

    scope, auth, acc, inputs = h["scope"], h["authority"], h["acceptance"], h["inputs"]
    deps = h.get("depends_on")
    if deps is not None and (not isinstance(deps, list) or
                             not all(isinstance(d, str) and d for d in deps)):
        errs.append(("malformed:depends_on", "depends_on must be a list of idempotency keys "
                                             "(non-empty strings)"))
    str_list(scope.get("forbidden"), "scope.forbidden")
    str_list(scope.get("owned_paths"), "scope.owned_paths")
    str_list(auth.get("allowed_tools"), "authority.allowed_tools")
    str_list(auth.get("approval_required_for"), "authority.approval_required_for")
    str_list(acc.get("required_evidence"), "acceptance.required_evidence")
    for i, ref in enumerate(obj_list(inputs.get("artifact_refs"), "inputs.artifact_refs", ["path"])):
        if ref.get("sha256") is not None and not _is_sha256(ref.get("sha256")):
            errs.append((f"bad_sha256:inputs.artifact_refs[{i}]",
                         f"inputs.artifact_refs[{i}].sha256 must be a full 64-hex SHA-256 "
                         f"(abbreviated or placeholder hashes are not accepted)"))
    for i, act in enumerate(obj_list(h.get("planned_actions"), "planned_actions", ["name", "tool"])):
        for k in ("est_tokens", "est_usd", "est_minutes"):
            v = act.get(k)
            if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0):
                errs.append((f"malformed:planned_actions[{i}].{k}", f"{k} must be a non-negative number"))
        if act.get("params") is not None and not isinstance(act.get("params"), dict):
            errs.append((f"malformed:planned_actions[{i}].params", "params must be an object"))
    for i, appr in enumerate(obj_list(auth.get("approvals"), "authority.approvals", ["action", "approver"])):
        if appr.get("params") is not None and not isinstance(appr.get("params"), dict):
            errs.append((f"malformed:authority.approvals[{i}].params", "params must be an object"))
    for i, ev in enumerate(obj_list(acc.get("evidence"), "acceptance.evidence", ["kind"])):
        if ev.get("sha256") is not None and not _is_sha256(ev.get("sha256")):
            errs.append((f"bad_sha256:acceptance.evidence[{i}]",
                         f"acceptance.evidence[{i}].sha256 must be a full 64-hex SHA-256"))
    budget = auth.get("budget")
    if isinstance(budget, dict):
        for k in ("tokens", "usd", "minutes"):
            v = budget.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v < 0:
                errs.append(("malformed:authority.budget", f"authority.budget.{k} must be >= 0"))
    return errs


def _is_sha256(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


def _verify_packet_signature(packet: dict, h_signed: dict, registry: dict | None,
                             policy: dict | None, reasons: list, info: dict) -> None:
    sig = packet.get("signature")
    if sig is None:
        info["signature"] = "absent"
        if policy and policy.get("require_signatures"):
            fail("invalid", "signature_missing",
                 "receiver policy requires a signed packet; none present", reasons)
        return
    try:
        import synthe_crypto as sc
    except ImportError:
        fail("invalid", "signature_unsupported", "synthe_crypto.py not found next to the checker", reasons)
        return
    if not isinstance(sig, dict) or not isinstance(sig.get("sig"), str):
        fail("invalid", "signature_malformed", "signature must be an object with a 'sig' string", reasons)
        return
    if sig.get("alg", sc.ALG) != sc.ALG:
        fail("invalid", "signature_alg_unsupported", f"unsupported signature alg: {sig.get('alg')}", reasons)
        return
    signer = sig.get("signer")
    if signer != h_signed.get("from"):
        fail("invalid", "signature_signer_mismatch",
             f"packet signed by '{signer}' but claims to be from '{h_signed.get('from')}'", reasons)
        return
    if sig.get("kid") is None and len(sc.usable_keys(registry, signer)) > 1:
        fail("invalid", "signature_kid_required",
             f"'{signer}' has more than one key on record, so the signature must name its kid "
             f"(without one, a rotated-out key could still be picked)", reasons)
        return
    key = sc.find_key(registry, signer, sig.get("kid"))
    if key is None:
        fail("invalid", "signature_key_unknown",
             f"no Ed25519 key on record for '{signer}' (kid={sig.get('kid')})", reasons)
        return
    try:
        raw = sc.unb64u(sig["sig"])
    except Exception:
        raw = b""
    if not sc.verify_bytes(key, sc.packet_signing_input(h_signed), raw):
        fail("invalid", "signature_invalid",
             "packet signature does not verify (packet altered after signing, or wrong key)", reasons)
        return
    info["signature"] = "verified"


def _approval_ok(name: str, candidates: list, h: dict, registry, policy, at) -> list:
    """Return [] if any candidate approval is valid for `name`, else the
    (code, message) problems of the candidates."""
    problems: list = []
    trusted = (policy or {}).get("trusted_approvers")
    need_sig = bool((policy or {}).get("require_signed_approvals"))
    for appr in candidates:
        mine: list = []
        if appr.get("expires_at"):
            aexp, why = parse_utc(appr["expires_at"])
            if aexp is None:
                mine.append(("approval_expires_invalid", f"approval for '{name}': expires_at {why}"))
            elif aexp <= at:
                mine.append(("approval_expired", f"approval for '{name}' expired at {appr['expires_at']}"))
        if trusted is not None and appr.get("approver") not in trusted:
            mine.append(("approver_not_trusted",
                         f"approval for '{name}' is from '{appr.get('approver')}', "
                         f"who is not a trusted approver for this receiver"))
        if appr.get("sig") is not None:
            ambiguous = False
            try:
                import synthe_crypto as sc
                ambiguous = (appr.get("kid") is None
                             and len(sc.usable_keys(registry, appr.get("approver"))) > 1)
                key = None if ambiguous else sc.find_key(registry, appr.get("approver"), appr.get("kid"))
                good = key is not None and sc.verify_bytes(
                    key, sc.approval_signing_input(appr, h), sc.unb64u(appr["sig"]))
            except Exception:
                good = False
            if ambiguous:
                mine.append(("approval_kid_required",
                             f"approval for '{name}' names no kid, and approver "
                             f"'{appr.get('approver')}' has more than one key on record"))
            elif not good:
                mine.append(("approval_signature_invalid",
                             f"approval for '{name}' carries a signature that does not verify "
                             f"for approver '{appr.get('approver')}' on this handoff"))
        elif need_sig:
            mine.append(("approval_unsigned",
                         f"approval for '{name}' is unsigned; receiver policy requires the "
                         f"approver's signature (a sender cannot write approvals on others' behalf)"))
        if not mine:
            return []
        problems.extend(mine)
    return problems


def _dependency_cycle(ledger: dict, key: str, deps) -> list | None:
    """A wait-for cycle that runs through this handoff: key -> dep -> ... ->
    key, following the depends_on recorded on live (RESERVED) claims. No
    handoff in such a cycle could ever commit, so it is refused at claim."""
    deps = [d for d in deps or [] if isinstance(d, str)]
    if key in deps:
        return [key, key]
    stack, seen = [(d, [key, d]) for d in dict.fromkeys(deps)], set()
    while stack:
        node, path = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        entry = ledger.get(node)
        if not isinstance(entry, dict) or entry_state(entry) != "RESERVED":
            continue
        for nxt in entry.get("depends_on") or []:
            if nxt == key:
                return path + [key]
            if isinstance(nxt, str) and nxt not in seen:
                stack.append((nxt, path + [nxt]))
    return None


def _path_conflicts(ledger: dict, h: dict, key: str) -> list:
    """Other live claims on h's receiver whose owned_paths may overlap h's
    (v0.5 exclusive_paths): [(key, entry, [(mine, theirs), ...])]. A claim
    recorded without its paths (before v0.5) is assumed to overlap."""
    mine = [p for p in (h.get("scope") or {}).get("owned_paths") or [] if isinstance(p, str)]
    out: list = []
    if not mine:
        return out
    for other, entry in ledger.items():
        if other == key or not isinstance(entry, dict) or entry_state(entry) != "RESERVED":
            continue
        if entry.get("to") not in (None, h.get("to")):
            continue
        theirs = entry.get("owned_paths")
        if not isinstance(theirs, list):
            pairs = [(mine[0], "(paths not recorded)")]
        else:
            pairs = [(a, b) for a in mine for b in theirs
                     if isinstance(b, str) and globs_may_overlap(a, b)]
        if pairs:
            out.append((other, entry, pairs))
    return out


def _dependency_problem(ledger: dict, h: dict, entry: dict | None = None):
    """Why h may not commit yet (v0.5 wait-for), or None: every key in
    depends_on (the packet's, and what its claim recorded) must be COMPLETED
    in this same ledger. Checked inside the fence, so the dependency check
    and the effect are one atomic step."""
    deps = list(h.get("depends_on") or []) + list((entry or {}).get("depends_on") or [])
    if not all(isinstance(d, str) and d for d in deps):
        return _reject("invalid", "malformed:depends_on",
                       "depends_on must be a list of idempotency keys (non-empty strings)")
    pending, unknown = [], []
    for d in dict.fromkeys(deps):
        dep = ledger.get(d)
        if not isinstance(dep, dict):
            unknown.append(d)
        elif entry_state(dep) != "COMPLETED":
            pending.append(f"{d} ({entry_state(dep)})")
    reasons = []
    if pending:
        reasons.append({"state": "blocked", "code": "dependency_incomplete",
                        "message": f"waiting for upstream handoff(s) to complete: {', '.join(pending)}; "
                                   f"commit again once they are COMPLETED"})
    if unknown:
        reasons.append({"state": "blocked", "code": "dependency_unknown",
                        "message": f"depends_on names key(s) this ledger has never claimed: "
                                   f"{', '.join(unknown)}; the upstream handoff must be claimed and "
                                   f"completed in the same ledger first"})
    return {"decision": "REJECT", "state": "blocked", "reasons": reasons} if reasons else None


UNPLANNED_APPROVAL_PINS = ("commit",)  # params an approval may pin that the plan cannot


def validate(packet: dict, *, registry: dict | None, ledger: dict,
             workspace: Path | None, at: dt.datetime,
             reserve_ttl_hours: float = 24.0, info: dict | None = None,
             verify_evidence: bool = False, extra_approvals: list | None = None,
             defer_approvals=None, as_receiver: str | None = None) -> tuple[bool, list]:
    """Validate one packet (sections 6-7 of SPEC.md).

    v0.5, both default off: `extra_approvals` are signed approvals for this
    handoff that arrived outside the packet (detached), checked exactly like
    embedded ones; `defer_approvals` names planned actions whose approval may
    still be missing (whatever performs them must check it at commit time),
    so a missing approval for them is recorded in info["approvals_deferred"]
    instead of failing."""
    reasons: list = []
    info = {} if info is None else info
    h_signed = packet.get("handoff") if isinstance(packet, dict) else None
    if not isinstance(h_signed, dict):
        fail("invalid", "missing_handoff", "packet must contain a 'handoff' object", reasons)
        return False, reasons
    # Work on a copy: receiver defaults never alter the bytes the sender signed.
    h = copy.deepcopy(h_signed)
    policy = receiver_policy(registry, h.get("to")) if isinstance(h.get("to"), str) else None
    applied = apply_receiver_defaults(h, policy)
    if applied:
        info["defaults_applied"] = applied
    info["_effective"] = h  # defaults applied; internal, never part of a verdict

    # 1. structural / required fields
    for field in REQUIRED:
        if field not in h or h[field] in (None, ""):
            fail("invalid", f"missing_field:{field}", f"required field missing: {field}", reasons)
    if reasons:
        return False, reasons
    if h["schema_version"] != "0.1":
        fail("invalid", "bad_schema_version", f"unsupported schema_version: {h['schema_version']}", reasons)
    if h["on_failure"] not in {"reject", "retry_with_budget", "escalate", "request_human"}:
        fail("invalid", "bad_on_failure", f"unknown on_failure: {h['on_failure']}", reasons)
    for name in ("id", "idempotency_key", "trace_id", "from", "to", "purpose"):
        if not isinstance(h[name], str):
            fail("invalid", f"malformed:{name}", f"{name} must be a string", reasons)
    if as_receiver is not None and h.get("to") != as_receiver:
        fail("invalid", "receiver_mismatch",
             f"handoff is addressed to {h.get('to')!r}, not the authenticated receiver {as_receiver!r}", reasons)

    scope, auth, acc = h["scope"], h["authority"], h["acceptance"]
    for d, name in ((scope, "scope"), (auth, "authority"), (acc, "acceptance"), (h["inputs"], "inputs")):
        if not isinstance(d, dict):
            fail("invalid", f"malformed:{name}", f"{name} must be an object", reasons)
    if reasons:
        return False, reasons

    nested = [
        ("inputs.state_revision", h["inputs"].get("state_revision")),
        ("inputs.artifact_refs", h["inputs"].get("artifact_refs")),
        ("scope.owned_paths", scope.get("owned_paths")),
        ("scope.forbidden", scope.get("forbidden")),
        ("authority.allowed_tools", auth.get("allowed_tools")),
        ("authority.approval_required_for", auth.get("approval_required_for")),
        ("acceptance.output_schema", acc.get("output_schema")),
        ("acceptance.required_evidence", acc.get("required_evidence")),
        ("acceptance.expires_at", acc.get("expires_at")),
    ]
    allow_empty = {"scope.forbidden", "scope.owned_paths", "authority.approval_required_for"}
    for name, value in nested:
        if value is None or value == "" or (value == [] and name not in allow_empty):
            fail("invalid", f"missing_field:{name}", f"required field missing: {name}", reasons)
    budget = auth.get("budget")
    if not isinstance(budget, dict) or any(
            isinstance(budget.get(k), bool) or not isinstance(budget.get(k), (int, float))
            for k in ("tokens", "usd", "minutes")):
        fail("invalid", "missing_field:authority.budget",
             "authority.budget must define numeric tokens, usd, and minutes", reasons)
    if reasons:
        return False, reasons
    for code, msg in _shape_errors(h):
        fail("invalid", code, msg, reasons)
    if policy and policy.get("require_planned_actions") and not h.get("planned_actions"):
        fail("invalid", "planned_actions_missing",
             "receiver policy requires planned_actions: authority cannot be checked "
             "against actions the sender did not declare", reasons)
    if reasons:
        return False, reasons

    # 2. identity (canonical registry; aliases must resolve) + signature
    if registry is not None:
        agents = registry.get("agents", {})
        for role in ("from", "to"):
            who = h[role]
            if who not in agents:
                fail("invalid", f"unknown_agent:{role}", f"{role} '{who}' is not in the agent registry", reasons)
            elif agents[who].get("alias_of"):
                fail("invalid", f"alias_not_canonical:{role}",
                     f"{role} '{who}' is an alias of '{agents[who]['alias_of']}'; use the canonical id", reasons)
    _verify_packet_signature(packet, h_signed, registry, policy, reasons, info)

    # 3. duplication (idempotency claim state machine)
    key = h["idempotency_key"]
    prev = ledger.get(key)
    if isinstance(prev, dict) and prev.get("state") == "RELEASED":
        prev = None  # reconciled and reopened by the operator (see release())
    if prev is not None:
        if not isinstance(prev, dict):
            prev = {}
        if entry_state(prev) == "COMPLETED":
            same = prev.get("handoff_id") == h["id"] and prev.get("trace_id") == h["trace_id"]
            when = prev.get("completed_at") or prev.get("accepted_at") or "an earlier run"
            fail("duplicate" if same else "conflicting", "duplicate_idempotency_key",
                 f"idempotency_key already completed by handoff {prev.get('handoff_id')} at {when}",
                 reasons)
        else:  # RESERVED: claimed at ACCEPT, effect not yet confirmed
            claimed_at = prev.get("reserved_at") or prev.get("accepted_at")
            claimed = parse_ts(claimed_at) if claimed_at else None
            if claimed is not None and claimed.tzinfo is None:
                claimed = claimed.replace(tzinfo=dt.timezone.utc)
            fresh = claimed is not None and (at - claimed) <= dt.timedelta(hours=reserve_ttl_hours)
            if fresh:
                fail("duplicate", "idempotency_key_reserved",
                     f"idempotency_key claimed by handoff {prev.get('handoff_id')} at {claimed_at} "
                     f"and not yet completed; reconcile before redispatch", reasons)
            else:
                fail("unknown", "unknown_outcome",
                     f"idempotency_key claimed by handoff {prev.get('handoff_id')} at {claimed_at} "
                     f"and never completed; the receiver may have crashed before or after the "
                     f"effect, so reconcile against the receiver's effect receipt before redispatch",
                     reasons)

    # 3b. (v0.5) wait-for cycles and exclusive paths. Both read the ledger, so
    #     check() runs them under its lock, atomically with the claim itself.
    #     Unmet dependencies do not block a claim (the receiver may work
    #     ahead); they block the commit (fenced / fenced_effect / complete).
    cycle = _dependency_cycle(ledger, key, h.get("depends_on"))
    if cycle:
        fail("invalid", "dependency_cycle",
             f"depends_on forms a wait-for cycle ({' -> '.join(cycle)}); no handoff in it "
             f"could ever commit", reasons)
    if policy and policy.get("exclusive_paths"):
        for other, entry, pairs in _path_conflicts(ledger, h, key):
            shown = ", ".join(f"{a} ~ {b}" for a, b in pairs[:5])
            fail("blocked", "claim_conflict",
                 f"receiver '{h['to']}' requires exclusive paths and handoff {entry.get('handoff_id')} "
                 f"(key {other}) holds a live claim that may touch the same files ({shown}); "
                 f"claim again once it completes or is released", reasons)

    # 4. freshness
    exp, why = parse_utc(acc["expires_at"])
    if exp is None:
        fail("invalid", "bad_expires_at", f"acceptance.expires_at: {why}", reasons)
    elif exp <= at:
        fail("stale", "handoff_expired", f"handoff expired at {acc['expires_at']}", reasons)
    max_ttl = (policy or {}).get("max_ttl_hours")
    if (max_ttl is not None and not _is_number(max_ttl)) or (_is_number(max_ttl) and max_ttl <= 0):
        fail("invalid", "registry_malformed",
             "receiver policy max_ttl_hours must be a positive number of hours", reasons)
    elif max_ttl is not None and exp is not None and (exp - at).total_seconds() > max_ttl * 3600:
        fail("invalid", "ttl_exceeded",
             f"handoff stays valid until {acc['expires_at']}, longer than this receiver's maximum "
             f"of {max_ttl} hours from now; a long-lived handoff is a bearer token for whoever "
             f"holds its bytes", reasons)

    # 5. authority: planned actions vs tools / forbidden / approvals / budget,
    #    with the receiver policy as a ceiling the packet can only narrow.
    pol = policy or {}
    forbidden = set(scope.get("forbidden", [])) | set(pol.get("forbidden", []))
    allowed = set(auth.get("allowed_tools", []))
    ceiling_tools = set(pol["allowed_tools"]) if "allowed_tools" in pol else None
    needs_approval = set(auth.get("approval_required_for", [])) | set(pol.get("approval_required_for", []))
    if ceiling_tools is not None and allowed - ceiling_tools:
        fail("blocked", "authority_exceeds_receiver_policy",
             f"packet grants tools the receiver never allows: {sorted(allowed - ceiling_tools)}", reasons)
    approvals_by_action: dict = {}
    # Detached approvals count only when signed: anyone could write an unsigned one.
    detached = [a for a in extra_approvals or [] if isinstance(a, dict) and a.get("sig") and a.get("action")]
    for a in (auth.get("approvals", []) or []) + detached:
        approvals_by_action.setdefault(a["action"], []).append(a)
    defer = set(defer_approvals or ())
    est = {"tokens": 0.0, "usd": 0.0, "minutes": 0.0}
    for act in h.get("planned_actions", []) or []:
        name, tool = act["name"], act["tool"]
        if tool not in allowed:
            fail("blocked", "tool_not_allowed", f"action '{name}' uses tool '{tool}' not in allowed_tools", reasons)
        elif ceiling_tools is not None and tool not in ceiling_tools:
            fail("blocked", "tool_not_allowed_by_receiver",
                 f"action '{name}' uses tool '{tool}' that receiver policy does not allow", reasons)
        if name in forbidden or tool in forbidden:
            fail("blocked", "forbidden_action", f"action '{name}' is forbidden by scope", reasons)
        if name in needs_approval or tool in needs_approval:
            cands = approvals_by_action.get(name, []) + (
                approvals_by_action.get(tool, []) if tool != name else [])
            # v0.4: an approval that pins params covers only a plan with those
            # params (the sender cannot retarget an approved action).
            planned_params = act.get("params") if isinstance(act.get("params"), dict) else {}
            # `commit` can be pinned by the approver but never by the sender's plan (the
            # commit does not exist yet); the effect executor enforces it at commit time.
            fitting = [a for a in cands if not isinstance(a.get("params"), dict)
                       or all(k in UNPLANNED_APPROVAL_PINS or planned_params.get(k) == v
                              for k, v in a["params"].items())]
            problems: list = []
            if not cands:
                problems = [("approval_missing", f"action '{name}' needs approval; none recorded")]
            elif not fitting:
                problems = [("approval_params_mismatch",
                             f"approvals for '{name}' pin params the plan does not have "
                             f"(approved {cands[0].get('params')}, planned {planned_params})")]
            else:
                problems = _approval_ok(name, fitting, h, registry, policy, at)
            if problems and not cands and name in defer:
                info.setdefault("approvals_deferred", []).append(name)
                problems = []
            if problems:
                info.setdefault("approval_problems", {})[name] = [c for c, _ in problems]
            for code, msg in problems:
                fail("blocked", code, msg, reasons)
        for k in est:
            est[k] += float(act.get(f"est_{k}", 0) or 0)
    ceiling_budget = pol.get("budget") or {}
    for k in ("tokens", "usd", "minutes"):
        limit = float(budget[k])
        if k in ceiling_budget:
            if limit > float(ceiling_budget[k]):
                fail("blocked", "authority_exceeds_receiver_policy",
                     f"packet budget {k} {budget[k]} exceeds receiver ceiling {ceiling_budget[k]}", reasons)
            limit = min(limit, float(ceiling_budget[k]))
        if est[k] > limit:
            fail("blocked", "budget_exceeded", f"estimated {k} {est[k]} exceeds budget {limit:g}", reasons)

    # 6. artifacts: existence + hash (when a workspace root is given)
    if workspace is None and pol and h["inputs"].get("artifact_refs"):
        # Fail closed: a receiver with a policy expects its pins to hold, and
        # without a workspace root the artifact hashes cannot be checked.
        fail("invalid", "workspace_required",
             "receiver policy is in force but no workspace root was given, so the "
             "pinned artifact hashes cannot be checked; run the checker with --workspace",
             reasons)
    if workspace is not None:
        for ref in h["inputs"].get("artifact_refs", []):
            p = resolve_in_workspace(workspace, ref["path"])
            if p is None:
                fail("invalid", "artifact_path_escapes_workspace",
                     f"artifact path is absolute or escapes the workspace: {ref['path']}", reasons)
            elif not p.is_file():
                fail("incomplete", "artifact_missing", f"input artifact not found: {ref['path']}", reasons)
            elif ref.get("sha256") and sha256_file(p) != ref["sha256"].lower():
                fail("stale", "artifact_hash_mismatch", f"artifact changed since handoff: {ref['path']}", reasons)

    # 7. evidence fidelity + completeness
    evidence = acc.get("evidence", []) or []
    kinds = {e.get("kind") for e in evidence}
    for req in acc.get("required_evidence", []):
        if req not in kinds:
            fail("incomplete", "evidence_missing", f"required evidence missing: {req}", reasons)
    for e in evidence:
        if e.get("kind") in VERBATIM_KINDS and e.get("verbatim") is not True:
            fail("invalid", "evidence_not_verbatim",
                 f"evidence '{e.get('kind')}' must be verbatim, not a paraphrase/summary", reasons)
    if verify_evidence or pol.get("verify_evidence"):
        # Evidence is only as good as the bytes it points at: every item must
        # reference a workspace file, and verbatim items must pin its hash.
        if workspace is None and evidence:
            # Fail closed: without a workspace root the pinned hashes cannot
            # be checked, so the policy's guarantee would silently not hold.
            fail("invalid", "workspace_required",
                 "evidence verification is required but no workspace root was given; "
                 "run the checker with --workspace", reasons)
        for i, e in enumerate(evidence):
            if e.get("kind") in VERBATIM_KINDS and not e.get("sha256"):
                fail("invalid", "verbatim_evidence_unpinned",
                     f"evidence[{i}] '{e.get('kind')}' claims verbatim but pins no sha256; "
                     f"'verbatim' is unverifiable without the hash of the quoted source", reasons)
            ref = e.get("ref")
            if not ref:
                fail("incomplete", "evidence_unreferenced",
                     f"evidence[{i}] '{e.get('kind')}' has no ref; nothing to verify", reasons)
                continue
            if workspace is None:
                continue
            p = resolve_in_workspace(workspace, ref.split("#", 1)[0])
            if p is None:
                fail("invalid", "evidence_path_escapes_workspace",
                     f"evidence[{i}] ref is absolute or escapes the workspace: {ref}", reasons)
            elif not p.is_file():
                fail("incomplete", "evidence_ref_missing", f"evidence[{i}] ref not found: {ref}", reasons)
            elif e.get("sha256") and sha256_file(p) != e["sha256"].lower():
                fail("stale", "evidence_hash_mismatch",
                     f"evidence[{i}] bytes do not match the pinned sha256: {ref}", reasons)

    return not reasons, reasons


def _reject(state: str, code: str, message: str) -> dict:
    return {"decision": "REJECT", "state": state,
            "reasons": [{"state": state, "code": code, "message": message}]}


def _result(ok: bool, reasons: list, h: dict, info: dict) -> dict:
    if ok:
        out = {"decision": "ACCEPT", "handoff_id": h.get("id"), "trace_id": h.get("trace_id")}
    else:
        out = {"decision": "REJECT", "state": reasons[0]["state"], "reasons": reasons}
    if info.get("defaults_applied"):
        out["defaults_applied"] = info["defaults_applied"]
    if info.get("signature") == "verified":
        out["signature"] = "verified"
    if info.get("approvals_deferred"):  # v0.5, only when the caller deferred them
        out["approvals_deferred"] = list(info["approvals_deferred"])
    return out


def check(packet, *, registry: dict | None, ledger_path: Path | None,
          workspace: Path | None, dry_run: bool = False,
          reserve_ttl_hours: float = 24.0, verify_evidence: bool = False,
          extra_approvals: list | None = None, defer_approvals=None,
          as_receiver: str | None = None) -> dict:
    """Validate a packet and (unless dry_run) atomically record a RESERVED
    claim on ACCEPT. Returns the verdict as a dict. Used by the CLI, the GitHub
    Action and every integration, so every entry point shares one code path."""
    if not isinstance(packet, dict):
        return _reject("invalid", "missing_handoff", "packet must be a JSON object with a 'handoff' object")
    bad = _non_finite_reject(packet)
    if bad:
        return bad
    h = packet.get("handoff") if isinstance(packet.get("handoff"), dict) else {}
    info: dict = {}
    kwargs = dict(registry=registry, workspace=workspace, at=now_utc(),
                  reserve_ttl_hours=reserve_ttl_hours, info=info,
                  verify_evidence=verify_evidence, extra_approvals=extra_approvals,
                  defer_approvals=defer_approvals, as_receiver=as_receiver)
    if ledger_path is not None and not dry_run:
        # Atomic claim: validate and record RESERVED under one lock, so two
        # concurrent presentations of the same key cannot both pass.
        with LockedLedger(ledger_path) as locked:
            ledger = locked.ledger
            if ledger.get("_corrupt"):
                return _reject("invalid", "ledger_corrupt", "ledger file is not valid JSON")
            ok, reasons = validate(packet, ledger=ledger, **kwargs)
            if not ok:
                return _result(ok, reasons, h, info)
            # The claim is bound to this exact packet (digest) and to whoever
            # holds the token returned below. `epoch` is the fencing number:
            # it rises every time the key is re-claimed after a release, so a
            # stale holder's fenced() effect is refused (found by model checking).
            prev = ledger.get(h["idempotency_key"])
            epoch = (prev.get("epoch", 0) if isinstance(prev, dict) else 0) + 1
            # Never starts with "-": argparse reads a leading "-" value as an option, so a
            # token like "-x3k..." (1 in 64 urlsafe tokens) broke `--claim-token TOKEN` in
            # every CLI that takes it, and made test_cli_push_and_receipts_verify flaky.
            token = "ct_" + secrets.token_urlsafe(24)
            effective = info.get("_effective") or h
            ledger[h["idempotency_key"]] = {
                "state": "RESERVED",
                "handoff_id": h["id"],
                "trace_id": h["trace_id"],
                "from": h["from"],
                "to": h["to"],
                "reserved_at": now_utc().isoformat(),
                "signature": info.get("signature", "absent"),
                "epoch": epoch,
                "packet_sha256": handoff_digest(h),
                "claim_token_sha256": _token_hash(token),
                # v0.5: what this claim may touch (receiver defaults applied),
                # for exclusive_paths, and what it waits for.
                "owned_paths": list((effective.get("scope") or {}).get("owned_paths") or []),
            }
            if h.get("depends_on"):
                ledger[h["idempotency_key"]]["depends_on"] = list(h["depends_on"])
            if info.get("approvals_deferred"):
                ledger[h["idempotency_key"]]["approvals_deferred"] = list(info["approvals_deferred"])
            locked.dirty = True
            out = _result(ok, reasons, h, info)
            out["claim"] = {"epoch": epoch, "token": token}
            return out
    ledger = load_ledger(ledger_path) if ledger_path else {}
    if ledger.get("_corrupt"):
        return _reject("invalid", "ledger_corrupt", "ledger file is not valid JSON")
    ok, reasons = validate(packet, ledger=ledger, **kwargs)
    return _result(ok, reasons, h, info)


def _claim_problem(entry, h: dict, claim_token: str | None, require_token: bool):
    """Why `h` (+ token) may NOT act on this ledger entry, or None. Shared by
    complete() and fenced(): only the claim's own packet, and its token
    holder when tokens are in use, may complete it or run its effect."""
    key = h.get("idempotency_key")
    if entry is None or entry_state(entry) == "RELEASED":
        return _reject("invalid", "completion_unknown_key",
                       f"no live ledger claim for idempotency_key '{key}'; "
                       f"nothing is reserved under this key")
    if entry.get("handoff_id") not in (None, h.get("id")):
        return _reject("conflicting", "completion_handoff_mismatch",
                       f"idempotency_key '{key}' was claimed by handoff "
                       f"{entry.get('handoff_id')}, not {h.get('id')}")
    if entry.get("packet_sha256") and handoff_digest(h) != entry["packet_sha256"]:
        return _reject("conflicting", "completion_packet_mismatch",
                       f"this is not the packet that claimed idempotency_key '{key}' "
                       f"(digest differs); only the claimed packet can complete it")
    want = entry.get("claim_token_sha256")
    if want and claim_token is not None:
        if not hmac.compare_digest(_token_hash(str(claim_token)), want):
            return _reject("conflicting", "claim_token_invalid",
                           f"claim token does not match the claim on '{key}'")
    elif want and require_token:
        return _reject("invalid", "claim_token_required",
                       f"completing '{key}' requires the claim token returned with its ACCEPT")
    return None


def complete(packet, ledger_path: Path | None, claim_token: str | None = None,
             require_token: bool = False) -> dict:
    """Flip the packet's idempotency-key entry RESERVED -> COMPLETED.

    Run by the receiver after it has actually performed the effect. Safe to
    re-run: completing an already-COMPLETED entry is a no-op success. Only
    the packet that made the claim can complete it (digest-bound), and when
    `claim_token` is given or `require_token` is set, only the holder of the
    token the ACCEPT returned. (v0.3 matched on key + id alone, so any agent
    that had seen the packet could close someone else's claim; a model check
    found it.)
    """
    h = packet.get("handoff") if isinstance(packet, dict) else None
    if not isinstance(h, dict) or not h.get("idempotency_key"):
        return _reject("invalid", "missing_idempotency_key",
                       "packet must contain a 'handoff' object with an idempotency_key")
    bad = _non_finite_reject(packet)
    if bad:
        return bad
    if not ledger_path:
        return _reject("invalid", "ledger_required",
                       "--complete requires --ledger (the claim lives there)")
    key = h["idempotency_key"]
    with LockedLedger(Path(ledger_path)) as locked:
        ledger = locked.ledger
        if ledger.get("_corrupt"):
            return _reject("invalid", "ledger_corrupt", "ledger file is not valid JSON")
        entry = ledger.get(key)
        problem = _claim_problem(entry, h, claim_token, require_token)
        if problem:
            return problem
        if entry_state(entry) == "COMPLETED":
            return {"decision": "COMPLETED", "handoff_id": h.get("id"),
                    "trace_id": h.get("trace_id"), "idempotency_key": key,
                    "note": "already completed; no-op"}
        problem = _dependency_problem(ledger, h, entry)
        if problem:
            return problem
        entry["state"] = "COMPLETED"
        entry["completed_at"] = now_utc().isoformat()
        locked.dirty = True
        return {"decision": "COMPLETED", "handoff_id": h.get("id"),
                "trace_id": h.get("trace_id"), "idempotency_key": key}


def release(packet, ledger_path: Path | None, reserve_ttl_hours: float = 24.0,
            force: bool = False) -> dict:
    """Operator reconcile for an `unknown` claim whose effect is NOT on
    record: reopen the key for redispatch. The next claim gets a higher
    epoch, so the old holder can no longer run a fenced() effect or
    complete. Refuses a claim still inside its TTL unless `force` (use it
    only when you know the old holder is gone)."""
    h = packet.get("handoff") if isinstance(packet, dict) else None
    if not isinstance(h, dict) or not h.get("idempotency_key"):
        return _reject("invalid", "missing_idempotency_key",
                       "packet must contain a 'handoff' object with an idempotency_key")
    bad = _non_finite_reject(packet)
    if bad:
        return bad
    if not ledger_path:
        return _reject("invalid", "ledger_required", "--release requires --ledger")
    key = h["idempotency_key"]
    with LockedLedger(Path(ledger_path)) as locked:
        ledger = locked.ledger
        if ledger.get("_corrupt"):
            return _reject("invalid", "ledger_corrupt", "ledger file is not valid JSON")
        entry = ledger.get(key)
        if not isinstance(entry, dict) or entry_state(entry) != "RESERVED":
            return _reject("invalid", "release_not_reserved",
                           f"idempotency_key '{key}' has no RESERVED claim to release")
        claimed = parse_ts(entry.get("reserved_at") or entry.get("accepted_at") or "")
        if claimed is not None and claimed.tzinfo is None:
            claimed = claimed.replace(tzinfo=dt.timezone.utc)
        fresh = claimed is not None and (now_utc() - claimed) <= dt.timedelta(hours=reserve_ttl_hours)
        if fresh and not force:
            return _reject("duplicate", "release_claim_fresh",
                           f"claim on '{key}' is younger than the {reserve_ttl_hours:g}h TTL; its "
                           f"holder may still act. Wait, or --force if you know it is gone")
        entry["state"] = "RELEASED"
        entry["released_at"] = now_utc().isoformat()
        locked.dirty = True
        return {"decision": "RELEASED", "idempotency_key": key, "epoch": entry.get("epoch", 0),
                "note": "key reopened; the next claim gets a higher epoch"}


class FenceError(Exception):
    """fenced() refused: the claim is no longer this caller's to act on."""

    def __init__(self, verdict: dict):
        super().__init__(verdict["reasons"][0]["message"])
        self.verdict = verdict


@contextlib.contextmanager
def fenced(packet, ledger_path, claim_token: str, complete_on_success: bool = True):
    """Execution boundary for a non-idempotent effect:

        with fenced(packet, "ledger.json", verdict["claim"]["token"]):
            send_the_email()

    The body runs under the ledger lock, and only while this exact claim is
    still RESERVED for this token; on normal exit it is flipped to
    COMPLETED in the same critical section. If the body raises, the claim
    stays RESERVED (outcome unknown) and the exception propagates. Model
    checking showed that without this, a slow receiver whose claim was
    released and redispatched performs the effect twice.
    The lock is held for the duration of the effect, so keep it short.
    v0.5: refused while any depends_on key is not COMPLETED."""
    h = packet.get("handoff") if isinstance(packet, dict) else None
    if not isinstance(h, dict) or not h.get("idempotency_key"):
        raise FenceError(_reject("invalid", "missing_idempotency_key",
                                 "packet must contain a 'handoff' object with an idempotency_key"))
    with LockedLedger(Path(ledger_path)) as locked:
        entry = locked.ledger.get(h["idempotency_key"])
        problem = _claim_problem(entry, h, claim_token, require_token=True)
        if problem is None and entry_state(entry) != "RESERVED":
            problem = _reject("duplicate", "duplicate_idempotency_key",
                              f"idempotency_key '{h['idempotency_key']}' is already {entry_state(entry)}")
        if problem is None:
            problem = _dependency_problem(locked.ledger, h, entry)
        if problem:
            raise FenceError(problem)
        yield entry.get("epoch", 0)
        if complete_on_success:
            entry["state"] = "COMPLETED"
            entry["completed_at"] = now_utc().isoformat()
            locked.dirty = True


@contextlib.contextmanager
def fenced_effect(packet, ledger_path, claim_token: str, action: str, final_actions=()):
    """fenced() for one named effect of a multi-effect handoff (v0.4, for an
    effect executor). Yields a dict the body fills with what it observed; on normal
    exit that record is stored under entry["effects"][action] in the same
    critical section, and the claim flips to COMPLETED once every action in
    `final_actions` has an EXECUTED record. Refuses (FenceError) when the
    claim is not this token's, not RESERVED, or `action` was already
    executed or left with an unknown outcome, or (v0.5) while any
    depends_on key is not COMPLETED. If the body sets record["state"] to
    something other than EXECUTED, it is stored as-is (e.g. UNCONFIRMED)
    and the claim stays RESERVED."""
    h = packet.get("handoff") if isinstance(packet, dict) else None
    if not isinstance(h, dict) or not h.get("idempotency_key"):
        raise FenceError(_reject("invalid", "missing_idempotency_key",
                                 "packet must contain a 'handoff' object with an idempotency_key"))
    with LockedLedger(Path(ledger_path)) as locked:
        if locked.ledger.get("_corrupt"):
            raise FenceError(_reject("invalid", "ledger_corrupt", "ledger file is not valid JSON"))
        entry = locked.ledger.get(h["idempotency_key"])
        problem = _claim_problem(entry, h, claim_token, require_token=True)
        if problem is None and entry_state(entry) != "RESERVED":
            problem = _reject("duplicate", "duplicate_idempotency_key",
                              f"idempotency_key '{h['idempotency_key']}' is already {entry_state(entry)}")
        prior = (entry.get("effects") or {}).get(action) if problem is None else None
        if prior is not None and prior.get("state") == "EXECUTED":
            problem = _reject("duplicate", "effect_already_executed",
                              f"effect '{action}' already executed for this handoff "
                              f"(receipt {prior.get('receipt_seq')})")
        elif prior is not None:
            problem = _reject("unknown", "effect_outcome_unknown",
                              f"effect '{action}' was attempted with outcome {prior.get('state')}; "
                              f"reconcile before retrying")
        if problem is None:
            problem = _dependency_problem(locked.ledger, h, entry)
        if problem:
            raise FenceError(problem)
        record: dict = {"state": "EXECUTED", "epoch": entry.get("epoch", 0)}
        yield record
        record.setdefault("at", now_utc().isoformat())
        entry.setdefault("effects", {})[action] = record
        done = {a for a, r in entry["effects"].items() if r.get("state") == "EXECUTED"}
        if final_actions and set(final_actions) <= done:
            entry["state"] = "COMPLETED"
            entry["completed_at"] = now_utc().isoformat()
        locked.dirty = True


def exit_code(result: dict) -> int:
    return 0 if result.get("decision") in ("ACCEPT", "COMPLETED", "RELEASED") else 2


def load_registry(path) -> tuple[dict | None, dict | None]:
    """Return (registry, None) or (None, reject_result)."""
    if not path:
        return None, None
    try:
        reg = strict_loads(Path(path).read_text())
    except (OSError, ValueError) as exc:  # ValueError covers JSONDecodeError and StrictJSONError
        return None, _reject("invalid", "registry_unreadable", f"cannot read registry: {exc}")
    if not isinstance(reg, dict) or not isinstance(reg.get("agents", {}), dict):
        return None, _reject("invalid", "registry_malformed", "registry must be an object with an 'agents' object")
    return reg, None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Handoff Contract validator (packet wire format v0.1; v0.2 claim ledger; "
                    "v0.3 receiver policy + signatures)")
    ap.add_argument("packet", help="handoff packet JSON file")
    ap.add_argument("--registry", help="agent registry JSON (canonical ids, aliases, keys, policy)")
    ap.add_argument("--ledger", help="idempotency ledger JSON file (created if absent)")
    ap.add_argument("--workspace", help="workspace root for artifact existence/hash checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate only; do not record a RESERVED claim in the ledger")
    ap.add_argument("--complete", action="store_true",
                    help="mark this packet's idempotency key COMPLETED in the ledger "
                         "(run after the receiver performs the effect); requires --ledger")
    ap.add_argument("--claim-token",
                    help="with --complete: the claim token the ACCEPT returned (binds completion "
                         "to the claimant)")
    ap.add_argument("--release", action="store_true",
                    help="operator: reopen an expired RESERVED claim whose effect is NOT on record "
                         "(the next claim gets a higher epoch); requires --ledger")
    ap.add_argument("--force", action="store_true",
                    help="with --release: release even inside the TTL (holder known to be gone)")
    ap.add_argument("--reserve-ttl-hours", type=float, default=24.0,
                    help="hours a RESERVED claim stays fresh before a re-presentation "
                         "flips to UNKNOWN (default: 24)")
    ap.add_argument("--verify-evidence", action="store_true",
                    help="require every evidence item to reference a workspace file and "
                         "check pinned sha256 hashes (also enabled by registry policy)")
    ap.add_argument("--as-receiver", help="authenticated receiver identity; reject packets addressed elsewhere")
    args = ap.parse_args(argv)

    try:
        packet = strict_loads(Path(args.packet).read_text())
    except StrictJSONError as exc:
        result = _reject("invalid", exc.code, f"packet refused: {exc}")
    except (OSError, ValueError) as exc:  # ValueError covers JSONDecodeError and oversized integers
        result = _reject("invalid", "packet_unreadable", f"cannot read packet: {exc}")
    else:
        if args.complete:
            result = complete(packet, Path(args.ledger) if args.ledger else None,
                              claim_token=args.claim_token)
        elif args.release:
            result = release(packet, Path(args.ledger) if args.ledger else None,
                             reserve_ttl_hours=args.reserve_ttl_hours, force=args.force)
        else:
            registry, err = load_registry(args.registry)
            result = err or check(
                packet, registry=registry,
                ledger_path=Path(args.ledger) if args.ledger else None,
                workspace=Path(args.workspace) if args.workspace else None,
                dry_run=args.dry_run, reserve_ttl_hours=args.reserve_ttl_hours,
                verify_evidence=args.verify_evidence, as_receiver=args.as_receiver)
    print(json.dumps(result, indent=2))
    return exit_code(result)


if __name__ == "__main__":
    sys.exit(main())
