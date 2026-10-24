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
        # Re-seal the chain over the full table (one scan): the header row is
        # written in the same transaction. Skipped when the current seal
        # already covers these exact rows (e.g. nothing changed since adopt).
        rows = self.conn.execute("SELECT key, value FROM claims").fetchall()
        data = {k: json.loads(v) for k, v in rows}
        if not _seal_is_current(data, data.get(LEDGER_META_KEY)):
            seal_ledger(data)
            self.conn.execute("INSERT INTO claims(key, value) VALUES (?, ?) "
                              "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                              (LEDGER_META_KEY, json.dumps(data[LEDGER_META_KEY],
                                                           sort_keys=True, separators=(",", ":"))))
        self.dirty_keys.clear()


def load_ledger(path: Path) -> dict:
    if sqlite_ledger(path):
        if not path or not Path(path).exists():
            return {}
        try:
            conn = _sqlite_connect(Path(path))
            conn.execute("SELECT key FROM claims LIMIT 1").fetchone()
            conn.close()
            # SQLite stays lazy: the seal + anchor are verified when the
            # ledger is locked for mutation (LockedLedger.__enter__); see
            # _sqlite_verify_and_anchor. Read-only callers get raw rows.
            return SQLiteLedger(Path(path))
        except (OSError, sqlite3.DatabaseError):
            return _corrupt_marker("ledger_corrupt", "ledger database is not readable")
    if path and path.exists():
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            return _corrupt_marker("ledger_corrupt", "ledger file is not valid JSON")
        if not isinstance(data, dict):
            return _corrupt_marker("ledger_corrupt", "ledger file must contain a JSON object")
        return _verify_json_ledger(data, path)
    # Missing file: a fresh chain starts here -- unless an out-of-cache
    # anchor says a chain already exists (rollback/deletion guard).
    ok, code, message = check_ledger_anchor(exists=False, sealed=False)
    if not ok:
        return _corrupt_marker(code, message)
    return {}


def save_ledger(path: Path, ledger: dict) -> None:
    """Write the ledger atomically: temp file in the same dir + os.replace,
    so a concurrent reader never observes a torn file. Every save (re-)seals
    the chain -- skipped only when the current seal already covers these
    exact entries -- so every persisted state is verifiable. Never persists
    a fail-closed corrupt marker."""
    if not isinstance(ledger, dict) or ledger.get("_corrupt"):
        raise ValueError("refusing to persist a corrupt ledger")
    if not _seal_is_current(ledger, ledger.get(LEDGER_META_KEY)):
        seal_ledger(ledger)
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
        raise ValueError(f"source ledger is corrupt: {ledger.get('_corrupt_reason')}: "
                         f"{ledger.get('_corrupt_message')}")
    save_ledger(destination, ledger)
    copied = load_ledger(destination)
    if copied.get("_corrupt") or _ledger_claims(copied) != _ledger_claims(ledger):
        raise ValueError("ledger migration verification failed")
    return {"source": str(source), "destination": str(destination),
            "entries": len(_ledger_claims(ledger))}


# ---------------------------------------------------------------------------
# Ledger integrity binding (v2): HMAC-sealed hash chain + out-of-cache anchor.
#
# Every ledger write seals a chain header under the reserved top-level key
# "~synthe" -- the ONE reserved namespace for chain metadata in the ledger
# file (idempotency keys may not start with "~"; see validate()). The header's
# chain_head is a hash-chain link over (chain_seq, chain_prev, entries):
#
#   head_n = MAC("synthe-ledger-chain/v2" || seq_n || head_{n-1} || canonical(entries_n))
#
# MAC is HMAC-SHA256 keyed by the SYNTHE_LEDGER_HMAC_KEY environment variable
# when set -- a CI secret is the intended home -- and plain SHA-256 otherwise.
# Without the key the seal detects accidental corruption (bit-rot, hand
# edits, truncation, torn writes) but NOT forgery by someone who can write the
# file; the header records chain_keyed so a keyed seal and an unkeyed seal are
# never mixed (mixing fails closed as ledger_corrupt). Key rotation is
# supported via SYNTHE_LEDGER_HMAC_KEY_PREVIOUS: verification accepts either
# key, sealing always uses the current one, so a rotation heals on next save.
#
# Rollback -- a stale cache restoring an older snapshot, a forged empty
# ledger, a deleted file -- is not detectable from the file alone, so the
# chain also carries a monotonic chain_seq that is checked against an anchor
# stored OUTSIDE the cache: the SYNTHE_LEDGER_ANCHOR environment variable
# ("seq:head"), which the GitHub Action populates from the
# SYNTHE_LEDGER_ANCHOR repository variable before each run and republishes
# after it. A loaded ledger must match or extend the anchor; anything older,
# divergent, or missing fails closed with a named reason code.
#
# When no anchor is configured (local runs, tests, first run), the checker
# degrades gracefully: the seal is still verified (corruption detection), a
# legacy unsealed ledger is adopted in place as a new genesis chain -- no
# manual --adopt-legacy step -- and a warning notes that rollback is not
# provable. Set SYNTHE_LEDGER_ANCHOR_REQUIRED=1 (the Action does this whenever
# it fetched an anchor) to make a missing/unreadable anchor fail closed as
# ledger_anchor_unavailable instead. SYNTHE_LEDGER_BOOTSTRAP=1 skips anchor
# enforcement for one run (the documented recovery after a total cache
# eviction); the chain restarts and the anchor is republished.
# ---------------------------------------------------------------------------

LEDGER_CHAIN_FORMAT = "synthe-ledger-chain/v2"
LEDGER_META_KEY = "~synthe"  # the ONE reserved namespace for chain metadata keys
LEDGER_GENESIS_PREV = "synthe-ledger-genesis"

LEDGER_HMAC_KEY_ENV = "SYNTHE_LEDGER_HMAC_KEY"
LEDGER_HMAC_PREV_ENV = "SYNTHE_LEDGER_HMAC_KEY_PREVIOUS"
LEDGER_ANCHOR_ENV = "SYNTHE_LEDGER_ANCHOR"  # "seq:head"
LEDGER_ANCHOR_REQUIRED_ENV = "SYNTHE_LEDGER_ANCHOR_REQUIRED"
LEDGER_BOOTSTRAP_ENV = "SYNTHE_LEDGER_BOOTSTRAP"
LEDGER_ADOPT_LEGACY_ENV = "SYNTHE_LEDGER_ADOPT_LEGACY"

_truthy = {"1", "true", "yes", "on"}

_warned: set[str] = set()


def _ledger_warn(message: str) -> None:
    """Stderr warning, once per distinct message per process (the checker is
    usually one CLI invocation, so operators still see it every run)."""
    if message not in _warned:
        _warned.add(message)
        print(f"handoff_check: WARNING: {message}", file=sys.stderr)


def _is_meta_key(key) -> bool:
    """Chain-metadata namespace: reserved, never an idempotency claim."""
    return isinstance(key, str) and key.startswith("~")


def _ledger_claims(ledger: dict) -> dict:
    """The claim entries of a ledger: everything except the chain header."""
    return {k: v for k, v in ledger.items() if k != LEDGER_META_KEY}


def _corrupt_marker(code: str, message: str) -> dict:
    """Fail-closed ledger stand-in: every operation path checks `_corrupt`
    and reports the specific reason via _ledger_seal_reject()."""
    return {"_corrupt": True, "_corrupt_reason": code, "_corrupt_message": message}


def _ledger_seal_reject(ledger: dict) -> dict:
    code = ledger.get("_corrupt_reason") or "ledger_corrupt"
    message = ledger.get("_corrupt_message") or "ledger file is not valid JSON"
    return _reject("invalid", code, message)


def _hmac_keys() -> tuple[bytes | None, bytes | None]:
    """(current, previous) HMAC keys from the environment; None when unset."""
    cur = os.environ.get(LEDGER_HMAC_KEY_ENV)
    prev = os.environ.get(LEDGER_HMAC_PREV_ENV)
    return (cur.encode() if cur else None, prev.encode() if prev else None)


def _canonical_entries(entries: dict) -> bytes:
    return json.dumps(entries, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def ledger_chain_link(seq: int, prev_head: str, entries: dict,
                      key: bytes | None) -> str:
    """One hash-chain link. Keyed (HMAC-SHA256) when a key is configured,
    plain SHA-256 otherwise. The previous head is bound into the link, so
    editing it invalidates the seal."""
    msg = b"|".join((LEDGER_CHAIN_FORMAT.encode(), str(seq).encode(),
                      prev_head.encode(), _canonical_entries(entries)))
    if key is not None:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def seal_ledger(ledger: dict, *, created_by: str = "synthe") -> dict:
    """(Re-)seal a ledger dict in place: bump chain_seq, link chain_prev to
    the previous head, recompute chain_head. Unknown "~synthe" fields (e.g.
    written by other tooling) are preserved. Returns the ledger."""
    if not isinstance(ledger, dict) or ledger.get("_corrupt"):
        raise ValueError("refusing to seal a corrupt ledger")
    entries = _ledger_claims(ledger)
    old = ledger.get(LEDGER_META_KEY)
    old = old if isinstance(old, dict) else {}
    try:
        seq = int(old.get("chain_seq") or 0) + 1
    except (TypeError, ValueError):
        seq = 1
    prev = old.get("chain_head") or LEDGER_GENESIS_PREV
    key, _prev_key = _hmac_keys()
    head = ledger_chain_link(seq, prev, entries, key)
    header = dict(old)
    header.update({
        "chain_format": LEDGER_CHAIN_FORMAT,
        "chain_seq": seq,
        "chain_prev": prev,
        "chain_head": head,
        "chain_keyed": key is not None,
        "sealed_at": now_utc().isoformat(),
        "sealed_by": created_by,
    })
    ledger[LEDGER_META_KEY] = header
    return ledger


def verify_ledger_seal(ledger: dict):
    """Verify the chain seal of a ledger dict that carries a "~synthe"
    header with chain fields. Returns (ok, code, message, header,
    used_prev_key). Callers must have established that chain fields exist;
    a header without them is unsealed (legacy), not corrupt."""
    header = ledger.get(LEDGER_META_KEY)
    if not isinstance(header, dict):
        return False, "ledger_corrupt", "chain header '~synthe' is malformed", {}, False
    seq, prev, head = header.get("chain_seq"), header.get("chain_prev"), header.get("chain_head")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        return False, "ledger_corrupt", "chain header has a malformed chain_seq", header, False
    if not isinstance(prev, str) or not prev or not isinstance(head, str) or not head:
        return False, "ledger_corrupt", "chain header has a malformed chain link", header, False
    key, prev_key = _hmac_keys()
    keyed_env = key is not None
    if bool(header.get("chain_keyed", False)) != keyed_env:
        return (False, "ledger_corrupt",
                "chain seal key state does not match the environment "
                f"(header says keyed={bool(header.get('chain_keyed', False))}, "
                f"environment {'has' if keyed_env else 'has no'} {LEDGER_HMAC_KEY_ENV}); "
                "refusing to mix keyed and unkeyed seals", header, False)
    entries = _ledger_claims(ledger)
    expected = ledger_chain_link(seq, prev, entries, key)
    used_prev = False
    if not hmac.compare_digest(expected, head) and keyed_env and prev_key:
        expected = ledger_chain_link(seq, prev, entries, prev_key)
        used_prev = hmac.compare_digest(expected, head)
    if not hmac.compare_digest(expected, head):
        return (False, "ledger_corrupt",
                "chain seal mismatch: the ledger file was edited, truncated, "
                "or forged outside the checker (or the HMAC key changed without "
                f"{LEDGER_HMAC_PREV_ENV})", header, False)
    return True, "", "", header, used_prev


def _seal_is_current(ledger: dict, header) -> bool:
    """True when the ledger's seal already covers its exact entries with the
    environment's current key state (so save_ledger can skip the reseal). A
    seal made with the previous rotation key counts as stale: it verifies,
    but the next save re-seals with the current key."""
    if not isinstance(header, dict) or not isinstance(header.get("chain_head"), str):
        return False
    ok, _code, _msg, _hdr, used_prev = verify_ledger_seal(ledger)
    return ok and not used_prev


def _parse_anchor(raw: str):
    """Parse a "seq:head" anchor; None when malformed."""
    seq_s, sep, head = raw.partition(":")
    if not sep or not head:
        return None
    try:
        seq = int(seq_s)
    except ValueError:
        return None
    if isinstance(seq, bool) or seq < 1:
        return None
    return seq, head


def _read_anchor():
    """Return (status, anchor, required, bootstrap).

    status is "ok" (anchor usable), "absent" (not configured), or "malformed"
    (set but unparseable -- treated as unavailable). required mirrors
    SYNTHE_LEDGER_ANCHOR_REQUIRED (the Action sets it whenever it fetched an
    anchor); bootstrap mirrors SYNTHE_LEDGER_BOOTSTRAP (one-run recovery)."""
    raw = os.environ.get(LEDGER_ANCHOR_ENV, "").strip()
    anchor = _parse_anchor(raw) if raw else None
    status = "ok" if anchor else ("malformed" if raw else "absent")
    required = os.environ.get(LEDGER_ANCHOR_REQUIRED_ENV, "").strip().lower() in _truthy
    bootstrap = os.environ.get(LEDGER_BOOTSTRAP_ENV, "").strip().lower() in _truthy
    return status, anchor, required, bootstrap


def check_ledger_anchor(*, exists: bool, sealed: bool, seq: int = 0, head: str = ""):
    """Enforce the out-of-cache anchor. A present anchor must be matched or
    extended by the loaded chain; anything older, divergent, or missing fails
    closed. Returns (ok, code, message)."""
    status, anchor, required, bootstrap = _read_anchor()
    if bootstrap:
        _ledger_warn(f"{LEDGER_BOOTSTRAP_ENV}=1: anchor enforcement skipped for this run; "
                     "the chain restarts here and the anchor will be republished.")
        return True, "", ""
    if status == "ok":
        aseq, ahead = anchor
        if not exists:
            return (False, "ledger_rollback",
                    f"ledger file is missing but an out-of-cache anchor exists (chain seq {aseq}); "
                    "refusing to start a fresh chain -- this looks like a total cache eviction or a "
                    f"deleted ledger. Re-run once with {LEDGER_BOOTSTRAP_ENV}=1 to re-bootstrap "
                    "the chain deliberately.")
        if not sealed:
            return (False, "ledger_rollback",
                    f"ledger has no verifiable chain seal but an out-of-cache anchor exists "
                    f"(chain seq {aseq}); an unsealed file cannot extend a sealed chain -- refusing "
                    "as a downgrade (possible forged or stale-cache file).")
        if seq < aseq:
            return (False, "ledger_rollback",
                    f"ledger chain seq {seq} is behind the out-of-cache anchor seq {aseq}; the "
                    "cache likely restored a stale snapshot. Refusing to forget newer claims.")
        if seq == aseq and not hmac.compare_digest(head, ahead):
            return (False, "ledger_diverged",
                    f"ledger chain seq {seq} matches the anchor but the head differs: two writers "
                    "sealed different states at the same sequence number. Refusing; reconcile "
                    "outside the checker (the Action requires a `concurrency` group for safety).")
        return True, "", ""
    # Anchor unavailable.
    if required:
        detail = "is set but malformed" if status == "malformed" else "is not set"
        return (False, "ledger_anchor_unavailable",
                f"anchoring is required ({LEDGER_ANCHOR_REQUIRED_ENV}=1) but {LEDGER_ANCHOR_ENV} "
                f"{detail}; refusing to run without the out-of-cache anchor.")
    if exists and sealed:
        _ledger_warn(f"no out-of-cache anchor configured ({LEDGER_ANCHOR_ENV}); chain seal "
                     "verified, but rollback to an older snapshot is not provable in this mode.")
    # Unsealed + no anchor: the caller adopts the ledger as a new genesis
    # chain and logs the details itself.
    return True, "", ""


def _adopt_json_ledger(data: dict, path: Path) -> dict:
    """Seal a legacy (unsealed) JSON ledger in place as a new genesis chain,
    preserving every claim. Loudly logged; no manual migration step."""
    n = len(_ledger_claims(data))
    _ledger_warn(f"ledger {path} has no chain seal; adopting {n} existing claim(s) as a new "
                 "genesis chain (entries preserved).")
    return seal_ledger(data)


def _unsealed_adoption_refusal(path: Path):
    """None when an unsealed ledger may be adopted as a new genesis chain, else
    a fail-closed corrupt marker. Without an HMAC key the seal is only a
    checksum, so adoption is automatic (upgrade path). With a key, an unsealed
    file is exactly what a forger who lacks the key would produce by stripping
    the seal, so it is adopted only when the operator says so for this run."""
    key, _prev = _hmac_keys()
    if not key:
        return None
    if (os.environ.get(LEDGER_ADOPT_LEGACY_ENV, "").strip().lower() in _truthy
            or os.environ.get(LEDGER_BOOTSTRAP_ENV, "").strip().lower() in _truthy):
        return None
    return _corrupt_marker(
        "ledger_corrupt",
        f"ledger {path} has no chain seal, but {LEDGER_HMAC_KEY_ENV} is set: an unsealed file may be "
        "a forgery with its seal stripped, so it is not adopted automatically. If it is a genuine "
        "pre-seal ledger, adopt it once with `handoff_check.py --init-ledger PATH --adopt-legacy` "
        f"(or {LEDGER_ADOPT_LEGACY_ENV}=1, or the Action's ledger-bootstrap: 'true').")


def _verify_json_ledger(data: dict, path: Path) -> dict:
    """Seal verification + anchor enforcement for a parsed JSON ledger.
    Returns the ledger dict, or a fail-closed corrupt marker."""
    header = data.get(LEDGER_META_KEY)
    has_chain = isinstance(header, dict) and isinstance(header.get("chain_head"), str)
    if has_chain:
        ok, code, message, header, _used_prev = verify_ledger_seal(data)
        if not ok:
            return _corrupt_marker(code, message)
        ok, code, message = check_ledger_anchor(exists=True, sealed=True,
                                                seq=header["chain_seq"], head=header["chain_head"])
        if not ok:
            return _corrupt_marker(code, message)
        return data
    ok, code, message = check_ledger_anchor(exists=True, sealed=False)
    if not ok:
        return _corrupt_marker(code, message)
    refusal = _unsealed_adoption_refusal(path)
    if refusal:
        return refusal
    return _adopt_json_ledger(data, path)


def _sqlite_verify_and_anchor(conn: sqlite3.Connection, path: Path, existed: bool):
    """Verify the chain seal + anchor for a SQLite ledger inside the caller's
    transaction. Returns None when the ledger may be used, else a fail-closed
    corrupt marker. A legacy (unsealed) table is adopted: the genesis header
    row is written immediately so the chain is sealed from this point on."""
    try:
        rows = conn.execute("SELECT key, value FROM claims").fetchall()
    except sqlite3.DatabaseError:
        return _corrupt_marker("ledger_corrupt", "ledger database is not readable")
    data: dict = {}
    for k, v in rows:
        try:
            data[k] = json.loads(v)
        except ValueError:
            return _corrupt_marker("ledger_corrupt", f"ledger row {k!r} is not valid JSON")
    header = data.get(LEDGER_META_KEY)
    has_chain = isinstance(header, dict) and isinstance(header.get("chain_head"), str)
    if has_chain:
        ok, code, message, header, _used_prev = verify_ledger_seal(data)
        if not ok:
            return _corrupt_marker(code, message)
        ok, code, message = check_ledger_anchor(exists=True, sealed=True,
                                                seq=header["chain_seq"], head=header["chain_head"])
        if not ok:
            return _corrupt_marker(code, message)
        return None
    ok, code, message = check_ledger_anchor(exists=existed, sealed=False)
    if not ok:
        return _corrupt_marker(code, message)
    if existed:
        refusal = _unsealed_adoption_refusal(path)
        if refusal:
            return refusal
    n = len(_ledger_claims(data))
    _ledger_warn(f"SQLite ledger {path}: no chain seal; adopting {n} existing claim(s) as a new "
                 "genesis chain (entries preserved).")
    ledger = seal_ledger(dict(data))
    conn.execute("INSERT INTO claims(key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (LEDGER_META_KEY, json.dumps(ledger[LEDGER_META_KEY],
                                              sort_keys=True, separators=(",", ":"))))
    return None


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
            existed = self.path.exists()
            try:
                self._conn = _sqlite_connect(self.path)
                self._conn.execute("BEGIN IMMEDIATE")
                # Verify the chain seal + out-of-cache anchor before yielding;
                # a legacy table is adopted (genesis header row written here).
                marker = _sqlite_verify_and_anchor(self._conn, self.path, existed)
                self.ledger = marker if marker is not None else SQLiteLedger(self.path, self._conn)
            except (OSError, sqlite3.DatabaseError):
                if self._conn is not None:
                    self._conn.close()
                    self._conn = None
                self.ledger = _corrupt_marker("ledger_corrupt", "ledger database is not readable")
            return self
        self._fh = open(self.path.with_name(self.path.name + ".lock"), "a+")
        try:
            import fcntl
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass  # Windows: best-effort, atomic replace still applies
        # load_ledger verifies the chain seal + anchor (or adopts a legacy
        # file); a fail-closed marker is never saved back (see __exit__).
        self.ledger = load_ledger(self.path)
        return self

    def __exit__(self, *exc) -> bool:
        try:
            if self._conn is not None:
                if self.ledger.get("_corrupt"):
                    self._conn.rollback()  # never persist a failed verification
                else:
                    if self.dirty:
                        self.ledger.flush()  # flush() re-seals the chain
                    self._conn.commit()
            elif self.dirty and not self.ledger.get("_corrupt"):
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
          "require_planned_actions", "exclusive_paths",
          "require_capability_declaration", "require_topology")  # v0.6
_MINIMUMS = ("max_ttl_hours",)                              # ceilings on time: the smallest wins


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _cap_strs(cap: dict, field: str) -> list:
    """The string entries of a capability list dimension (robust to malformed
    entries: the shape check reports those, this just never crashes)."""
    v = cap.get(field)
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _norm_cap_path(p) -> str | None:
    """Normalize a capability path for matching. Returns the normalized
    relative path, or None when the path is rejected outright: absolute paths,
    backslashes, and `..` segments are never allowed (fail closed) — no
    normalized path may escape its declared root. `.` and empty segments are
    dropped; glob tokens (`*`, `?`, `**`) survive as segments."""
    if not isinstance(p, str) or not p:
        return None
    if p.startswith("/") or "\\" in p:
        return None
    segs = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            return None
        segs.append(seg)
    return "/".join(segs) or None


def _glob_covers(covering: str, covered: str) -> bool:
    """Is every path matching `covered` also matched by `covering`? Sound but
    conservative: equality always holds; a wildcard-free covering path covers
    itself and paths beneath it (directory semantics); a `/**`-suffixed
    covering glob covers anything whose literal prefix sits under it; anything
    else must match exactly. Both sides are normalized first (absolute paths,
    backslashes and `..` segments are rejected outright), so a traversal like
    `src/../secrets` can never be "covered" by `src`. Used to decide whether a
    declared path narrows a ceiling path; unsure means not covered (fail closed)."""
    covering = _norm_cap_path(covering)
    covered = _norm_cap_path(covered)
    if covering is None or covered is None:
        return False
    if covering == covered:
        return True
    if covering == "**":
        return True
    if not any(w for w, _ in _glob_tokens(covering)):
        return covered.startswith(covering + "/")
    if covering.endswith("/**"):
        prefix = covering[:-3]
        # literal prefix of `covered`: the text before its first wildcard
        lit_parts = []
        for wild, text in _glob_tokens(covered):
            if wild:
                break
            lit_parts.append(text)
        lit = "".join(lit_parts)
        return lit == prefix or lit.startswith(prefix + "/")
    return False


def _merge_capability_ceiling(cur: dict | None, new: dict) -> dict:
    """Narrow two capability ceilings (authority may only narrow): env/tools
    intersect, network ANDs, paths keep only the new paths covered by a
    current path, and a version pin follows the later layer."""
    if not isinstance(cur, dict):
        return copy.deepcopy(new)
    merged = copy.deepcopy(cur)
    for dim in ("env", "tools"):
        if dim in new:
            have = set(_cap_strs(merged, dim)) if dim in merged else None
            want = set(_cap_strs(new, dim))
            merged[dim] = sorted(want if have is None else (have & want))
    if "network" in new:
        merged["network"] = bool(new["network"]) and bool(merged.get("network", True))
    if "paths" in new:
        if "paths" in merged:
            merged["paths"] = [p for p in _cap_strs(new, "paths")
                               if any(_glob_covers(c, p) for c in _cap_strs(merged, "paths"))]
        else:
            merged["paths"] = list(_cap_strs(new, "paths"))
    if "version" in new:
        merged["version"] = new["version"]
    return merged


def _capability_shape(cap, where: str = "capability", require_version: bool = True) -> list:
    """Element-level shape of a capability object. Returns (code, message)
    pairs; the caller decides the state (invalid for packets, registry_malformed
    for policy ceilings, topology_malformed for role capabilities)."""
    if not isinstance(cap, dict):
        return [(f"malformed:{where}", f"{where} must be an object")]
    errs = []
    if require_version and (not isinstance(cap.get("version"), str) or not cap.get("version")):
        errs.append((f"malformed:{where}.version",
                     f"{where}.version must be a non-empty string"))
    for field in ("env", "tools", "paths"):
        v = cap.get(field)
        if v is not None and (not isinstance(v, list)
                              or not all(isinstance(x, str) and x for x in v)):
            errs.append((f"malformed:{where}.{field}",
                         f"{where}.{field} must be a list of non-empty strings"))
    for p in _cap_strs(cap, "paths"):
        # Declared paths must normalize to a safe relative path: absolute
        # paths, backslashes and `..` segments are rejected outright, because a
        # traversal inside a signed declaration could otherwise smuggle access
        # past the declared root.
        if _norm_cap_path(p) is None:
            errs.append((f"malformed:{where}.paths",
                         f"{where}.paths entry {p!r} is not a safe relative path: "
                         f"absolute paths, backslashes and '..' segments are rejected"))
            break
    if cap.get("network") is not None and not isinstance(cap.get("network"), bool):
        errs.append((f"malformed:{where}.network", f"{where}.network must be a boolean"))
    ar = cap.get("admission_receipt")
    if ar is not None and (not isinstance(ar, str) or not ar):
        errs.append((f"malformed:{where}.admission_receipt",
                     f"{where}.admission_receipt must be a non-empty string"))
    return errs


def _cap_allows(cap, kind: str, value, ceiling: bool = False) -> bool:
    """Does one capability source allow this access? A declaration
    (ceiling=False) is exhaustive: a dimension it does not declare allows
    nothing, and network is denied unless declared true. A ceiling
    (ceiling=True) constrains only the dimensions it declares."""
    if not isinstance(cap, dict):
        return ceiling
    if kind == "network":
        if "network" not in cap:
            return ceiling
        return cap["network"] is True
    field = {"env": "env", "path": "paths", "tool": "tools"}[kind]
    if field not in cap:
        return ceiling
    options = cap[field]
    if not isinstance(options, list):
        return False
    if kind == "path":
        value = _norm_cap_path(value)
        if value is None:
            # A traversal is not "undeclared", it is rejected outright: it can
            # never be inside any declared root.
            return False
        return any(isinstance(p, str) and (pn := _norm_cap_path(p)) is not None
                   and glob_match(pn, value) for p in options)
    return isinstance(value, str) and value in _cap_strs(cap, field)


def check_capability_use(declaration, kind: str, value=None) -> dict | None:
    """Runtime enforcement hook for a least-privilege proxy (SPEC section 15).

    `declaration` is the signed capability object in force for the acting
    agent; `kind` is one of "env" (value: the variable name), "path" (value:
    the file path), "tool" (value: the tool/API name) or "network". Returns
    None when the access is inside the declaration, else a reason dict with
    code `capability_not_declared`. A path that is absolute, contains a
    backslash, or contains a `..` segment is rejected outright with code
    `capability_path_unsafe`: no traversal can ever match a declared root.
    With no declaration in force everything is denied: an undeclared env var,
    path or tool is outside the (empty) declaration, and network egress is
    denied by default.
    """
    cap = declaration if isinstance(declaration, dict) else {}
    has_decl = isinstance(declaration, dict) and bool(declaration)

    def deny(what: str) -> dict:
        return {"state": "blocked", "code": "capability_not_declared",
                "message": f"{what} is outside the signed capability declaration"
                           + ("" if has_decl else "; no capability declaration is in force")}

    if kind == "env":
        if isinstance(value, str) and value in _cap_strs(cap, "env"):
            return None
        return deny(f"read of env var {value!r}")
    if kind == "path":
        if isinstance(value, str):
            norm = _norm_cap_path(value)
            if norm is None:
                # Fail closed with a named code: a traversal is not merely
                # "outside the declaration", it is an unsafe shape that can
                # never match any declared root.
                return {"state": "blocked", "code": "capability_path_unsafe",
                        "message": f"file access to {value!r} is rejected outright: "
                                   "capability paths must be relative and may not contain "
                                   "'..' segments or backslashes"}
            for p in _cap_strs(cap, "paths"):
                pn = _norm_cap_path(p)
                if pn is not None and glob_match(pn, norm):
                    return None
        return deny(f"file access to {value!r}")
    if kind == "tool":
        if isinstance(value, str) and value in _cap_strs(cap, "tools"):
            return None
        return deny(f"call to tool {value!r}")
    if kind == "network":
        if cap.get("network") is True:
            return None
        return deny("network egress (denied by default; declare \"network\": true)")
    return deny(f"access of unknown capability kind {kind!r}")


def _cap_within_ceiling(decl: dict, ceiling: dict) -> list:
    """(code, message) problems when the packet's capability declaration
    exceeds the receiver's capability ceiling: blocked /
    capability_exceeds_receiver_policy. Authority may only narrow."""
    problems = []
    if ceiling.get("version") is not None and decl.get("version") != ceiling["version"]:
        problems.append(("capability_exceeds_receiver_policy",
                         f"capability declaration version {decl.get('version')!r} does not match "
                         f"the receiver's required version {ceiling['version']!r}"))
    for dim in ("env", "tools"):
        if dim in ceiling:
            extra = set(_cap_strs(decl, dim)) - set(_cap_strs(ceiling, dim))
            if extra:
                problems.append(("capability_exceeds_receiver_policy",
                                 f"capability declaration claims {dim} the receiver never "
                                 f"allows: {sorted(extra)}"))
    if "paths" in ceiling:
        uncovered = [p for p in _cap_strs(decl, "paths")
                     if not any(_glob_covers(c, p) for c in _cap_strs(ceiling, "paths"))]
        if uncovered:
            problems.append(("capability_exceeds_receiver_policy",
                             f"capability declaration claims paths outside the receiver's "
                             f"ceiling: {uncovered}"))
    if "network" in ceiling and ceiling.get("network") is not True and decl.get("network") is True:
        problems.append(("capability_exceeds_receiver_policy",
                         "capability declaration claims network egress, which the "
                         "receiver's capability ceiling denies"))
    return problems


def _action_capability_problems(name: str, act: dict, packet_cap, role_cap, pol_cap) -> list:
    """A planned action's declared intent against the capability sources in
    force. Conventions (SPEC section 15): `params.env` lists env vars the
    action reads, `params.paths` lists files it touches, `params.network: true`
    declares egress. Anything outside the narrowed declaration is
    `capability_not_declared` (blocked)."""
    decls = [c for c in (packet_cap, role_cap) if isinstance(c, dict)]
    ceiling = pol_cap if isinstance(pol_cap, dict) else None
    if not decls and ceiling is None:
        return []
    sources = [(c, False) for c in decls] + ([(ceiling, True)] if ceiling is not None else [])

    def denied(kind, value) -> bool:
        return not all(_cap_allows(c, kind, value, ceiling=is_ceil) for c, is_ceil in sources)

    problems = []
    tool = act.get("tool")
    if denied("tool", tool):
        problems.append(("capability_not_declared",
                         f"action '{name}' uses tool '{tool}', outside the signed "
                         f"capability declaration"))
    params = act.get("params") if isinstance(act.get("params"), dict) else {}
    envs = params.get("env")
    if isinstance(envs, list):
        for env in envs:
            if denied("env", env):
                problems.append(("capability_not_declared",
                                 f"action '{name}' reads env var {env!r}, outside the signed "
                                 f"capability declaration"))
    paths = params.get("paths")
    if isinstance(paths, list):
        for path in paths:
            if isinstance(path, str) and _norm_cap_path(path) is None:
                # Tripwire (see SPEC 15.1): the sender volunteers these params,
                # but an outright-unsafe shape is rejected before matching.
                problems.append(("capability_path_unsafe",
                                 f"action '{name}' touches path {path!r}, which is rejected "
                                 f"outright: capability paths must be relative and may not "
                                 f"contain '..' segments or backslashes"))
            elif denied("path", path):
                problems.append(("capability_not_declared",
                                 f"action '{name}' touches path {path!r}, outside the signed "
                                 f"capability declaration"))
    if params.get("network") is True and denied("network", None):
        problems.append(("capability_not_declared",
                         f"action '{name}' needs network egress, which is denied by default "
                         f"(declare \"network\": true in the capability declaration)"))
    return problems


def _verify_topology(name: str, registry: dict | None, reasons: list) -> dict | None:
    """Return the verified team topology, or None (reasons already failed).

    Checks the registry defines it, its shape is sound, and its founder
    signature verifies. The signature covers the name, version, roles, edges,
    role capabilities and the role membership binding, so any topology change
    requires re-signing."""
    topos = registry.get("topologies") if isinstance(registry, dict) else None
    topo = topos.get(name) if isinstance(topos, dict) else None
    if not isinstance(topo, dict):
        fail("invalid", "registry_malformed",
             f"receiver policy names team topology '{name}', but the registry defines "
             f"no such topology", reasons)
        return None
    problems = []
    if not isinstance(topo.get("version"), str) or not topo["version"]:
        problems.append("version must be a non-empty string")
    roles = topo.get("roles")
    if not isinstance(roles, list) or not roles \
            or not all(isinstance(r, str) and r for r in roles):
        problems.append("roles must be a non-empty list of non-empty strings")
    edges = topo.get("edges")
    if not isinstance(edges, list) or any(
            not isinstance(e, list) or len(e) != 2
            or not all(isinstance(x, str) and x for x in e) for e in edges):
        problems.append("edges must be a list of [from_role, to_role] pairs")
    elif isinstance(roles, list):
        known = {r for r in roles if isinstance(r, str)}
        bad = [e for e in edges if e[0] not in known or e[1] not in known]
        if bad:
            problems.append(f"edges name roles not in 'roles': {bad[:3]}")
    rcaps = topo.get("role_capabilities", {})
    if not isinstance(rcaps, dict):
        problems.append("role_capabilities must be an object")
    else:
        for role, cap in rcaps.items():
            for _code, msg in _capability_shape(cap, f"topology role_capabilities.{role}",
                                                require_version=False):
                problems.append(msg)
            if isinstance(roles, list) and role not in roles:
                problems.append(f"role_capabilities names unknown role '{role}'")
    members = topo.get("members", {})
    if not isinstance(members, dict):
        problems.append("members must be an object mapping roles to lists of agent ids")
    else:
        for role, agents in members.items():
            if not isinstance(role, str) or not role:
                problems.append("members keys must be non-empty role names")
                break
            if not isinstance(agents, list) or not agents \
                    or not all(isinstance(a, str) and a for a in agents):
                problems.append(f"members[{role!r}] must be a non-empty list of agent ids")
                break
    if problems:
        fail("invalid", "topology_malformed",
             f"team topology '{name}' is malformed: {problems[0]}", reasons)
        return None
    if not isinstance(topo.get("signed_by"), str) or not isinstance(topo.get("sig"), str):
        fail("invalid", "topology_signature_missing",
             f"team topology '{name}' carries no founder signature; topology "
             f"declarations must be signed", reasons)
        return None
    try:
        sc = _crypto()
    except ImportError as exc:
        fail("invalid", "signature_unsupported",
             f"synthe_crypto.py unusable: {exc}", reasons)
        return None
    signer = topo["signed_by"]
    agent = (registry.get("agents", {}) or {}).get(signer) if isinstance(registry, dict) else None
    if not isinstance(agent, dict) or agent.get("kind") != "human":
        fail("invalid", "topology_signer_not_founder",
             f"team topology '{name}' is signed by '{signer}', who is not a registered "
             f"human founder; topologies must be signed by a founder", reasons)
        return None
    key = sc.find_key(registry, signer, topo.get("kid"))
    if key is None:
        fail("invalid", "topology_signature_invalid",
             f"no Ed25519 key on record for topology signer '{signer}' "
             f"(kid={topo.get('kid')})", reasons)
        return None
    try:
        raw = sc.unb64u(topo["sig"])
    except Exception:
        raw = b""
    if not sc.verify_bytes(key, sc.topology_signing_input(name, topo), raw):
        fail("invalid", "topology_signature_invalid",
             f"team topology '{name}' signature does not verify: the topology was changed "
             f"after signing; re-sign it with a founder key", reasons)
        return None
    return topo


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
            elif k == "capability" and isinstance(v, dict):
                # v0.6: a capability ceiling narrows like every other ceiling.
                merged[k] = _merge_capability_ceiling(merged.get(k), v)
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
    # v0.6: capability declaration and team roles (SPEC section 15)
    if h.get("capability") is not None:
        errs.extend(_capability_shape(h["capability"]))
    for role_field in ("sender_role", "receiver_role"):
        rv = h.get(role_field)
        if rv is not None and (not isinstance(rv, str) or not rv):
            errs.append((f"malformed:{role_field}",
                         f"{role_field} must be a non-empty string"))
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
        for field, dims in (("budget", ("tokens", "usd", "minutes")),
                            ("estimates", ("est_tokens", "est_usd", "est_minutes"))):
            pinned = appr.get(field)
            if pinned is None:
                continue
            if not isinstance(pinned, dict):
                errs.append((f"malformed:authority.approvals[{i}].{field}", f"{field} must be an object"))
                continue
            for dim in dims:
                v = pinned.get(dim)
                if v is not None and (not _is_number(v) or v < 0):
                    errs.append((f"malformed:authority.approvals[{i}].{field}",
                                 f"{field}.{dim} must be a non-negative number"))
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


# Functions this checker needs from synthe_crypto.py. An older copy next to a
# newer checker must fail closed with a clear reason, not crash mid-check.
_CRYPTO_REQUIRED = ("find_key", "usable_keys", "agent_kids", "kid_is_revoked",
                    "topology_signing_input")


def _crypto():
    """Import synthe_crypto, or raise ImportError naming what is missing."""
    import synthe_crypto as sc
    missing = [name for name in _CRYPTO_REQUIRED if not hasattr(sc, name)]
    if missing:
        raise ImportError(f"synthe_crypto.py next to the checker is older than handoff_check.py "
                          f"(missing {', '.join(missing)}); install matching versions")
    return sc


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
        sc = _crypto()
    except ImportError as exc:
        fail("invalid", "signature_unsupported", f"synthe_crypto.py unusable: {exc}", reasons)
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
    # Fail closed on a revoked kid even when the signature is otherwise valid.
    ekid = sig.get("kid")
    if ekid is None:
        usable = sc.usable_keys(registry, signer)
        ekid = usable[0] if len(usable) == 1 else None
        if ekid is None:
            # the only key(s) on record may all be revoked: still name the revocation
            revoked = [k for k in sc.agent_kids(registry, signer)
                       if sc.kid_is_revoked(registry, signer, k)]
            ekid = revoked[0] if revoked else None
    if ekid is not None and sc.kid_is_revoked(registry, signer, ekid):
        fail("invalid", "signature_key_revoked",
             f"packet signed with revoked key '{ekid}' of '{signer}': the revocation operator "
             f"revoked this kid; rotate to a fresh key", reasons)
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


_APPROVAL_BUDGET_DIMS = ("tokens", "usd", "minutes")
_APPROVAL_ESTIMATE_FIELDS = ("est_tokens", "est_usd", "est_minutes")


def _approval_spend_ok(name: str, appr: dict, h: dict) -> list:
    """The spend ceilings a verified approval carries. The packet's
    `authority.budget` and the approved action's cost estimates must not exceed
    what the approver pinned when signing: an approval for a $50 budget does
    not cover a packet claiming $5000. Returns (code, message) problems.

    Stance: a v2 approval that pins NO budget is REJECTED outright
    (`approval_budget_missing`). It caps nothing, so it authorizes nothing --
    treating it as an unlimited approval would let a defaults-supplied budget
    of any size through. v2 signatures are only minted with a budget pin, so
    an unpinned v2 approval is hand-built or predates the rule; either way it
    fails closed here.
    """
    problems: list = []
    approved_budget = appr.get("budget")
    if not isinstance(approved_budget, dict):
        problems.append(("approval_budget_missing",
                         f"approval for '{name}' pins no budget: a v2 approval must "
                         f"carry the budget ceiling it authorizes (it caps nothing "
                         f"otherwise); have '{appr.get('approver')}' re-approve with a budget"))
        return problems
    packet_budget = (h.get("authority") or {}).get("budget") or {}
    for dim in _APPROVAL_BUDGET_DIMS:
        cap = approved_budget.get(dim)
        if not _is_number(cap):
            continue
        val = packet_budget.get(dim)
        if _is_number(val) and val > cap:
            problems.append(("approval_budget_exceeded",
                             f"approval for '{name}' caps {dim} at {cap:g}, "
                             f"but the packet budgets {val:g}"))
    approved_est = appr.get("estimates")
    if isinstance(approved_est, dict):
        planned = None
        for act in h.get("planned_actions") or []:
            if isinstance(act, dict) and name in (act.get("name"), act.get("tool")):
                planned = act
                break
        if isinstance(planned, dict):
            for field in _APPROVAL_ESTIMATE_FIELDS:
                cap = approved_est.get(field)
                if not _is_number(cap):
                    continue
                val = planned.get(field)
                if _is_number(val) and val > cap:
                    problems.append(("approval_estimates_exceeded",
                                     f"approval for '{name}' caps {field} at {cap:g}, "
                                     f"but the plan estimates {val:g}"))
    return problems


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
            revoked = False
            version_old = False
            try:
                import synthe_crypto as sc
                # Ed25519 (passphrase key) or ES256 (Touch ID key): the registered key decides which.
                ambiguous = (appr.get("kid") is None
                             and len(sc.usable_approval_keys(registry, appr.get("approver"))) > 1)
                # A revoked kid fails closed even when the signature verifies.
                ekid = appr.get("kid")
                if ekid is None:
                    usable = sc.usable_approval_keys(registry, appr.get("approver"))
                    ekid = usable[0] if len(usable) == 1 else None
                    if ekid is None:
                        revoked_all = [k for k in sc.agent_kids(registry, appr.get("approver"))
                                       if sc.kid_is_revoked(registry, appr.get("approver"), k)]
                        ekid = revoked_all[0] if revoked_all else None
                revoked = (ekid is not None
                           and sc.kid_is_revoked(registry, appr.get("approver"), ekid))
                good = False
                if not ambiguous and not revoked:
                    raw_sig = sc.unb64u(appr["sig"])
                    good = sc.verify_approval(
                        registry, appr.get("approver"), appr.get("kid"),
                        sc.approval_signing_input(appr, h), raw_sig)
                    if not good:
                        # A signature that verifies under the retired v1 scheme
                        # is an old approval: fail closed with an explicit
                        # version code, never re-verified under the new
                        # budget-binding semantics.
                        version_old = sc.verify_approval(
                            registry, appr.get("approver"), appr.get("kid"),
                            sc.approval_signing_input_v1(appr, h), raw_sig)
            except Exception:
                good = False
            if ambiguous:
                mine.append(("approval_kid_required",
                             f"approval for '{name}' names no kid, and approver "
                             f"'{appr.get('approver')}' has more than one key on record"))
            elif revoked:
                mine.append(("approval_key_revoked",
                             f"approval for '{name}' is signed with revoked key '{ekid}' of approver "
                             f"'{appr.get('approver')}': the revocation operator revoked this kid"))
            elif version_old:
                mine.append(("approval_version_unsupported",
                             f"approval for '{name}' was signed under the retired v1 approval scheme, "
                             f"before approvals bound the budget; have '{appr.get('approver')}' re-approve"))
            elif not good:
                mine.append(("approval_signature_invalid",
                             f"approval for '{name}' carries a signature that does not verify "
                             f"for approver '{appr.get('approver')}' on this handoff"))
            else:
                # The signature is good, so its pins are the approver's word:
                # the packet's budget and the approved action's cost estimates
                # are ceilings the packet may only come down from, never up.
                mine.extend(_approval_spend_ok(name, appr, h))
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
        if other == key or _is_meta_key(other):
            continue
        if not isinstance(entry, dict) or entry_state(entry) != "RESERVED":
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
    # The "~" prefix is the reserved chain-metadata namespace ("~synthe"): no
    # packet may claim it, or the header could be clobbered by an ACCEPT.
    # ("_"-prefixed keys are ordinary idempotency keys; only "~" is reserved.)
    if isinstance(h["idempotency_key"], str) and h["idempotency_key"].startswith("~"):
        fail("invalid", "reserved_idempotency_key",
             f"idempotency_key {h['idempotency_key']!r} starts with '~', which is reserved "
             f"for ledger chain metadata ('{LEDGER_META_KEY}'); choose a different key", reasons)
    if as_receiver is not None and h.get("to") != as_receiver:
        fail("invalid", "receiver_mismatch",
             f"handoff is addressed to {h.get('to')!r}, not the authenticated receiver {as_receiver!r}", reasons)

    scope, auth, acc = h["scope"], h["authority"], h["acceptance"]
    for d, name in ((scope, "scope"), (auth, "authority"), (acc, "acceptance"), (h["inputs"], "inputs")):
        if not isinstance(d, dict):
            fail("invalid", f"malformed:{name}", f"{name} must be an object", reasons)
    if reasons:
        return False, reasons

    # inputs.state_revision is optional and informational (SPEC.md section 2):
    # the checker cannot compare it against anything, so it is not required.
    nested = [
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
    # v0.6: capability declarations and team roles are optional unless the
    # receiver's policy requires them (SPEC section 15).
    if policy and policy.get("require_capability_declaration") and h.get("capability") is None:
        fail("invalid", "capability_declaration_missing",
             "receiver policy requires a signed capability declaration; the packet carries none",
             reasons)
    if policy and policy.get("require_topology") \
            and (h.get("sender_role") is None or h.get("receiver_role") is None):
        fail("invalid", "topology_declaration_missing",
             "receiver policy requires sender_role and receiver_role; the packet declares "
             "no team roles", reasons)
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

    # 5a. (v0.6) team topology (SPEC section 15): the (sender_role,
    #     receiver_role) edge must be declared in the receiver's team topology,
    #     whose founder signature is re-verified on every check. A receiver
    #     role's declared capability narrows the packet further.
    topo_name = pol.get("topology")
    sender_role, receiver_role = h.get("sender_role"), h.get("receiver_role")
    role_cap = None
    if topo_name is not None and not isinstance(topo_name, str):
        fail("invalid", "registry_malformed",
             "receiver policy 'topology' must name a team topology (a string)", reasons)
    elif topo_name is None and pol.get("require_topology"):
        fail("invalid", "registry_malformed",
             "receiver policy requires team topologies but names none: set the "
             "'topology' policy key to a topology in the registry", reasons)
    elif topo_name is not None:
        topo = _verify_topology(topo_name, registry, reasons)
        if topo is not None:
            # Roles stay optional unless require_topology: with no roles the
            # packet makes no routing claim, so there is no edge to verify.
            if sender_role is not None or receiver_role is not None:
                info["topology"] = topo_name
                if [sender_role, receiver_role] not in topo.get("edges", []):
                    fail("blocked", "topology_violation",
                         f"handoff edge '{sender_role}' -> '{receiver_role}' is not in team "
                         f"topology '{topo_name}'; handoffs on undeclared edges are rejected",
                         reasons)
                rcaps = topo.get("role_capabilities") or {}
                if isinstance(receiver_role, str) and isinstance(rcaps.get(receiver_role), dict):
                    role_cap = rcaps[receiver_role]
                # v0.6.1: roles are bound to agent ids in the SIGNED topology
                # (`members: {role: [agent ids]}`), because roles are otherwise
                # sender-asserted labels: a sender could claim any role that
                # has the edge they want. The packet's from/to (already
                # signature-bound: the signer must equal `from`) must be
                # members of the claimed roles. A topology with no binding for
                # a claimed role fails closed: an unverifiable role claim is
                # rejected, never silently passed.
                members = topo.get("members") if isinstance(topo.get("members"), dict) else {}
                for claimed, who, field in ((sender_role, h.get("from"), "sender_role"),
                                            (receiver_role, h.get("to"), "receiver_role")):
                    if isinstance(claimed, str) and who not in members.get(claimed, []):
                        fail("blocked", "topology_role_unbound",
                             f"handoff claims {field} '{claimed}' for agent '{who}', but "
                             f"'{who}' is not bound to role '{claimed}' in team topology "
                             f"'{topo_name}'; roles are bound to agent ids in the signed "
                             f"topology, not asserted by the sender", reasons)
    elif sender_role is not None or receiver_role is not None:
        # The packet claims team roles but this receiver enforces no topology,
        # so the edge cannot be verified: fail closed.
        fail("blocked", "topology_violation",
             "packet declares sender_role/receiver_role but this receiver's policy names "
             "no team topology, so the handoff edge cannot be verified", reasons)

    # 5b. (v0.6) capability ceiling (SPEC section 15): the packet's signed
    #     declaration may only narrow what the receiver's policy allows.
    packet_cap = h.get("capability")
    pol_cap = pol.get("capability")
    if pol_cap is not None:
        shape = _capability_shape(pol_cap, "policy.capability", require_version=False)
        if shape:
            fail("invalid", "registry_malformed",
                 f"receiver policy capability is malformed: {shape[0][1]}", reasons)
            pol_cap = None
    if isinstance(packet_cap, dict) and isinstance(pol_cap, dict):
        for code, msg in _cap_within_ceiling(packet_cap, pol_cap):
            fail("blocked", code, msg, reasons)

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
        # v0.6: the action's declared intent against the capability sources in
        # force (packet declaration, receiver role capability, policy ceiling).
        for code, msg in _action_capability_problems(name, act, packet_cap, role_cap, pol_cap):
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
    if info.get("topology"):  # v0.6: the team topology that admitted this edge
        out["topology"] = info["topology"]
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
                return _ledger_seal_reject(ledger)
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
        return _ledger_seal_reject(ledger)
    ok, reasons = validate(packet, ledger=ledger, **kwargs)
    return _result(ok, reasons, h, info)


def _claim_problem(entry, h: dict, claim_token: str | None, require_token: bool):
    """Why `h` (+ token) may NOT act on this ledger entry, or None. Shared by
    complete() and fenced(): only the claim's own packet, and its token
    holder when tokens are in use, may complete it or run its effect.
    Entries written before v0.3.1 carry no claim_token_sha256; a still-live
    (RESERVED) one can never be completed, because there is no token to bind
    the completion to. It is refused outright (no silent downgrade): release
    it and re-claim to get a claim token."""
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
    if entry_state(entry) == "RESERVED" and not want:
        # Backward-compat hole (closed): pre-v0.3.1 entries have no token
        # hash, so any completion would skip token binding entirely. Refuse
        # instead of silently downgrading; the operator path is --release
        # (after the TTL) and re-claim, which issues a real claim token.
        return _reject("invalid", "legacy_claim_unbound",
                       f"idempotency_key '{key}' was claimed before claim tokens existed "
                       f"(the ledger entry has no claim_token_sha256), so completion cannot "
                       f"be bound to a token holder. Release the claim (--release) and re-claim "
                       f"it to get a claim token, then complete.")
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
    found it.) A still-RESERVED entry written before claim tokens existed
    (no claim_token_sha256) is refused outright (`legacy_claim_unbound`):
    there is no silent downgrade path that skips token binding.
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
            return _ledger_seal_reject(ledger)
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
            return _ledger_seal_reject(ledger)
        entry = ledger.get(key)
        if not isinstance(entry, dict) or entry_state(entry) != "RESERVED":
            return _reject("invalid", "release_not_reserved",
                           f"idempotency_key '{key}' has no RESERVED claim to release")
        # A claim with any recorded effect (EXECUTED or outcome-unknown) is not
        # a bare reservation: releasing it would let the next epoch's holder
        # re-run fenced_effect() for the same action, because check() writes a
        # fresh entry on re-claim and the effect records go with the old epoch.
        # Refuse, --force included; reconcile the effect receipts instead.
        acted = sorted(a for a, r in (entry.get("effects") or {}).items() if isinstance(r, dict))
        if acted:
            return _reject("unknown", "release_effect_unreconciled",
                           f"claim on '{key}' has recorded effects ({', '.join(acted)}); releasing it "
                           f"would re-run them under the next epoch. Reconcile the effect receipts "
                           f"(complete, or record the outcome) instead of releasing")
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
        if locked.ledger.get("_corrupt"):
            raise FenceError(_ledger_seal_reject(locked.ledger))
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
            raise FenceError(_ledger_seal_reject(locked.ledger))
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


def init_ledger(path: Path):
    """Operator command: ensure a sealed ledger chain exists at PATH.

    Returns (ok, message). Missing file -> sealed genesis. Already sealed ->
    idempotent no-op (the seal and anchor are verified first). Legacy
    unsealed file -> adopted in place as a new genesis chain, entries
    preserved, loudly logged (no manual migration step). Corrupt file, or an
    out-of-cache anchor that forbids a fresh chain, -> refused: never
    overwritten, never silently adopted.
    """
    path = Path(path)
    if sqlite_ledger(path):
        had_chain = False
        if path.exists():
            try:
                conn = _sqlite_connect(path)
                try:
                    row = conn.execute("SELECT value FROM claims WHERE key = ?",
                                       (LEDGER_META_KEY,)).fetchone()
                finally:
                    conn.close()
                had_chain = bool(row and isinstance(json.loads(row[0]), dict)
                                 and json.loads(row[0]).get("chain_head"))
            except (OSError, sqlite3.DatabaseError, ValueError):
                return False, f"refusing to initialize: ledger database at {path} is not readable"
        with LockedLedger(path) as locked:
            if locked.ledger.get("_corrupt"):
                return (False,
                        f"refusing to initialize: {locked.ledger.get('_corrupt_reason')}: "
                        f"{locked.ledger.get('_corrupt_message')}")
            locked.dirty = True  # persist the (possibly just adopted) seal
        if had_chain:
            return True, f"ledger already sealed at {path}; no-op"
        return True, f"initialized sealed ledger chain at {path}"
    existed = path.exists()
    raw_sealed = False
    if existed:
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            return False, f"refusing to initialize: {path} is not valid JSON"
        if not isinstance(raw, dict):
            return False, f"refusing to initialize: {path} must contain a JSON object"
        header = raw.get(LEDGER_META_KEY)
        raw_sealed = isinstance(header, dict) and isinstance(header.get("chain_head"), str)
    data = load_ledger(path)  # verifies seal + anchor, or adopts a legacy file
    if data.get("_corrupt"):
        return (False,
                f"refusing to initialize: {data.get('_corrupt_reason')}: {data.get('_corrupt_message')}")
    if raw_sealed:
        seq = data[LEDGER_META_KEY]["chain_seq"]
        return True, f"ledger already sealed at {path} (chain seq {seq}); no-op"
    save_ledger(path, data)  # persists the genesis / adopted chain
    n = len(_ledger_claims(data))
    if existed:
        return True, f"adopted {n} existing claim(s) at {path} into a new sealed chain"
    return True, f"initialized new sealed ledger chain at {path} (genesis)"


def ledger_head(path: Path) -> str:
    """Return the "seq:head" anchor string for a sealed ledger, else "".

    Used by the GitHub Action to publish the out-of-cache anchor. A missing,
    unsealed, or corrupt ledger yields "" (nothing to anchor). The seal is
    verified, but the anchor itself is NOT enforced here: publishing reads,
    it does not gate.
    """
    path = Path(path)
    try:
        if sqlite_ledger(path):
            if not path.exists():
                return ""
            conn = _sqlite_connect(path)
            try:
                rows = conn.execute("SELECT key, value FROM claims").fetchall()
            finally:
                conn.close()
            data = {k: json.loads(v) for k, v in rows}
        else:
            if not path.exists():
                return ""
            data = json.loads(path.read_text())
            if not isinstance(data, dict):
                return ""
    except (OSError, ValueError, sqlite3.DatabaseError):
        return ""
    header = data.get(LEDGER_META_KEY)
    if not isinstance(header, dict) or not isinstance(header.get("chain_head"), str):
        return ""
    ok, _code, _msg, header, _used_prev = verify_ledger_seal(data)
    if not ok:
        return ""
    return f"{header['chain_seq']}:{header['chain_head']}"


def exit_code(result: dict) -> int:
    return 0 if result.get("decision") in ("ACCEPT", "COMPLETED", "RELEASED") else 2


GENESIS_PIN_FILENAME = "registry-genesis.key"
GENESIS_PIN_ENV = "SYNTHE_REGISTRY_GENESIS_KEY"


def resolve_genesis_pin(explicit=None):
    """Return the configured genesis pin value, or None.

    Precedence: explicit --registry-genesis-key flag > SYNTHE_REGISTRY_GENESIS_KEY
    env var > registry-genesis.key file next to this checker file. The value is
    either base64url of the 32-byte genesis Ed25519 public key or the 64-char
    hex sha256 fingerprint of that key (parsed by synthe_crypto.genesis_pin_matches).
    """
    if explicit:
        return explicit
    env = os.environ.get(GENESIS_PIN_ENV)
    if env and env.strip():
        return env
    pin_file = Path(__file__).resolve().parent / GENESIS_PIN_FILENAME
    try:
        if pin_file.is_file():
            return pin_file.read_text(encoding="utf-8")
    except OSError:
        return None
    return None


def load_registry(path, allow_unsigned=True, genesis_key=None) -> tuple[dict | None, dict | None]:
    """Return (registry, None) or (None, reject_result).

    The trust anchor is a genesis pin: the operator's genesis public key (or
    its sha256 fingerprint) from --registry-genesis-key, the
    SYNTHE_REGISTRY_GENESIS_KEY env var, or a registry-genesis.key file the
    operator places next to the checker (nothing ships one).

    - Pin configured: the registry MUST be signed, its rotation chain must
      verify link by link back to the pinned genesis key, and the body
      signature must verify under the chain's current key. Anything else
      (unsigned, tampered, wrong genesis) fails closed with
      registry_signature_invalid, whatever allow_unsigned says.
    - No pin: a self-issued signature proves nothing, so the registry is
      loaded as unsigned (today's behavior) unless allow_unsigned is False,
      in which case it is rejected and the caller is told to pin a key.

    The returned registry never contains the signature block itself.
    """
    if not path:
        return None, None
    try:
        reg = strict_loads(Path(path).read_text())
    except (OSError, ValueError) as exc:  # ValueError covers JSONDecodeError and StrictJSONError
        return None, _reject("invalid", "registry_unreadable", f"cannot read registry: {exc}")
    if not isinstance(reg, dict) or not isinstance(reg.get("agents", {}), dict):
        return None, _reject("invalid", "registry_malformed", "registry must be an object with an 'agents' object")
    pin = resolve_genesis_pin(genesis_key)
    if pin and pin.strip():
        if "signature" not in reg:
            return None, _reject(
                "invalid", "registry_signature_invalid",
                "a registry genesis key is pinned, so the registry must be signed, but it carries "
                "no signature block: sign it with `synthe-sign sign-registry`")
        try:
            sc = _crypto()
        except ImportError as exc:
            return None, _reject("invalid", "registry_signature_invalid",
                                 f"registry signature cannot be checked: {exc}")
        ok, info = sc.verify_registry_signature(reg, genesis_pin=pin)
        if not ok:
            return None, _reject("invalid", "registry_signature_invalid",
                                 f"registry signature rejected: {info}")
        return {k: v for k, v in reg.items() if k != "signature"}, None
    if not allow_unsigned:
        return None, _reject(
            "invalid", "registry_signature_invalid",
            "a signed registry is required but no genesis key is pinned, so no signature can be "
            "trusted: pin the operator's genesis key with --registry-genesis-key, the "
            "SYNTHE_REGISTRY_GENESIS_KEY env var, or a registry-genesis.key file next to the checker")
    return {k: v for k, v in reg.items() if k != "signature"}, None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Handoff Contract validator (packet wire format v0.1; v0.2 claim ledger; "
                    "v0.3 receiver policy + signatures)")
    ap.add_argument("packet", nargs="?",
                    help="handoff packet JSON file (required unless --init-ledger or --ledger-head)")
    ap.add_argument("--registry", help="agent registry JSON (canonical ids, aliases, keys, policy)")
    ap.add_argument("--require-signed-registry", action="store_true",
                    help="refuse any registry that is not signed and verified against a pinned "
                         "genesis key (needs --registry-genesis-key, SYNTHE_REGISTRY_GENESIS_KEY, "
                         "or registry-genesis.key next to the checker)")
    ap.add_argument("--registry-genesis-key",
                    help="pin the registry's genesis operator key: base64url of the 32-byte "
                         "Ed25519 public key, or its 64-char sha256 hex fingerprint. Overrides "
                         "SYNTHE_REGISTRY_GENESIS_KEY and the registry-genesis.key file next to "
                         "the checker. With a pin, the registry must be signed and verify back to "
                         "this key. Without one, registries load unverified (a warning says so).")
    ap.add_argument("--ledger", help="idempotency ledger JSON file (created if absent)")
    ap.add_argument("--init-ledger", metavar="PATH",
                    help="operator: ensure a sealed ledger chain exists at PATH (missing -> sealed "
                         "genesis; legacy unsealed -> adopted in place; already sealed -> no-op; "
                         "corrupt or anchor-forbidden -> refused, never overwritten)")
    ap.add_argument("--adopt-legacy", action="store_true",
                    help="with --init-ledger: adopt an unsealed ledger as a new genesis chain even "
                         "though SYNTHE_LEDGER_HMAC_KEY is set (only for a genuine pre-seal ledger)")
    ap.add_argument("--ledger-head", metavar="PATH",
                    help="print the 'seq:head' chain anchor for the ledger at PATH (empty when "
                         "unsealed/missing/corrupt); used by the GitHub Action to publish the "
                         "out-of-cache anchor")
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

    if args.init_ledger:
        saved = os.environ.get(LEDGER_ADOPT_LEGACY_ENV)
        if args.adopt_legacy:
            os.environ[LEDGER_ADOPT_LEGACY_ENV] = "1"
        try:
            ok, message = init_ledger(Path(args.init_ledger))
        finally:
            if saved is None:
                os.environ.pop(LEDGER_ADOPT_LEGACY_ENV, None)
            else:
                os.environ[LEDGER_ADOPT_LEGACY_ENV] = saved
        if ok:
            print(message)
            return 0
        print(f"handoff_check: ERROR: {message}", file=sys.stderr)
        return 2
    if args.ledger_head:
        print(ledger_head(Path(args.ledger_head)))
        return 0
    if not args.packet:
        ap.error("the 'packet' argument is required (unless --init-ledger or --ledger-head)")

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
            if args.registry and not (resolve_genesis_pin(args.registry_genesis_key) or "").strip() \
                    and not args.require_signed_registry:
                sys.stderr.write(
                    "WARNING: no registry genesis key is pinned, so the agent registry is NOT "
                    "verified: whoever can edit it decides who exists. Sign it with `synthe-sign "
                    "sign-registry` and pin the key (--registry-genesis-key or "
                    "SYNTHE_REGISTRY_GENESIS_KEY).\n")
            registry, err = load_registry(args.registry,
                                          allow_unsigned=not args.require_signed_registry,
                                          genesis_key=args.registry_genesis_key)
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
