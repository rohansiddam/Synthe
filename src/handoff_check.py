#!/usr/bin/env python3
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
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

REQUIRED = [
    "id", "idempotency_key", "trace_id", "schema_version", "from", "to",
    "purpose", "inputs", "scope", "authority", "acceptance", "on_failure",
]
FAILURE_STATES = {"invalid", "incomplete", "stale", "conflicting", "blocked", "retryable", "duplicate", "unknown"}
# Evidence kinds that must be verbatim-fidelity by default (rule/code text).
VERBATIM_KINDS = {"code_text", "verbatim_quote", "legal_text"}


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


def load_ledger(path: Path) -> dict:
    if path and path.exists():
        try:
            return json.loads(path.read_text()) or {}
        except json.JSONDecodeError:
            return {"_corrupt": True}
    return {}


def save_ledger(path: Path, ledger: dict) -> None:
    """Write the ledger atomically: temp file in the same dir + os.replace,
    so a concurrent reader never observes a torn file."""
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, path)


def entry_state(entry: dict) -> str:
    """Ledger entry state. Pre-v0.2 entries (no 'state' field) were written
    only after acceptance in the old claim-on-accept model and count as
    COMPLETED."""
    return entry.get("state") or "COMPLETED"


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

    def __enter__(self) -> "LockedLedger":
        self.path.parent.mkdir(parents=True, exist_ok=True)
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
            if self.dirty:
                save_ledger(self.path, self.ledger)
        finally:
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


def validate(packet: dict, *, registry: dict | None, ledger: dict,
             workspace: Path | None, at: dt.datetime,
             reserve_ttl_hours: float = 24.0) -> tuple[bool, list]:
    reasons: list = []
    h = packet.get("handoff")
    if not isinstance(h, dict):
        fail("invalid", "missing_handoff", "packet must contain a 'handoff' object", reasons)
        return False, reasons

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
            not isinstance(budget.get(k), (int, float)) for k in ("tokens", "usd", "minutes")):
        fail("invalid", "missing_field:authority.budget",
             "authority.budget must define numeric tokens, usd, and minutes", reasons)
    if reasons:
        return False, reasons

    # 2. identity (canonical registry; aliases must resolve)
    if registry is not None:
        agents = registry.get("agents", {})
        for role in ("from", "to"):
            who = h[role]
            if who not in agents:
                fail("invalid", f"unknown_agent:{role}", f"{role} '{who}' is not in the agent registry", reasons)
            elif agents[who].get("alias_of"):
                fail("invalid", f"alias_not_canonical:{role}",
                     f"{role} '{who}' is an alias of '{agents[who]['alias_of']}'; use the canonical id", reasons)

    # 3. duplication (idempotency claim state machine)
    key = h["idempotency_key"]
    prev = ledger.get(key)
    if prev is not None:
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

    # 4. freshness
    exp = parse_ts(acc["expires_at"])
    if exp is None:
        fail("invalid", "bad_expires_at", "acceptance.expires_at is not a valid ISO 8601 timestamp", reasons)
    elif exp <= at:
        fail("stale", "handoff_expired", f"handoff expired at {acc['expires_at']}", reasons)

    # 5. authority: planned actions vs tools / forbidden / approvals / budget
    est = {"tokens": 0.0, "usd": 0.0, "minutes": 0.0}
    approvals = {a["action"]: a for a in auth.get("approvals", [])}
    forbidden = set(scope.get("forbidden", []))
    allowed = set(auth.get("allowed_tools", []))
    for act in h.get("planned_actions", []):
        name, tool = act["name"], act["tool"]
        if tool not in allowed:
            fail("blocked", "tool_not_allowed", f"action '{name}' uses tool '{tool}' not in allowed_tools", reasons)
        if name in forbidden or tool in forbidden:
            fail("blocked", "forbidden_action", f"action '{name}' is forbidden by scope", reasons)
        if name in auth.get("approval_required_for", []):
            appr = approvals.get(name)
            if appr is None:
                fail("blocked", "approval_missing", f"action '{name}' needs approval; none recorded", reasons)
            else:
                aexp = parse_ts(appr["expires_at"]) if appr.get("expires_at") else None
                if aexp is not None and aexp <= at:
                    fail("blocked", "approval_expired", f"approval for '{name}' expired at {appr['expires_at']}", reasons)
        for k in est:
            est[k] += float(act.get(f"est_{k if k != 'minutes' else 'minutes'}", 0) or 0)
    budget = auth["budget"]
    for k in ("tokens", "usd", "minutes"):
        if est[k] > float(budget[k]):
            fail("blocked", "budget_exceeded", f"estimated {k} {est[k]} exceeds budget {budget[k]}", reasons)

    # 6. artifacts: existence + hash (when a workspace root is given)
    if workspace is not None:
        for ref in h["inputs"].get("artifact_refs", []):
            p = (workspace / ref["path"])
            if not p.exists():
                fail("incomplete", "artifact_missing", f"input artifact not found: {ref['path']}", reasons)
            elif ref.get("sha256") and sha256_file(p) != ref["sha256"]:
                fail("stale", "artifact_hash_mismatch", f"artifact changed since handoff: {ref['path']}", reasons)

    # 7. evidence fidelity + completeness
    evidence = acc.get("evidence", [])
    kinds = {e.get("kind") for e in evidence}
    for req in acc.get("required_evidence", []):
        if req not in kinds:
            fail("incomplete", "evidence_missing", f"required evidence missing: {req}", reasons)
    for e in evidence:
        if e.get("kind") in VERBATIM_KINDS and e.get("verbatim") is not True:
            fail("invalid", "evidence_not_verbatim",
                 f"evidence '{e.get('kind')}' must be verbatim, not a paraphrase/summary", reasons)

    return not reasons, reasons


def _print_reject(state: str, code: str, message: str) -> int:
    print(json.dumps({"decision": "REJECT", "state": state, "reasons": [
        {"state": state, "code": code, "message": message}]}, indent=2))
    return 2


def _emit(ok: bool, reasons: list, h: dict) -> int:
    if ok:
        print(json.dumps({"decision": "ACCEPT", "handoff_id": h.get("id"),
                          "trace_id": h.get("trace_id")}, indent=2))
        return 0
    print(json.dumps({"decision": "REJECT", "state": reasons[0]["state"],
                      "reasons": reasons}, indent=2))
    return 2


def complete_mode(args, packet: dict) -> int:
    """Flip the packet's idempotency-key entry RESERVED -> COMPLETED.

    Run by the receiver after it has actually performed the effect. Safe to
    re-run: completing an already-COMPLETED entry is a no-op success.
    """
    h = packet.get("handoff")
    if not isinstance(h, dict) or not h.get("idempotency_key"):
        return _print_reject("invalid", "missing_idempotency_key",
                             "packet must contain a 'handoff' object with an idempotency_key")
    if not args.ledger:
        return _print_reject("invalid", "ledger_required",
                             "--complete requires --ledger (the claim lives there)")
    key = h["idempotency_key"]
    with LockedLedger(Path(args.ledger)) as locked:
        ledger = locked.ledger
        if ledger.get("_corrupt"):
            return _print_reject("invalid", "ledger_corrupt", "ledger file is not valid JSON")
        entry = ledger.get(key)
        if entry is None:
            return _print_reject("invalid", "completion_unknown_key",
                                 f"no ledger claim for idempotency_key '{key}'; "
                                 f"nothing was reserved under this key")
        if entry.get("handoff_id") not in (None, h.get("id")):
            return _print_reject("conflicting", "completion_handoff_mismatch",
                                 f"idempotency_key '{key}' was claimed by handoff "
                                 f"{entry.get('handoff_id')}, not {h.get('id')}")
        if entry_state(entry) == "COMPLETED":
            print(json.dumps({"decision": "COMPLETED", "handoff_id": h.get("id"),
                              "trace_id": h.get("trace_id"), "idempotency_key": key,
                              "note": "already completed; no-op"}, indent=2))
            return 0
        entry["state"] = "COMPLETED"
        entry["completed_at"] = now_utc().isoformat()
        locked.dirty = True
        print(json.dumps({"decision": "COMPLETED", "handoff_id": h.get("id"),
                          "trace_id": h.get("trace_id"), "idempotency_key": key}, indent=2))
        return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Handoff Contract validator (packet wire format v0.1; v0.2 claim ledger)")
    ap.add_argument("packet", help="handoff packet JSON file")
    ap.add_argument("--registry", help="agent registry JSON (canonical ids + aliases)")
    ap.add_argument("--ledger", help="idempotency ledger JSON file (created if absent)")
    ap.add_argument("--workspace", help="workspace root for artifact existence/hash checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate only; do not record a RESERVED claim in the ledger")
    ap.add_argument("--complete", action="store_true",
                    help="mark this packet's idempotency key COMPLETED in the ledger "
                         "(run after the receiver performs the effect); requires --ledger")
    ap.add_argument("--reserve-ttl-hours", type=float, default=24.0,
                    help="hours a RESERVED claim stays fresh before a re-presentation "
                         "flips to UNKNOWN (default: 24)")
    args = ap.parse_args(argv)

    try:
        packet = json.loads(Path(args.packet).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return _print_reject("invalid", "packet_unreadable", f"cannot read packet: {exc}")

    if args.complete:
        return complete_mode(args, packet)

    registry = json.loads(Path(args.registry).read_text()) if args.registry else None
    ledger_path = Path(args.ledger) if args.ledger else None
    workspace = Path(args.workspace) if args.workspace else None
    h = packet.get("handoff", {}) if isinstance(packet.get("handoff"), dict) else {}

    if ledger_path is not None and not args.dry_run:
        # Atomic claim: validate and record RESERVED under one lock, so two
        # concurrent presentations of the same key cannot both pass.
        with LockedLedger(ledger_path) as locked:
            ledger = locked.ledger
            if ledger.get("_corrupt"):
                return _print_reject("invalid", "ledger_corrupt", "ledger file is not valid JSON")
            ok, reasons = validate(packet, registry=registry, ledger=ledger,
                                   workspace=workspace, at=now_utc(),
                                   reserve_ttl_hours=args.reserve_ttl_hours)
            if ok:
                ledger[h["idempotency_key"]] = {
                    "state": "RESERVED",
                    "handoff_id": h["id"],
                    "trace_id": h["trace_id"],
                    "from": h["from"],
                    "to": h["to"],
                    "reserved_at": now_utc().isoformat(),
                }
                locked.dirty = True
            return _emit(ok, reasons, h)

    ledger = load_ledger(ledger_path) if ledger_path else {}
    if ledger.get("_corrupt"):
        return _print_reject("invalid", "ledger_corrupt", "ledger file is not valid JSON")
    ok, reasons = validate(packet, registry=registry, ledger=ledger,
                           workspace=workspace, at=now_utc(),
                           reserve_ttl_hours=args.reserve_ttl_hours)
    return _emit(ok, reasons, h)


if __name__ == "__main__":
    sys.exit(main())
