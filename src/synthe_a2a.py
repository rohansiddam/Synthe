#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthe as an A2A (Agent2Agent v1.0) extension (stdlib only).

A2A moves messages and tasks between agents from any vendor; it leaves
deduplication optional ("Agents may utilize the messageId to detect duplicate
messages") and does not check the work itself. This adapter carries a Synthe
packet inside an A2A Message and turns the checker's verdict into an A2A
TaskStatus, so an A2A server can gate every incoming task:

    msg = to_message(packet)                 # sender side
    status = check_message(msg, registry=..., ledger_path=..., workspace=...)
    # receiver: only start work if status["state"] == "TASK_STATE_SUBMITTED"

Wire format (JSON form of the A2A v1.0 proto; Part has no `kind` field):
  Message.parts  = [{"text": purpose, "mediaType": "text/plain"},
                    {"data": <packet>, "mediaType": MEDIA_TYPE}]
  Message.extensions = [EXTENSION_URI]
  Message.messageId == handoff.id, Message.contextId == handoff.trace_id
Clients activate the extension with the `A2A-Extensions: <EXTENSION_URI>`
HTTP header; agents advertise it with `agent_card_extension()`.

CLI:
  python3 src/synthe_a2a.py wrap PACKET > message.json
  python3 src/synthe_a2a.py check message.json --registry R --workspace W --ledger L
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc  # noqa: E402

EXTENSION_URI = "https://github.com/rohansiddam/Synthe/ext/handoff/v1"
MEDIA_TYPE = "application/vnd.synthe.handoff+json"
VERDICT_MEDIA_TYPE = "application/vnd.synthe.verdict+json"

# A REJECT that a human approval could cure is an interrupted task, not a
# terminal one: A2A's INPUT_REQUIRED lets the requester come back with it.
_NEEDS_INPUT = {"approval_missing", "approval_expired", "approval_unsigned"}


def to_message(packet: dict, role: str = "ROLE_USER") -> dict:
    h = packet["handoff"]
    return {
        "messageId": h["id"],
        "contextId": h["trace_id"],
        "role": role,
        "parts": [{"text": h.get("purpose", ""), "mediaType": "text/plain"},
                  {"data": packet, "mediaType": MEDIA_TYPE}],
        "extensions": [EXTENSION_URI],
        "metadata": {f"{EXTENSION_URI}/idempotency_key": h["idempotency_key"]},
    }


def from_message(message: dict) -> tuple[dict | None, dict | None]:
    """Extract the packet. Returns (packet, None) or (None, reject_result)."""
    if not isinstance(message, dict):
        return None, hc._reject("invalid", "a2a_malformed_message", "A2A message must be an object")
    parts = [p for p in message.get("parts", []) or []
             if isinstance(p, dict) and p.get("mediaType") == MEDIA_TYPE and "data" in p]
    if not parts:
        return None, hc._reject("invalid", "a2a_no_handoff_part",
                                f"no part with mediaType {MEDIA_TYPE}; the sender did not attach a packet")
    if len(parts) > 1:
        return None, hc._reject("invalid", "a2a_multiple_handoff_parts",
                                "exactly one handoff packet per message")
    packet = parts[0]["data"]
    h = packet.get("handoff") if isinstance(packet, dict) else None
    if isinstance(h, dict):
        if message.get("messageId") != h.get("id"):
            return None, hc._reject("invalid", "a2a_envelope_mismatch",
                                    f"messageId '{message.get('messageId')}' != handoff.id '{h.get('id')}'")
        if message.get("contextId") not in (None, h.get("trace_id")):
            return None, hc._reject("invalid", "a2a_envelope_mismatch",
                                    f"contextId '{message.get('contextId')}' != handoff.trace_id "
                                    f"'{h.get('trace_id')}'")
    return packet, None


def verdict_to_state(verdict: dict) -> str:
    if verdict.get("decision") == "ACCEPT":
        return "TASK_STATE_SUBMITTED"
    codes = {r.get("code") for r in verdict.get("reasons", [])}
    if verdict.get("state") == "blocked" and codes and codes <= _NEEDS_INPUT:
        return "TASK_STATE_INPUT_REQUIRED"
    return "TASK_STATE_REJECTED"


def task_status(verdict: dict, handoff_id: str | None) -> dict:
    if verdict.get("decision") == "ACCEPT":
        summary = "Handoff accepted by Synthe; work may start."
    else:
        codes = ", ".join(r.get("code", "") for r in verdict.get("reasons", []))
        summary = f"Handoff rejected by Synthe ({verdict.get('state')}): {codes}"
    return {
        "state": verdict_to_state(verdict),
        "message": {
            "messageId": f"{handoff_id or 'unknown'}:synthe-verdict",
            "role": "ROLE_AGENT",
            "parts": [{"text": summary, "mediaType": "text/plain"},
                      {"data": verdict, "mediaType": VERDICT_MEDIA_TYPE}],
            "extensions": [EXTENSION_URI],
        },
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def check_message(message: dict, return_claim: bool = False, **check_kwargs):
    """Gate an incoming A2A message. Returns the TaskStatus to send back to
    the requester. The requester is the *sender*, so the claim token is
    stripped from it: whoever holds the token can complete the claim. The
    receiver gets the claim ({epoch, token}) with `return_claim=True`, as
    (status, claim)."""
    packet, err = from_message(message)
    verdict = err or hc.check(packet, **check_kwargs)
    claim = verdict.get("claim")
    if claim:
        verdict = {**verdict, "claim": {"epoch": claim.get("epoch")}}
    hid = (packet or {}).get("handoff", {}).get("id") if isinstance(packet, dict) else None
    status = task_status(verdict, hid or (message or {}).get("messageId"))
    return (status, claim) if return_claim else status


def agent_card_extension(require_signatures: bool = True) -> dict:
    """AgentExtension entry for AgentCard.capabilities.extensions."""
    return {
        "uri": EXTENSION_URI,
        "description": "Every task must carry a Synthe handoff packet; it is validated (identity, "
                       "signatures, receiver policy, artifacts, evidence, idempotency) before work starts.",
        "required": True,
        "params": {"mediaType": MEDIA_TYPE, "signatureAlg": "Ed25519",
                   "requireSignatures": require_signatures},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Synthe A2A adapter")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("wrap")
    w.add_argument("packet")
    c = sub.add_parser("check")
    c.add_argument("message")
    c.add_argument("--registry")
    c.add_argument("--ledger")
    c.add_argument("--workspace")
    c.add_argument("--dry-run", action="store_true")
    sub.add_parser("card-extension")
    a = ap.parse_args(argv)
    if a.cmd == "wrap":
        print(json.dumps(to_message(json.loads(Path(a.packet).read_text())), indent=2))
        return 0
    if a.cmd == "card-extension":
        print(json.dumps(agent_card_extension(), indent=2))
        return 0
    registry, err = hc.load_registry(a.registry)
    if not err:
        try:
            message = hc.strict_loads(Path(a.message).read_text())
        except hc.StrictJSONError as exc:  # duplicate keys, NaN/Infinity: refuse, never guess
            err = hc._reject("invalid", exc.code, f"message refused: {exc}")
        except (OSError, ValueError) as exc:
            err = hc._reject("invalid", "packet_unreadable", f"cannot read message: {exc}")
    if err:
        status = task_status(err, None)
    else:
        status, claim = check_message(message, return_claim=True,
                                      registry=registry,
                                      ledger_path=Path(a.ledger) if a.ledger else None,
                                      workspace=Path(a.workspace) if a.workspace else None,
                                      dry_run=a.dry_run)
        if claim:  # for the receiver only: stdout (the status) may go back to the sender
            sys.stderr.write(f"synthe-a2a: claim epoch {claim['epoch']} token {claim['token']}\n")
    print(json.dumps(status, indent=2))
    return 0 if status["state"] == "TASK_STATE_SUBMITTED" else 2


if __name__ == "__main__":
    sys.exit(main())
