#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
"""Plan anchor (v0.5): hand the agent its signed plan at every step.

Agents don't keep plans in mind. In "Plans Don't Persist" (arXiv 2606.22953)
the plan's signal fell 4.1x after a single step, and dropping the plan from
context cut ALFWorld success by 34.7 points. So every response that moves a
handoff forward (an ACCEPT, a claim through the broker, every broker receipt)
carries `plan`: the purpose, each planned action with its status, what is
left, and the constraints the agent must stay inside.

Statuses: `executed` / `unconfirmed` (from the ledger's effect records),
`pending`, `denied` (the latest proposal of this action was refused; it is
still pending), `staged` (v0.5: the broker holds a checked proposal and commits
it when its approval or upstream arrives), and `not_mediated` (a step the agent does itself, which
Synthe does not observe). The plan never contains a claim token or any other
secret: it is built from the signed handoff, the receiver's policy and the
ledger.

Private (the commit broker, MCP, Lab): the public checker's verdict shape is
unchanged.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc  # noqa: E402

NOTE = ("Re-read this plan before every step. Act only on the remaining actions, inside these "
        "constraints; anything else will be refused.")


def _approved(h: dict, action: dict, at, extra=()) -> bool:
    for ap in list((h.get("authority") or {}).get("approvals") or []) + list(extra or ()):
        if not isinstance(ap, dict) or ap.get("action") not in (action.get("name"), action.get("tool")):
            continue
        exp, _ = hc.parse_utc(ap.get("expires_at")) if ap.get("expires_at") else (None, None)
        if exp is None and ap.get("expires_at"):
            continue
        if exp is not None and exp <= at:
            continue
        if isinstance(ap.get("params"), dict) and isinstance(action.get("params"), dict) and any(
                action["params"].get(k) != v for k, v in ap["params"].items()
                if k not in hc.UNPLANNED_APPROVAL_PINS):
            continue
        return True
    return False


def plan_for(packet, registry: dict | None, ledger: dict | None, mediated_tools=(),
             current: tuple | None = None, extra_approvals=(), staged_actions=()) -> dict | None:
    """The plan anchor for a packet, or None if it has no handoff.

    `ledger` gives each mediated action's status and the depends_on states;
    `current` = (action, decision) overlays the proposal being receipted, whose
    outcome the ledger may not show yet. `extra_approvals` are the detached
    approvals the broker holds for this handoff (verified when received);
    `staged_actions` the actions it holds staged proposals for."""
    h = packet.get("handoff") if isinstance(packet, dict) else None
    if not isinstance(h, dict):
        return None
    policy = hc.receiver_policy(registry, h.get("to")) or {}
    eff = copy.deepcopy(h)
    hc.apply_receiver_defaults(eff, policy)
    ledger = ledger if isinstance(ledger, dict) else {}
    entry = ledger.get(h.get("idempotency_key"))
    entry = entry if isinstance(entry, dict) else None
    effects = (entry or {}).get("effects") or {}
    at = hc.now_utc()
    needs = set((eff.get("authority") or {}).get("approval_required_for") or []) | \
        set(policy.get("approval_required_for") or [])
    actions, remaining, approvals_needed = [], [], []
    for a in h.get("planned_actions") or []:
        if not isinstance(a, dict):
            continue
        name, tool = a.get("name"), a.get("tool")
        if tool in mediated_tools:
            rec = effects.get(name) or {}
            status = {"EXECUTED": "executed", "UNCONFIRMED": "unconfirmed"}.get(rec.get("state"), "pending")
            if status == "pending" and name in staged_actions:
                status = "staged"
            if current and current[0] == name:
                if current[1] == "executed":
                    status = "executed"
                elif current[1] == "staged" and status != "executed":
                    status = "staged"
                elif current[1] == "unconfirmed":
                    status = "unconfirmed"
                elif status != "executed":  # a replay of an executed effect stays executed
                    status = "denied"
            if status != "executed":
                remaining.append(name)
        else:
            status = "not_mediated"
        item = {"name": name, "tool": tool, "status": status}
        if isinstance(a.get("params"), dict):
            item["params"] = a["params"]
        actions.append(item)
        if (name in needs or tool in needs) and status != "executed" and not _approved(h, a, at, extra_approvals):
            approvals_needed.append(name)
    claim_state = hc.entry_state(entry) if entry else None
    if claim_state == "RESERVED" and current and current[1] == "executed" and not remaining:
        claim_state = "COMPLETED"  # the fence completes the claim with this effect
    scope = eff.get("scope") or {}
    depends = []
    for key in h.get("depends_on") or []:
        dep = ledger.get(key)
        depends.append({"key": key, "state": hc.entry_state(dep) if isinstance(dep, dict) else "UNKNOWN"})
    return {
        "purpose": h.get("purpose"),
        "handoff": {k: h.get(k) for k in ("id", "idempotency_key", "trace_id", "from", "to")},
        "claim_state": claim_state,
        "planned_actions": actions,
        "remaining": remaining,
        "constraints": {
            "owned_paths": list(scope.get("owned_paths") or []),
            "forbidden": sorted(set(scope.get("forbidden") or []) | set(policy.get("forbidden") or [])),
            "allowed_tools": list((eff.get("authority") or {}).get("allowed_tools") or []),
            "approvals_needed": approvals_needed,
            "expires_at": (eff.get("acceptance") or {}).get("expires_at"),
            "depends_on": depends,
        },
        "note": NOTE,
    }


def with_plan(verdict: dict, packet, registry, ledger_path, mediated_tools=()) -> dict:
    """An ACCEPT verdict plus its plan anchor (other verdicts unchanged)."""
    if not isinstance(verdict, dict) or verdict.get("decision") != "ACCEPT":
        return verdict
    ledger = hc.load_ledger(Path(ledger_path)) if ledger_path else {}
    plan = plan_for(packet, registry, ledger, mediated_tools)
    return {**verdict, "plan": plan} if plan else verdict
