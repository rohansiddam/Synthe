#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""synthe-approve: approve a staged push from your own terminal.

  synthe-approve [--broker URL] [--key ~/.synthe/approver.key.json] [--id ID] [--expires-in 30]
  synthe-approve --list

An agent proposes a push and the broker holds it, staged, until a human approves. This command
lists what the broker is holding, shows one proposal the way the broker will push it (the diff
from the broker's own copy, never the agent's description of it; study F03), and on "approve"
signs a detached approval with your Touch ID key (if you set one up with `synthe-init touchid`;
the prompt names the branch, commit and files) or your passphrase-protected key. The approval pins that exact
commit and lasts a short time (30 minutes by default). The broker then pushes only if nothing
moved since, and writes a signed receipt either way.

Choices are approve once or skip, as in Zed's agent permission prompt. There is no "always":
approving a pattern once (lane templates, study F11) comes later.

Everything the agent wrote (its stated purpose, commit messages, file names, the patch) is shown
with terminal control codes neutralized, so it can't clear the screen or fake a prompt.

Card v2 (specs/approval-card-v2.md): people stop reading prompts that always look the same (users
accept 93% of Claude Code's permission prompts). So the card assesses each push from the broker's
data alone (size, deletions, sensitive paths, incomplete evidence) and looks different by risk; the
agent's words come after the diff; a high-risk push asks you to type the end of the commit hash
before Touch ID, and a non-routine push with a long diff can only be approved after you viewed all
of it. Each decision is noted in a local log (never sent anywhere) for `--stats`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_client as scl  # noqa: E402
import synthe_risk  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_touchid as st  # noqa: E402
import synthe_ui as sui  # noqa: E402

DEFAULT_EXPIRES_MIN = 30
MAX_EXPIRES_MIN = 24 * 60
DEFAULT_KEY = Path("~/.synthe/approver.key.json")
DEFAULT_TOUCHID_KEY = Path("~/.synthe") / st.KEY_NAME
PREVIEW_LINES = 60

# The risk tiers, thresholds and sensitive paths live in synthe_risk.py, shared with the broker, so the
# card shows the same assessment the broker acts on for a risk-aware lane grant.
TIERS, HIGH_PATHS, REVIEW_PATHS = synthe_risk.TIERS, synthe_risk.HIGH_PATHS, synthe_risk.REVIEW_PATHS
REVIEW_LINES, HIGH_LINES = synthe_risk.REVIEW_LINES, synthe_risk.HIGH_LINES
HIGH_DELETED_FILES = synthe_risk.HIGH_DELETED_FILES
REVIEW_COMMITS, HIGH_COMMITS = synthe_risk.REVIEW_COMMITS, synthe_risk.HIGH_COMMITS
CHECK_CHARS = 4  # how much of the commit hash a high-risk approval must type back
DEFAULT_LOG = Path("~/.synthe/approvals.log")

clean = synthe_risk.clean  # agent-controlled text made safe to print (control codes become visible escapes)


def _full(sha) -> str:
    """The whole commit hash, for a card whose check asks you to type its end."""
    return sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) else clean(sha, one_line=True)


def _short(sha) -> str:
    return sha[:12] if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) else clean(sha, one_line=True)


def _part(detail: dict, key: str) -> dict:
    """detail[key] when it is a dict, else {} (the assessment then calls the evidence incomplete)."""
    value = detail.get(key) if isinstance(detail, dict) else None
    return value if isinstance(value, dict) else {}


_shortstat = synthe_risk.shortstat


def assess(detail: dict) -> dict:
    """How carefully this push deserves to be read: {"tier": routine|review|high, "reasons": [...]}.
    Computed only from the broker's record (target, its own diff, file list, commits); never from
    anything the agent wrote about the push. Reasons are short plain sentences, already cleaned.
    The rules are synthe_risk's; when the broker escalated the push under a risk-aware lane grant, its
    own assessment (`risk` in the detail) can only raise the tier shown here, never lower it."""
    return synthe_risk.stricter(synthe_risk.assess(detail), detail.get("risk") if isinstance(detail, dict) else None)


def waiting_for_approval(staged: list) -> list:
    return [s for s in staged if s.get("state") == "STAGED" and "approval" in (s.get("waiting_for") or [])]


def _paint(lines: list, ui) -> list:
    """Colour for a person's terminal: fixed labels and the diff's +/- lines only. Every line here was
    already passed through clean(), so agent text can't carry its own escape codes; we add ours around it."""
    if ui is None or not ui.color:
        return lines
    out, in_diff = [], False
    labels = ("Proposal", "Agents", "Push", "Changes", "Commits", "Handoff")
    for line in lines:
        if line.startswith("═") or line.startswith("─"):
            out.append(ui.c(line, "muted"))
            in_diff = False  # every section, the diff included, ends with a rule
        elif line.startswith("━") or line.startswith("▓"):
            out.append(ui.c(line, "warn", bold=line.startswith("▓")))
            in_diff = False
        elif line == " A push is waiting for your approval":
            out.append(ui.c(line, "brand", bold=True))
        elif line.startswith(" High-risk push:") or line.startswith(" Check this push:") \
                or line.startswith(" Why this is flagged") or line.startswith("   • ") \
                or line.startswith(" Outside your lane") or line.startswith(" Your lane sent this"):
            out.append(ui.c(line, "warn", bold=line.startswith(" High-risk")))
        elif line.startswith(" The agent says") or line.startswith(" Task written by the agent"):
            out.append(ui.c(line, "warn", bold=True))
        elif line.startswith(" Task signed by") or line.startswith(" Your instructions for this lane"):
            out.append(ui.c(line, "brand", bold=True))
        elif line.startswith(" Diff"):
            in_diff = True
            out.append(ui.c(line, "brand", bold=True))
        elif in_diff and line.startswith("   +") and not line.startswith("   +++"):
            out.append(ui.c(line, "ok"))
        elif in_diff and line.startswith("   -") and not line.startswith("   ---"):
            out.append(ui.c(line, "bad"))
        elif in_diff and line.startswith("   @@"):
            out.append(ui.c(line, "muted"))
        elif any(line.startswith(f" {k} ") for k in labels):
            key = line.split()[0]
            out.append(" " + ui.c(key, "muted") + line[1 + len(key):])
        else:
            out.append(line)
    return out


FRAME = {"routine": "═", "review": "━", "high": "▓"}


def headline(risk: dict) -> str:
    """The card's first line. It changes with the risk, so a push that deserves attention never looks
    like the routine ones you have learned to skim."""
    why = risk["reasons"][0] if risk["reasons"] else "the broker rated it above routine"
    if risk["tier"] == "high":
        return f" High-risk push: {why}"
    if risk["tier"] == "review":
        return f" Check this push: {why}"
    return " A push is waiting for your approval"


def _strings(value, limit: int = 20) -> list:
    return [clean(x, one_line=True) for x in value[:limit] if isinstance(x, str)] if isinstance(value, list) else []


def lane_lines(detail: dict) -> list:
    """Why a lane grant sent this push to you, from the broker's record: `lane_scope` when it touches files
    outside the grant's paths, `risk` (escalated) when the grant doesn't approve its risk tier. Nothing
    when no lane was involved. Paths and reasons are the broker's, cleaned like everything else here."""
    scope, risk = _part(detail, "lane_scope"), _part(detail, "risk")
    out = []
    if scope:
        outside = _strings(scope.get("outside_paths"), 10)
        count = scope.get("outside_count")
        n = count if isinstance(count, int) and not isinstance(count, bool) and count >= len(outside) else len(outside)
        covers = _strings(scope.get("path_scope"), 5)
        out.append(f" Outside your lane: {n} file{'s' if n != 1 else ''}."
                   + (f" Your lane covers {', '.join(covers)}, so it sent this to you." if covers else
                      " Your lane sent this to you."))
        out += [f"   • {p}" for p in outside]
        if n > len(outside):
            out.append(f"   … and {n - len(outside)} more")
    if risk.get("escalated") is True:
        reasons = _strings(risk.get("reasons"), 5)
        out.append(" Your lane sent this to you because: " + ("; ".join(reasons) if reasons else
                   f"it is {clean(risk.get('tier'), one_line=True)} risk, a level the lane does not approve on its own")
                   + ".")
    return out


def render(detail: dict, full: bool = False, ui=None) -> str:
    """The approval card. Facts first, from the broker's record; the agent's words last, labeled.
    With `ui` on a colour terminal, labels and diff lines are coloured; the text is the same."""
    eff, ch = _part(detail, "effect"), _part(detail, "changes")
    old = eff.get("expected_old")
    risk = assess(detail)
    rule = FRAME[risk["tier"]] * 72
    lines = ["", rule, headline(risk), rule]
    if risk["reasons"]:
        lines.append(" Why this is flagged (from the broker's copy, not the agent's words):")
        lines += [f"   • {r}" for r in risk["reasons"]]
        lines.append(rule)
    if lane_lines(detail):
        lines += lane_lines(detail) + [rule]
    lines += [
             f" Proposal     {clean(detail.get('id'), True)}   (handoff {clean(detail.get('handoff_id'), True)})",
             f" Agents       {clean(detail.get('from'), True)} → {clean(detail.get('to'), True)}",
             f" Push         commit {_full(eff.get('commit')) if risk['tier'] == 'high' else _short(eff.get('commit'))}"
             f" to {clean(eff.get('remote'), True)} / "
             f"{clean(eff.get('branch'), True)}"
             + ("   (a new branch)" if old in (None, "new") else f"   (replacing {_short(old)})")]
    budget = detail.get("effective_budget")
    if not isinstance(budget, dict):
        budget = (((detail.get("packet") or {}).get("handoff") or {}).get("authority") or {}).get("budget")
    if isinstance(budget, dict) and budget:
        # The approval binds this budget: the spend may only come down afterwards.
        dims = " / ".join(f"{k} {budget[k]}" for k in ("tokens", "usd", "minutes") if k in budget)
        lines.append(f" Budget       {clean(dims, True)}   [the approval caps the spend at this]")
    if ch.get("available"):
        lines.append(f" Changes      {clean(ch.get('stat'), True) or 'no file changes'}   "
                     f"[from the broker's copy]")
        for f in (ch.get("files") or [])[:40]:
            lines.append(f"   {clean(f.get('status'), True):<2} {clean(f.get('path'), True)}")
        if len(ch.get("files") or []) > 40:
            lines.append(f"   … and {len(ch['files']) - 40} more files")
        lines.append(" Commits")
        for c in (ch.get("commits") or [])[:20]:
            lines.append(f"   {_short(c.get('sha'))}  {clean(c.get('author'), True)}: {clean(c.get('subject'), True)}")
    else:
        lines.append(f" Changes      not shown: {clean(ch.get('note'), True)}")
    lines.append(f" Handoff      expires {clean(detail.get('handoff_expires_at'), True)}")
    lines.append("─" * 72)
    if ch.get("available"):
        patch = clean(ch.get("patch") or "").splitlines()
        shown = patch if full else patch[:PREVIEW_LINES]
        lines += [" Diff" + ("" if full or len(patch) <= PREVIEW_LINES else
                             f" (first {PREVIEW_LINES} of {len(patch)} lines; press v for all)")]
        lines += [f"   {line}" for line in shown]
        if ch.get("patch_truncated"):
            lines.append("   … the broker cut the patch at its size limit; read the commit itself before approving")
        lines.append("─" * 72)
    # The task's words come last: read the change first, then what the task says. Its heading says who wrote it,
    # from the broker's task_origin (the signed packet and the registry), never from the text itself.
    origin = detail.get("task_origin") if isinstance(detail.get("task_origin"), dict) else {}
    said = clean((detail.get("agent_says") or {}).get("purpose")).splitlines() or [""]
    if origin.get("kind") == "self_issued":
        lines.append(f" Task written by the agent (self-issued under lane {clean(origin.get('template_id'), True)}, "
                     f"signed by {clean(origin.get('granted_by'), True)}, task {clean(origin.get('issue'), True)}):")
        lines += [f"   {line}" for line in said]
        if isinstance(detail.get("lane_brief"), str):
            lines.append(" Your instructions for this lane (you signed these):")
            lines += [f"   {line}" for line in clean(detail["lane_brief"]).splitlines() or [""]]
    elif origin.get("kind") == "signed" and origin.get("sender_kind") == "human":
        lines.append(f" Task signed by {clean(origin.get('sender'), True)} (a person, not the agent):")
        lines += [f"   {line}" for line in said]
    else:
        lines.append(" The agent says (its own words, not verified by Synthe):")
        lines += [f"   {line}" for line in said]
    lines.append("─" * 72)
    return "\n".join(_paint(lines, ui))


def diff_has_more(detail: dict) -> bool:
    """Whether `v` can reveal patch lines not already present in the approval card."""
    ch = _part(detail, "changes")
    return bool(ch.get("available") and
                len(clean(ch.get("patch") or "").splitlines()) > PREVIEW_LINES)


def build_approval(detail: dict, key: dict, expires_in_min: int = DEFAULT_EXPIRES_MIN, now=None) -> dict:
    """A detached approval for exactly this proposal: the plan's params plus the commit the broker
    showed, signed with the approver's key, valid for `expires_in_min` minutes. The approval pins
    the broker-supplied effective budget (the ceiling the checker will apply), so minimal packets
    that name no budget of their own are still capped."""
    if not 0 < expires_in_min <= MAX_EXPIRES_MIN:
        raise ValueError(f"approvals last between 1 and {MAX_EXPIRES_MIN} minutes")
    eff, ch = _part(detail, "effect"), _part(detail, "changes")
    commit = eff.get("commit")
    if not (isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit)):
        raise ValueError("this proposal has no commit to pin; approve it with synthe-sign approve --detached")
    if ch.get("available") and ch.get("commit") != commit:
        raise ValueError("the broker's diff and its proposal name different commits; not approving")
    packet = detail.get("packet") or {}
    h = packet.get("handoff") or {}
    params = ss.planned_params(h, detail.get("action"))
    if params is None:
        raise ValueError("the handoff's plan names no params for this action, so the approval can't pin them")
    expires = (now or dt.datetime.now(dt.timezone.utc)) + dt.timedelta(minutes=expires_in_min)
    budget = detail.get("effective_budget")
    if budget is not None and not isinstance(budget, dict):
        raise ValueError("the broker's effective_budget is malformed; not approving")
    try:
        return ss.detached_approval(packet, key, detail["action"], expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                    {**params, "commit": commit}, budget=budget)
    except ValueError as e:
        # No budget to bind (packet names none, broker supplied none): fail
        # closed with the remedy, never sign an uncapped approval.
        raise ValueError(f"{e} Approve it with "
                         f"synthe-sign approve --detached --budget '{{\"tokens\": ..., \"usd\": ..., \"minutes\": ...}}'") \
            from None


def touchid_reason(detail: dict) -> str:
    """What the Touch ID prompt says, from the broker's view of the proposal (names cleaned: an agent
    chose the branch and file names, and they must not fake the prompt's wording)."""
    eff, ch = _part(detail, "effect"), _part(detail, "changes")
    files = ch.get("files") or []
    first = ", ".join(clean(f.get("path"), True) for f in files[:3] if isinstance(f, dict))
    more = f" and {len(files) - 3} more" if len(files) > 3 else ""
    what = f"{len(files)} file{'s' if len(files) != 1 else ''}" + (f" ({first}{more})" if first else "")
    risk = assess(detail)
    prefix = {"high": "HIGH-RISK: ", "review": "CHECK: "}.get(risk["tier"], "")
    if risk["reasons"]:
        what = risk["reasons"][0] + (f", {len(files)} file{'s' if len(files) != 1 else ''}" if files else "")
    text = (f"{prefix}approve pushing {clean(eff.get('branch'), True)} at {_short(eff.get('commit'))} "
            f"to {clean(eff.get('remote') or 'origin', True)}: {what}")
    return text[:300]


def must_view_full_diff(detail: dict) -> bool:
    """A push that isn't routine and whose diff doesn't fit on the card is approved only after the
    whole diff was shown (the terminal's version of "route large pushes to a proper review")."""
    return assess(detail)["tier"] != "routine" and diff_has_more(detail)


def confirm_commit(detail: dict, ask=None) -> bool:
    """High-risk pushes only: type the last characters of the commit hash shown on the card (number
    matching, the fix for push-approval fatigue). Three misses and nothing is signed."""
    ask = ask or _ask
    commit = str((_part(detail, "effect")).get("commit") or "")
    want = commit[-CHECK_CHARS:].lower()
    if len(want) != CHECK_CHARS:
        return False
    for _ in range(3):
        if ask(f" High-risk push. Type the last {CHECK_CHARS} characters of the full commit on the Push line: ") == want:
            return True
        print(" That doesn't match the commit on the card.")
    print(" Not approved. It stays staged.")
    return False


LOG_KEEP = 1000  # decisions kept; older lines are dropped when the file passes twice this


def log_path() -> Path | None:
    """Where decisions are logged: local telemetry for --stats, never sent anywhere. Set
    SYNTHE_APPROVALS_LOG=off to turn it off, or to a path to move it."""
    value = os.environ.get("SYNTHE_APPROVALS_LOG")
    if value and value.strip().lower() in ("off", "0", "false", "no"):
        return None
    return Path(value or DEFAULT_LOG).expanduser()


def record(detail: dict, decision: str, shown_at: float, decided_at: float | None = None) -> None:
    """One line per decision in a local file, for --stats. It never leaves this machine and holds no
    agent text: the proposal id, tier, size and timing only. A write failure never blocks a decision."""
    risk = assess(detail)
    ins, dels = _shortstat((_part(detail, "changes")).get("stat"))
    entry = {"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "id": clean(detail.get("id"), True), "tier": risk["tier"], "decision": decision,
             "lines": ins + dels, "seconds": round((decided_at or time.monotonic()) - shown_at, 1)}
    path = log_path()
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        os.chmod(path, 0o600)
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > 2 * LOG_KEEP:
            tmp = path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(lines[-LOG_KEEP:]) + "\n")
            os.replace(tmp, path)
    except OSError:
        pass


def stats(path: Path | None = None) -> str:
    """Approval rate and time-to-decision by tier, from the local log. A fast approval of a big
    high-risk push is the pattern of approving without reading; it is called out."""
    path = path or log_path()
    if path is None:
        return "The local approval log is off (SYNTHE_APPROVALS_LOG=off)."
    rows = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("tier") in TIERS:
                rows.append(row)
    except OSError:
        return "No decisions recorded yet."
    if not rows:
        return "No decisions recorded yet."
    out = [f"{len(rows)} decisions in {path}"]
    for tier in TIERS:
        group = [r for r in rows if r["tier"] == tier]
        if not group:
            continue
        approved = [r for r in group if r.get("decision") == "approved"]
        secs = sorted(float(r.get("seconds") or 0) for r in group)
        median = secs[len(secs) // 2]
        out.append(f"  {tier:<8} {len(group):>4} shown, {len(approved) * 100 // len(group):>3}% approved, "
                   f"median {median:.0f}s to decide")
    rushed = [r for r in rows if r.get("decision") == "approved" and r["tier"] == "high"
              and float(r.get("seconds") or 0) < max(2.0, 2.0 * int(r.get("lines") or 0) / 100)]
    if rushed:
        out.append(f"  ! {len(rushed)} high-risk approval{'s' if len(rushed) != 1 else ''} came faster than "
                   f"2s per 100 changed lines. A heuristic, not proof of reading; worth a look.")
    return "\n".join(out)


def summarize(result: dict, ui=None) -> str:
    rec = result.get("receipt") or {}
    paint = (lambda w: ui.decision(w)) if ui is not None and ui.color else (lambda w: w)
    out = [f" Approval: {paint(str(rec.get('decision')))} (receipt #{rec.get('seq')})"]
    out += [f"   {r.get('code')}: {clean(r.get('message'), True)}" for r in rec.get("reasons") or []]
    for c in result.get("commits") or []:
        eff = c.get("effect") or {}
        out.append(f" Push: {paint(str(c.get('decision')))} (receipt #{c.get('seq')})"
                   + (f"  {_short(eff.get('commit'))} → {clean(eff.get('branch'), True)}"
                      if c.get("decision") == "executed" else ""))
        out += [f"   {r.get('code')}: {clean(r.get('message'), True)}" for r in c.get("reasons") or []]
    if not result.get("commits") and rec.get("decision") == "approval_accepted":
        out.append(" Nothing pushed yet: the proposal still waits for something else (see the receipt).")
    return "\n".join(out)


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return "q"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Approve a staged push from your own terminal.")
    ap.add_argument("--broker", help="unix:///path/to/broker.sock or tcp://host:port (default $SYNTHE_BROKER)")
    ap.add_argument("--key", default=os.environ.get("SYNTHE_APPROVER_KEY", str(DEFAULT_KEY)),
                    help=f"your encrypted approver key (default $SYNTHE_APPROVER_KEY or {DEFAULT_KEY})")
    ap.add_argument("--touchid-key", default=os.environ.get("SYNTHE_TOUCHID_KEY", str(DEFAULT_TOUCHID_KEY)),
                    help=f"your Touch ID key, used when it exists (default {DEFAULT_TOUCHID_KEY})")
    ap.add_argument("--passphrase", action="store_true",
                    help="approve with the passphrase key even if a Touch ID key is set up")
    ap.add_argument("--id", help="go straight to this proposal (idempotency_key/action)")
    ap.add_argument("--list", action="store_true", help="list what waits for an approval, then exit")
    ap.add_argument("--stats", action="store_true",
                    help="show your approval rate and time-to-decision by risk, from the local log, then exit")
    ap.add_argument("--expires-in", type=int, default=DEFAULT_EXPIRES_MIN,
                    help=f"minutes the approval stays valid (default {DEFAULT_EXPIRES_MIN}, at most {MAX_EXPIRES_MIN})")
    a = ap.parse_args(argv)
    if a.stats:
        print(stats())
        return 0
    ui = sui.UI()
    if ui.color:
        print(ui.header("approve"))
    try:
        client = scl.BrokerClient(a.broker)
        waiting = waiting_for_approval(client.call("staged").get("staged") or [])
    except scl.BrokerError as e:
        print(f"synthe-approve: {e.code}: {e}", file=sys.stderr)
        return 2
    if a.list or not waiting:
        if not waiting:
            print("Nothing is waiting for your approval.")
        for s in waiting:
            print(f"  {clean(s.get('idempotency_key'), True)}/{clean(s.get('action'), True)}  "
                  f"{_short((s.get('params') or {}).get('commit'))} → {clean((s.get('params') or {}).get('branch'), True)}"
                  f"  staged {clean(s.get('staged_at'), True)}")
        return 0
    if not sys.stdin.isatty():
        print("synthe-approve is interactive: run it in your own terminal.", file=sys.stderr)
        return 2
    ids = [f"{s['idempotency_key']}/{s['action']}" for s in waiting]
    if a.id and a.id not in ids:
        print(f"synthe-approve: {clean(a.id, True)} is not waiting for an approval", file=sys.stderr)
        return 2
    key = None
    for sid in ([a.id] if a.id else ids):
        try:
            detail = client.call("staged_detail", id=sid)
        except scl.BrokerError as e:
            print(f"synthe-approve: {e.code}: {e}", file=sys.stderr)
            continue
        print(render(detail, ui=ui))
        shown_at = time.monotonic()
        viewed_all = not must_view_full_diff(detail)
        while True:
            truncated = bool((_part(detail, "changes")).get("patch_truncated"))
            view = ("[v] view the diff the broker returned   " if truncated else "[v] view the whole diff   ") \
                if diff_has_more(detail) else ""
            approve = "[a] approve once   " if viewed_all else ""
            if not viewed_all:
                print(" This push needs a careful read: view the diff (v) before approving." +
                      (" The broker cut it at its size limit, so read the commit itself as well." if truncated else ""))
            choice = _ask(f" {approve}{view}[s] skip   [q] quit > ")
            if choice == "v":
                if diff_has_more(detail):
                    print(render(detail, full=True, ui=ui))
                    viewed_all = True
                else:
                    print(" The whole diff is already shown above.")
                continue
            if choice == "a" and not viewed_all:
                continue
            break
        if choice == "q":
            record(detail, "quit", shown_at)
            return 0
        if choice != "a":
            record(detail, "skipped", shown_at)
            print(" Skipped. It stays staged, and it can't be pushed without an approval.")
            continue
        if assess(detail)["tier"] == "high" and not confirm_commit(detail):
            record(detail, "check_failed", shown_at)
            continue
        decided_at = time.monotonic()
        touchid = not a.passphrase and Path(a.touchid_key).expanduser().is_file()
        try:
            if touchid:
                reason = touchid_reason(detail)
                signer = st.signing_key(Path(a.touchid_key), reason)
                print(f" Touch ID as {clean(signer['agent'], True)} (key {clean(signer['kid'], True)}): {reason}.")
                print(" Touch the sensor to approve, or cancel. (--passphrase uses your passphrase key instead.)")
                approval = build_approval(detail, signer, a.expires_in)
            else:
                if key is None:
                    key = ss.load_key(str(Path(a.key).expanduser()), require_encrypted=True)
                    print(f" Approving as {clean(key.get('agent'), True)} (key {clean(key.get('kid'), True)}).")
                approval = build_approval(detail, key, a.expires_in)
            print(summarize(client.call("submit_approval", approval=approval), ui))
            record(detail, "approved", shown_at, decided_at)
        except st.TouchIDError as e:
            print(f"synthe-approve: not approved: {e}. It stays staged.", file=sys.stderr)
        except (ValueError, ss.KeyFileError) as e:
            print(f"synthe-approve: not approved: {e}", file=sys.stderr)
        except scl.BrokerError as e:
            print(f"synthe-approve: {e.code}: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
