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
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_client as scl  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_touchid as st  # noqa: E402
import synthe_ui as sui  # noqa: E402

DEFAULT_EXPIRES_MIN = 30
MAX_EXPIRES_MIN = 24 * 60
DEFAULT_KEY = Path("~/.synthe/approver.key.json")
DEFAULT_TOUCHID_KEY = Path("~/.synthe") / st.KEY_NAME
PREVIEW_LINES = 60

# C0/C1 controls except tab and newline (ESC starts ANSI sequences; CR overwrites a line), DEL,
# and the bidi controls that reorder what you read (Trojan Source).
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")


def clean(text, one_line: bool = False) -> str:
    """Agent-controlled text made safe to print: control codes become visible escapes."""
    s = "" if text is None else str(text)
    if one_line:
        s = s.replace("\n", "\\n")

    def esc(m):
        c = ord(m.group())
        return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}"
    return _CONTROL.sub(esc, s)


def _short(sha) -> str:
    return sha[:12] if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) else clean(sha, one_line=True)


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
        elif line == " A push is waiting for your approval":
            out.append(ui.c(line, "brand", bold=True))
        elif line.startswith(" The agent says"):
            out.append(ui.c(line, "warn", bold=True))
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


def render(detail: dict, full: bool = False, ui=None) -> str:
    """The approval card. Facts first, from the broker's record; the agent's words last, labeled.
    With `ui` on a colour terminal, labels and diff lines are coloured; the text is the same."""
    eff, ch = detail.get("effect") or {}, detail.get("changes") or {}
    old = eff.get("expected_old")
    lines = ["", "═" * 72, " A push is waiting for your approval", "═" * 72,
             f" Proposal     {clean(detail.get('id'), True)}   (handoff {clean(detail.get('handoff_id'), True)})",
             f" Agents       {clean(detail.get('from'), True)} → {clean(detail.get('to'), True)}",
             f" Push         commit {_short(eff.get('commit'))} to {clean(eff.get('remote'), True)} / "
             f"{clean(eff.get('branch'), True)}"
             + ("   (a new branch)" if old in (None, "new") else f"   (replacing {_short(old)})")]
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
    lines += ["─" * 72, " The agent says (its own words, not verified by Synthe):"]
    lines += [f"   {line}" for line in clean((detail.get("agent_says") or {}).get("purpose")).splitlines() or [""]]
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
    return "\n".join(_paint(lines, ui))


def diff_has_more(detail: dict) -> bool:
    """Whether `v` can reveal patch lines not already present in the approval card."""
    ch = detail.get("changes") or {}
    return bool(ch.get("available") and
                len(clean(ch.get("patch") or "").splitlines()) > PREVIEW_LINES)


def build_approval(detail: dict, key: dict, expires_in_min: int = DEFAULT_EXPIRES_MIN, now=None) -> dict:
    """A detached approval for exactly this proposal: the plan's params plus the commit the broker
    showed, signed with the approver's key, valid for `expires_in_min` minutes."""
    if not 0 < expires_in_min <= MAX_EXPIRES_MIN:
        raise ValueError(f"approvals last between 1 and {MAX_EXPIRES_MIN} minutes")
    eff, ch = detail.get("effect") or {}, detail.get("changes") or {}
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
    return ss.detached_approval(packet, key, detail["action"], expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                {**params, "commit": commit})


def touchid_reason(detail: dict) -> str:
    """What the Touch ID prompt says, from the broker's view of the proposal (names cleaned: an agent
    chose the branch and file names, and they must not fake the prompt's wording)."""
    eff, ch = detail.get("effect") or {}, detail.get("changes") or {}
    files = ch.get("files") or []
    first = ", ".join(clean(f.get("path"), True) for f in files[:3] if isinstance(f, dict))
    more = f" and {len(files) - 3} more" if len(files) > 3 else ""
    what = f"{len(files)} file{'s' if len(files) != 1 else ''}" + (f" ({first}{more})" if first else "")
    text = (f"approve pushing {clean(eff.get('branch'), True)} at {_short(eff.get('commit'))} "
            f"to {clean(eff.get('remote') or 'origin', True)}: {what}")
    return text[:300]


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
    ap.add_argument("--expires-in", type=int, default=DEFAULT_EXPIRES_MIN,
                    help=f"minutes the approval stays valid (default {DEFAULT_EXPIRES_MIN}, at most {MAX_EXPIRES_MIN})")
    a = ap.parse_args(argv)
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
        while True:
            view = "[v] view the whole diff   " if diff_has_more(detail) else ""
            choice = _ask(f" [a] approve once   {view}[s] skip   [q] quit > ")
            if choice == "v":
                if diff_has_more(detail):
                    print(render(detail, full=True, ui=ui))
                else:
                    print(" The whole diff is already shown above.")
                continue
            break
        if choice == "q":
            return 0
        if choice != "a":
            print(" Skipped. It stays staged, and it can't be pushed without an approval.")
            continue
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
        except st.TouchIDError as e:
            print(f"synthe-approve: not approved: {e}. It stays staged.", file=sys.stderr)
        except (ValueError, ss.KeyFileError) as e:
            print(f"synthe-approve: not approved: {e}", file=sys.stderr)
        except scl.BrokerError as e:
            print(f"synthe-approve: {e.code}: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
