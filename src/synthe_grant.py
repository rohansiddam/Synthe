#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lane grants from your own terminal, in one command (behind `synthe-task grant|grants|revoke-grant`).

  synthe-task grant [--branch 'agent/*'] [--paths 'src/**,tests/**'] [--uses 50] [--until 7d]
                    [--auto-approve routine,review] [--self-issue] [--remote origin] [--agent openclaw]
                    [--delegate ID] [--brief TEXT] [--passphrase]
  synthe-task grants [--all]
  synthe-task revoke-grant ID

A lane grant (synthe_lane_templates.py) lets pushes inside its limits go out without asking you each
time: one agent, git_push only, a branch pattern, the files it may touch, the risk tiers it approves, and
optionally a number of uses and an expiry. `grant` fills what it can from your setup (remote, agent,
branches, allowed paths), shows what you are about to allow in plain words, asks, then signs with your key
(Touch ID if you enrolled one, otherwise your passphrase) and hands it to the broker. The broker computes
the lineage digests the grant is signed against and re-checks everything at every push; this file only
builds, shows and signs.

By default a lane has no use limit and no expiry: it stays open until you revoke it. A grant that omits
`max_uses` or `expires_at` has no such limit; --uses and --until add one. It approves routine and review
pushes on its own (`auto_approve`, the broker's default; --auto-approve routine,review,high overrides it):
a high-risk push, and a push that touches files outside the lane's paths, wait for you. What a lane never
covers are the stops: main, master and patterns that reach them, and the policy's forbidden paths.

With --self-issue (on for the lane setup offers) the agent may also start its own work inside the lane: a
plain `git push` on a lane branch with no task from you gets a task the broker issues under the grant, signed
by its own task issuer key and labelled everywhere as written by the agent (SPEC section 16). There is no
limit on how many unless the grant names one; revoking or expiring the grant kills every such task that hasn't
landed. In v1 such a lane must send high-risk pushes to you (no "high" in --auto-approve) or name a reviewer.

Only you can run it: it needs a terminal you are typing in, and the signature needs your passphrase or
your finger. There is no --yes. An unattended lane trades review for speed within its limits: while it
is open, nobody reads each push before it goes out (the receipt still records it).
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import secrets
import shlex
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_lane_templates as lanes  # noqa: E402
import synthe_risk  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_touchid as touchid  # noqa: E402
import synthe_ui as sui  # noqa: E402

MAX_USES = lanes.MAX_USES   # what --uses may cap a lane at; a lane with no cap carries no max_uses at all
# Lanes opened before limits were optional used these in place of "none": still shown as no limit / no expiry.
LEGACY_NO_LIMIT = 10000
NO_EXPIRY = dt.datetime(9999, 1, 1, tzinfo=dt.timezone.utc)   # --until this far out is the same as leaving it out
MIN_MINUTES = 5
REFUSED_BRANCHES = ("main", "master")   # also anything that matches them: '*', '**', 'ma*'
RENEW_WITHIN = dt.timedelta(hours=24)
RENEW_USES = 0.10           # flag a grant with less than this fraction of its uses left
INACTIVE = {
    "template_expired": "expired",
    "template_revoked": "revoked",
    "template_exhausted": "used up",
    "template_stale": "stale (the policy, approvers or config changed since you signed it)",
}
EXPLAIN = {
    "template_scope": "lane grants aren't switched on for this agent on this broker",
    "approver_not_trusted": "your approver identity isn't trusted for this agent in the broker's registry",
    "template_stale": "the broker's policy, approvers or config changed while you were signing; try again",
    "template_signature_invalid": "the broker doesn't recognise the signature (is this key registered with it? "
                                  "after enrolling Touch ID the admin step must run first)",
    "delegate_invalid": "the delegate isn't a registered model approver (see docs/COMMIT.md)",
    "template_malformed": "the broker found the grant malformed",
    "risk_rules_invalid": "the risk rules in the broker's config are malformed (effects.git_push.risk); fix them first",
}


# ---- reading what you asked for --------------------------------------------------------------

def _csv(text) -> list:
    return [x.strip() for x in re.split(r"[,\n]", text or "") if x.strip()]


def _join(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def unlimited_uses(t: dict) -> bool:
    return t.get("max_uses") is None or t["max_uses"] >= LEGACY_NO_LIMIT


def no_expiry(end: dt.datetime | None) -> bool:
    return end is None or end >= NO_EXPIRY


def expiry_of(t: dict) -> dt.datetime | None:
    """When a grant ends; None for a grant that carries no `expires_at`."""
    return hc.parse_ts(t["expires_at"]) if t.get("expires_at") else None


def parse_tiers(value) -> list:
    """--auto-approve: the risk tiers the grant approves on its own, as the broker wants them (distinct, known)."""
    items = [x.lower() for x in (_csv(value) if isinstance(value, str) else list(value or []))]
    bad = [x for x in items if x not in synthe_risk.TIERS]
    if bad or not items:
        raise SystemExit(f"--auto-approve {value if isinstance(value, str) else ','.join(map(str, items))!r}: "
                         + (f"unknown tier {bad[0]!r}; " if bad else "name at least one tier; ")
                         + f"choose from {', '.join(synthe_risk.TIERS)} (e.g. routine,review)")
    return [t for t in synthe_risk.TIERS if t in items]


def parse_until(text: str, now: dt.datetime, tz=None) -> dt.datetime:
    """When the grant ends: a length (90m, 12h, 7d, 2w) or a date/time (2026-10-30, 2026-10-30T17:00, local
    time unless it names a zone). Not sooner than MIN_MINUTES; there is no upper bound."""
    text = (text or "").strip()
    m = re.fullmatch(r"(\d{1,5})\s*([mhdw])", text.lower())
    if m:
        unit = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}[m.group(2)]
        end = now + dt.timedelta(**{unit: int(m.group(1))})
    else:
        try:
            end = dt.datetime.fromisoformat(text)
        except ValueError:
            raise SystemExit(f"--until {text!r}: say how long (90m, 12h, 7d, 2w) or give a date (2026-10-30)")
        if len(text) == 10:  # a bare date means the end of that day
            end = end.replace(hour=23, minute=59, second=59)
        if end.tzinfo is None:
            end = end.replace(tzinfo=tz) if tz else end.astimezone()
    try:
        end = end.astimezone(dt.timezone.utc).replace(microsecond=0)
    except OverflowError:
        raise SystemExit(f"--until {text!r} is past the year 9999; leave --until out for no expiry")
    if end < now + dt.timedelta(minutes=MIN_MINUTES):
        raise SystemExit(f"--until {text!r} is too soon: a grant lasts at least {MIN_MINUTES} minutes")
    return min(end, NO_EXPIRY)


def _sample(pattern: str) -> str:
    """One path a glob matches, with the widest wildcard reading: to ask whether a pattern stays inside another."""
    return re.sub(r"\*\*/|\*\*|\*|\?", lambda m: {"**/": "x/y/", "**": "x/y", "*": "x", "?": "x"}[m.group()], pattern)


def _inside(patterns: list, wanted: str) -> bool:
    return any(hc.glob_match(p, _sample(wanted)) for p in patterns)


def check_branch(pattern: str, allowed: list) -> str:
    pattern = (pattern or "").strip()
    if not pattern or re.search(r"\s", pattern) or pattern.startswith("/") or ".." in pattern.split("/"):
        raise SystemExit(f"--branch {pattern!r}: give a branch pattern such as 'agent/*'")
    if pattern in REFUSED_BRANCHES or any(hc.glob_match(pattern, b) for b in REFUSED_BRANCHES):
        raise SystemExit(f"--branch {pattern!r}: a lane covers the agent's own branches, never main or master "
                         f"(or a pattern that reaches them, like '*'). A human merges; try 'agent/*'")
    if allowed and not _inside(allowed, pattern):
        raise SystemExit(f"--branch {pattern!r} is outside the branches the broker may push "
                         f"({', '.join(allowed)}); a push there would be refused")
    return pattern


def check_paths(paths: list, policy: dict) -> list:
    """Each path glob must stay inside what the receiver's policy allows and clear of what it forbids: a grant
    can only narrow the policy, so anything else could never be used (the broker would refuse the push)."""
    if not paths:
        raise SystemExit("--paths: give at least one glob, e.g. 'src/**'")
    if len(paths) > 100:
        raise SystemExit("--paths: at most 100 globs")
    allowed, forbidden = policy.get("allowed_paths") or [], policy.get("forbidden_paths") or []
    for p in paths:
        if p.startswith("/") or ".." in p.split("/") or "\\" in p:
            raise SystemExit(f"--paths {p!r}: paths are relative to the repo root, with no '..' or backslashes")
        if _inside(forbidden, p):
            raise SystemExit(f"--paths {p!r} is on the agent's forbidden list ({', '.join(forbidden)}): the broker "
                             f"refuses those files whatever a grant says")
        if allowed and not _inside(allowed, p):
            raise SystemExit(f"--paths {p!r} is outside what the agent's policy allows ({', '.join(allowed)}); a "
                             f"push touching it would be refused. Use paths inside that, or change the policy first")
    return paths


def _local(when: dt.datetime, tz=None) -> str:
    d = when.astimezone(tz) if tz else when.astimezone()
    return f"{d:%a %b} {d.day} {d:%H:%M %Z}".strip()


TIER_NAMES = {"routine": "routine", "review": "review-level", "high": "high-risk"}
CI_HINTS = (".github/", ".gitlab-ci", ".circleci", "jenkinsfile", "azure-pipelines", ".buildkite")
SECRET_HINTS = (".pem", ".key", "id_rsa", "id_ed25519", ".env", "secret", "credential")


def _kinds(patterns, limit: int = 3) -> list:
    """A tier's path patterns from the broker's rules, in words: CI workflows and key files by name, any other
    pattern (the operator's own) as written."""
    pats = [synthe_risk.clean(p, True) for p in patterns if isinstance(p, str)]
    ci = any(h in p.lower() for p in pats for h in CI_HINTS)
    secret = any(h in p.lower() for p in pats for h in SECRET_HINTS)
    other = [p for p in pats if not any(h in p.lower() for h in CI_HINTS + SECRET_HINTS)]
    return ["CI workflows"] * ci + ["key and secret files"] * secret + other[:limit] + ["..."] * (len(other) > limit)


REVIEW_KINDS = (("dependency manifests and lockfiles", ("package", "lock", "requirements", "go.sum", "go.mod", "cargo",
                                                          "pyproject", "gemfile", "pom.xml", "gradle")),
                ("Dockerfiles", ("dockerfile",)),
                ("build scripts", ("setup.py", "makefile", "scripts/", "bin/", ".sh")))


def _review_kinds(patterns, limit: int = 3) -> list:
    """The review tier's path patterns from the broker's rules, in words; a pattern that is none of these
    kinds (the operator's own, CODEOWNERS) is shown as written."""
    pats = [synthe_risk.clean(p, True) for p in patterns if isinstance(p, str)]
    words = [name for name, hints in REVIEW_KINDS if any(h in p.lower() for p in pats for h in hints)]
    other = [p for p in pats if not any(h in p.lower() for _, hints in REVIEW_KINDS for h in hints)]
    return words + other[:limit] + ["..."] * (len(other) > limit)


def risk_words(tier: str, rules: dict | None) -> str:
    """What makes a push this risky, as the broker's rules (the draft's `risk_rules`) have it, in a parenthesis."""
    r = rules if isinstance(rules, dict) else {}
    if tier == "high":
        what = _kinds(r.get("high_paths") or synthe_risk.HIGH_PATHS)
        what += [f"{r.get('high_lines', synthe_risk.HIGH_LINES)}+ changed lines", "mass deletions",
                 f"{r.get('high_commits', synthe_risk.HIGH_COMMITS)}+ commits"]
    else:
        what = _review_kinds(r.get("review_paths") or synthe_risk.REVIEW_PATHS)
        what += [f"{r.get('review_lines', synthe_risk.REVIEW_LINES)}+ changed lines", "any deletion"]
    return "(" + ", ".join(what) + ", per the broker's rules)"


def interrupts(body: dict, rules: dict | None = None) -> str:
    """What still asks you inside this lane, in plain words."""
    if "auto_approve" not in body:
        return ("This grant is not risk-aware: it lets every kind of push through, high-risk ones included. "
                "Pushes outside these paths still ask you.")
    left = [t for t in synthe_risk.TIERS if t not in body["auto_approve"]]
    if not left:
        return "It lets every risk level through. Only pushes outside these paths still ask you."
    names = " and ".join(f"{TIER_NAMES[t]} pushes {risk_words(t, rules)}" if t != "routine" else "routine pushes"
                         for t in left)
    text = (f"{names[0].upper()}{names[1:]} and pushes outside these paths still ask you. "
            f"The risk check reads paths and sizes, not code.")
    if "review" in body["auto_approve"] and "high" in left:  # the default: say what goes out, and how to make it ask
        text += (f" Review-level changes {risk_words('review', rules)} go out without asking you "
                 f"(synthe-notify digest lists them afterwards); --auto-approve routine makes them ask too.")
    return text


def summary(body: dict, policy: dict | None = None, tz=None, rules: dict | None = None) -> str:
    """What this grant allows, in plain words, for the person about to sign it. `rules` are the broker's risk
    rules (from the draft), so the words about what counts as high-risk are the ones it will apply."""
    n, until = body.get("max_uses"), expiry_of(body)
    where = body["params"]["branch_pattern"] + ("" if body["params"]["remote"] == "origin"
                                                  else f" on {body['params']['remote']}")
    limit = "with no limit on pushes" if unlimited_uses(body) else "once" if n == 1 else f"up to {n} times"
    lines = [f"Agent {body['receiver']} may push to {where} changing {_join(body['path_scope'])}, {limit}, "
             + ("with no expiry." if no_expiry(until) else f"until {_local(until, tz)}."),
             "Pushes to other branches still ask you. " + interrupts(body, rules)]
    if "self_issue" in body:
        lines.append("The agent may also start its own work in the lane: a plain git push on these branches with no "
                     "task from you gets a task Synthe issues under this grant, labelled as written by the agent. "
                     + ("There is no limit on how many. " if not any(k in body["self_issue"] for k in
                                                                     ("max_tasks", "max_open", "max_per_hour"))
                        else "") + "Revoking the grant stops them.")
    if "delegate" in body:
        lines.append(f"Each push in the lane is reviewed by {body['delegate']} instead of you; it can send a push "
                     f"back to you. It may approve what a fooled reviewer would: the limits above are the bound.")
    else:
        lines.append("Inside the lane nobody reviews each push before it goes out: Synthe still checks the branch "
                     "and files and signs a receipt for every push, but you are not asked.")
    if unlimited_uses(body) and no_expiry(until):
        lines.append(f"With no limit and no expiry this is a standing permission: it stays open until you close it "
                     f"(synthe-task revoke-grant {body['template_id']}).")
    never = (policy or {}).get("forbidden_paths") or []
    if never:
        lines.append(f"Never, whatever this says: {', '.join(never)}.")
    return "\n".join(lines)


# ---- building, signing, submitting -----------------------------------------------------------

def plan(s: dict, *, client, branch: str, paths: list, uses: int | None = None, until: str | None = None,
         remote: str = "origin", auto_approve=None,
         receiver: str | None = None, delegate: str | None = None, brief: str | None = None,
         now: dt.datetime | None = None, template_id: str | None = None, tz=None,
         self_issue=False) -> tuple[dict, str]:
    """The unsigned grant and its summary, after every check that can be made before you sign. `s` is
    synthe_task.setup_of(home). The broker supplies the lineage digests (op lane_template_draft) and, when
    `auto_approve` (the risk tiers the lane approves on its own) is not given, the tiers a new grant carries.
    No `uses` / `until` means the grant carries no `max_uses` / `expires_at`: that limit does not exist.
    `self_issue` (v0.7): True adds `self_issue` (the agent may start its own tasks in the lane), naming the
    broker's task issuer; "if-available" does the same when the broker has an issuer and the tiers allow it."""
    now = (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
    receiver = receiver or s["receiver"]
    if receiver != s["receiver"]:
        raise SystemExit(f"--agent {receiver!r}: this setup has one agent, {s['receiver']!r}")
    if uses is not None and (not isinstance(uses, int) or isinstance(uses, bool) or not 1 <= uses <= MAX_USES):
        raise SystemExit(f"--uses: between 1 and {MAX_USES} (leave it out for no limit)")
    tiers = parse_tiers(auto_approve) if auto_approve is not None else None
    if brief is not None and (not brief.strip() or len(brief) > lanes.MAX_BRIEF):
        raise SystemExit(f"--brief: say something, in up to {lanes.MAX_BRIEF} characters")
    remotes = {"origin": s["remote"].get("branches") or []}
    if remote not in remotes:
        remotes = {remote: (client.call("hello").get("remotes") or {}).get(remote, {}).get("branches")}
        if remotes[remote] is None:
            raise SystemExit(f"--remote {remote!r}: the broker has no such remote")
    branch = check_branch(branch, remotes[remote])
    paths = check_paths(paths, s["policy"])
    end = parse_until(until, now, tz) if until is not None else None
    if receiver not in (client.call("lane_templates").get("enabled_receivers") or []):
        raise SystemExit(f"lane grants aren't switched on for {receiver} on this broker. Setups from before they "
                         f"existed need \"lane_templates\": {{\"receivers\": [\"{receiver}\"]}} in "
                         f"{s.get('broker_config') or 'the broker config'}, then a broker restart")
    body = {"template_id": template_id or f"lane-{now:%Y%m%d}-{secrets.token_hex(3)}", "receiver": receiver,
            "tool": "git_push", "params": {"remote": remote, "branch_pattern": branch}, "path_scope": paths}
    if uses is not None:
        body["max_uses"] = uses
    if end is not None and not no_expiry(end):   # an expiry past the year 9999 is no expiry at all
        body["expires_at"] = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    if delegate:
        body["delegate"] = delegate
    if brief:
        body["brief"] = brief
    try:
        draft = client.call("lane_template_draft", receiver=receiver, **({"delegate": delegate} if delegate else {}),
                            **({"auto_approve": tiers} if tiers else {}))
        if tiers is None:  # the broker's default for a new grant; its lineage must be for exactly these tiers
            tiers = draft.get("auto_approve_default")
            tiers = parse_tiers(tiers) if isinstance(tiers, list) and tiers else list(lanes.DEFAULT_AUTO_APPROVE)
            draft = client.call("lane_template_draft", receiver=receiver, auto_approve=tiers,
                                **({"delegate": delegate} if delegate else {}))
        body["auto_approve"], body["lineage"] = tiers, draft["lineage"]
    except scl.BrokerError as e:
        raise SystemExit(f"the broker can't prepare a grant: {e.code}: {e.message}")
    if self_issue:
        issuer = (draft.get("self_issue_default") or {}).get("issuer")
        reviewed = bool(delegate) or "high" not in tiers
        if issuer and reviewed:
            body["self_issue"] = {"issuer": issuer}
        elif self_issue is True and not issuer:
            raise SystemExit("--self-issue: this broker holds no task issuer key (set up before v0.7); re-run the "
                             "admin step to add one, or leave --self-issue out")
        elif self_issue is True:
            raise SystemExit("--self-issue: a lane where the agent starts its own work must send high-risk pushes to "
                             "you: leave 'high' out of --auto-approve, or name a reviewer with --delegate")
    return body, summary(body, s["policy"], tz, draft.get("risk_rules"))


def unlock_key(home: Path, sender: str, reason: str, passphrase: bool = False, prompt=ss.prompt_passphrase) -> dict:
    """Your approver key, the way synthe-approve opens it: Touch ID when you enrolled one (its prompt shows
    `reason`), otherwise the passphrase key. Typed or touched by you, in your terminal; never by an agent."""
    tid = touchid.key_path(home)
    try:
        if not passphrase and tid.is_file():
            key = touchid.signing_key(tid, reason)
        else:
            key = ss.load_key(str(home / "approver.key.json"), require_encrypted=True, prompt=prompt)
    except touchid.TouchIDError as e:
        raise SystemExit(f"not signed: {e} (--passphrase uses your passphrase key instead)")
    if key.get("agent") != sender:
        raise SystemExit(f"the approver key belongs to {key.get('agent')!r}, not {sender!r}")
    return key


def submit(client, body: dict, key: dict) -> dict:
    """Sign with an unlocked key and give the grant to the broker; the broker re-validates all of it."""
    try:
        signed = lanes.sign(body, key)
    except touchid.TouchIDError as e:
        raise SystemExit(f"not signed: {e}")
    try:
        return client.call("submit_lane_template", template=signed)
    except scl.BrokerError as e:
        raise SystemExit(f"the broker refused the grant: {e.code}: {EXPLAIN.get(e.code, e.message)}")


def _terminal() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def _yes(question: str) -> bool:
    try:
        answer = input(question).strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes") or (answer == "" and "[Y/n]" in question)


def issue(home: Path, *, client=None, key=None, confirm=None, out=print, passphrase: bool = False,
          question: str = "Sign this lane grant? [y/N] ", **spec):
    """Build, show, ask, sign and submit one grant. Returns the broker's answer, or None if you said no."""
    import synthe_task as stk
    confirm = confirm or _yes
    s = stk.setup_of(home)
    client = client or scl.BrokerClient(s["broker"])
    body, text = plan(s, client=client, **spec)
    out("\n" + text + "\n")
    if not confirm(question):
        out("Nothing signed. Pushes keep asking you.")
        return None
    key = key or unlock_key(home, s["sender"], text.splitlines()[0], passphrase)
    result = submit(client, body, key)
    end = expiry_of(body)
    out(f"Lane open: {body['template_id']} ({'no use limit' if unlimited_uses(body) else str(body['max_uses']) + ' uses'}, "
        f"{'no expiry' if no_expiry(end) else 'until ' + _local(end)}).\n"
        f"See it with synthe-task grants; close it any time with synthe-task revoke-grant {body['template_id']}.")
    return result


# ---- listing, renewing, revoking -------------------------------------------------------------

def _left(delta: dt.timedelta) -> str:
    mins = int(delta.total_seconds() // 60)
    if mins <= 0:
        return "now"
    d, rest = divmod(mins, 1440)
    h, m = divmod(rest, 60)
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m"


def renew_command(t: dict) -> str:
    cmd = ["synthe-task", "grant", "--branch", t["params"]["branch_pattern"], "--paths", ",".join(t["path_scope"])]
    if not unlimited_uses(t):
        cmd += ["--uses", str(t["max_uses"])]
    if not no_expiry(expiry_of(t)):
        cmd += ["--until", "7d"]
    if t.get("auto_approve") and t["auto_approve"] != list(lanes.DEFAULT_AUTO_APPROVE):
        cmd += ["--auto-approve", ",".join(t["auto_approve"])]
    if t["params"]["remote"] != "origin":
        cmd += ["--remote", t["params"]["remote"]]
    if t.get("self_issue"):
        cmd += ["--self-issue"]
    if t.get("delegate"):
        cmd += ["--delegate", t["delegate"]]
    if t.get("brief") and len(t["brief"]) <= 200:
        cmd += ["--brief", t["brief"]]
    return shlex.join(cmd) + ("   (add your --brief again)" if t.get("brief") and len(t["brief"]) > 200 else "")


def list_grants(client, now: dt.datetime | None = None) -> list:
    """Every grant the broker holds, newest expiry first, each with `left` (time to expiry), `hints` (why to
    renew it: under 24 hours left, or under 10% of its uses) and `renew` (the command that makes a fresh one)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    rows = []
    for t in client.call("lane_templates").get("templates") or []:
        end = expiry_of(t)
        hints = []
        if t["status"] == "active":   # a lane with no limit has nothing to run out of
            if not no_expiry(end) and end - now <= RENEW_WITHIN:
                hints.append(f"expires in {_left(end - now)}")
            if not unlimited_uses(t) and t["uses_left"] < RENEW_USES * t["max_uses"]:
                hints.append(f"only {t['uses_left']} of {t['max_uses']} uses left")
        rows.append({**t, "left": None if end is None else end - now, "hints": hints, "renew": renew_command(t)})
    return sorted(rows, key=lambda r: dt.timedelta.max if r["left"] is None else r["left"], reverse=True)


def alone(t: dict) -> str:
    """Which pushes this grant lets through without asking you, and which still ask."""
    if "auto_approve" not in t:
        return "not risk-aware: every kind of push goes out, high-risk ones too; pushes outside its paths ask you"
    left = [TIER_NAMES.get(x, str(x)) for x in synthe_risk.TIERS if x not in t["auto_approve"]]
    ask = (_join(left) + " pushes and ") if left else ""
    own = "; the agent may start its own tasks in it" if t.get("self_issue") else ""
    return (f"goes out on its own: {_join([TIER_NAMES.get(x, str(x)) for x in t['auto_approve']])}; "
            f"{ask}pushes outside its paths ask you{own}")


def render_grants(rows: list, show_all: bool = False, ui=None, tz=None) -> str:
    ui = ui or sui.UI()
    shown = [r for r in rows if show_all or r["status"] == "active"]
    hidden = len(rows) - len(shown)
    if not shown:
        out = ["No open lanes. Every push asks you. Open one: synthe-task grant"]
    else:
        out = []
        for r in shown:
            state = "open" if r["status"] == "active" else INACTIVE.get(r["status"], r["status"])
            who = f", reviewed by {r['delegate']}" if r.get("delegate") else ", no per-push review"
            out.append(f"{ui.c(r['template_id'], 'brand', bold=True)}  {ui.c(state, 'ok' if r['status'] == 'active' else 'muted')}")
            out.append(f"  {r['receiver']} may push to {r['params']['branch_pattern']} changing "
                       f"{', '.join(r['path_scope'])}{who}")
            end = expiry_of(r)
            until = "" if no_expiry(end) else _local(end, tz)
            uses = "no use limit" if unlimited_uses(r) else f"{r['uses_left']} of {r['max_uses']} uses left"
            out.append(f"  {uses}, " + ("no expiry (open until you revoke it)" if no_expiry(end) else
                       f"until {until} (in {_left(r['left'])})" if r["status"] == "active" else f"ended or ends {until}"))
            out.append("  " + alone(r))
            if r["hints"]:
                out.append("  " + ui.c("renew soon: " + "; ".join(r["hints"]), "warn", bold=True))
                out.append(f"  renew: {r['renew']}")
                out.append("  (the old grant keeps working until it runs out or you revoke it)")
            out.append("")
    if hidden:
        out.append(f"{hidden} more not open (expired, revoked, used up or stale): synthe-task grants --all")
    return "\n".join(out).rstrip()


def revoke(client, home: Path, grant_id: str, key=None, passphrase: bool = False, out=print) -> dict:
    import synthe_task as stk
    s = stk.setup_of(home)
    known = {t["template_id"]: t for t in client.call("lane_templates").get("templates") or []}
    if grant_id not in known:
        raise SystemExit(f"no grant {grant_id!r}; synthe-task grants --all lists them"
                         + (f" (closest: {', '.join(sorted(known)[:5])})" if known else ""))
    key = key or unlock_key(home, s["sender"], f"revoke lane grant {grant_id}", passphrase)
    try:
        signed = lanes.sign({"template_id": grant_id}, key, revoke=True)
    except touchid.TouchIDError as e:
        raise SystemExit(f"not signed: {e}")
    try:
        result = client.call("revoke_lane_template", revocation=signed)
    except scl.BrokerError as e:
        raise SystemExit(f"the broker refused the revocation: {e.code}: {e.message}")
    out(f"Lane closed: {grant_id}. Pushes in it ask you again.")
    return result


# ---- setup: "how hands-off?" -----------------------------------------------------------------

QUESTION = """How hands-off?
  [1] Ask me before every push
  [2] Agents push without asking; Synthe only interrupts for what it blocks or flags as high-risk (recommended)
      With [2] the agent can also start its own work in the lane: a plain git push needs no task from you."""


def _connect(broker: str, tries: int, sleep):
    """The broker was started moments ago by the admin step: give it a few seconds to listen."""
    for n in range(tries):
        try:
            c = scl.BrokerClient(broker)
            c.call("hello")
            return c
        except scl.BrokerError as e:
            if e.code != "broker_unreachable" or n == tries - 1:
                raise
            sleep(1)


def offer_lane(home: Path, *, interactive: bool | None = None, ask=input, out=print, client=None, key=None,
               confirm=None, tries: int = 10, sleep=time.sleep) -> str:
    """Ask once at the end of setup. Returns "lane" if a default grant was signed, else "ask" (today's
    behaviour, and the only outcome without a person at a terminal: nothing is ever granted silently).
    At a terminal, Return alone picks [2], the recommended choice; it still shows the terms and asks before
    anything is signed. Option 2 is the same code as `synthe-task grant` with the defaults from your setup:
    its branches and allowed paths, the broker's default risk tiers (routine and review go out alone, high-risk
    and out-of-path pushes ask you), no use limit, no expiry (until you revoke it), and self-issue (the agent may
    start its own tasks in the lane) when the broker has a task issuer."""
    if interactive is None:
        interactive = _terminal()
    later = "Open a lane any time: synthe-task grant"
    if not interactive:
        out(f"Every push will ask you (the default). {later}")
        return "ask"
    out("\n" + QUESTION)
    try:
        choice = ask("Choose 1 or 2 [2]: ").strip() or "2"
    except EOFError:
        choice = "1"
    if choice != "2":
        out(f"Every push will ask you. {later}")
        return "ask"
    import synthe_task as stk
    try:
        s = stk.setup_of(home)
        client = client or _connect(s["broker"], tries, sleep)
        made = 0
        for pattern in s["remote"].get("branches") or []:
            made += bool(issue(home, client=client, key=key, confirm=confirm, out=out, branch=pattern,
                               paths=list(s["policy"].get("allowed_paths") or []), self_issue="if-available",
                               question="Sign it with your key? [Y/n] "))
    except (SystemExit, scl.BrokerError) as e:
        out(f"Couldn't open a lane: {e}\nEvery push will ask you. {later}")
        return "ask"
    return "lane" if made else "ask"


# ---- the synthe-task subcommands ---------------------------------------------------------------

def add_parsers(sub) -> None:
    g = sub.add_parser("grant", help="let routine pushes inside a lane go without asking you (signs a lane grant)")
    g.add_argument("--branch", help="branch pattern, e.g. 'agent/*' (default: your setup's branches)")
    g.add_argument("--paths", help="comma-separated globs the agent may change (default: your setup's allowed paths)")
    g.add_argument("--uses", type=int, help=f"cap the number of pushes, 1 to {MAX_USES} (default: no limit)")
    g.add_argument("--auto-approve", metavar="TIERS", help="risk tiers that go out without asking you, from routine,"
                   " review, high (default: the broker's, routine,review: high-risk pushes still ask you)")
    g.add_argument("--until", help="cap how long it stays open: 90m, 12h, 7d, 2w, or a date (default: no expiry; "
                                   "it stays open until you revoke it)")
    g.add_argument("--self-issue", action="store_true",
                   help="let the agent start its own work in the lane: a plain git push with no task from you gets a "
                        "task the broker issues under this grant (no limit on how many)")
    g.add_argument("--remote", default="origin")
    g.add_argument("--agent", help="the agent this applies to (default: the one in your setup)")
    g.add_argument("--delegate", help="a registered model approver that reviews each push instead of you")
    g.add_argument("--brief", help="your instructions to that reviewer (signed with the grant)")
    g.add_argument("--passphrase", action="store_true", help="sign with the passphrase key even if Touch ID is set up")
    g.add_argument("--home", default="~/.synthe")
    ls = sub.add_parser("grants", help="list open lanes: uses left, expiry, and which to renew")
    ls.add_argument("--all", action="store_true", help="include expired, revoked, used-up and stale grants")
    ls.add_argument("--home", default="~/.synthe")
    r = sub.add_parser("revoke-grant", help="close a lane now")
    r.add_argument("id")
    r.add_argument("--passphrase", action="store_true")
    r.add_argument("--home", default="~/.synthe")


def run(a) -> int:
    import synthe_task as stk
    home = Path(a.home).expanduser()
    s = stk.setup_of(home)  # a missing or broken setup fails here, before any prompt
    try:
        client = scl.BrokerClient(s["broker"])
        if a.cmd == "grants":
            print(render_grants(list_grants(client), a.all))
            return 0
        if not _terminal():
            print(f"synthe-task {a.cmd} is interactive: run it in your own terminal (it signs with your key).",
                  file=sys.stderr)
            return 2
        if a.cmd == "revoke-grant":
            revoke(client, home, a.id, passphrase=a.passphrase)
            return 0
        patterns = [a.branch] if a.branch else list(s["remote"].get("branches") or [])
        if len(patterns) != 1:
            raise SystemExit("--branch: say which branch pattern, e.g. 'agent/*' (your setup has "
                             f"{len(patterns)}: {', '.join(patterns) or 'none'})")
        issue(home, client=client, passphrase=a.passphrase, branch=patterns[0],
              paths=_csv(a.paths) if a.paths else list(s["policy"].get("allowed_paths") or []), uses=a.uses,
              until=a.until, remote=a.remote, receiver=a.agent, delegate=a.delegate, brief=a.brief,
              auto_approve=a.auto_approve, self_issue=a.self_issue)
    except scl.BrokerError as e:
        raise SystemExit(f"synthe-task: {e.code}: {e.message}")
    return 0
