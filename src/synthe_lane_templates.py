"""Human-signed, bounded lane grants. Plan-library templates are not authority.

All submissions, revocations and use reservations share the same durable lock.
A use is consumed before dispatch, including an uncertain/failed push: never
refund automatically after a crash. No agent can mint a human signature.

A grant may name a `delegate`: an approver identity (registry kind
"model_approver", e.g. a reviewing model) that must approve each push itself.
The grant then stands in for the human's per-push approval only together with
the delegate's own signed approval of that exact commit. The delegate:
- is never the sender or the receiver of the handoff it approves;
- approves only a proposal the broker has staged, pinned to its commit, for
  at most MAX_DELEGATE_MINUTES and never past the grant;
- can escalate instead: a signed "send this to the human". An escalation
  sticks to that proposal (idempotency key + action, whatever commit comes
  next), so re-pushing never buys a second review; only a human approves it.
A human's own approval always works as before, and consumes no grant use.

A grant may be risk-aware: `"auto_approve": ["routine"]` (signed with the rest of the grant) lists the
risk tiers (synthe_risk) it approves without a human, on its own or through its delegate. The broker
classifies what it is about to push, from its own copy of every pushed commit, under the lane lock
immediately before dispatch; a tier the grant doesn't list stays staged for a human (`risk_escalated`),
the delegate is not asked, and no use is spent. A grant without the field (signed before risk-aware
lanes) is not risk-aware: it approves every tier, as before. Likewise a push that touches any path
outside a grant's path_scope is not the grant's to approve: it waits for a human (`outside_lane_paths`).

`max_uses` and `expires_at` are optional: a signed grant that omits one has no such limit (a standing
lane, valid until revoked or stale); one that carries a malformed value is refused.

A grant may let its agent start work without a human-signed task (v0.7, `self_issue`, signed with the rest
of the grant): the broker then issues tasks under it, signed by its own task issuer key (registry kind
"task_issuer", held by the broker's OS user, never an agent's), each embedding the grant verbatim
(SPEC section 16). `self_issue` names the issuer and may cap the tasks (max_tasks, max_open, max_per_hour:
enforced only when present, like max_uses) and narrow them (task_hours, tools, max_purpose_chars,
escalate_at). The issuer is never the receiver, the delegate or a trusted approver. In v1 a self-issue grant
must send high-risk pushes to a human: it lists auto_approve without "high", or names a delegate
(`self_issue_unreviewed`). Revoking or expiring the grant kills every task issued under it that hasn't
landed, even one a human would approve. The issue store (self-issued.json) shares the lane lock.
"""
import datetime as dt
import hashlib
import json
import os
import re
from contextlib import contextmanager

import handoff_check as hc
import synthe_crypto as sc
import synthe_risk

DOMAIN = b"synthe/approval-template/v1\n"
REVOKE_DOMAIN = b"synthe/approval-template-revoke/v1\n"
DELEGATE_DOMAIN = b"synthe/delegate-approval/v1\n"
ESCALATE_DOMAIN = b"synthe/delegate-escalation/v1\n"
DELEGATE_KIND = "model_approver"
MAX_DELEGATE_MINUTES = 60
FIELDS = {"template_id", "approver", "kid", "receiver", "tool", "params", "path_scope", "lineage", "sig"}
# delegate: who reviews each push; brief: the human's own instructions to that reviewer (signed with the grant,
# so the reviewer can tell them apart from anything an agent wrote); auto_approve: the risk tiers the grant
# approves without a human (an allowlist: a tier it doesn't name, today's or a future one, goes to a human).
# max_uses / expires_at: limits. Present, they are enforced as always; omitted from the signed grant, there
# is no such limit (a standing lane, valid until revoked or stale). Present but malformed: refused.
OPTIONAL = {"delegate", "brief", "auto_approve", "max_uses", "expires_at", "self_issue"}
# self_issue: issuer (required); limits, enforced only when present; and narrowings of the issued tasks.
SELF_ISSUE_FIELDS = {"issuer", "max_tasks", "max_open", "max_per_hour", "task_hours", "tools",
                     "max_purpose_chars", "escalate_at"}
MAX_PER_HOUR = 1000
MAX_BRIEF = 4000
MAX_USES = 10000
# What new grants should carry (grant CLIs, Studio): routine and review-tier pushes go out without a human
# (through the delegate, if the grant names one); only a high-risk push waits for one.
DEFAULT_AUTO_APPROVE = ("routine", "review")
DOC_FIELDS = {"template_id", "approver", "kid", "idempotency_key", "from", "to", "action", "params", "note", "sig"}
APPROVE_FIELDS = DOC_FIELDS | {"expires_at"}
ESCALATE_FIELDS = DOC_FIELDS | {"recommendation"}
RECOMMENDATIONS = ("reject", "unsure")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def fail(code):
    from synthe_commit import Deny
    raise Deny("blocked", code, code.replace("_", " "))


def digest(x):
    return hashlib.sha256(sc.canonical_json(x)).hexdigest()


def signing_input(x, revoke=False):
    if not revoke:  # the checker verifies the grant a self-issued task embeds with this same rule
        return sc.approval_template_signing_input(x)
    return REVOKE_DOMAIN + sc.canonical_json({k: v for k, v in x.items() if k != "sig"})


def _sig(key, msg):
    """A Touch ID key signs through its helper (`_sign`); a passphrase key with its Ed25519 secret."""
    return key["_sign"](msg) if callable(key.get("_sign")) else sc.sign_bytes(key["_secret"], msg)


def sign(body, key, revoke=False):
    x = dict(body, approver=key["agent"], kid=key["kid"])
    x["sig"] = sc.b64u(_sig(key, signing_input(x, revoke)))
    return x


def default_auto_approve(delegate=None):
    """The tiers a new grant should list (`auto_approve`), with a delegate or without one."""
    return list(DEFAULT_AUTO_APPROVE)


def exhausted(s, t):
    """Every use of a grant with `max_uses` is spent. A grant without the field has no use limit."""
    return "max_uses" in t and s["uses"].get(t["template_id"], 0) >= t["max_uses"]


def auto_approve_ok(v):
    """A risk-aware grant's tiers: a non-empty list of distinct known tiers. Anything else is refused."""
    return isinstance(v, list) and bool(v) and len(set(map(str, v))) == len(v) \
        and all(isinstance(t, str) and t in synthe_risk.TIERS for t in v)


def risk_rules(cfg):
    """The effective risk rules: the operator's effects.git_push.risk over synthe_risk's defaults."""
    try:
        return synthe_risk.load_rules((cfg.effects.get("git_push") or {}).get("risk"))
    except ValueError:
        fail("risk_rules_invalid")


def lineage(cfg, registry, receiver, risk_aware=False):
    """What a grant was signed against. A risk-aware grant also pins the effective risk rules, so changing
    them (the operator's lists, or the defaults in a new release) makes it `template_stale`."""
    policy = hc.receiver_policy(registry, receiver) or {}
    trusted = policy.get("trusted_approvers") or []
    out = {"receiver_policy_digest": digest(policy),
           "approvers_digest": digest({a: registry["agents"].get(a) for a in sorted(trusted)}),
           "effects_digest": digest({"effects": cfg.effects, "lane_templates": cfg.raw.get("lane_templates")})}
    if risk_aware:
        out["risk_rules_digest"] = synthe_risk.rules_digest(risk_rules(cfg))
    return out


def auto_approves(t, tier, self_issued=False):
    """Whether grant `t` approves a push of this tier without a human. Not risk-aware: every tier, as before."""
    return tier in approved_tiers(t, self_issued)


def approved_tiers(t, self_issued=False) -> list:
    """The tiers grant `t` pushes without a human. For a self-issued task's push under
    `self_issue.escalate_at: "review"`, review-tier pushes go to a human too."""
    tiers = list(t["auto_approve"]) if "auto_approve" in t else list(synthe_risk.TIERS)
    if self_issued and (t.get("self_issue") or {}).get("escalate_at") == "review":
        tiers = [x for x in tiers if x == "routine"]
    return tiers


def issuer_config(cfg):
    """This broker's task issuer, `lane_templates.self_issue` in broker.json ({"issuer", "key_file"}), or None.
    It sits inside the grant lineage's effects digest, so changing it makes existing grants stale."""
    c = (cfg.raw.get("lane_templates") or {}).get("self_issue")
    ok = isinstance(c, dict) and isinstance(c.get("issuer"), str) and isinstance(c.get("key_file"), str)
    return c if ok else None


def _whole(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _validate_self_issue(cfg, registry, x, policy):
    si = x["self_issue"]
    if not isinstance(si, dict) or "issuer" not in si or not set(si) <= SELF_ISSUE_FIELDS:
        fail("template_malformed")
    cap = si["max_tasks"] if _whole(si.get("max_tasks"), 1, MAX_USES) else MAX_USES
    for k, hi in (("max_tasks", MAX_USES), ("max_open", cap), ("max_per_hour", MAX_PER_HOUR),
                  ("max_purpose_chars", hc.SELF_ISSUE_MAX_PURPOSE_CHARS)):
        if k in si and not _whole(si[k], 1, hi):
            fail("template_malformed")
    max_ttl = policy.get("max_ttl_hours")
    if "task_hours" in si and (not hc._is_number(si["task_hours"]) or si["task_hours"] <= 0
                               or (hc._is_number(max_ttl) and si["task_hours"] > max_ttl)):
        fail("template_malformed")
    if "tools" in si:
        t, ceiling = si["tools"], policy.get("allowed_tools")
        if not isinstance(t, list) or not t or any(not isinstance(v, str) or not v for v in t) \
                or len(set(t)) != len(t) or "git_push" not in t or (ceiling is not None and set(t) - set(ceiling)):
            fail("template_malformed")
    if "escalate_at" in si and si["escalate_at"] not in ("review", "high"):
        fail("template_malformed")
    issuer, mine = si["issuer"], issuer_config(cfg)
    entry = registry.get("agents", {}).get(issuer) if isinstance(issuer, str) else None
    if not isinstance(entry, dict) or entry.get("kind") != hc.ISSUER_KIND or not sc.usable_keys(registry, issuer) \
            or issuer in (x["receiver"], x.get("delegate")) or issuer in (policy.get("trusted_approvers") or []) \
            or mine is None or mine["issuer"] != issuer:
        fail("issuer_invalid")
    # v1: no unreviewed self-issue. The agent picks, writes and lands its own work, so a high-risk push must
    # reach a human: the grant is risk-aware and doesn't approve "high" alone, or it names a delegate.
    if "delegate" not in x and ("auto_approve" not in x or "high" in x["auto_approve"]):
        fail("self_issue_unreviewed")


def enabled(cfg, receiver):
    return receiver in (cfg.raw.get("lane_templates") or {}).get("receivers", []) and receiver != "claude"


def validate(cfg, registry, x):
    if not isinstance(x, dict) or x.get("tool") != "git_push" or not enabled(cfg, x.get("receiver")):
        fail("template_scope")
    if not FIELDS <= set(x) <= FIELDS | OPTIONAL:
        fail("template_malformed")
    if "brief" in x and (not isinstance(x["brief"], str) or not x["brief"].strip() or len(x["brief"]) > MAX_BRIEF):
        fail("template_malformed")
    if "auto_approve" in x and not auto_approve_ok(x["auto_approve"]):
        fail("template_malformed")
    if not all(isinstance(x.get(k), str) and x[k] for k in ("template_id", "approver", "kid", "receiver", "sig")):
        fail("template_malformed")
    if "expires_at" in x and (not isinstance(x["expires_at"], str) or not x["expires_at"]):
        fail("template_malformed")
    if "max_uses" in x and (not isinstance(x["max_uses"], int) or isinstance(x["max_uses"], bool)
                            or not 1 <= x["max_uses"] <= MAX_USES):
        fail("template_malformed")
    if len(x["template_id"]) > 120:
        fail("template_malformed")
    if not isinstance(x["params"], dict) or set(x["params"]) != {"remote", "branch_pattern"} or not all(isinstance(v, str) and v for v in x["params"].values()):
        fail("template_malformed")
    paths = x["path_scope"]
    if not isinstance(paths, list) or not paths or len(paths) > 100 or any(not isinstance(p, str) or not p or p.startswith("/") or ".." in p.split("/") or "\\" in p for p in paths):
        fail("template_malformed")
    policy = hc.receiver_policy(registry, x["receiver"]) or {}
    who = registry.get("agents", {}).get(x["approver"]) or {}
    if x["approver"] not in (policy.get("trusted_approvers") or []) or who.get("kind") != "human":
        fail("approver_not_trusted")
    if "delegate" in x:
        d = x["delegate"]
        entry = registry.get("agents", {}).get(d) if isinstance(d, str) else None
        if not isinstance(entry, dict) or entry.get("kind") != DELEGATE_KIND or d == x["receiver"]:
            fail("delegate_invalid")
    if "self_issue" in x:
        _validate_self_issue(cfg, registry, x, policy)
    # Ed25519 (passphrase key) or ES256 (Touch ID key): the registered key decides which.
    if not _verifies(registry, x, signing_input(x)):
        fail("template_signature_invalid")
    if "expires_at" in x:  # omitted from the signed grant: no expiry, valid until revoked (or stale)
        expiry = hc.parse_ts(x["expires_at"])
        if expiry is None or expiry <= hc.now_utc():
            fail("template_expired")
    if x["lineage"] != lineage(cfg, registry, x["receiver"], risk_aware="auto_approve" in x):
        fail("template_stale")


def _verifies(registry, x, msg):
    try:
        return sc.verify_approval(registry, x.get("approver"), x.get("kid"), msg, sc.unb64u(x.get("sig") or ""))
    except Exception:
        return False


def path(cfg):
    return cfg.state_dir / "lane-templates.json"


def load(cfg):
    p = path(cfg)
    if not p.exists():
        return {"templates": {}, "uses": {}, "revoked": {}}
    try:
        s = json.loads(p.read_text())
        if set(s) != {"templates", "uses", "revoked"} or not all(isinstance(v, dict) for v in s.values()):
            raise ValueError()
        if any(not isinstance(n, int) or isinstance(n, bool) or n < 0 for n in s["uses"].values()):
            raise ValueError()
        return s
    except (OSError, ValueError, TypeError):
        fail("template_store_corrupt")


def save(cfg, s, p=None):
    p = p or path(cfg)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(s, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    if os.name != "nt":
        fd = os.open(p.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextmanager
def locked(cfg):
    from synthe_commit import _file_lock
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    with _file_lock(cfg.state_dir / "lane-templates.lock"):
        yield


def submit(cfg, x):
    with locked(cfg):
        # Signed registry: enforced once a genesis key is pinned
        # (SYNTHE_REGISTRY_GENESIS_KEY or registry-genesis.key); unsigned otherwise
        registry, err = hc.load_registry(str(cfg.registry_path), allow_unsigned=True)
        if err:
            fail("registry_unreadable")
        validate(cfg, registry, x)
        s = load(cfg)
        tid = x["template_id"]
        if tid in s["revoked"] or (tid in s["templates"] and s["templates"][tid] != x):
            fail("template_id_reused")
        s["templates"][tid] = x
        save(cfg, s)
        return {"template_id": tid, "status": "accepted"}


def revoke(cfg, x):
    with locked(cfg):
        s = load(cfg)
        t = s["templates"].get(x.get("template_id"))
        # Signed registry: enforced once a genesis key is pinned
        # (SYNTHE_REGISTRY_GENESIS_KEY or registry-genesis.key); unsigned otherwise
        registry, err = hc.load_registry(str(cfg.registry_path), allow_unsigned=True)
        if err or not t:
            fail("template_revocation_invalid")
        # Pulling a grant is a safety action: any human trusted for its receiver may, not only its signer.
        trusted = (hc.receiver_policy(registry, t["receiver"]) or {}).get("trusted_approvers") or []
        who = registry.get("agents", {}).get(x.get("approver")) or {}
        if x.get("approver") != t["approver"] and (x.get("approver") not in trusted or who.get("kind") != "human"):
            fail("template_revocation_invalid")
        if not _verifies(registry, x, signing_input(x, True)):
            fail("template_revocation_invalid")
        s["revoked"][x["template_id"]] = x
        save(cfg, s)
        return {"template_id": x["template_id"], "status": "revoked"}


def select(cfg, registry, receiver, params, *, paths=None, template_id=None):
    from synthe_commit import any_match, Deny
    if not enabled(cfg, receiver):
        return None
    s = load(cfg)
    for tid, t in sorted(s["templates"].items()):
        if template_id and tid != template_id:
            continue
        if t.get("receiver") != receiver:
            continue
        try:
            validate(cfg, registry, t)
            if tid in s["revoked"]:
                fail("template_revoked")
            if exhausted(s, t):
                fail("template_exhausted")
            if params.get("remote") != t["params"]["remote"] or not any_match([t["params"]["branch_pattern"]], params.get("branch", "")):
                fail("template_scope")
            if paths is not None and any(not any_match(t["path_scope"], p) for p in paths):
                fail("template_scope")
            return t
        except Deny:
            if template_id:
                raise
    if template_id:
        fail("template_unavailable")
    return None


def reserve(cfg, receiver, params, paths, tid):
    """Caller holds lane lock inside the claim fence, immediately before dispatch."""
    # Signed registry: enforced once a genesis key is pinned
    # (SYNTHE_REGISTRY_GENESIS_KEY or registry-genesis.key); unsigned otherwise
    registry, err = hc.load_registry(str(cfg.registry_path), allow_unsigned=True)
    if err:
        fail("registry_unreadable")
    t = select(cfg, registry, receiver, params, paths=paths, template_id=tid)
    if not t:
        fail("template_unavailable")
    s = load(cfg)
    n = s["uses"].get(tid, 0) + 1
    s["uses"][tid] = n
    save(cfg, s)
    return {"template_id": tid, "use": n, "approver": t["approver"], "expires_at": t.get("expires_at"),
            "max_uses": t.get("max_uses")}


def view(cfg):
    from synthe_commit import Deny
    # Signed registry: enforced once a genesis key is pinned
    # (SYNTHE_REGISTRY_GENESIS_KEY or registry-genesis.key); unsigned otherwise
    registry, err = hc.load_registry(str(cfg.registry_path), allow_unsigned=True)
    if err:
        fail("registry_unreadable")
    with locked(cfg):
        s = load(cfg)
        out = []
        for tid, t in s["templates"].items():
            status = "active"
            try:
                validate(cfg, registry, t)
                if tid in s["revoked"]:
                    fail("template_revoked")
                if exhausted(s, t):
                    fail("template_exhausted")
            except Deny as e:
                status = e.reason["code"]
            out.append({**{k: v for k, v in t.items() if k != "sig"}, "status": status,
                        "uses_left": max(0, t["max_uses"] - s["uses"].get(tid, 0)) if "max_uses" in t else None})
        return {"templates": out, "enabled_receivers": (cfg.raw.get("lane_templates") or {}).get("receivers", [])}


# --------------------------------------------------------------------------
# self-issued tasks (v0.7): the broker issues tasks under a grant that allows it (synthe_commit.issue_task)

def issue_path(cfg):
    return cfg.state_dir / "self-issued.json"


def issue_load(cfg):
    """{"grants": {template_id: {"issued": n, "recent": [issued_at...], "tasks": {"n": record}}},
    "requests": {request_id: {"template_id", "issue", "body_sha256"}}}. Caller holds locked(cfg) to write."""
    p = issue_path(cfg)
    if not p.exists():
        return {"grants": {}, "requests": {}}
    try:
        s = json.loads(p.read_text())
        if set(s) != {"grants", "requests"} or not all(isinstance(v, dict) for v in s.values()):
            raise ValueError()
        if any(not isinstance(g, dict) or not _whole(g.get("issued"), 0, 10**9) or not isinstance(g.get("tasks"), dict)
               or not isinstance(g.get("recent"), list) for g in s["grants"].values()):
            raise ValueError()
        return s
    except (OSError, ValueError, TypeError):
        fail("template_store_corrupt")


def issue_save(cfg, s):
    save(cfg, s, issue_path(cfg))


def issue_record(cfg, template_id, issue):
    """The broker's record of one issued task, or None."""
    g = issue_load(cfg)["grants"].get(template_id) if isinstance(template_id, str) else None
    return (g or {}).get("tasks", {}).get(str(issue)) if g else None


def check_issued(cfg, registry, h):
    """A self-issued handoff's standing at the broker, or Deny: its grant is the one in the store, byte for
    byte, still valid (signature, expiry, lineage), not revoked, and the broker issued exactly this packet.
    Run at claim, at propose, for staged retries, and again under the lane lock at dispatch: revoking or
    expiring the grant kills the task even under a human's approval (the human can sign a task instead).
    Returns (grant, issue record)."""
    iug = h.get("issued_under_grant") if isinstance(h, dict) else None
    g = iug.get("grant") if isinstance(iug, dict) else None
    tid = g.get("template_id") if isinstance(g, dict) else None
    s = load(cfg)
    t = s["templates"].get(tid) if isinstance(tid, str) else None
    if t is None or t != g:
        fail("template_unavailable")
    if tid in s["revoked"]:
        fail("template_revoked")
    validate(cfg, registry, t)
    rec = issue_record(cfg, tid, iug.get("issue"))
    if not isinstance(rec, dict) or rec.get("packet_sha256") != hc.handoff_digest(h):
        fail("self_issue_unknown")
    return t, rec


def select_self_issue(cfg, registry, receiver, branch, owned_paths, remote=None, template_id=None):
    """The grant to issue a task under: a live grant for this receiver with `self_issue` whose branch pattern,
    remote and paths cover the request (the first by id, as select() picks). `template_id` pins one."""
    from synthe_commit import Deny
    s = load(cfg)
    if template_id is not None and "self_issue" not in (s["templates"].get(template_id) or {}):
        fail("self_issue_not_granted")
    live = []
    for tid, t in sorted(s["templates"].items()):
        if (template_id and tid != template_id) or t.get("receiver") != receiver or "self_issue" not in t:
            continue
        try:
            validate(cfg, registry, t)
            if tid in s["revoked"]:
                fail("template_revoked")
            if exhausted(s, t):
                fail("template_exhausted")
            live.append(t)
        except Deny:
            if template_id:
                raise
    if not live:
        fail("self_issue_not_granted")
    for t in live:
        if (remote or t["params"]["remote"]) == t["params"]["remote"] \
                and hc.glob_match(t["params"]["branch_pattern"], branch) \
                and all(any(hc._glob_covers(p, o) for p in t["path_scope"]) for o in owned_paths or t["path_scope"]):
            return t
    fail("self_issue_scope")


# --------------------------------------------------------------------------
# delegates: a grant's named approver signs each push (or sends it to a human)

def delegate_path(cfg):
    return cfg.state_dir / "delegate-approvals.json"


def delegate_load(cfg):
    p = delegate_path(cfg)
    if not p.exists():
        return {"approvals": {}, "escalations": {}}
    try:
        s = json.loads(p.read_text())
        if set(s) != {"approvals", "escalations"} or not all(isinstance(v, dict) for v in s.values()):
            raise ValueError()
        return s
    except (OSError, ValueError, TypeError):
        fail("delegate_store_corrupt")


def delegate_input(x, escalate=False):
    return (ESCALATE_DOMAIN if escalate else DELEGATE_DOMAIN) + sc.canonical_json(
        {k: v for k, v in x.items() if k != "sig"})


def sign_delegate(body, key, escalate=False):
    """The delegate's signature (an Ed25519 key in the approver process, never in an agent's)."""
    x = dict(body, approver=key["agent"], kid=key["kid"])
    x["sig"] = sc.b64u(_sig(key, delegate_input(x, escalate)))
    return x


def proposal_id(x):
    return f"{x['idempotency_key']}/{x['action']}"


def _delegate_doc(registry, s, x, escalate):
    """Shape, signature and standing of a delegate approval/escalation; returns its grant."""
    fields = ESCALATE_FIELDS if escalate else APPROVE_FIELDS
    if not isinstance(x, dict) or set(x) != fields:
        fail("delegate_malformed")
    if not all(isinstance(x[k], str) and x[k] for k in fields - {"params", "note"}) or not isinstance(x["note"], str) \
            or len(x["note"]) > 4000:
        fail("delegate_malformed")
    q = x["params"]
    if not isinstance(q, dict) or set(q) != {"remote", "branch", "commit"} or not all(isinstance(v, str) and v for v in q.values()) \
            or not _SHA.match(q["commit"]):
        fail("delegate_malformed")
    if escalate and x["recommendation"] not in RECOMMENDATIONS:
        fail("delegate_malformed")
    t = s["templates"].get(x["template_id"])
    if not t or t.get("delegate") != x["approver"]:
        fail("delegate_not_named")
    # Independence: the reviewer is never a party to the handoff it reviews.
    if x["approver"] in (x["from"], x["to"]):
        fail("delegate_is_party")
    if x["to"] != t["receiver"]:
        fail("template_scope")
    if not _verifies(registry, x, delegate_input(x, escalate)):
        fail("delegate_signature_invalid")
    return t


def _matches(x, h, action, params):
    return (x["idempotency_key"], x["from"], x["to"], x["action"]) == (
        h.get("idempotency_key"), h.get("from"), h.get("to"), action) and x["params"] == {
        k: params.get(k) for k in ("remote", "branch", "commit")}


def submit_delegate(cfg, registry, x, staged):
    """Store the delegate's approval of a staged proposal. Caller holds locked(cfg). `staged` is the broker's
    own record of that proposal (or None): the delegate approves what the broker staged, nothing else."""
    from synthe_commit import any_match
    s = load(cfg)
    t = _delegate_doc(registry, s, x, False)
    validate(cfg, registry, t)
    if t["template_id"] in s["revoked"]:
        fail("template_revoked")
    if exhausted(s, t):
        fail("template_exhausted")
    if x["params"]["remote"] != t["params"]["remote"] or not any_match([t["params"]["branch_pattern"]], x["params"]["branch"]):
        fail("template_scope")
    now = hc.now_utc()
    exp = hc.parse_ts(x["expires_at"])
    if exp is None or exp <= now:
        fail("delegate_approval_expired")
    if exp > now + dt.timedelta(minutes=MAX_DELEGATE_MINUTES) \
            or ("expires_at" in t and exp > hc.parse_ts(t["expires_at"])):  # a grant without expiry: the 60 minutes
        fail("delegate_approval_too_long")
    d = delegate_load(cfg)
    sid = proposal_id(x)
    if sid in d["escalations"]:
        fail("delegate_escalated")
    h = ((staged or {}).get("packet") or {}).get("handoff") or {}
    if not staged or staged.get("state") != "STAGED" or not _matches(x, h, staged.get("action"), staged.get("params") or {}):
        fail("delegate_approval_stale")
    held = set(staged.get("waiting_for") or [])  # the broker sent it to a human: not the delegate's to review
    if "risk" in held:
        fail("risk_escalated")
    if "scope" in held:
        fail("outside_lane_paths")
    d["approvals"][sid] = x
    save(cfg, d, delegate_path(cfg))
    return {"id": sid, "template_id": t["template_id"], "status": "accepted"}


def escalate(cfg, registry, x):
    """The delegate sends a proposal to the human. Caller holds locked(cfg). Sticks to the proposal id."""
    s = load(cfg)
    t = _delegate_doc(registry, s, x, True)
    d = delegate_load(cfg)
    sid = proposal_id(x)
    d["escalations"][sid] = x
    d["approvals"].pop(sid, None)
    save(cfg, d, delegate_path(cfg))
    return {"id": sid, "template_id": t["template_id"], "status": "escalated", "recommendation": x["recommendation"]}


def delegate_approval(cfg, registry, h, action, params, t):
    """The grant's delegate approved exactly this push and it still stands, or Deny. Read under the lane lock
    at dispatch, so an escalation or a revocation can't race the push."""
    d = delegate_load(cfg)
    sid = f"{h.get('idempotency_key')}/{action}"
    if sid in d["escalations"]:
        fail("delegate_escalated")
    x = d["approvals"].get(sid)
    if x is None:
        fail("delegate_approval_missing")
    s = load(cfg)
    if x.get("template_id") != t["template_id"] or _delegate_doc(registry, s, x, False)["template_id"] != t["template_id"]:
        fail("delegate_approval_stale")
    if not _matches(x, h, action, params):
        fail("delegate_approval_stale")
    exp = hc.parse_ts(x["expires_at"])
    if exp is None or exp <= hc.now_utc():
        fail("delegate_approval_expired")
    return {"approver": x["approver"], "kid": x["kid"], "action": action, "params": x["params"], "delegate": True,
            "delegated_by": t["approver"], "template_id": t["template_id"], "expires_at": x["expires_at"]}


def delegate_view(cfg, sid=None):
    """What delegates decided, for Studio and the approver (signatures left out)."""
    d = delegate_load(cfg)
    strip = lambda x: {k: v for k, v in x.items() if k != "sig"}  # noqa: E731
    out = {"approvals": {k: strip(v) for k, v in d["approvals"].items()},
           "escalations": {k: strip(v) for k, v in d["escalations"].items()}}
    if sid is not None:
        out = {k: {sid: v[sid]} if sid in v else {} for k, v in out.items()}
    return out
