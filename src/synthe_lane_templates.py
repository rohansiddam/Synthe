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
"""
import datetime as dt
import hashlib
import json
import os
import re
from contextlib import contextmanager

import handoff_check as hc
import synthe_crypto as sc

DOMAIN = b"synthe/approval-template/v1\n"
REVOKE_DOMAIN = b"synthe/approval-template-revoke/v1\n"
DELEGATE_DOMAIN = b"synthe/delegate-approval/v1\n"
ESCALATE_DOMAIN = b"synthe/delegate-escalation/v1\n"
DELEGATE_KIND = "model_approver"
MAX_DELEGATE_MINUTES = 60
FIELDS = {"template_id", "approver", "kid", "receiver", "tool", "params", "path_scope", "max_uses", "expires_at",
          "lineage", "sig"}
# delegate: who reviews each push; brief: the human's own instructions to that reviewer (signed with the grant,
# so the reviewer can tell them apart from anything an agent wrote)
OPTIONAL = {"delegate", "brief"}
MAX_BRIEF = 4000
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
    return (REVOKE_DOMAIN if revoke else DOMAIN) + sc.canonical_json({k: v for k, v in x.items() if k != "sig"})


def _sig(key, msg):
    """A Touch ID key signs through its helper (`_sign`); a passphrase key with its Ed25519 secret."""
    return key["_sign"](msg) if callable(key.get("_sign")) else sc.sign_bytes(key["_secret"], msg)


def sign(body, key, revoke=False):
    x = dict(body, approver=key["agent"], kid=key["kid"])
    x["sig"] = sc.b64u(_sig(key, signing_input(x, revoke)))
    return x


def lineage(cfg, registry, receiver):
    policy = hc.receiver_policy(registry, receiver) or {}
    trusted = policy.get("trusted_approvers") or []
    return {"receiver_policy_digest": digest(policy),
            "approvers_digest": digest({a: registry["agents"].get(a) for a in sorted(trusted)}),
            "effects_digest": digest({"effects": cfg.effects, "lane_templates": cfg.raw.get("lane_templates")})}


def enabled(cfg, receiver):
    return receiver in (cfg.raw.get("lane_templates") or {}).get("receivers", []) and receiver != "claude"


def validate(cfg, registry, x):
    if not isinstance(x, dict) or x.get("tool") != "git_push" or not enabled(cfg, x.get("receiver")):
        fail("template_scope")
    if not FIELDS <= set(x) <= FIELDS | OPTIONAL:
        fail("template_malformed")
    if "brief" in x and (not isinstance(x["brief"], str) or not x["brief"].strip() or len(x["brief"]) > MAX_BRIEF):
        fail("template_malformed")
    if not all(isinstance(x.get(k), str) and x[k] for k in ("template_id", "approver", "kid", "receiver", "expires_at", "sig")):
        fail("template_malformed")
    if len(x["template_id"]) > 120 or not isinstance(x["max_uses"], int) or isinstance(x["max_uses"], bool) or not 1 <= x["max_uses"] <= 10000:
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
    # Ed25519 (passphrase key) or ES256 (Touch ID key): the registered key decides which.
    if not _verifies(registry, x, signing_input(x)):
        fail("template_signature_invalid")
    expiry = hc.parse_ts(x["expires_at"])
    if expiry is None or expiry <= hc.now_utc():
        fail("template_expired")
    if x["lineage"] != lineage(cfg, registry, x["receiver"]):
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
        registry, err = hc.load_registry(str(cfg.registry_path))
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
        registry, err = hc.load_registry(str(cfg.registry_path))
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
            if s["uses"].get(tid, 0) >= t["max_uses"]:
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
    registry, err = hc.load_registry(str(cfg.registry_path))
    if err:
        fail("registry_unreadable")
    t = select(cfg, registry, receiver, params, paths=paths, template_id=tid)
    if not t:
        fail("template_unavailable")
    s = load(cfg)
    n = s["uses"].get(tid, 0) + 1
    s["uses"][tid] = n
    save(cfg, s)
    return {"template_id": tid, "use": n, "approver": t["approver"], "expires_at": t["expires_at"]}


def view(cfg):
    from synthe_commit import Deny
    registry, err = hc.load_registry(str(cfg.registry_path))
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
                if s["uses"].get(tid, 0) >= t["max_uses"]:
                    fail("template_exhausted")
            except Deny as e:
                status = e.reason["code"]
            out.append({**{k: v for k, v in t.items() if k != "sig"}, "status": status,
                        "uses_left": max(0, t["max_uses"] - s["uses"].get(tid, 0))})
        return {"templates": out, "enabled_receivers": (cfg.raw.get("lane_templates") or {}).get("receivers", [])}


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
    if s["uses"].get(t["template_id"], 0) >= t["max_uses"]:
        fail("template_exhausted")
    if x["params"]["remote"] != t["params"]["remote"] or not any_match([t["params"]["branch_pattern"]], x["params"]["branch"]):
        fail("template_scope")
    now = hc.now_utc()
    exp = hc.parse_ts(x["expires_at"])
    if exp is None or exp <= now:
        fail("delegate_approval_expired")
    if exp > now + dt.timedelta(minutes=MAX_DELEGATE_MINUTES) or exp > hc.parse_ts(t["expires_at"]):
        fail("delegate_approval_too_long")
    d = delegate_load(cfg)
    sid = proposal_id(x)
    if sid in d["escalations"]:
        fail("delegate_escalated")
    h = ((staged or {}).get("packet") or {}).get("handoff") or {}
    if not staged or staged.get("state") != "STAGED" or not _matches(x, h, staged.get("action"), staged.get("params") or {}):
        fail("delegate_approval_stale")
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
