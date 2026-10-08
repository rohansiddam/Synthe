"""TM-REVOKE-SPEC: Spec tests for lookup (C6, P12).

Intent key: loop-redteam. Playbook: C6 (broker enforces revocation and
re-checks at lookup), P12 (revocation wins at every lookup), P7 (re-check
before every reuse), G1 (fail closed).

These are the cases a future template-lookup must REFUSE once it exists --
revoked, stale, or superseded templates must never be handed out for reuse,
and the broker (never the model) must be the one refusing:

1. a revoked template is still served              -> revoke_revoked
2. an older version outranks its replacement       -> revoke_stale_version
3. a template whose depends_on moved (branch head, policy version, file
   hashes) is reused without a re-check            -> revoke_depends_moved
4. revocation lands while a reuse is in flight
   (check-then-act)                               -> revoke_race

TARGET STATUS (2026-10-05): lookup revocation (C6) does not exist yet.
Every denial test is therefore marked xfail(strict=True) with reason
"TASK: LB-C6 <refusal>", so the suite stays green today and the LB-C6 build
task has an exact definition of done: make each of these pass for real.

The `test_attack_lookup_*` tests run NOW against a deliberately naive
lookup stub (labeled NAIVE/VULNERABLE) and prove each attack genuinely
results in a revoked/stale template being served -- no broker needed to
see that the hazard is real.
"""

import pytest

_NO_BROKER = "lookup revocation (C6) not implemented; task LB-C6 will make these pass"


# --------------------------------------------------------------------------
# template records and a deliberately naive lookup (VULNERABLE -- demonstrates
# the hazard; the real broker must do the opposite)
# --------------------------------------------------------------------------

def _record(template, version, revoked=False, superseded_by=None,
            branch_head="abc123", policy_version="pol-v3",
            file_hashes=None):
    return {
        "template": template,
        "version": version,
        "revoked": revoked,
        "superseded_by": superseded_by,
        "depends_on": {
            "branch_head": branch_head,
            "policy_version": policy_version,
            "file_hashes": file_hashes or {"plans/core.md": "hash1"},
        },
    }


class NaiveLookup:
    """VULNERABLE: serves without revocation / freshness / re-check logic."""

    def __init__(self, records, current_head="abc123",
                 current_policy="pol-v3", current_hashes=None):
        self.records = records
        self.current_head = current_head
        self.current_policy = current_policy
        self.current_hashes = current_hashes or {"plans/core.md": "hash1"}

    def lookup(self, template, version=None, on_after_check=None):
        cands = [r for r in self.records if r["template"] == template]
        if version is None:
            rec = cands[0]  # BUG: first inserted, not latest, no checks
        else:
            rec = next(r for r in cands if r["version"] == version)
        # BUG: no revocation check, no supersession check, no depends_on
        # re-check -- and a check-then-act gap before serving:
        if on_after_check:
            on_after_check(self, rec)
        return ("served", rec)


def _require_broker_lookup():
    """Seam for the broker's revocation-enforcing lookup (C6, task LB-C6).

    Rewire to the real entry point when LB-C6 lands. Must return an object
    with:
        lookup(template, version=None) -> denial with .code
        startswith "revoke_"
    """
    raise RuntimeError(_NO_BROKER)


# --------------------------------------------------------------------------
# attack builders: each returns (lookup_stub, served_record)
# --------------------------------------------------------------------------

def build_revoked_served():
    """Revoked template handed out anyway."""
    rec = _record("deploy-plan", 2, revoked=True)
    lib = NaiveLookup([rec])
    return lib, lib.lookup("deploy-plan")[1]


def build_stale_outranks():
    """v1 served as 'latest' although v2 superseded it."""
    v1 = _record("deploy-plan", 1, superseded_by=2)
    v2 = _record("deploy-plan", 2)
    lib = NaiveLookup([v1, v2])
    return lib, lib.lookup("deploy-plan")[1]  # version=None -> "latest"


def build_depends_moved():
    """depends_on drifted (branch head moved); served without re-check."""
    rec = _record("deploy-plan", 2, branch_head="abc123")
    lib = NaiveLookup([rec], current_head="def456")  # head moved on
    return lib, lib.lookup("deploy-plan")[1]


def build_revoke_in_flight():
    """Revocation lands between lookup check and serve (check-then-act)."""
    rec = _record("deploy-plan", 2, revoked=False)
    lib = NaiveLookup([rec])

    def revoke_mid_lookup(lookup, record):
        record["revoked"] = True  # revocation lands in the gap

    return lib, lib.lookup("deploy-plan", on_after_check=revoke_mid_lookup)[1]


# --------------------------------------------------------------------------
# Part 1 (runs NOW): each attack genuinely serves a template that must be
# refused, under the naive lookup.
# --------------------------------------------------------------------------

def test_attack_lookup_revoked_served():
    _lib, served = build_revoked_served()
    assert served["revoked"] is True  # revoked... yet served


def test_attack_lookup_stale_outranks():
    _lib, served = build_stale_outranks()
    assert served["version"] == 1  # stale v1 served...
    assert served["superseded_by"] == 2  # ...although v2 replaced it


def test_attack_lookup_depends_moved():
    lib, served = build_depends_moved()
    assert served["depends_on"]["branch_head"] != lib.current_head
    # drifted dependency, served with no re-check


def test_attack_lookup_revoke_in_flight():
    _lib, served = build_revoke_in_flight()
    assert served["revoked"] is True  # revoked mid-lookup... yet served


# --------------------------------------------------------------------------
# Part 2 (xfail until LB-C6): each case must end in a revoke_* refusal by
# the broker. The broker, never the model, refuses.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C6 must refuse revoked templates at lookup")
def test_lookup_refuses_revoked():
    lib, _served = build_revoked_served()
    denial = _require_broker_lookup().lookup("deploy-plan")
    assert denial.code.startswith("revoke_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C6 must refuse stale versions at lookup")
def test_lookup_refuses_stale_version():
    lib, _served = build_stale_outranks()
    denial = _require_broker_lookup().lookup("deploy-plan")
    assert denial.code.startswith("revoke_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C6 must re-check depends_on before reuse")
def test_lookup_refuses_moved_depends():
    lib, _served = build_depends_moved()
    denial = _require_broker_lookup().lookup("deploy-plan")
    assert denial.code.startswith("revoke_")


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-C6 revocation must win even mid-lookup")
def test_lookup_refuses_revoke_in_flight():
    lib, rec = build_revoke_in_flight()
    rec["revoked"] = True  # revocation landed; lookup must still refuse
    denial = _require_broker_lookup().lookup("deploy-plan")
    assert denial.code.startswith("revoke_")
