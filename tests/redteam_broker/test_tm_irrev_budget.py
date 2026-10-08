"""TM-IRREV-BUDGET: Spec tests -- a daily cap on executed pushes, broker-side.

Intent key: loop-redteam. Playbook: G1 (fail closed), C5 (library_write as
a broker effect with a signed receipt).

The broker caps executed pushes per agent and per fleet per 24h (S9, The
Irreversibility Budget), but only in its proxy. These tests specify the
BROKER-side guarantee:

1. past the per-agent cap, a propose is denied with a reason code
2. past the per-fleet cap, a propose is denied with a reason code
3. the denial is receipted (not a silent drop)
4. the cap cannot be dodged via a second connector
5. the cap cannot be dodged via a direct socket call (bypassing the proxy)
6. under the cap, proposes are still executed (the cap is a cap, not a ban)

NOTE on the xfail reason: the brief marks tests reason="TASK-ID" without
naming the build task id (unlike LB-C5/LB-C6). "TASK: LB-IRREV-BUDGET" is
used as the placeholder; the coordinator should confirm or replace it.

TARGET STATUS (2026-10-05): broker-side budget enforcement does not exist.
The denial tests below are therefore marked xfail(strict=True): they record
the missing target as evidence and become the live battery the moment the
checks land (rewire `_require_broker_budget()` to the real entry point and
remove the marks).

The `test_*` Part 1 tests run NOW against a reference BudgetLedger
(test-only spec of the counting rule) and prove each dodge vector is real:
a naive per-connector counter misses the second-connector dodge, and a
proxy-only cap misses the direct-socket call.
"""

import time

import pytest

_NO_BROKER = (
    "TM-IRREV-BUDGET: broker-side irreversibility budget not implemented"
)

WINDOW_S = 24 * 3600
PER_AGENT_CAP = 10
PER_FLEET_CAP = 40


class BudgetLedger:
    """Reference spec of the broker-side irreversibility budget.

    Test-only counting rule, NOT the broker. Counts executed pushes per
    agent id and per fleet id over a rolling 24h window. Connector ids
    and channels are recorded but never trusted for identity.
    """

    def __init__(self, per_agent_cap=PER_AGENT_CAP,
                 per_fleet_cap=PER_FLEET_CAP):
        self.per_agent_cap = per_agent_cap
        self.per_fleet_cap = per_fleet_cap
        self.executions = []  # (ts, agent_id, connector_id, channel)

    def record(self, ts, agent_id, connector_id="conn-1",
               channel="mcp", fleet_id="fleet-1"):
        self.executions.append((ts, agent_id, connector_id, channel,
                                fleet_id))

    def check(self, ts, agent_id, fleet_id="fleet-1"):
        recent = [e for e in self.executions if ts - e[0] < WINDOW_S]
        agent_n = sum(1 for e in recent if e[1] == agent_id)
        fleet_n = sum(1 for e in recent if e[4] == fleet_id)
        if agent_n >= self.per_agent_cap:
            return ("denied", "budget_exceeded")
        if fleet_n >= self.per_fleet_cap:
            return ("denied", "budget_exceeded")
        return ("allowed", None)


def _fill(ledger, ts, agent_id, n, connector_id="conn-1",
          channel="mcp", fleet_id="fleet-1"):
    for _ in range(n):
        ledger.record(ts, agent_id, connector_id, channel, fleet_id)


def _require_broker_budget():
    """Seam for the broker-side irreversibility budget.

    Rewire to the real entry point when it lands. Must return an object
    with:
        propose(agent_id, connector_id, channel) -> result with
        .decision ("executed"/"denied"), .code ("budget_exceeded" on
        deny), and .receipt_seq (not None on deny: the deny is receipted).
    """
    raise RuntimeError(_NO_BROKER)


# --------------------------------------------------------------------------
# Part 1 (runs NOW): the counting rule and the dodge vectors are real.
# --------------------------------------------------------------------------

def test_agent_cap_counts():
    ledger = BudgetLedger()
    now = time.time()
    _fill(ledger, now, "agent-cy", PER_AGENT_CAP)
    assert ledger.check(now, "agent-cy") == ("denied", "budget_exceeded")
    assert ledger.check(now, "agent-dee") == ("allowed", None)  # others free


def test_fleet_cap_counts():
    ledger = BudgetLedger()
    now = time.time()
    agents = ["agent-ada", "agent-ben", "agent-cy", "agent-dee"]
    for i in range(PER_FLEET_CAP):
        ledger.record(now, agents[i % len(agents)])
    assert ledger.check(now, "agent-eli") == ("denied", "budget_exceeded")


def test_second_connector_dodge_is_real():
    # Naive counting per connector id misses the dodge...
    per_connector = {}
    now = time.time()
    for _ in range(PER_AGENT_CAP):
        per_connector["conn-1"] = per_connector.get("conn-1", 0) + 1
    naive_allows = per_connector.get("conn-2", 0) < PER_AGENT_CAP
    assert naive_allows  # dodge succeeds against naive counting
    # ...while agent-id counting (the spec) catches it:
    ledger = BudgetLedger()
    _fill(ledger, now, "agent-cy", PER_AGENT_CAP, connector_id="conn-1")
    assert ledger.check(now, "agent-cy") == ("denied", "budget_exceeded")


def test_direct_socket_still_carries_agent_identity():
    # A direct socket call bypasses the proxy, not the agent identity:
    # the propose still names its agent, so a broker-side counter sees it.
    propose = {"agent_id": "agent-cy", "connector_id": "conn-1",
               "channel": "direct-socket"}
    ledger = BudgetLedger()
    now = time.time()
    _fill(ledger, now, "agent-cy", PER_AGENT_CAP)
    assert ledger.check(now, propose["agent_id"]) == (
        "denied", "budget_exceeded")


def test_window_rolls():
    ledger = BudgetLedger()
    now = time.time()
    _fill(ledger, now - WINDOW_S - 1, "agent-cy", PER_AGENT_CAP)
    assert ledger.check(now, "agent-cy") == ("allowed", None)  # old ones aged out


# --------------------------------------------------------------------------
# Part 2 (xfail until the broker enforces the budget): every over-cap
# propose is denied with a reason code, the deny is receipted, and neither
# dodge works.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-IRREV-BUDGET broker must deny over agent cap")
def test_broker_denies_over_agent_cap():
    b = _require_broker_budget()
    for _ in range(PER_AGENT_CAP):
        b.propose("agent-cy", "conn-1", "mcp")
    r = b.propose("agent-cy", "conn-1", "mcp")
    assert r.decision == "denied" and r.code == "budget_exceeded"


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-IRREV-BUDGET broker must deny over fleet cap")
def test_broker_denies_over_fleet_cap():
    b = _require_broker_budget()
    agents = ["agent-ada", "agent-ben", "agent-cy", "agent-dee",
              "agent-eli", "agent-fay"]
    for i in range(PER_FLEET_CAP):
        b.propose(agents[i % len(agents)], "conn-1", "mcp")
    r = b.propose("agent-ada", "conn-1", "mcp")
    assert r.decision == "denied" and r.code == "budget_exceeded"


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-IRREV-BUDGET cap must survive a second connector")
def test_broker_cap_survives_second_connector():
    b = _require_broker_budget()
    for _ in range(PER_AGENT_CAP):
        b.propose("agent-cy", "conn-1", "mcp")
    r = b.propose("agent-cy", "conn-2", "mcp")  # different connector
    assert r.decision == "denied" and r.code == "budget_exceeded"


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-IRREV-BUDGET cap must survive a direct socket call")
def test_broker_cap_survives_direct_socket():
    b = _require_broker_budget()
    for _ in range(PER_AGENT_CAP):
        b.propose("agent-cy", "conn-1", "mcp")
    r = b.propose("agent-cy", "conn-1", "direct-socket")  # bypasses proxy
    assert r.decision == "denied" and r.code == "budget_exceeded"


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-IRREV-BUDGET budget denials must be receipted")
def test_broker_denial_is_receipted():
    b = _require_broker_budget()
    for _ in range(PER_AGENT_CAP):
        b.propose("agent-cy", "conn-1", "mcp")
    r = b.propose("agent-cy", "conn-1", "mcp")
    assert r.decision == "denied"
    assert r.receipt_seq is not None  # not a silent drop


@pytest.mark.xfail(strict=True,
                   reason="TASK: LB-IRREV-BUDGET broker must execute under the cap")
def test_broker_allows_under_cap():
    b = _require_broker_budget()
    r = b.propose("agent-cy", "conn-1", "mcp")
    assert r.decision == "executed"
