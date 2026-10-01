# Local Simulation — Handoff Contract Check action

Simulated the action's entrypoint (`checker/run_check.sh`, the same script
`action.yml` invokes) locally on 2026-09-30, from
`~/workspace/ideas/handoff-contract/`, using the examples in `../examples/`.
No network access used; python3 stdlib only.

Commands (env vars are how `action.yml` passes the action inputs):

```bash
HANDOFF_PACKET=examples/valid.json              HANDOFF_REGISTRY=examples/registry.json HANDOFF_WORKSPACE=. bash github-action/checker/run_check.sh
HANDOFF_PACKET=examples/bad-expired.json        HANDOFF_REGISTRY=examples/registry.json HANDOFF_WORKSPACE=. bash github-action/checker/run_check.sh
HANDOFF_PACKET=examples/bad-forbidden-email.json HANDOFF_REGISTRY=examples/registry.json HANDOFF_WORKSPACE=. bash github-action/checker/run_check.sh
```

## Run 1 — valid example → PASS (exit 0)

```
{
  "decision": "ACCEPT",
  "handoff_id": "h-0001",
  "trace_id": "trace-cadros-2026-09-30-001"
}
Handoff ACCEPTED - safe for the receiver to start work.
exit=0
```

## Run 2 — expired handoff → FAIL (exit 1)

```
{
  "decision": "REJECT",
  "state": "stale",
  "reasons": [
    {
      "state": "stale",
      "code": "handoff_expired",
      "message": "handoff expired at 2020-01-01T00:00:00Z"
    }
  ]
}
::error::Handoff REJECTED - stale: handoff expired at 2020-01-01T00:00:00Z
exit=1
```

## Run 3 — forbidden/unapproved email action → FAIL (exit 1)

```
{
  "decision": "REJECT",
  "state": "blocked",
  "reasons": [
    {
      "state": "blocked",
      "code": "tool_not_allowed",
      "message": "action 'send_email' uses tool 'gmail_send' not in allowed_tools"
    },
    {
      "state": "blocked",
      "code": "forbidden_action",
      "message": "action 'send_email' is forbidden by scope"
    },
    {
      "state": "blocked",
      "code": "approval_missing",
      "message": "action 'send_email' needs approval; none recorded"
    }
  ]
}
::error::Handoff REJECTED - blocked: action 'send_email' uses tool 'gmail_send' not in allowed_tools; blocked: action 'send_email' is forbidden by scope; blocked: action 'send_email' needs approval; none recorded
exit=1
```

## Verdict

| Case | Packet | Expected | Got | Exit |
|------|--------|----------|-----|------|
| 1 | `examples/valid.json` | ACCEPT | ACCEPT | 0 |
| 2 | `examples/bad-expired.json` | REJECT (`stale`) | REJECT (`stale`) | 1 |
| 3 | `examples/bad-forbidden-email.json` | REJECT (`blocked`) | REJECT (`blocked`) | 1 |

All three runs behave as a CI gate should: the valid handoff passes, both
broken handoffs fail with the reason printed in the log and surfaced as an
`::error::` annotation. Note: the raw checker exits `2` on reject; the
action's entrypoint normalizes any rejection to exit `1`.

## Two-runner simulation (2026-09-30, Option 2)

`simulate_two_runners.py` (this folder) models the cross-run behavior the
single-run runs above cannot reach: each "runner" is an isolated temp
workspace running the real, unmodified checker; the ledger moves between
runners only via an explicit cache hand-off. **This is a local model of
hosted runners, not a GitHub run** — it does not model cache eviction,
queueing, or clock skew. Recorded output (`--mode all`, exit 0):

```
=== MODE: legacy (v0.2 action: independent runners, same empty cache) ===
runner A: ACCEPT  (ledger: RESERVED)
runner B: ACCEPT  (ledger: RESERVED)
EXPECTED (the bug): both ACCEPT -> REPRODUCED

=== MODE: fixed (concurrency group serializes runs; cache chaining) ===
runner A claim : ACCEPT  (ledger: RESERVED)
cache hand-off A->B: snapshot restored
runner B claim : REJECT [duplicate: idempotency_key_reserved]  (ledger: RESERVED)
EXPECTED: exactly one ACCEPT, B REJECT duplicate -> HOLDS

=== MODE: complete (claim, then complete step, then replay) ===
runner A claim : ACCEPT  (ledger: RESERVED)
cache hand-off A->B: snapshot restored
runner B claim : REJECT [duplicate: idempotency_key_reserved]  (ledger: RESERVED)
runner A complete-step: COMPLETED  (ledger: COMPLETED)
cache hand-off A->C: snapshot restored
runner C replay : REJECT [duplicate: duplicate_idempotency_key]  (ledger: COMPLETED)
EXPECTED: complete flips to COMPLETED; replay REJECT duplicate -> HOLDS
```

These three modes are pinned as automated tests in
`../tests/test_two_runner.py` (S1/S2/S3). S1 is the permanent regression
witness for the v0.2 failure: if the legacy shape ever stops
double-accepting in the model, the model has drifted from the properties
that caused the bug.
