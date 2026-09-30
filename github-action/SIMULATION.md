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
