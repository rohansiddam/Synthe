# Handoff Contract v0.1 — verification layer

A tiny checker that validates an agent-to-agent handoff packet **before** the
receiver runs. Bad handoffs get rejected with a reason, not silently executed.

## Layout

- `HANDOFF_CONTRACT_V0.1.md` — the one-page spec
- `schema/handoff.schema.json` — JSON Schema for the packet
- `src/handoff_check.py` — stdlib-only CLI validator (no dependencies)
- `examples/` — a valid packet, five rejected packets, an agent registry, a sample artifact
- `tests/test_validator.py` — 14 tests modeled on real Cadros failure classes

## Quickstart

```bash
python3 src/handoff_check.py examples/valid.json \
  --registry examples/registry.json --workspace . --ledger ledger.json
# ACCEPT, recorded in ledger.json (running it again -> REJECT duplicate)

python3 src/handoff_check.py examples/bad-paraphrase-evidence.json \
  --registry examples/registry.json --workspace . --dry-run
# REJECT invalid: evidence_not_verbatim
```

Exit code 0 = ACCEPT, 2 = REJECT with a failure state and reason codes.

## Ledger semantics (v0.2)

The idempotency ledger records a **claim**, not just a sighting:

- **ACCEPT** (non-dry-run) atomically records the packet's idempotency key
  as `RESERVED` with the claiming handoff id and timestamp. The write runs
  under a file lock with a temp-file rename, so two concurrent
  presentations of the same key cannot both pass.
- Once the receiver has actually performed the effect, it completes the
  claim (terminal state, safe to re-run):

  ```bash
  python3 src/handoff_check.py examples/valid.json \
    --ledger ledger.json --complete
  ```

- Re-presenting a `COMPLETED` key -> REJECT `duplicate` ("already completed
  by handoff X").
- Re-presenting a `RESERVED` key younger than `--reserve-ttl-hours`
  (default 24) -> REJECT `duplicate` ("claimed by handoff X; reconcile
  before redispatch").
- Re-presenting a `RESERVED` key older than the TTL -> REJECT `unknown`:
  the receiver may have crashed before or after the effect, so reconcile
  against the receiver's effect receipt before redispatching.

Ledger entries written by v0.1 (no `state` field) count as `COMPLETED`.
The ledger is still just a local JSON file; on GitHub-hosted runners the
bundled Action persists it across runs via `actions/cache` (see
`github-action/README.md`), because runner workspaces are ephemeral.

## What v0.1 checks

Required fields (incl. nested), canonical agent identity (aliases must
resolve), duplicate idempotency keys (ledger), handoff expiry, planned actions
against allowed tools / forbidden actions / approvals / budgets, input artifact
existence + SHA-256 when a `--workspace` root is given, required evidence
present, and verbatim fidelity for code/legal-text evidence.

## What v0.1 deliberately does not do

- No semantic judgment: it can't tell whether the *content* of a deliverable is
  right. It verifies the envelope and the evidence trail, humans keep verdicts.
- Artifact checks only run against a local workspace root (no URL fetching).
- The ledger is a local JSON file, not a hosted service.

## Failure states

`invalid`, `incomplete`, `stale`, `conflicting`, `blocked`, `retryable`
(reserved; transient-retry classification lands with a runner), `duplicate`,
`unknown` (v0.2: a claim was reserved but never completed past its TTL; the
effect's outcome is unknown until reconciled).
