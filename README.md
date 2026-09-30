# Handoff Contract v0.1 — verification layer

A tiny checker that validates an agent-to-agent handoff packet **before** the
receiver runs. Bad handoffs get rejected with a reason, not silently executed.

## Layout

- `SPEC.md` — the one-page spec
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

## Use it on your own handoff

1. Write a packet like `examples/valid.json` for the work being handed over (fields are defined in `schema/handoff.schema.json`).
2. Register your agents in a registry file (see `examples/registry.json`).
3. Validate before the receiving agent runs:

```bash
python3 src/handoff_check.py your-handoff.json --registry your-agents.json --workspace . --ledger ledger.json
```

Or as a GitHub Action: `uses: rohansiddam/Synthe/github-action@main` (see `github-action/README.md`). Agents: `AGENTS.md` explains all of this in agent-readable form.

Exit code 0 = ACCEPT, 2 = REJECT with a failure state and reason codes.

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
(reserved; transient-retry classification lands with a runner), `duplicate`.
