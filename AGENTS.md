# If you are an AI agent reading this

You were pointed at this repo to validate an agent-to-agent handoff packet before the receiving agent acts on it.

## The 30-second version

- A handoff packet is a JSON file (see `examples/valid.json`) describing one unit of work moving from agent A to agent B: who is sending, who receives, what artifacts are included, what evidence supports it, and an idempotency key.
- `src/handoff_check.py` validates that packet. Exit 0 = ACCEPT. Exit 2 = REJECT, printing the failure state (`invalid`, `incomplete`, `stale`, `conflicting`, `blocked`, `duplicate`) and reason codes.
- Every packet goes through it before the receiving agent touches the work.

## Validate a packet

```bash
python3 src/handoff_check.py <packet.json> \
  --registry <registry.json> --workspace . --ledger ledger.json
```

## Rules of the road

- Evidence marked `verbatim` must be byte-for-byte. Never paraphrase it.
- Re-running a packet with the same idempotency key MUST be rejected as a duplicate.
- On REJECT: surface the state and reason codes to the sender and stop. Never bypass, never guess.

## As a GitHub Action

```yaml
- uses: rohansiddam/Synthe/github-action@main
  with:
    packet: handoff.json
    registry: agents.json
    workspace: .
```

## Full detail

- `SPEC.md` — the one-page contract
- `schema/handoff.schema.json` — the packet format
- `README.md` — layout, failure states, what v0.1 does and does not do
