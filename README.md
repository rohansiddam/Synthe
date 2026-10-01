# Synthe

Synthe checks every handoff between AI agents before the receiving agent acts on it.

Most agent-to-agent handoffs today are blobs of text that the receiving agent takes on trust. That is how the same work gets done twice, stale artifacts get acted on, and actions nobody approved slip through. Synthe puts a gate in the middle: every handoff arrives as a typed packet, gets validated against a registry and the actual artifacts it points to, and gets an ACCEPT or a REJECT with a reason. Every accepted handoff is recorded, so the same one cannot be claimed twice.

## v0.3

Receiver policy (authority can only narrow), Ed25519-signed packets and
approvals, evidence pinning, fail-closed parsing, and a hardened claim ledger
(claim tokens, `--release`, `fenced()`).

- **The contract:** [`SPEC.md`](SPEC.md): fields, policy, signatures, validation order, every reason code
- **What it does and doesn't protect:** [`THREAT_MODEL.md`](THREAT_MODEL.md)
- **Try to break it:** `examples/v03/` has one valid signed packet and 8 attacks
  (tampered after signing, spoofed sender, self-granted authority, forged approval,
  replayed approval, exceeding receiver policy, paraphrased "verbatim" evidence,
  undeclared actions). The keys in `examples/v03/test-keys/` are public test keys.

```bash
for f in examples/v03/packets/*.json; do
  echo "== $(basename $f)"
  python3 src/handoff_check.py "$f" --registry examples/v03/registry.json \
    --workspace examples/v03/workspace --dry-run | head -8
done
```

## Layout

- `SPEC.md`: the contract (v0.3)
- `THREAT_MODEL.md`: what the gate stops and what it doesn't
- `schema/handoff.schema.json`: JSON Schema for the packet
- `src/handoff_check.py`: the checker (stdlib only; CLI + `check()` used by every entry point)
- `src/synthe_crypto.py`, `src/synthe_sign.py`: Ed25519 signing and the keygen/approve/sign/verify CLI
- `examples/`: v0.1 packets; `examples/v03/`: signed packet + 8 attack packets (test-only keys)
- `github-action/`: the gate as a GitHub Action
- `tests/`: 45 tests

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
- The ACCEPT returns `claim: {epoch, token}`. Completion is bound to that exact
  packet (and token, when given). For non-idempotent effects, use
  `fenced()` so a released claim's old holder can't act (see `SPEC.md` §8).
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
