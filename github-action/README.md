# Handoff Contract Check — GitHub Action

> **Status (2026-09-30):** Option 2 hardening is included on main and is
> **proven by a local simulation only** (`tests/test_two_runner.py`,
> `simulate_two_runners.py` in this folder): the simulation models two
> isolated runner workspaces plus an ordered cache hand-off. It is **not**
> a run on real GitHub infrastructure. One real two-runner GitHub run (the
> manual "Synthe two-runner verification" workflow) is still required
> before the cross-run exactly-one claim can be stated without the
> "simulated" qualifier (see "What is proven, what is not"). The public
> repo's README/AGENTS keep the v0.2 claim until that run passes; the
> checker CLI and its verdict states are unchanged.

A composite GitHub Action that runs the **Handoff Contract** validator on
an agent-to-agent handoff packet and fails the CI step when the handoff is
rejected. Use it to gate agent work: an agent that wants another agent
(or a human) to pick up its work must present a valid handoff packet, and
the claim must be completed after the effect is real, or the packet
cannot be replayed as if nothing happened.

The checker is a single stdlib-only Python file (vendored under
`checker/`), so the action needs **no network access and no
dependencies** — just `python3`, which is preinstalled on GitHub-hosted
runners.

## What it checks

Given a handoff packet (see `../SPEC.md` for the format), the validator
confirms, before the receiver starts work:

- all required fields are present and the schema version is supported;
- the sender and receiver are canonical agent ids in the registry (no
  aliases, no unknown agents);
- the handoff has not expired;
- every planned action uses an allowed tool, is not forbidden by scope,
  has any required approval on file (and unexpired), and fits the budget;
- every referenced artifact exists in the workspace and matches its
  recorded SHA-256 hash (no stale files);
- all required evidence is attached, and evidence that must be verbatim
  (quotes, code, legal text) is flagged as verbatim, not paraphrased;
- duplicate protection via the idempotency ledger: the handoff's key has
  not already been claimed or executed (see "Duplicate protection &
  cross-run safety" below).

The checker exits `0` on ACCEPT and `2` on REJECT (printing the failure
state — `invalid`, `incomplete`, `stale`, `conflicting`, `blocked`,
`duplicate`, `unknown` — and reason codes); the Action's entrypoint
normalizes a rejection to step exit `1` with the reasons shown in the
step log and as a workflow error annotation.

## The two phases: claim, then complete

A handoff claim is a two-step state machine, not a single "seen it" flag,
and each step is a separate invocation of this Action:

1. **Claim** (`phase: claim`, the default) — run *before* the receiving
   agent acts. The checker validates the packet and, on ACCEPT, records
   the idempotency key as `RESERVED` in the ledger. This is only a
   claim: the effect has not happened yet.
2. **Complete** (`phase: complete`) — run *after* the receiving agent's
   effect is real. The Action restores the ledger again, flips the key
   from `RESERVED` to `COMPLETED`, and saves the ledger back.

Re-presenting a `COMPLETED` key is rejected as `duplicate`
(terminal: that effect already happened). Re-presenting a `RESERVED`
key within 24 hours (`--reserve-ttl-hours` on the checker) is also
`duplicate` ("claimed by handoff X; reconcile before redispatch"). A
`RESERVED` claim older than the TTL yields the failure state `unknown`:
the receiver may have crashed before *or after* the effect, so reconcile
against the receiver's effect receipt before redispatching. Completing
an already-`COMPLETED` key is an idempotent no-op success.

Why two invocations instead of one? Because persistence has to wrap each
transition. In v0.2 the Action saved its ledger cache *before* the
receiver ran, so a `--complete` performed later in the job flipped only
a throwaway workspace file and the `COMPLETED` state was never persisted
by the Action. Now each phase restores → mutates → re-saves.

## Duplicate protection & cross-run safety

Duplicate detection needs memory: which idempotency keys have already
been claimed. That memory lives in a JSON **ledger**. GitHub-hosted
runners are **ephemeral** — each job gets a fresh machine and the
workspace is discarded — so when you don't pass the `ledger` input, the
Action manages one at `.synthe/ledger.json`:

1. `actions/cache/restore` restores it before the phase (key
   `synthe-ledger-<owner>/<repo>`, prefix fallback to the newest
   snapshot).
2. The checker validates against it and records the transition in it.
3. `actions/cache/save` writes it back under a per-run key, **even if
   the step failed** (`if: always()`), so a rejected claim attempt is
   persisted state too.

That gives each run the previous run's ledger ("cache chaining"). It is
**not sufficient on its own**: cache entries are immutable snapshots,
not an atomic compare-and-set. Two workflow runs that start at the same
time restore the *same* snapshot, both see the key as unclaimed, and
both ACCEPT — the checker's file lock cannot help, because the runners
share no filesystem. An independent reviewer demonstrated exactly this
against v0.2. The missing piece is ordering: your workflow must
serialize the runs that share a ledger. GitHub provides that as a
workflow-level `concurrency` group.

### Required caller workflow shape

```yaml
# .github/workflows/handoff.yml
name: Handoff

on:
  workflow_dispatch:        # or pull_request / your real trigger

# REQUIRED for cross-run exactly-one claims: every run that touches the
# ledger joins this one group, so GitHub runs them strictly one at a
# time, in order. Without it, two simultaneous runs can both ACCEPT the
# same packet (both restore the pre-claim snapshot). Do NOT set
# cancel-in-progress: a cancelled claimant would strand the queue.
concurrency:
  group: synthe-handoff-ledger
  cancel-in-progress: false

permissions:
  contents: read

jobs:
  handoff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # 1. CLAIM: validate + record RESERVED. Fails the job on REJECT.
      - name: Claim handoff
        id: claim
        uses: rohansiddam/Synthe/github-action@main
        with:
          packet: handoff.json
          registry: agents/registry.json
          workspace: .
          phase: claim

      # 2. THE EFFECT: the receiving agent does the actual work here.
      - name: Do the work
        run: ./run_receiver.sh

      # 3. COMPLETE: flip RESERVED -> COMPLETED and persist it. Runs even
      #    if the effect step failed? No: only complete an effect that
      #    actually happened. If the effect failed, leave the claim
      #    RESERVED; it expires to `unknown` after the TTL for
      #    reconciliation instead of pretending completion.
      - name: Complete handoff
        uses: rohansiddam/Synthe/github-action@main
        with:
          packet: handoff.json
          registry: agents/registry.json
          workspace: .
          phase: complete
```

Notes on the shape:

- The `concurrency` group belongs to the **caller** workflow: a
  composite action cannot declare one. Every workflow that uses this
  Action against the same repository ledger must use the **same group
  name**, or those workflows can still race each other (see "What is
  proven, what is not").
- Serialization costs throughput: handoff runs queue instead of running
  in parallel. For a claim ledger that is the correct trade.
- The group can also be declared per-job (`jobs.<id>.concurrency`) if a
  workflow has unrelated jobs that should not queue behind handoffs;
  the group string must still be identical everywhere the ledger is
  used.
- If you pass your own `ledger` path, the cache steps are skipped and
  persisting/completing that file between runs is up to you, but the
  ordering requirement is the same: only one claimant at a time against
  a given ledger state, or exactly-one is not guaranteed.

### What is proven, what is not

Proven:

- **Checker semantics** (unchanged by this hardening): 26 tests in
  `../tests/` — validator behavior, the RESERVED/COMPLETED/`unknown`
  conformance suite, and ledger invariants (including exactly-one-winner
  among concurrent processes sharing one filesystem).
- **The v0.2 cross-run failure**, reproduced in a local model:
  `simulate_two_runners.py --mode legacy` runs the real checker in two
  isolated workspaces that both restore from the same empty snapshot;
  both ACCEPT the same key.
- **The fix at simulation level**: with runs serialized and the second
  runner restoring the first runner's saved ledger, exactly one ACCEPT
  and a `duplicate` rejection; after a simulated complete step, a replay
  is rejected against the `COMPLETED` entry (`--mode fixed`,
  `--mode complete`; pinned by `tests/test_two_runner.py`).

Not yet proven:

- **Anything on real GitHub infrastructure.** The simulation does not
  model cache eviction (entries unused for 7 days, or evicted past the
  10 GB repo limit, silently reopen all keys), restore-key partial
  matching edge cases, concurrency-group queueing behavior at scale, or
  cross-branch cache visibility. Until the one-time real two-runner
  verification workflow passes, describe cross-run protection as
  "designed and simulation-tested", not as demonstrated.
- **Forks and other repositories.** Caches do not cross forks; a fork's
  runs start from an empty ledger.
- **Two different workflows (or a workflow that omits the group) sharing
  one ledger.** Serialization only covers runs that join the group.
- **High-stakes effects generally.** Even fully chained, the cache is
  best-effort storage. Keep the receiver's own effect receipt as the
  source of truth for reconciliation; the ledger is one layer.

## Inputs

| Input       | Required | Default | Description |
|-------------|----------|---------|-------------|
| `packet`    | yes      | —       | Path to the handoff packet JSON. |
| `registry`  | no       | —       | Path to the agent registry JSON (canonical ids + aliases). Without it, identity checks are skipped. |
| `ledger`    | no       | *(managed)* | Path to an idempotency ledger JSON for duplicate detection. Leave unset and the Action persists `.synthe/ledger.json` across runs via `actions/cache` (see above). Set it only if you manage that file's persistence yourself. |
| `workspace` | no       | `.`     | Root for artifact existence/hash checks. |
| `phase`     | no       | `claim` | `claim`: validate + record the key as `RESERVED`. `complete`: after the effect is real, flip the key to `COMPLETED` (same packet/registry/ledger inputs). |

## Output

| Output     | Description |
|------------|-------------|
| `decision` | `ACCEPT` or `REJECT` (claim phase); `COMPLETED` or `REJECT` (complete phase). |

## Local test

The entrypoints are plain bash scripts, so you can simulate CI locally:

```bash
# claim
HANDOFF_PACKET=../examples/valid.json \
HANDOFF_REGISTRY=../examples/registry.json \
HANDOFF_LEDGER=ledger.json \
HANDOFF_WORKSPACE=.. \
  bash checker/run_check.sh

# complete (after the "effect"), then replay the claim to see the
# terminal duplicate rejection
HANDOFF_PACKET=../examples/valid.json HANDOFF_LEDGER=ledger.json \
  bash checker/run_complete.sh
HANDOFF_PACKET=../examples/valid.json \
HANDOFF_REGISTRY=../examples/registry.json \
HANDOFF_LEDGER=ledger.json \
HANDOFF_WORKSPACE=.. \
  bash checker/run_check.sh   # -> REJECT duplicate
```

Two-runner simulation (local model of the cross-run behavior, including
the v0.2 failure mode):

```bash
python3 simulate_two_runners.py            # all modes; exit 0 = expectations hold
python3 simulate_two_runners.py --mode legacy   # reproduces the double-ACCEPT
```
