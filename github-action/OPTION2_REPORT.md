# Option 2 report — GitHub Action cross-run hardening

Date: 2026-09-30 (MDT). Scope: implement and simulation-test the fix in
the publish copy (`publish/handoff-contract/`). **Nothing was pushed to
the public repo** (github.com/rohansiddam/Synthe); publication is a
separate step after Rohan's review. Checker CLI (`src/handoff_check.py`)
untouched; its verdict states unchanged.

## What failed (independent finding, reproduced)

An independent reviewer (impartshadow, crewAIInc/crewAI#5802, re-run of
v0.2 head `4abf152`) confirmed the local checker fixes (RESERVED /
COMPLETED / `unknown` state machine, exactly-one-winner under concurrent
processes on one filesystem, 21/21 shipped tests) and then falsified the
GitHub Action's cross-run claim with two concrete defects:

1. **Double ACCEPT across runners.** Two hosted runners starting from
   the same empty `actions/cache` state both ACCEPTed the same packet.
   Root cause: cache entries are immutable snapshots, not an atomic
   compare-and-set; two simultaneous runs restore the *same* prior
   snapshot, each sees the key unclaimed, each passes, and each saves
   its own run-keyed snapshot. The checker's `flock` only serializes
   processes sharing one filesystem, which two runners never do.
2. **COMPLETED never persisted by the Action.** The composite Action's
   cache save runs when the Action returns; the receiver effect and the
   `--complete` flip necessarily happen *after* that, so the flip only
   mutated a throwaway workspace file. The saved ledger therefore never
   advanced past RESERVED under Action-managed persistence.

## Reproduction (local model)

`publish/handoff-contract/github-action/simulate_two_runners.py` models
exactly the two properties the bug depends on — isolated runner
workspaces (no shared filesystem, so no shared lock) and ledger transfer
only through an explicit cache hand-off — and runs the real, unmodified
checker CLI in each. `--mode legacy` reproduces the finding: both
runners ACCEPT, both ledgers show RESERVED. Recorded output is in
`github-action/SIMULATION.md`; the mode is pinned as test S1 in
`tests/test_two_runner.py` so the failure stays a permanent witness.

Honest label: this is a simulation of runner semantics, not a GitHub
run. It does not model cache eviction, cache partial-restore matching,
concurrency-group queueing at scale, cross-branch cache visibility, or
clock skew.

## The design (Option 2)

Three coordinated changes, all in `publish/handoff-contract/github-action/`:

1. **Serialized runs (caller-side, documented).** The caller workflow
   declares a workflow-level `concurrency` group
   (`group: synthe-handoff-ledger`, `cancel-in-progress: false`) so
   GitHub executes runs sharing a ledger strictly one at a time, in
   order. A composite action cannot declare a concurrency group, so the
   README carries the required workflow shape verbatim. This converts
   the cache race into an ordered chain.
2. **Restore-latest cache chaining.** Restore already used prefix
   fallback (`restore-keys`) so a run restores the newest saved ledger;
   the save key is now
   `synthe-ledger-<repo>-<run_id>-<run_attempt>` (immutable per run,
   re-runs included). With (1) ordering the runs, each run restores
   exactly its predecessor's saved state. Ledger save still runs
   `if: always()` so rejected claim attempts are persisted too.
3. **Claim / complete phase split.** New `phase` input on the Action
   (default `claim`). `phase: claim` runs the existing
   `checker/run_check.sh` (validate + record RESERVED) and saves the
   ledger. After the caller's effect step, a second invocation with
   `phase: complete` restores the ledger, runs the new
   `checker/run_complete.sh` (checker `--complete`: RESERVED →
   COMPLETED; idempotent no-op if already COMPLETED), and saves again.
   Each phase therefore wraps its own state transition in
   restore/mutate/save, which is precisely what v0.2 lacked. Output
   `decision` now also emits `COMPLETED` in the complete phase.

Files changed (publish copy only):

- `github-action/action.yml` — `phase` input, phase dispatch,
  per-run-attempt save key, comments stating the ordering requirement.
- `github-action/checker/run_complete.sh` — new completion entrypoint.
- `github-action/simulate_two_runners.py` — new two-runner harness.
- `github-action/README.md` — rewritten: two-phase flow, required
  caller workflow shape, proven/not-proven section (see below).
- `github-action/SIMULATION.md` — recorded two-runner transcripts.
- `tests/test_two_runner.py` — new S1/S2/S3 simulation tests.

Explicitly NOT changed: `src/handoff_check.py`, the vendored
`github-action/checker/handoff_check.py` (byte-identical, md5 verified),
the schema, root `README.md`/`AGENTS.md` (public claim untouched until
approval), and no reply to the reviewer (deferred by Rohan).

## What the simulation proves, and does not

Proves (at model level, with the real checker binary):

- S1: the v0.2 shape double-ACCEPTs when two runners restore the same
  snapshot with no ordering — the reported bug, reproduced.
- S2: with serialization + restore-latest chaining, the second runner
  restoring the first's post-claim ledger is REJECTED `duplicate`
  (`idempotency_key_reserved`). Exactly one ACCEPT.
- S3: claim → complete-step save → replay yields REJECT `duplicate`
  (`duplicate_idempotency_key`) against the persisted COMPLETED entry —
  the completion-persistence gap is closed in the model.
- No regressions: full suite **29/29** with
  `~/workspace/land-dev-prototype/venv/bin/python -m pytest tests/ -q`
  (14 validator + 7 conformance + 5 invariants + 3 new simulation).

Does not prove:

- Real GitHub behavior of the same design: cache eviction (unused
  entries expire after 7 days; >10 GB per repo evicts LRU) can silently
  drop the ledger and reopen every key; restore-key prefix matching can
  pick an unexpected snapshot if other caches share the prefix space;
  concurrency-group pending-run supersession and throughput under real
  load; cross-branch cache visibility rules. The simulation orders runs
  by construction; GitHub orders them by queue discipline I asserted
  from docs but have not observed for this workflow.
- Any behavior of self-hosted or persistent runners (different, easier
  failure surface; untested).

## Exact remaining step to verify on real GitHub

One disposable verification run, after Rohan approves publishing a
branch/workflow (nothing here requires touching public `main`):

1. In a scratch repo (or a non-`main` ref), add
   `.github/workflows/handoff-verify.yml` using exactly the caller shape
   in the README (concurrency group `synthe-handoff-ledger`), with the
   claim step pointed at `examples/valid.json`.
2. Trigger **two** `workflow_dispatch` runs as simultaneously as the UI
   allows. Expected: first run's claim step ACCEPTs; second run queues
   behind the concurrency group, restores the first run's saved ledger,
   and its claim step fails `REJECT duplicate
   (idempotency_key_reserved)`. PASS = exactly one ACCEPT in the run
   logs and one RESERVED entry across both runs' ledger snapshots.
3. Re-run with an effect step + `phase: complete`, then dispatch a
   third run replaying the same packet. Expected: REJECT `duplicate
   (duplicate_idempotency_key)`; ledger snapshot shows COMPLETED.
4. If (2)-(3) pass, the same workflow can graduate into a CI conformance
   workflow (schedule/manual) and the public README claim can be widened
   from simulation language. If any step differs (e.g. second run
   doesn't restore the first's cache), fall back to the honest narrowed
   claim (per-job guard + caller-managed durable storage) and treat the
   backend ledger variant (shared conditional-write store) as the next
   design iteration.

## Residual races (precise)

- **Different workflows sharing one ledger.** The concurrency group is
  per-workflow-file declaration; two workflow files that both use the
  Action but declare *different* group strings (or one omits it) do not
  serialize against each other and can still double-ACCEPT. Mitigation
  is documentation (same group name everywhere the repo ledger is used);
  GitHub offers no repo-global lock to enforce it.
- **What the group covers.** GitHub concurrency serializes runs of the
  same group *within a repository*, keyed by the group string;
  `cancel-in-progress: false` queues rather than cancels (a queued run
  can still be superseded if a newer run arrives while one is pending —
  documented GitHub behavior for pending runs — but a superseded
  *pending* claimant never executed, so it cannot double-ACCEPT; the
  surviving run still restores the latest saved ledger). It does not
  cover runs in forks (separate cache namespace anyway) or across
  repositories.
- **Eviction window.** If the ledger cache entry is evicted between a
  claim and a replay (>7 days idle or repo cache pressure), the replay
  sees an empty ledger and ACCEPTs. This is inherent to
  actions/cache as the store; the README states it and keeps the
  receiver's effect receipt as source of truth. Closing it requires a
  durable conditional-write backend, which Rohan's reviewer named as
  alternative (2); deliberately not built here — Option 2 as scoped is
  the GitHub-native serialized-cache design.
- **Claim without completion.** If the effect step fails and the
  complete step never runs, the key sits RESERVED until the 24h TTL,
  then replays yield `unknown` (reconcile before redispatch) — by
  design, and documented in the caller shape (do not complete an effect
  that didn't happen).
