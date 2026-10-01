# Handoff Contract Check — GitHub Action

A composite GitHub Action that runs the **Handoff Contract v0.1** validator on
an agent-to-agent handoff packet and fails the CI step when the handoff is
rejected. Use it to gate pull requests: an agent that wants another agent (or
a human) to pick up its work must attach a valid handoff packet, or the PR
cannot merge.

The checker is a single stdlib-only Python file (vendored under `checker/`),
so the action needs **no network access and no dependencies** — just
`python3`, which is preinstalled on GitHub-hosted runners.

## What it checks

Given a handoff packet (see `../HANDOFF_CONTRACT_V0.1.md` for the format),
the validator confirms, before the receiver starts work:

- all required fields are present and the schema version is supported;
- the sender and receiver are canonical agent ids in the registry (no
  aliases, no unknown agents);
- the handoff has not expired;
- every planned action uses an allowed tool, is not forbidden by scope, has
  any required approval on file (and unexpired), and fits the budget;
- every referenced artifact exists in the workspace and matches its recorded
  SHA-256 hash (no stale files);
- all required evidence is attached, and evidence that must be verbatim
  (quotes, code, legal text) is flagged as verbatim, not paraphrased;
- duplicate protection via the idempotency ledger: the handoff's key has
  not already been claimed or executed (see "Duplicate protection & the
  ledger" below — the Action persists the ledger across runs for you).

Exit code `0` = ACCEPT. Any rejection exits `1` and prints the failure state
(`stale`, `incomplete`, `blocked`, `invalid`, `duplicate`, `unknown`, ...)
with a human-readable reason in the step log and as a workflow error
annotation.

## Duplicate protection & the ledger (v0.2)

Duplicate detection needs memory: which idempotency keys have already been
claimed. That memory lives in a JSON **ledger**. This matters because
GitHub-hosted runners are **ephemeral**: each job runs on a fresh machine
and the workspace is discarded afterwards. A ledger left as a plain file in
the repo workspace would silently vanish between runs, and with it all
duplicate protection.

So when you don't pass the `ledger` input, the Action manages one at
`.synthe/ledger.json` for you:

1. `actions/cache/restore` restores it before the check (key
   `synthe-ledger-<owner>/<repo>`, prefix fallback to the newest entry).
2. The checker validates against it and records claims in it.
3. `actions/cache/save` writes it back **even if the check failed**
   (`if: always()`), under a per-run key.

Claims are a two-step state machine, not a single "seen it" flag:

- **ACCEPT** records the key as `RESERVED` (atomically, under a file lock,
  so two simultaneous presentations can't both pass). This is only a claim:
  the effect has not happened yet.
- After the receiving agent actually performs the work, mark the claim
  complete:

  ```bash
  python3 checker/handoff_check.py handoff.json \
    --ledger .synthe/ledger.json --complete
  ```

- Re-presenting a `COMPLETED` key is rejected as `duplicate`. Re-presenting
  a `RESERVED` key within 24 hours (`--reserve-ttl-hours`) is also
  `duplicate` ("claimed by handoff X; reconcile before redispatch"). A
  `RESERVED` claim older than the TTL flips to the failure state `unknown`:
  the receiver may have crashed before *or after* the effect, so reconcile
  against the receiver's effect receipt before redispatching.

If you pass your own `ledger` path, the cache steps are skipped and
persisting that file between runs is up to you (e.g. commit it back, or use
your own cache step).

Caveat: the GitHub cache is per-repository and best-effort (entries can be
evicted, and caches don't cross forks). For high-stakes effects, treat the
ledger as one layer and keep the receiver's own effect receipt as the
source of truth for reconciliation.

## Usage

Copy this folder into your repo (or reference it from a shared repo) and add
a workflow like the one below. The flow: an agent opens a PR and commits a
`handoff.json` packet describing the work it is handing off; CI validates the
packet; only a green check lets the PR merge and the receiving agent start.

```yaml
# .github/workflows/handoff-check.yml
name: Handoff Check

on:
  pull_request:
    paths:
      - 'handoff.json'        # only run when a handoff packet changes

permissions:
  contents: read

jobs:
  handoff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # If you copied this folder into your repo at .github/actions/handoff-check:
      - name: Validate handoff packet
        id: handoff
        uses: ./.github/actions/handoff-check
        with:
          packet: handoff.json
          registry: agents/registry.json   # canonical agent ids + aliases
          workspace: .                     # repo root, for artifact hash checks

      - name: Report
        if: always()
        run: echo "Handoff decision: ${{ steps.handoff.outputs.decision }}"
```

Then make the `handoff` check a **required status check** on your protected
branch (Settings → Branches → Branch protection). That is what turns a failed
validation into a blocked merge.

### Referencing from another repository

If this action lives in its own repo (say `your-org/handoff-contract`), use
it directly without copying:

```yaml
      - uses: your-org/handoff-contract/github-action@main
        with:
          packet: handoff.json
          registry: agents/registry.json
```

Adjust the path to wherever `action.yml` sits in that repo.

## Inputs

| Input       | Required | Default | Description |
|-------------|----------|---------|-------------|
| `packet`    | yes      | —       | Path to the handoff packet JSON. |
| `registry`  | no       | —       | Path to the agent registry JSON (canonical ids + aliases). Without it, identity checks are skipped. |
| `ledger`    | no       | *(managed)* | Path to an idempotency ledger JSON for duplicate detection. Leave unset and the Action persists `.synthe/ledger.json` across runs via `actions/cache` (see "Duplicate protection & the ledger"). Set it only if you manage that file's persistence yourself. |
| `workspace` | no       | `.`     | Root for artifact existence/hash checks. |

## Output

| Output     | Description |
|------------|-------------|
| `decision` | `ACCEPT` or `REJECT`. |

## Local test

The entrypoint is a plain bash script, so you can simulate CI locally:

```bash
HANDOFF_PACKET=../examples/valid.json \
HANDOFF_REGISTRY=../examples/registry.json \
HANDOFF_WORKSPACE=.. \
  bash checker/run_check.sh
```

See `SIMULATION.md` for recorded local runs (valid packet accepted; two
broken packets rejected with reasons).
