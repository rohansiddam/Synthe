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
- optionally, with a ledger: the handoff's idempotency key has not already
  been executed (no duplicate work).

Exit code `0` = ACCEPT. Any rejection exits `1` and prints the failure state
(`stale`, `incomplete`, `blocked`, `invalid`, `duplicate`, ...) with a
human-readable reason in the step log and as a workflow error annotation.

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
| `ledger`    | no       | —       | Path to an idempotency ledger JSON for duplicate detection. Without it, duplicate checks are skipped. |
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
