# Synthe

**The commit barrier for AI agents.** Agents propose. You approve. Synthe commits, exactly once, and
writes a signed receipt anyone can verify.

An AI agent with a GitHub token can push whatever it decides to. With Synthe, the agent holds no
credential at all. It commits on its own branch and *proposes* the push. The Synthe broker runs as its
own user and holds the only GitHub token. It shows you its own copy of the diff, waits for your
passphrase-signed approval, and pushes exactly that commit. It records every decision, allowed or
refused, in a hash-chained receipt log.

## What's proven

Verified on 2026-10-07 on macOS, against real GitHub. The evidence is in
[`docs/OPENCLAW_RESULTS.md`](docs/OPENCLAW_RESULTS.md).

- **ENFORCED:** the broker runs as `_synthe` and the agent in its own account with no credentials.
  All 8 doctor checks pass.
- **A real OpenClaw agent** (Claude Opus) followed the rules on its own: it proposed, then stopped for
  approval.
- **A live red team of 33 attacks** from the agent's account was refused or contained
  ([`docs/REDTEAM.md`](docs/REDTEAM.md)):
  - forged, tampered and replayed tasks;
  - pushes outside the allowed files or branches, or to `main`;
  - history rewrites;
  - self-approvals;
  - swapping the commit while you read the diff.

  Every refusal left a signed receipt, and the chain verifies with the broker's published key.

## Get started (macOS, OpenClaw)

[`QUICKSTART_OPENCLAW.md`](QUICKSTART_OPENCLAW.md). Your coding agent can do the preparation
(`skills/synthe-setup/SKILL.md`). You run one command, which asks for a passphrase, your GitHub token
(hidden) and your Mac password.

## What's here

| Part | Where | License |
|---|---|---|
| The handoff contract: spec, schema, conformance vectors | `SPEC.md`, `schema/`, `examples/` | Apache-2.0 |
| Checker, signing, client, MCP server, setup and approval tools | `src/` (except the broker files) | Apache-2.0 |
| The OpenClaw plugin and skill; the setup skill | `integrations/openclaw/`, `skills/` | Apache-2.0 |
| The broker and its installers | `src/synthe_commit.py`, `synthe_broker.py`, `synthe_plan.py`, `deploy/` | FSL-1.1-ALv2 |

See [`LICENSING.md`](LICENSING.md). "Synthe" and the logo are trademarks of Synthe.

## What Synthe doesn't claim

- **The OpenClaw plugin is a seatbelt.** The wall is that the agent holds no credential.
- **Synthe mediates git effects.** It doesn't stop prompt injection, and it doesn't judge whether
  approved code is correct.
- **What each part does and doesn't protect** is in [`THREAT_MODEL.md`](THREAT_MODEL.md).
