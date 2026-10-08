# ClawHub listing draft — do not publish

This is review copy and release metadata, not a claim that the integration is published or generally
available. Confirm ClawHub's current submission schema, asset requirements, compatibility rules, and
licensing fields before converting it to a live listing.

## Listing metadata

| Field | Draft value |
|---|---|
| Name | Synthe Commit Barrier |
| Slug | `synthe-commit-barrier` |
| Publisher | Synthe |
| Category | Developer tools |
| Package | `@synthe/openclaw-synthe-barrier` |
| Listing version | `0.1.0` |
| OpenClaw compatibility | OpenClaw and plugin API `2026.9.8` or newer |
| Components | `synthe-barrier` plugin + `synthe` skill |
| License | Apache-2.0 (plugin, skill, client, MCP server); the broker is FSL-1.1-ALv2. See `LICENSING.md` |
| Support URL | TODO: choose the public support or issue URL |
| Privacy URL | TODO: publish a privacy/data-handling statement |
| Source/release URL | TODO: choose the public release location |

**Short summary (100 characters)**

> Blocks direct code pushes and routes them through a human-approved, receipt-producing Synthe broker.

## Description

Synthe gives OpenClaw a controlled path for shipping code. The agent validates a signed task, commits
locally, and proposes a push. A separately isolated Synthe broker checks the task, branch, changed
paths, pinned commit, and human signature before it uses the only push credential. Every allow or
deny produces a signed, hash-chained receipt.

The OpenClaw plugin blocks common direct-push and GitHub-publish tool calls and adds a compact status
line for waiting approvals and the latest receipt. The companion skill teaches OpenClaw to validate,
claim, propose, and report through Synthe.

## Suggested feature bullets

- Human approval is bound to the exact commit and broker-rendered diff.
- The agent does not need a GitHub token or push-capable SSH key.
- Branch and changed-path allowlists are rechecked at execution time.
- Proposals are idempotent and broker actions produce signed, hash-chained receipts.
- The agent's account needs no GitHub access at all, not even to read: it clones and updates
  through the broker, so private repos work with no extra token.
- One command for the human: `synthe-init prepare` (any coding agent can run it) writes
  `finish-setup.sh`, which asks for the passphrase, the token (hidden) and one Mac password.
- `synthe-init doctor` reports ADVISORY, GUARDED or ENFORCED from observed controls.

## Evidence (all on 2026-10-07, macOS, real GitHub; `docs/OPENCLAW_RESULTS.md`)

- ENFORCED: all 8 doctor checks pass. The broker runs as `_synthe`; the agent runs in its own account
  with no credentials.
- A real OpenClaw agent (Claude Opus) followed the skill on its own: validated, committed, proposed,
  and stopped for approval. It never tried a direct push.
- Live red team, from the agent's account: 33 of 33 attacks refused or contained. Each refusal has
  a signed receipt, and the receipt chain verifies with the broker's published key. Nothing reached
  GitHub except the one approved change.

## Capabilities and data handling

The plugin reads tool names and arguments before execution to block common push/publish paths. It
queries the configured Synthe broker for read-only approval and receipt status, and adds that status
to OpenClaw context. The MCP integration sends signed handoffs, claim data, proposal parameters, and
a git bundle to the configured broker. It does not need the human approver's private key or the
broker's GitHub credential.

Configuration:

- `brokerSocket`: Unix-socket or loopback TCP broker address;
- `blockDirectPush`: block recognized direct push/publish calls (default `true`);
- `statusLine`: add broker status to each turn (default `true`).

## Honest security statement

The plugin's command matching is a seatbelt, not a complete sandbox, and it acts only through the
OpenClaw gateway: in embedded mode (`openclaw tui --local`, `openclaw chat`) OpenClaw doesn't run it.
Live tests confirmed both: in the gateway it blocked a real model's direct pushes; in embedded mode
the pushes ran and were stopped only by the wall. Obfuscated commands, scripts,
or other git libraries may bypass it. The security boundary is credential isolation: OpenClaw must
not hold a GitHub token, authenticated `gh` session, or push-capable SSH key; an isolated broker must
hold the only credential. `synthe-init doctor` checks the resulting enforcement level. Synthe does
not prevent prompt injection, inspect code quality, or make compliance/certification claims.

## Installation copy

Preferred installation is the two-step setup, which installs the broker, creates the agent's own
account, and wires OpenClaw (plugin, skill, MCP server, gateway) there:

```bash
synthe-init prepare --repo-url https://github.com/YOU/REPO.git --allowed-paths 'src/**'
bash ~/.synthe/finish-setup.sh
```

See `QUICKSTART_OPENCLAW.md` for the complete enforced setup and first approved push.

## Assets and submission checklist

- [ ] Confirm listing schema and compatibility syntax against current ClawHub documentation.
- [x] License terms decided by both founders (2026-10-07): see `LICENSING.md`. Counsel review pending.
- [ ] Confirm publisher name, package/release URL, support URL, and privacy URL.
- [ ] Produce a square icon and any required screenshots without implying certification.
- [ ] Run Python, OpenClaw gateway, wiring, and Node plugin tests from the release commit.
- [x] A real ENFORCED macOS + GitHub run, a real-model run and a live red team (2026-10-07).
- [ ] A clean-machine run (Rishab) and a stranger's timed run.
- [ ] Review all claims against `docs/OPENCLAW_RESULTS.md` and the signed release commit.
- [ ] Remove this “do not publish” marker only after founder approval.
