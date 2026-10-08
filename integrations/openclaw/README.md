# Synthe for OpenClaw

Start with [`../../QUICKSTART_OPENCLAW.md`](../../QUICKSTART_OPENCLAW.md). Release owners can review
the unpublished ClawHub copy in [`CLAWHUB_LISTING_DRAFT.md`](CLAWHUB_LISTING_DRAFT.md).

Two pieces, installed together by `synthe-init` (or by hand):

| Piece | What it does | Install by hand |
|---|---|---|
| `plugin/` (`synthe-barrier`) | **Blocks** tool calls that would push or publish around Synthe: `git push` in its common spellings, `gh pr merge`, `gh repo sync`, `gh release`, GitHub API writes, OpenClaw's `github_publish`. Each turn it **adds one line** of Synthe status: what waits for the human's approval, and the last receipt. | `openclaw plugins install -l ./plugin --accept-capabilities`, then set `plugins.entries.synthe-barrier.config.brokerSocket` |
| `skill/synthe` | Tells the agent how to ship through Synthe: validate, claim, propose, ask the human to run `synthe-approve`, and report the receipt. | `openclaw skills install ./skill/synthe` |

## Honest limits

- The plugin is a seatbelt in the request path. It catches the commands it can read as pushes. It
  can't catch obfuscated text, a script that pushes, or a git library in another language; those
  are pinned as known gaps in `plugin/policy.test.ts`.
- **The wall is credentials.** The agent must hold no GitHub token and no SSH key with push rights,
  and the broker must hold the only one. `synthe-init` checks this and reports the result as an
  enforcement level: Advisory, Guarded or Enforced.
- Synthe does not stop prompt injection or memory poisoning (MemGhost was measured at 87.5% on
  OpenClaw). It stops the *effect*: nothing reaches the remote without a human's signed approval.

## Tests

```bash
cd plugin && node --test policy.test.ts
```

That runs the block and allow matrix with no OpenClaw needed (Node 24+).

```bash
python -m pytest integrations/openclaw/tests
```

That runs the real OpenClaw gateway in a throwaway `OPENCLAW_HOME`: pushes return
`403 tool_call_blocked` and `git status` passes. It needs the openclaw CLI and takes about 30 seconds.
