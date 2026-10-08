<!-- SPDX-License-Identifier: Apache-2.0 -->
# `git push` becomes a proposal

Any agent already knows `git push`. With Synthe, the agent's clone has Synthe itself as `origin`, so a
plain `git push` doesn't go to GitHub. It goes to the broker as a proposal. A person approves it, then
the broker pushes exactly that commit and signs a receipt. It works the same for Claude Code, Codex,
Cursor or a person at a terminal. Nothing new to learn, and no plugin needed.

```text
$ git push
synthe: agent/greet at 4f1c2a9e07b3 is proposed for approval, not pushed yet (task ..., receipt #12).
synthe: A person reviews the diff and approves it with synthe-approve; then Synthe pushes exactly this
synthe: commit and signs a receipt. Don't push it another way, and don't approve it yourself.
To synthe::unix:///var/db/synthe-run/broker.sock
 * [new branch]      agent/greet -> agent/greet
```

The person runs `synthe-approve`, reads the diff and approves. Then the push lands on GitHub.

## How it works

- `git-remote-synthe` is a git remote helper, a small program git runs for `synthe::` URLs. It holds
  no credential and can do nothing the agent couldn't do with `synthe-client`. The broker still checks
  and receipts every proposal.
- **Which task:** the newest unexpired signed task in the inbox that plans a push of this branch
  (`synthe-task new "..." --branch agent/greet` leaves it there). To name one, set `SYNTHE_TASK` or
  `git config synthe.task PATH`. The inbox is `/Users/Shared/Synthe/inbox`, or `SYNTHE_INBOX` /
  `git config synthe.inbox`.
- **The claim:** the helper claims the task once and keeps the claim token in `.git/synthe/claims/`
  (mode 600). If the task was already claimed elsewhere, through the MCP tools for example, it says so:
  finish it there.
- **Honest output:** only the clone's own branch is tracked, so git never shows a proposed branch as if
  it were on GitHub. A refusal exits non-zero with the reason codes, and says nothing was pushed.
- **Reading:** `git pull` and `git fetch` on the clone's branch read through the broker too. The agent's
  account still has no GitHub credential, even to read.
- **Pinned broker:** the clone records the broker's uid. The helper refuses a different process on the
  socket before sending anything.
- **Not proposals:** deleting a branch, and pushing to anything but a branch. A force push goes to the
  broker like any other proposal, and the broker's checks apply unchanged (it refuses history
  rewrites).

## Setting it up

`finish-setup.sh` does it: it puts `git-remote-synthe` on the agent account's PATH, and
`synthe-client clone` gives the clone a Synthe `origin`. On an install from before this, in the agent's
account:

```bash
ln -sf /Library/Synthe/venv/bin/git-remote-synthe ~/.local/bin/git-remote-synthe
```
```bash
cd ~/repo && git remote add -t main origin synthe::unix:///var/db/synthe-run/broker.sock && git config push.default current
```

## On OpenClaw

The OpenClaw plugin still blocks the text `git push` and steers the agent to `synthe_propose_effect`,
which is the richer path there. The plugin is a seatbelt; either way, only the broker can push.
