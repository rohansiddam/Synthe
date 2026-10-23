# Hear from Synthe only when it matters

`synthe-notify` lets you work with agents and stay out of the way. It reads the broker's receipts, and tells
you when Synthe stopped something, flagged something, or is waiting for you. It says what that was worth,
in a sentence or two. Pushes that went out under a task or lane you already signed stay quiet.

It runs in **your** account: not the agent's, and not the broker's. Apache-2.0, Python's standard library only.

```sh
synthe-notify test              # a sample notification, so you know it reaches you
synthe-notify install-agent     # run `watch` at login (setup offers this)
synthe-notify watch             # stays running; notifies as things happen
synthe-notify digest            # "This week: ..." in plain English (--days 30, --json)
```

## What it notifies, and what it stays quiet about

| Receipt | You hear about it? |
|---|---|
| A push is waiting for your approval, or a reviewer sent one to you | **Yes**: "The agent wants to make a push on 'agent/fix' (3 files). Run synthe-approve to see the diff." |
| A push was refused for crossing a line you drew (a CI workflow, a forbidden path, a branch it may not use, a history rewrite, an approval that was forged or not yours) | **Yes**: "Blocked: the agent tried to change a CI workflow (.github/workflows/ci.yml). That file controls what runs in CI, often with your secrets. Nothing was pushed." |
| Something broke or ran out: Synthe has no GitHub credentials, GitHub refused a push, a push ran but GitHub does not show it, a lane grant expired or is used up | **Yes**, as "needs a look" |
| A receipt kind or decision this version does not know | **Yes**, once per receipt, saying so. Never silent. |
| A push executed under a task or lane you had already signed | No. It is counted in the digest. |
| An approval you gave yourself, or a reviewer's accepted approval | No |
| A refusal the agent can simply retry (the branch moved, a malformed request, an expired approval, a transient GitHub error) | No. `--all-refusals` turns these on. They are counted in the digest. |
| The same push or approval repeated | No |

If more than three things happen in one look (an agent looping on a forbidden path), you get one summary
message. Each is still printed to the log.

The first time it runs it starts from now; it does not replay your history. `--from-start` does.

## What the messages say, and what they do not

Every refusal reason code Synthe emits has a short plain-English message in `src/synthe_notify.py`
(`MESSAGES`): what the agent tried, and why it matters. A test fails if a code is added to the broker, the
checker, the grants or `docs/COMMIT.md` without one. A code the notifier has never seen gets a generic
message that says so.

The messages say what Synthe **refused** and what that would otherwise have allowed. They do not say why the
agent tried it, and they do not claim the agent was attacked or acting badly: a stale branch and a rewritten
history are both just things that did not happen. Synthe does not stop prompt injection, does not judge
whether code is good, and receipts show which key acted, not which model. The digest says so too.

## It will not talk from a chain it cannot verify

Before it says anything, it checks the whole receipt chain against the broker's public key, with the same
code `synthe-verify` runs (`src/synthe_verify.py`): signatures, sequence, links. If the chain does not
verify (an edited receipt, a deleted one, another signer, a chain that is shorter than the one it saw last
time), it prints `NOT VERIFIED` and sends **one** alert with the first reason, and nothing from the chain's
contents. It says it again only after the chain has verified once more. `digest` refuses the same way.

Where the key comes from, in order: `--key`, `key` in the config file, `/Users/Shared/Synthe/broker.pub.json`
(a configured Mac), the dev registry in `~/.synthe/broker/registry.json`. A key it finds on its own is
ignored if anyone other than its owner can write to it.

Where the receipts come from: `--receipts FILE`, else the broker socket, the same read-only `receipts` call
the console uses (`--broker`, `SYNTHE_BROKER`, or the address `synthe-init` wrote to `~/.synthe/setup.json`).
Your account must be allowed to use the socket, as it is for `synthe-approve`.

## How it delivers

- **macOS**: a notification through `osascript`. The text is passed as arguments to a fixed script, never
  spliced into it. On first use macOS may ask whether "Script Editor" can send notifications; allow it in
  System Settings, Notifications.
- **Linux**: `notify-send`, when there is a desktop session. Text is escaped so a branch name cannot add markup.
- **Slack** (optional): an incoming-webhook URL in `~/.synthe/notify.json`, which must be readable only by you
  (`chmod 600`) or Slack stays off. The URL is never printed, logged or taken from the command line or
  environment, and must be an `https://` address on `slack.com`. Message text is escaped so it cannot ping a
  channel or make a link.
- **The terminal or a log**: with `--stdout`, or when nothing else worked.

Everything in a receipt that an agent can influence (branch names, paths, messages) is treated as hostile
text: control codes and terminal escapes are stripped and it is shortened before it goes anywhere.

```json
{
  "slack_webhook": "https://hooks.slack.com/services/...",
  "all_refusals": false,
  "key": "/Users/Shared/Synthe/broker.pub.json"
}
```

## Run it at login

```sh
synthe-notify install-agent      # starts now and at every login, in this account
synthe-notify uninstall-agent    # stops it and removes the service
```

Setup offers this as its last question ("Turn notifications on? [Y/n]", after "How hands-off?"), in your
own terminal and your own account. Without a person at the terminal it installs nothing.

- **macOS**: a LaunchAgent, `~/Library/LaunchAgents/com.synthe.notify.plist`, started with
  `launchctl bootstrap gui/<your uid>`. It runs `synthe-notify watch --stdout`; the log is `~/.synthe/notify.log`.
- **Linux**: a systemd user service, `~/.config/systemd/user/synthe-notify.service`, enabled with
  `systemctl --user enable --now`. Log: `journalctl --user -u synthe-notify.service`. For it to run while
  you are logged out, `loginctl enable-linger` your account (your choice; setup does not do it).

It refuses to install as root, as the broker's account (`_synthe`, `synthe`), or in the agent's account
(where `~/.synthe/setup.json` says `"role": "agent"`): an agent that controls the notifier decides what you
hear. Running it again replaces the service. The command it runs is the `synthe-notify` on your `PATH`
(resolved to its real path), else this checkout's `src/synthe_notify.py` with the same Python.

## Limits

- **Silence is not proof.** It reports what the broker recorded. If an agent never proposes a push, or
  works outside the broker, there is no receipt and nothing to tell you. What stops an agent pushing around
  Synthe is that it holds no credential (see `THREAT_MODEL.md`), not this tool.
- **It polls** (every 15 seconds by default), so a notification can lag by that much.
- **Over the socket it sees the newest 1000 receipts.** A longer chain is checked in a window tied back to the
  last receipt this tool verified (kept with its digest in `~/.synthe/notify-state.json`, mode 0600). On a
  first run with a longer chain, or with that file gone, it cannot verify the window and says so; give it
  `--receipts FILE` with the whole chain. `digest` only covers what it could read.
- **That checkpoint lives in your account.** It catches a chain that was cut short or replaced since the last
  look. It is not an independent anchor (see `docs/VERIFY.md`).
- **"Without asking you"** means the push ran under a task or lane you had already signed, not that nobody
  was ever responsible.
- **No warning that a lane is nearly used up.** Receipts record which use of a grant a push was, not the
  grant's limit, so it cannot tell. You hear when the grant is exhausted or expired.
- **A desktop notification can be missed or turned off.** The receipts are the record; `digest` reads them.
