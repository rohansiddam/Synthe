# First approved OpenClaw push with Synthe (macOS)

At the end, OpenClaw proposes a push, you read the diff and approve it with your passphrase, and only
then does Synthe push it. **ENFORCED** means the agent can't push on its own. It runs in its own Mac
account with no GitHub login, and a hidden `_synthe` user holds the GitHub token. Synthe pushes only
after your signed approval.

You can hand steps 1 and 2 to your coding agent (Claude Code, Codex, OpenClaw): point it at
`skills/synthe-setup/SKILL.md`. Step 3 is yours, because it's where the secrets are typed. The steps
were verified on 2026-10-07 (`docs/OPENCLAW_RESULTS.md`), but they haven't been timed with a new user
yet.

## What you need

- macOS with Homebrew.
- The GitHub repo the agent should work on, private or public. Agent work lands only on `agent/*`
  branches, and only after you approve it.
- A fine-grained GitHub token for that one repo, with **Contents: Read and write**. You paste it
  once, hidden, in step 3.

## 1. Install

Run this from this Synthe folder. It builds Synthe its own environment, outside Documents and Desktop
(iCloud hides dot-folders there, and Python 3.14 then skips an editable install's path file), with a
Python that really works: Homebrew's newest Python can be installed but broken on an older macOS.

```bash
brew install python node git && PY=$(bash deploy/macos/find-python.sh) && "$PY" -m venv ~/synthe-venv && ~/synthe-venv/bin/pip install -q .
```

If it says no working Python was found, do what it prints (usually `brew install python@3.13`), then
run the same line again.

## 2. Prepare

Run this from this Synthe folder, with your repo URL and the paths the agent may change. It checks
the Mac, needs no secrets, and writes the one command for step 3.

```bash
~/synthe-venv/bin/synthe-init prepare --repo-url https://github.com/YOU/REPO.git --allowed-paths 'src/**'
```

## 3. Finish (you, about 2 minutes)

```bash
bash ~/.synthe/finish-setup.sh
```

It asks you for three things:
- a new **approval passphrase**, twice;
- your **GitHub token**, hidden as you paste it;
- your **Mac password**, once.

Then it does the rest:
- creates the agent's Mac account (`openclaw`) and installs the broker as `_synthe`;
- installs OpenClaw in the agent's account and wires in the Synthe plugin, skill and gateway;
- clones the repo there through the broker (the agent's account needs no GitHub
  access, even to read) and runs the doctor, which should say **ENFORCED**.

## 4. Give OpenClaw its model, and start it through the gateway

The Synthe plugin acts only through OpenClaw's gateway: `openclaw tui --local` and `openclaw chat`
skip it, which leaves only the wall.

```bash
sudo -iu openclaw
```
```bash
export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH" && openclaw onboard
```

During onboarding, give it your model and API key, and say no to the rest:
- **Plugins:** it scans the Mac's apps and may pre-tick some to install. Choose "Skip for now".
- **At the end it opens a chat for you.** That chat is embedded (`local embedded` in its title bar),
  so the Synthe plugin doesn't run in it. Quit it (Ctrl+C) and continue below.

```bash
openclaw gateway run
```

In a second window, also `sudo -iu openclaw`:

```bash
export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH" && cd ~/repo && openclaw tui
```

Check the title bar: it should say `ws://127.0.0.1:...` (the gateway), not `local embedded`.
If you set up a team of agents during onboarding, add `--session agent:<name>:main`.

## 5. Give OpenClaw a task (your account)

```bash
~/synthe-venv/bin/synthe-task new "Add a greeting and test it" --branch agent/first-push
```

Enter your passphrase. It prints what to tell OpenClaw. Paste that into OpenClaw: it validates the
task, works on the branch and proposes the push through Synthe. It can't push itself.

## 6. Read the diff and approve (your account)

When OpenClaw says the push is staged:

```bash
SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock ~/synthe-venv/bin/synthe-approve
```

The diff shown is the broker's own copy, not the agent's description. Approve with `a` and your
passphrase. The broker pushes, and you get a signed receipt.

## Check it yourself

`docs/REDTEAM.md` attacks your install from the agent's account (33 checks, no model) and verifies
the receipts with the broker's published key.


## What this does not claim

- **The plugin is a seatbelt, not the wall.** It works only through the gateway, and obfuscated
  commands or another git library can get past its text matching. The wall is credential custody:
  the agent's account has no GitHub token, `gh` login or SSH key that can push, and `doctor` checks
  that.
- **Synthe mediates git effects.** It doesn't stop prompt injection or judge whether approved code
  is correct.
