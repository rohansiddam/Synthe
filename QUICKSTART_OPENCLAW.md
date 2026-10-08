# First approved OpenClaw push with Synthe (macOS)

Using a different agent, Linux, or no AI? See [ANY_AGENT.md](docs/ANY_AGENT.md).
Audit exported receipts without the broker with [synthe-verify](docs/VERIFY.md).

At the end, OpenClaw proposes a push, you read the diff and approve it with Touch ID (or your
passphrase fallback), and only then does Synthe push it. **ENFORCED** means the agent can't push on
its own. It runs in its own Mac account with no GitHub login, and a hidden `_synthe` user holds the
GitHub token. Synthe pushes only after your signed approval.

You can hand steps 1 and 2 to your coding agent (Claude Code, Codex, OpenClaw): point it at
`skills/synthe-setup/SKILL.md`. Step 3 is yours, because it's where the secrets are typed. The steps
were verified on 2026-10-07 (`docs/OPENCLAW_RESULTS.md`), but they haven't been timed with a new user yet.

Using Claude Code, Cursor, Cline, or no AI at all? See [ANY_AGENT.md](docs/ANY_AGENT.md).

## What you need

- macOS with Homebrew.
- The GitHub repo the agent should work on, private or public. Agent work lands only on `agent/*`
  branches, and only after you approve it.
- A fine-grained GitHub token for that one repo, with **Contents: Read and write**. You paste it
  once, hidden, in step 3.

## Fast Track: 1-Line Setup

Run this one command from your terminal:

```bash
curl -sSL https://synthe.live/install | bash
```

It checks Homebrew, installs Python and Node, sets up the virtual environment, prepares your repository, and launches setup.

---

## Or Manual Step-by-Step Install

### 1. Install

Run this from this Synthe folder. It builds Synthe its own environment, outside Documents and Desktop
(iCloud hides dot-folders there, and Python 3.14 then skips an editable install's path file), with a
Python that really works: Homebrew's newest Python can be installed but broken on an older macOS.

```bash
brew install python node git && PY=$(bash deploy/macos/find-python.sh) && "$PY" -m venv ~/synthe-venv && ~/synthe-venv/bin/pip install -q .
```

If it says no working Python was found, do what it prints (usually `brew install python@3.13`), then
run the same line again.

### 2. Prepare

Run this from this Synthe folder, with your repo URL and the paths the agent may change. It checks
the Mac, needs no secrets, and writes the one command for step 3.

```bash
~/synthe-venv/bin/synthe-init prepare --repo-url https://github.com/YOU/REPO.git --allowed-paths 'src/**'
```

### 3. Finish (you, about 2 minutes)

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

### Optional: enroll Touch ID

After setup, enroll a Secure Enclave approval key from this Synthe folder, then install the updated
public registry and code into the broker:

```bash
~/synthe-venv/bin/synthe-init touchid
sudo bash deploy/macos/upgrade.sh
```

The existing passphrase-protected approval key stays registered as the fallback. Read
[`docs/TOUCHID.md`](docs/TOUCHID.md) before enrolling: Touch ID protects the approval key, but it does
not decide whether a diff is safe.

## 4. Give OpenClaw its model & start chatting

Setup already runs OpenClaw's gateway as a service in the agent's account. Connect to the agent account and configure your model without the onboarding wizard traps:

```bash
sudo -iu openclaw
export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH"
openclaw models auth add
```
*(Select your provider and paste your key)*

Then start chatting through the gateway:

```bash
cd ~/repo && openclaw tui
```

Check the title bar: it will say `ws://127.0.0.1:...` (the gateway). You are fully protected by Synthe.

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

The diff shown is the broker's own copy, not the agent's description. Approve with `a`. If Touch ID
is enrolled, verify the branch, commit and files in both the terminal card and system prompt before
touching the sensor. Otherwise Synthe asks for the approval passphrase. To force the fallback even
after enrollment, run:

```bash
SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock ~/synthe-venv/bin/synthe-approve --passphrase
```

The broker pushes only after the signed approval, and you get a signed receipt.

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
