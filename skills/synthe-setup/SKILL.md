---
name: synthe-setup
description: Set up Synthe on the user's Mac so an AI agent (OpenClaw) can only push code after the user approves it. Use when the user asks to install, set up or enforce Synthe. The agent does the preparation; the user types the secrets.
---

# Set up Synthe (macOS)

Synthe makes an AI agent's pushes wait for a human's signed approval. Its guarantee is that the
agent **can't** push or approve on its own. So you, the agent doing the setup, must never handle the
secrets that guarantee rests on. Your job is to prepare everything else and hand the user one command.

## Never

- Never ask for, read, type or store the user's **approval passphrase**, **GitHub token** or **Mac
  password**. Don't put them in a command, a file or a chat message.
- Never run `sudo` yourself, and never run the `finish-setup.sh` script for the user.
- If something needs one of those, stop and tell the user what to run.

## Steps

1. **Ask the user** for:
   - the GitHub repo the agent should work on (`https://github.com/OWNER/REPO.git`);
   - which paths the agent may change (for example `src/**`). Agent work lands only on `agent/*`
     branches.
2. **Check the prerequisites,** and install any that are missing (these need no secrets):
   ```bash
   brew install python node git
   ```
3. **Install Synthe** from its folder, into its own environment outside Documents and Desktop, with a
   Python that really works (Homebrew's newest can be installed but broken on an older macOS):
   ```bash
   PY=$(bash deploy/macos/find-python.sh) && "$PY" -m venv ~/synthe-venv && ~/synthe-venv/bin/pip install -q .
   ```
   If no working Python is found, tell the user what it printed (usually `brew install python@3.13`).
   Don't work around it.
4. **Prepare.** This checks the Mac and writes the user's one command:
   ```bash
   ~/synthe-venv/bin/synthe-init prepare --repo-url URL --allowed-paths 'src/**'
   ```
   Fix anything it lists as a problem, then run it again. It suggests `openclaw` as the agent's
   macOS account; the setup creates that account.
5. **Hand over.** Tell the user, in these words or close to them:
   > Run this in your own Terminal: `bash ~/.synthe/finish-setup.sh`. It asks for a new approval
   > passphrase (twice), a GitHub fine-grained token for the repo with Contents: Read and write
   > (hidden as you paste it), and your Mac password once. When it finishes it shows the enforcement
   > level; it should say ENFORCED.

   Then tell them how to create the token: GitHub, then Settings, then Developer settings, then
   Fine-grained tokens, limited to that one repo, with **Contents: Read and write**.
6. **After they finish,** the output ends with the last step, which is theirs: give OpenClaw its
   model (`openclaw onboard` in the agent's account), then run it through its gateway. Point them to
   it. If the doctor didn't say ENFORCED, read the check that failed and explain it.

