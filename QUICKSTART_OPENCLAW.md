# Quickstart: install Synthe, then just work (macOS, OpenClaw)

You start with a Mac and a GitHub repo. You finish with an OpenClaw agent that pushes its work to
GitHub on its own, inside a lane you signed once. You hear from Synthe only when it stops something
or needs you, and it tells you why that mattered.

How it works:
- The agent runs in its own Mac account (`openclaw`) and has no GitHub login.
- A hidden `_synthe` user holds the only GitHub token, and pushes only what a lane or task you signed
  allows.
- Inside your lane, routine pushes go out without asking you. High-risk pushes (CI workflows,
  secret-like files, very large diffs or deletions) and pushes outside the lane's files wait for you.
- Every push, and every refusal, gets a signed receipt. `synthe-notify` reads them and tells you only
  what is worth your attention.

The happy path is: **install → setup (say yes to the lane and to notifications) → give the agent work
→ hear from Synthe only when it matters → read the weekly digest.**

macOS on Apple silicon is the verified platform. Steps 1 to 6 match what was run on 2026-10-07
([`docs/OPENCLAW_RESULTS.md`](docs/OPENCLAW_RESULTS.md)); the lane and notification questions at
the end of setup are newer and nobody has timed the whole path with a new user yet. Not on a Mac, or
not using OpenClaw? See [`docs/ANY_AGENT.md`](docs/ANY_AGENT.md).

## Before you start

You need:
- **A Mac account with admin rights.** You'll type your Mac password once.
- **A GitHub repo** for the agent to work on, private or public. Agent work lands only on `agent/*`
  branches, and only after you approve it.
- **A fine-grained GitHub token for that one repo.** On GitHub go to Settings → Developer settings →
  Personal access tokens → Fine-grained tokens → Generate new token. Under Repository access choose
  **Only select repositories** and pick the repo. Under Permissions set **Contents: Read and write**.
  Copy the token (it starts with `github_pat_`). You'll paste it once, hidden, in step 5.
- **An API key for the model OpenClaw will use**, for step 6.

Open Terminal (Applications → Utilities → Terminal). Each step below is one command; paste it and
press Return.

## 1. Install Homebrew (skip if you have it)

```bash
brew --version
```

If that prints `Homebrew 4.x` or similar, go to step 2. If it says `command not found`, install it:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow what it prints at the end. It asks you to run two lines that add `brew` to your PATH. Then
`brew --version` should work.

## 2. Get Synthe

```bash
git clone https://github.com/rohansiddam/Synthe ~/synthe && cd ~/synthe
```

If macOS asks to install the command line developer tools, accept, wait for it to finish, and run
the line again.

**You should see:** `Cloning into '/Users/<you>/synthe'...`. Run every later command from this
`~/synthe` folder unless a step says otherwise. There's no one-line installer yet: a tagged release
comes first, so cloning is the install for now.

## 3. Install

```bash
brew install python node git && PY=$(bash deploy/macos/find-python.sh) && "$PY" -m venv ~/synthe-venv && ~/synthe-venv/bin/pip install -q .
```

This builds Synthe its own Python environment in `~/synthe-venv`. `find-python.sh` picks a Python
that really works: Homebrew's newest Python can be installed but broken on an older macOS.

If it says no working Python was found, run what it prints (usually `brew install python@3.13`), then
run the same line again.

**Check:**

```bash
ls ~/synthe-venv/bin/synthe-init
```

**You should see:** `/Users/<you>/synthe-venv/bin/synthe-init`

## 4. Prepare

Put in your repo's URL. `--allowed-paths` lists the files the agent may change; `'src/**'` means
everything under `src/`.

```bash
~/synthe-venv/bin/synthe-init prepare --repo-url https://github.com/YOU/REPO.git --allowed-paths 'src/**'
```

It checks the Mac, needs no secrets, and writes the script for step 5.

**You should see:** a `PASS  preflight checks passed` line, then:

```
bash /Users/<you>/.synthe/finish-setup.sh
```

If it says `can't prepare yet:` instead, fix each item it lists (for example `brew install node`) and
run the line again.

## 5. Finish setup (you type the secrets, then answer two questions)

```bash
bash ~/.synthe/finish-setup.sh
```

It asks for three things, in this order:
1. a new **approval passphrase**, twice. Pick a new one and remember it: it signs your lane, your
   tasks and any push you approve.
2. your **GitHub token**. Paste it; nothing shows as you paste.
3. your **Mac password**, once, for the admin step.

Then it does the rest by itself:
- creates the agent's Mac account `openclaw`;
- installs the broker as the hidden `_synthe` user;
- installs OpenClaw in the agent's account, with the Synthe plugin, skill and gateway;
- clones your repo there through the broker, so the agent's account needs no GitHub access, not
  even to read;
- runs the doctor.

**You should see:** the doctor's report, with the level **ENFORCED**, every check `PASS` except one
expected `WARN` for barrier plugin mode (it notes that `tui --local` skips the plugin). Its last lines
suggest OpenClaw's setup wizard; skip that and use step 6.

If the level isn't ENFORCED, stop here: the failing check says what's wrong.

### Question 1: how hands-off?

```
How hands-off?
  [1] Ask me before every push
  [2] Agents push without asking; Synthe only interrupts for what it blocks or flags as high-risk (recommended)
      With [2] the agent can also start its own work in the lane: a plain git push needs no task from you.
```

Press Return for `[2]`. Before anything is signed it shows the lane in plain words, roughly:

> Agent openclaw may push to agent/* changing src/\*\*, with no limit on pushes, with no expiry.
> Pushes to other branches still ask you. High-risk pushes (CI workflows, key and secret files, 400+
> changed lines, mass deletions, 30+ commits, per the broker's rules) and pushes outside these paths
> still ask you. The risk check reads paths and sizes, not code. Review-level changes (dependency
> manifests and lockfiles, Dockerfiles, build scripts, ...) go out without asking you
> (synthe-notify digest lists them afterwards); --auto-approve routine makes them ask too.
> The agent may also start its own work in the lane: a plain git push on these branches with no task
> from you gets a task Synthe issues under this grant, labelled as written by the agent. There is no
> limit on how many. Revoking the grant stops them.
> ...
> With no limit and no expiry this is a standing permission: it stays open until you close it.

Read it, answer `Y`, and type your passphrase (Touch ID instead, if you have enrolled it). That is
the lane: one signature, until you revoke it.

Choose `[1]` if you want to read every push before it goes out; step 8 then shows you how. A run with
no one at the keyboard never picks `[2]` for you.

### Question 2: notifications?

Setup then offers to turn notifications on. Answer `Y` (or press Return). It installs
`synthe-notify watch` as a login item **in your account**, not the agent's (a LaunchAgent,
`~/Library/LaunchAgents/com.synthe.notify.plist`), and starts it now.

Check that a notification reaches you:

```bash
~/synthe-venv/bin/synthe-notify test
```

**You should see:** a banner titled "Synthe test: ..." saying it is a test and nothing happened. If no
banner appears, macOS may be holding notifications from Script Editor (which shows them for scripts):
allow it in System Settings → Notifications. Prefer Slack? See [`docs/NOTIFY.md`](docs/NOTIFY.md).

Said no? Run `~/synthe-venv/bin/synthe-notify install-agent` any time; `uninstall-agent` turns it off.

## 6. Give OpenClaw a model and start it (agent's account)

Setup already runs OpenClaw's gateway as a service in the agent's account. Switch to that account and
add your model key:

```bash
sudo -iu openclaw
export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH"
openclaw models auth add
```

Pick your provider and paste your API key. Then start the chat:

```bash
cd ~/repo && openclaw tui
```

**You should see:** a title bar showing `ws://127.0.0.1:...` (the gateway). If it says local or
embedded instead, quit and run `openclaw tui` again without `--local`: in embedded mode the Synthe
plugin doesn't run, and only the missing credentials stop a push.

Leave this window open. It's the agent's window.

## 7. Give OpenClaw work

**With the lane (`[2]`)** you don't sign each task. In the agent's window from step 6, just ask:

> Add a greeting to the app and test it, on branch agent/first-push.

OpenClaw starts a task of its own inside your lane (`synthe_start_task`): Synthe issues it under the
lane you signed, labelled as written by the agent, and receipts it. Then OpenClaw commits on
`agent/first-push` and proposes the push through Synthe. It can't push by itself. (An agent that only
knows `git push` gets the same from a plain push in its clone: [`docs/GIT_PUSH.md`](docs/GIT_PUSH.md).)

**With `[1]`, or for work outside the lane,** sign a task yourself. Open a **new** Terminal window (⌘N);
it runs as you, not as `openclaw`:

```bash
cd ~/synthe && ~/synthe-venv/bin/synthe-task new "Add a greeting and test it" --branch agent/first-push
```

Type your approval passphrase. **You should see:** a `PASS` line for `signed with your key` and
`agent/first-push`, then a **Tell OpenClaw** paragraph. Copy that paragraph and paste it into the
agent's window. OpenClaw checks the task, commits and proposes the push through Synthe.

## 8. Let it go out, or approve it when Synthe asks

**With the lane (`[2]`):** a change to `src/` goes out on its own. OpenClaw reports the push as
**executed**, with a receipt number, and you hear nothing. That silence is the point.

**When Synthe needs you**, you get a notification that says what and why, for example:

> **Synthe is waiting for you.** Needs you: agent/first-push changes a CI workflow
> (.github/workflows/ci.yml). Your lane lets routine and review-level work through; this one is
> high-risk. Run synthe-approve to see the diff.

or "agent/first-push changes 3 files outside your lane (docs/a.md, …)". A push Synthe refused
outright (a forbidden path, a branch the agent may not use, a forged approval) arrives as
**Blocked**, with what it stopped and why that mattered. Nothing went out. With `[1]`, every push
waits for you like this.

To decide on a push that is waiting, run this in your window:

```bash
SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock ~/synthe-venv/bin/synthe-approve
```

The diff it shows is the broker's own copy of the commit, not the agent's description of it. The card
says why it came to you ("Outside your lane: N files", "Your lane sent this to you because: ...").

- Read it. A push that is large, deletes files, or touches CI, dependency or secrets-like files is
  marked CHECK or HIGH-RISK. For a high-risk push you type the last 4 characters of the commit first.
  A long diff has to be viewed in full (`v`) before you can approve.
- Press `a` to approve, then type your approval passphrase. Or reject it; nothing is pushed.

**You should see:**

```
 Approval: approval_accepted (receipt #N)
 Push: executed (receipt #M)  1a2b3c4d5e6f → agent/first-push
```

Your receipt numbers and commit will differ.

## Check: what you should see

From your own window, ask GitHub directly, outside Synthe:

```bash
git ls-remote https://github.com/YOU/REPO.git refs/heads/agent/first-push refs/heads/main
```

You're done when all four of these hold:
- [ ] `refs/heads/agent/first-push` exists, at the commit OpenClaw reported (or the one you approved).
- [ ] `refs/heads/main` is the same commit it was before you started.
- [ ] The doctor in step 5 said **ENFORCED**, with only the barrier plugin mode `WARN`.
- [ ] OpenClaw said it **proposed** the push through Synthe. It didn't push by itself.

If the branch isn't there, run `synthe-approve`: a push that is waiting for you stays staged, and its
receipt says what the broker decided.

## 9. See what Synthe did for you

A few days in, ask for the digest:

```bash
~/synthe-venv/bin/synthe-notify digest
```

It checks the receipt chain against the broker's key first, then says, in plain English, how many
pushes went out without asking you, how many needed you and why, and which risky attempts were
stopped. It also lists the review-level pushes that went out under your lane, for example "3
dependency or build changes went out under your lane without asking you", so you can look at them
afterwards, and the tasks the agent started itself under your lane, with which of them shipped (their
descriptions are the agent's own words). `--days 30` looks further back.

## Next

- **Change the lane.** `[2]` in step 5 is this command with your setup's defaults; run it yourself any
  time, in your own terminal:

  ```bash
  ~/synthe-venv/bin/synthe-task grant
  ```

  It shows what you are allowing, asks, then signs. Options:
  - `--auto-approve routine`: dependency manifests and lockfiles, Dockerfiles, build scripts, any
    deletion and larger diffs ask you too; only routine pushes go out alone.
  - `--uses 50 --until 7d`: a ceiling. With neither, there is no limit and no expiry.
  - `--self-issue`: the agent may start its own work in the lane (the setup lane has it). Without it,
    every piece of work starts with a task you sign.
  - also `--branch`, `--paths`, `--remote`, `--agent`, `--delegate` (a model reviewer instead of you),
    `--brief`.

  It refuses `main`, `master`, `*` and `**`, and any path your setup forbids.

  ```bash
  ~/synthe-venv/bin/synthe-task grants                 # open lanes, uses left, expiry, and which to renew
  ~/synthe-venv/bin/synthe-task revoke-grant lane-ID   # close one now
  ```

  Enrolling Touch ID, changing the agent's policy or the broker's risk rules makes existing lanes
  `stale`; sign a new one.
- **Approve with Touch ID.** Enroll a Secure Enclave key, then install the updated registry and code
  into the broker:

  ```bash
  ~/synthe-venv/bin/synthe-init touchid
  sudo bash deploy/macos/upgrade.sh
  ```

  Your passphrase key stays as the fallback (`synthe-approve --passphrase`). Read
  [`docs/TOUCHID.md`](docs/TOUCHID.md) first: Touch ID protects the approval key, but it doesn't
  decide whether a diff is safe.
- **Notifications in Slack, or more of them.** [`docs/NOTIFY.md`](docs/NOTIFY.md): a Slack webhook,
  `--all-refusals`, and exactly what stays quiet.
- **Your approval history.** `synthe-approve --stats` shows your approval rate and time to decision,
  from a local log that never leaves your Mac (owner-only, last 1,000 decisions;
  `SYNTHE_APPROVALS_LOG=off` turns it off).
- **Attack your own install.** [`docs/REDTEAM.md`](docs/REDTEAM.md) runs 30 attacks plus 3 controls
  from the agent's account, with no model, and checks the receipts against the broker's published
  key.
- **Audit receipts without the broker:** [`docs/VERIFY.md`](docs/VERIFY.md).
- **Let your coding agent do steps 2 to 4:** point it at `skills/synthe-setup/SKILL.md`. Step 5 is
  always yours, because that's where the secrets are typed and the lane is signed.

## What this does not claim

- **A lane is a standing permission.** With no limit and no expiry it stays open until you revoke it,
  and while it is open nobody reads each push before it goes out. Synthe still checks the branch and
  the files at every push, sends you what is high-risk or outside the lane, and signs a receipt for
  each one, so you can audit afterwards.
- **The risk check reads paths and sizes, not code.** A malicious change to an ordinary-looking file
  under `src/` is routine and goes out. Review-level changes (dependency manifests, lockfiles,
  Dockerfiles, build scripts) go out without asking under the default lane; the digest lists them
  afterwards, and `--auto-approve routine` makes them ask. Synthe doesn't judge whether the code is
  correct.
- **Silence is not proof.** Notifications report what the broker recorded, polled every 15 seconds.
  An agent that never proposes a push leaves no receipt. What stops it pushing around Synthe is that
  its account holds no credential, not the notifier.
- **The plugin is a seatbelt, not the wall.** It works only through the gateway, and obfuscated
  commands or another git library can get past its text matching. The wall is credential custody:
  the agent's account has no GitHub token, `gh` login or SSH key that can push, and `doctor` checks
  that.
- **Synthe mediates git effects.** It doesn't stop prompt injection.
