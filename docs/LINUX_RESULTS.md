# Linux results: test suite and install path

Run on 2026-10-23 in a cloud Linux container, with no GitHub credential anywhere. Every number below
was produced by the commands in [Reproduce](#reproduce) and read from their output. This is a record
of what ran, not a certification, and it says nothing about hosts or distributions not listed here.

## Where it ran

| | Host (test suite) | Container (install path) |
|---|---|---|
| Distro | Ubuntu 24.04.5 LTS | Ubuntu 24.04.5 LTS (`ubuntu:24.04` image) |
| Kernel | 6.18.44 (the host's; containers share it) | same |
| Init | none (PID 1 is the sandbox's process manager) | systemd 255, as PID 1, `--privileged` |
| Python | 3.13.16 | 3.12.3 (Ubuntu's `python3`) |
| git | 2.43.0 | 2.43.0 |
| Other | `cryptography` 50.0.2, pytest 9.1.1, Node 22.22.0, Docker 29.9.1 | `sudo`, `expect` |

Commits: the test suite ran on `1b02b39`. The systemd and install-path runs ran on `dabc58b`, its
parent; the only change between them is the Touch ID message in `src/synthe_touchid.py`, which neither
run reaches. Base: `4c0e0b7` (main, PR #18).

## Test suite

`python -m pytest -q -p no:cacheprovider` with `PYTHONPATH=src`, the way CI's `ubuntu-latest` job runs it
(`pip install '.[test]'` into a fresh venv, and a `sudo` stub on `PATH` that always refuses).

| Run | As | Passed | Failed | Skipped | xfailed |
|---|---|---|---|---|---|
| Before this PR, `4c0e0b7` | an ordinary user | 1509 | 0 | 82 | 37 |
| Before this PR, `4c0e0b7` | root | 1489 | **19** | 83 | 37 |
| After, `1b02b39` | an ordinary user | 1512 | 0 | 83 | 37 |
| After, `1b02b39` | root | 1483 | 0 | 112 | 37 |

- **The 19 root failures were not Linux bugs.** All 19 were in `tests/test_install_entrypoint.py`:
  `scripts/install_frictionless.sh` refuses to run as root on purpose, so every case stopped at that
  refusal. Under root those cases now skip with that reason (29 skips), and a new root-only test checks
  the refusal itself. The few cases in that file that used to pass under root passed for the wrong
  reason (the refusal also exits 1), so they skip too.
- **Skips as an ordinary user** (83): 62 + 18 conformance cases that need fixtures not in this
  repository (`public checker snapshot not present`, `no signature or registry`); 1
  `test_enforce_macos.py` case marked `macOS setup`; 1 case that needs the private `synthe_lab`
  module; and 1 new root-only case. Root adds the 29 installer cases above and
  `test_isolation.py`'s read-only case ("root can write anything").
- **xfailed** (37): `tests/redteam_broker/` strict xfails that record checks not built yet. They are
  the same on macOS and Linux.
- **OpenClaw plugin**: `node --test` in `integrations/openclaw/plugin`: 39 passed, 0 failed, on Node 22
  (CI uses Node 26).

No test failed on Linux as an ordinary user, so there was no Linux bug to fix in the suite itself. The
macOS-only tests (launchd, `dscl`, Touch ID) already run on Linux against stubs, or skip with a reason.

## Install path under real systemd

Two scripts, each in a throwaway `--privileged` container booted with systemd as PID 1. The remote is
a local bare repo; no GitHub, no token.

**`deploy/linux/systemd_test.sh`** (already in the repo): `install.sh`, the hardened unit started by
systemd, an agent pushing a pre-approved selftest packet through the socket. Result: `SYSTEMD TEST PASS`,
12 of 12 checks. Among them: the broker process runs as `synthe`; `NoNewPrivileges`,
`ProtectSystem=strict` and `ProtectHome` are in effect; `/var/lib/synthe` is 0700 and the key 0600;
the agent can't read the key; the receipt says `separate-user`, verified, with different uids; a root
client is refused with `broker_not_isolated`.

**`deploy/linux/human_path_test.sh`** (new): the path a person follows, with the same commands as the
docs.

1. `alice`, an ordinary account in the `sudo` group, clones Synthe, makes a venv, runs
   `pip install .` and `synthe-init prepare --agent-kind none --agent-account worker`. Prepare passes on
   Linux.
2. `alice` runs `bash ~/.synthe/finish-setup.sh` at a real terminal (driven by `expect`): a new approval
   passphrase twice, the hidden token prompt, then her sudo password. The token prompt got a
   placeholder string, because a local remote takes no token. `finish.sh` creates `worker`, installs the
   broker as `synthe`, starts it from systemd, clones the repo into `worker`'s account through the
   broker, and runs the doctor there: **ENFORCED**, 5 of 5 checks pass (no approver key, broker uid
   kernel-checked, no passwordless sudo, can't write the remote, no agent hook needed).
3. The wall, from `worker`: reading the broker's token, the broker's key and `alice`'s approver key
   all fail with `Permission denied`; `sudo -n true` fails; a direct `git push` to the bare repo fails.
4. `alice` signs a task (`synthe-task new`, passphrase). `worker` commits and runs a plain `git push`.
   The push becomes a proposal ("proposed for approval, not pushed yet"), and the remote doesn't
   change.
5. `alice` runs `synthe-approve --passphrase`, reads the broker's own diff and approves with `a` and
   her passphrase: `approval_accepted`, then `Push: executed`. The remote's `agent/first-push` is
   exactly the approved commit.
6. `synthe-verify` checks the receipt chain using only the published key
   `/var/lib/synthe-shared/broker.pub.json`: `VERIFIED 3 receipts`. A copy with one decision edited:
   `NOT VERIFIED`, exit 1.
7. The live red team (`scripts/redteam_live.py`, the battery in [REDTEAM.md](REDTEAM.md)): `alice` signs
   the three red-team tasks, `worker` attacks, and `alice` approves at the two pauses in a second
   terminal (the swap and the control). **33 passed, 0 failed, 0 skipped**: the 30 attacks or
   containment checks plus the 3 controls. The swapped commit never reached the remote ("Nothing pushed
   yet"). 12 refusals reached the broker and each has a matching signed receipt. The chain of 21
   receipts verifies with the published key, and an edited copy is caught. The raw report, exactly as
   `redteam_live.py` wrote it, is [`results/redteam-linux-2026-10-23.json`](results/redteam-linux-2026-10-23.json).

Result: `HUMAN PATH TEST PASS`, 22 of 22 checks. The remote was a local bare repo, so the red-team rows
that say "GitHub" mean that repo here.

## What this PR changed for Linux

- **`deploy/linux/finish.sh` publishes the broker's public key** at `/var/lib/synthe-shared/broker.pub.json`
  (root-owned, 0644, public fields only), as macOS does under `/Users/Shared/Synthe`. Before, a Linux
  install printed the key once and published nothing, so the receipts had no independent key to
  verify against.
- **`scripts/redteam_live.py` defaults follow the Linux install** on Linux: socket, inbox, state dir,
  published key, `synthe-mcp` path, and the report in the agent's home. Before, it used macOS paths
  only, so on Linux the token and key rows reported "not found" instead of testing the wall. The macOS
  defaults are unchanged.
- **`synthe-init touchid` on Linux** now says Touch ID needs a Mac and names
  `synthe-approve --passphrase`, instead of asking for the Xcode command-line tools. It was already
  failing closed.
- **Tests**: the root skip and root-only test above; tests for the key publication and the Linux
  red-team defaults; a test that Touch ID enrollment stops before any compiler lookup off macOS.
- **`deploy/linux/human_path_test.sh`**, and `SYNTHE_TEST_IMAGE` / `SYNTHE_TEST_DOCKER_ARGS` for both
  container scripts (defaults unchanged).

The Claude Code hooks plugin was not touched.

## Not supported on Linux yet, or not verified here

- **Touch ID** is macOS-only (Secure Enclave). On Linux the approval key is the passphrase-sealed
  Ed25519 key, and that is the path verified above.
- **launchd, `dscl` and the hidden `_synthe` user** are macOS mechanisms. Linux uses systemd,
  `useradd --system` (`synthe`) and `useradd` for the agent. That is a different implementation of the
  same boundary.
- **The one-line installer** (`scripts/install_frictionless.sh`) and the setup skill need Homebrew, so
  they're macOS-only. On Linux, install from a clone, as in Reproduce below.
- **No upgrade path on Linux.** `finish.sh` refuses an existing broker ("use a reviewed upgrade"), and
  only `deploy/macos/upgrade.sh` exists.
- **OpenClaw on Linux was not run.** Everything here used `--agent-kind none`. `finish.sh` has an OpenClaw
  branch (npm install, a gateway unit) that this run did not exercise.
- **A real GitHub remote was not used.** Pushes went to a local bare repo. Token handling over https
  (`token_file`, the GitHub token prefix check) was not exercised on Linux.
- **A live Linux host was not used.** Both scripts ran in a privileged container on one kernel. A clean
  VM or bare-metal install is still open, as [ANY_AGENT.md](ANY_AGENT.md) says.
- **Debian was not run.** The scripts default to `debian:bookworm-slim`, but this sandbox couldn't reach
  deb.debian.org, so both ran on `ubuntu:24.04` through `SYNTHE_TEST_IMAGE`.

## Observations

These are not fixed in this PR, and none of them weakens the boundary:

- With `--agent-kind none`, `synthe-task new` still prints "Tell OpenClaw: Use the synthe skill...".
  That's harmless text, but wrong for a non-OpenClaw agent. It's the same on macOS.
- During debugging, a stand-in remote with `core.sharedRepository` set refused the broker's push.
  Git sets the setgid bit on new directories, and the unit's `RestrictSUIDSGID=yes` blocks that. The
  broker reported `push_rejected` with a signed receipt, and nothing was pushed. Only local shared
  repos are affected; an https remote isn't.
- In that same run, `synthe-approve` printed `Push: denied` but exited 0.
- The unit's `UMask=0077` makes refs the broker writes into a *local* bare remote 0600. That's right
  for a private mirror, but other accounts can't read such a remote. The test adds a `post-receive`
  hook to the stand-in remote so that, like the public test repo used on macOS, every account can read
  it.
- `docker exec` in this sandbox ran with umask 000. The doctor correctly reported **ADVISORY** while
  the stand-in remote was world-writable. The scripts set `umask 022`, which a login shell would have.

## Reproduce

From a Synthe checkout on a Linux host, as an ordinary user:

```bash
python3 -m venv ~/synthe-test-venv && ~/synthe-test-venv/bin/pip install '.[test]'
PYTHONPATH=src ~/synthe-test-venv/bin/python -m pytest -q -p no:cacheprovider -rfEs
(cd integrations/openclaw/plugin && node --test)
```

With Docker (each script builds its own image and removes the container afterwards):

```bash
bash deploy/linux/systemd_test.sh        # expect: SYSTEMD TEST PASS
bash deploy/linux/human_path_test.sh     # expect: HUMAN PATH TEST PASS
```

`SYNTHE_TEST_REPORT=/path/report.json` keeps the red team's JSON, and `SYNTHE_TEST_KEEP=1` keeps the
human-path container for inspection. On a host that can't reach deb.debian.org, build an image with
`systemd systemd-sysv python3 python3-venv git ca-certificates procps sudo expect`, with
`/lib/systemd/systemd` as `CMD`. This run used `FROM ubuntu:24.04` and, because the sandbox intercepts
TLS, also trusted the sandbox's proxy CA and set `PIP_CERT`. Then:

```bash
SYNTHE_TEST_IMAGE=<that image> SYNTHE_TEST_DOCKER_ARGS="--network host" bash deploy/linux/systemd_test.sh
SYNTHE_TEST_IMAGE=<that image> SYNTHE_TEST_DOCKER_ARGS="--network host" bash deploy/linux/human_path_test.sh
```
