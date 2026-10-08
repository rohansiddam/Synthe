# Broker isolation (v0.5)

**The process that holds the keys is never the agent's process.** If an agent could run the
broker's code in its own process, it could read the broker's signing key and GitHub token, and
the commit barrier would be a seatbelt, not a wall. So the broker runs as **its own OS user** (or
in a container), and agents reach it only through a socket. They can propose; they never touch
a secret.

```
 agent (OS user "you")                          broker (OS user "_synthe" / "synthe")
 ─────────────────────                          ─────────────────────────────────────
 synthe_client.py / synthe_mcp.py --broker-url   synthe_commit.py serve
   claim, push (git bundle), receipts  ──unix──▶  signing key (0600), GitHub token (0600),
   holds: the packet, its claim token   socket    registry, ledger, receipts, git mirror
                                                  ── git push (compare-and-swap) ──▶ GitHub
```

Status: **verified on Linux** (two-user selftest, the systemd unit, the container; outputs below).
**macOS: not yet verified** until Rishab runs `deploy/macos/install.sh` and the checks at the end.

## How it works

- **One daemon holds everything secret:** `synthe_commit.py serve --config broker.json --socket PATH`,
  started as the broker's own user. Protocol: one JSON line in, one JSON line out, per connection.
  Ops: `hello`, `claim`, `complete`, `policy`, `bundle_bases`, `propose`, `receipts`. `release` is
  deliberately not exposed: it is operator-only, run as the broker's user.
- **The kernel names every client.** On a unix socket the broker reads the client's uid with
  `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS), never from the client. A client running as the
  broker's own user, or as root, could read the keys, so it is refused (`broker_not_isolated`).
  An optional `clients` allowlist refuses everyone else (`client_not_allowed`).
- **Modes** (`broker.json` → `"isolation": {"mode": ..., "clients": [...], "socket_group": ...}`):

  | Mode | Transport | Who may connect | Receipt says |
  |---|---|---|---|
  | `user` (default) | unix socket | any uid except the broker's and root (and only `clients`, if set) | `separate-user`, `verified: true`, both uids |
  | `container` | TCP + bearer token (`--listen`, token from `$SYNTHE_BROKER_TOKEN`) | whoever has the token | `container`, `verified: false` (declared by the operator) |
  | `none` | either | anyone, same user included (dev only) | `none`, `verified: false` |

  `--listen` with mode `user`, `--socket` with mode `container`, TCP without a token, or an
  allowlist naming users that don't exist: the broker refuses to start.
- **Startup checks** (also `synthe_commit.py doctor`): the broker refuses to serve if its key or a
  token file is not owned by it or is readable by others (`broker_key_exposed`,
  `broker_credentials_exposed`), or if its config, registry, ledger, receipts or state dir (or
  their directories), or the socket's directory, are writable by others (`broker_state_writable`;
  no sticky-bit exception: temp names are predictable, and whoever can write the socket's directory
  could swap in a fake broker). In mode `none` these only warn.
- **Commits travel as a git bundle.** `synthe_client.py push` asks `bundle_bases` for the remote
  tips, bundles `commit ^tips` and sends it base64 in the proposal. The broker verifies the bundle in
  its own mirror (`transfer.fsckObjects` on: a malformed tree never reaches the path checks), fetches
  missing prerequisites from the remote itself, and only the content-addressed commit matters. It
  never reads the agent's disk: a `source` path is refused in daemon mode
  (`source_path_not_allowed`) unless the operator sets `allow_path_sources`. Bundles over
  `max_bundle_mb` (default 50) → `bundle_too_large`.
- **Receipts record how each proposal arrived:** `via` (`unix` / `tcp` / `in-process`), `isolation`
  (e.g. `{"mode": "separate-user", "verified": true, "broker_uid": 997, "peer_uid": 1000}`) and
  `commits_from` (`bundle sha256:...` or `local path`, never the path itself).
- **No credential leaves the broker.** Every response and every receipt is scrubbed of URL userinfo
  and of every token value the broker holds, on the decoded value (so a JSON-escaped secret can't
  slip through), before it is signed or sent.
- **In-process use is dev-only and explicit.** `synthe_commit.py propose|push`,
  `synthe_mcp.py --broker` and the library call `synthe_commit.propose()` all refuse unless the
  config says `"isolation": {"mode": "none"}`, and their receipts say `in-process`.

## Install

### Linux (systemd), verified

```bash
sudo deploy/linux/install.sh --agent-user AGENT_USER
```

Creates the system user `synthe`, puts the code in `/opt/synthe/src` (root-owned) with a venv for
`cryptography`, creates the key and `broker.json` in `/var/lib/synthe` (0700) with `clients =
[AGENT_USER]`, and installs `synthe-broker.service`: `User=synthe`, `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `UMask=0077`, state in `/var/lib/synthe`, socket in
`/run/synthe` (0755). It prints the remaining steps: registry, GitHub token in a 0600
`token_file`, the remote, `doctor`, then `systemctl enable --now synthe-broker`.

### macOS (launchd), NOT YET VERIFIED

```bash
sudo deploy/macos/install.sh --agent-user "$USER"
```

Creates the hidden user and group `_synthe` (id below 500, via `dscl`), puts the code in
`/Library/Synthe/src` with a venv, the key and config in `/var/db/synthe` (0700), the socket in
`/var/db/synthe-run` (0755), and `/Library/LaunchDaemons/com.synthe.broker.plist`. The plist is
world-readable, so it holds no token: the GitHub token goes in `/var/db/synthe/github.token`
(0600, `token_file`). `_synthe` has no keychain, so a token file is the way. The script prints the
remaining steps (registry, token, remote, `doctor`, `launchctl bootstrap system ...`).
`--uninstall` removes it (`--purge` also deletes the key, ledger, receipts and the user).

**Then, on the Mac, run these checks** (this turns "not yet verified" into "verified"):

```bash
sudo -u _synthe /Library/Synthe/venv/bin/python /Library/Synthe/src/synthe_commit.py doctor --config /var/db/synthe/broker.json
```

```bash
python3 /Library/Synthe/src/synthe_client.py --broker unix:///var/db/synthe-run/broker.sock doctor --repo ~/Downloads/benchmark/Synthe-v0.5 --git-remote origin
```

```bash
cat /var/db/synthe/keys/synthe-broker.key.json
```

The last one must fail with `Permission denied`. Expect the client doctor to FAIL `direct push`
for as long as your own user still has GitHub credentials in the keychain: that is the honest
answer, because an agent running as you can push without Synthe. See the limits below.

### Container

```bash
docker build -f deploy/docker/Dockerfile -t synthe-broker:0.6 .
```

```bash
docker compose -f deploy/docker/compose.yaml up -d
```

The image runs as the unprivileged user `synthe` (uid 10001) with state in the `/synthe` volume;
compose publishes the port on `127.0.0.1` only, with a read-only root filesystem, no capabilities
and `no-new-privileges`. Agents use `SYNTHE_BROKER=tcp://127.0.0.1:8791` and
`SYNTHE_BROKER_TOKEN`. Initialise the volume with
`docker compose run --rm broker init --dir /synthe --isolation container`, then copy in the registry
and a 0600 token file. `deploy/docker/smoke_test.py` does all of this with throwaway keys and
checks it.

### Dev mode (one user, explicit)

```bash
python3 src/synthe_commit.py serve --config broker.json --socket /tmp/synthe-dev/broker.sock
```

with `"isolation": {"mode": "none"}` in `broker.json`. Everything works, and every receipt says
`none`. `scripts/demo_commit.py` runs the whole demo this way with throwaway keys.

## The two doctors

| | `synthe_commit.py doctor --config broker.json` (run as the broker's user) | `synthe_client.py doctor [--repo R --git-remote origin]` (run as the agent) |
|---|---|---|
| Checks | key and token files owned by the broker and 0600; config, registry, ledger, receipts, state dir not writable by others | the broker's uid **from the kernel** differs from yours (and matches what it claims); no passwordless `sudo`; not root; no `docker`/`podman` socket you control; no `GITHUB_TOKEN`/`GH_TOKEN`/`GIT_ASKPASS` in your env; you cannot push to the real remote yourself |
| Exit | 0 = safe to serve, 2 = problems listed | 0 = all PASS (WARN allowed), 2 = any FAIL |

The direct-push probe uses `git push --dry-run` for network remotes (authentication happens on
connect) and asks the filesystem for local remotes (a dry run never writes, and a local remote
only checks permissions when it writes).

## Honest limits

- **Root and passwordless `sudo`.** Anyone who can become root, or the broker's user, can read the
  key. The client doctor FAILs on passwordless `sudo` and on running as root; it can't see a `sudo`
  password you type for the agent.
- **The `docker` group is root.** In container mode, any user who can run `docker` can enter the
  container and read the key. The doctor WARNs when you can reach a Docker or Podman socket. Prefer
  a separate OS user when agents share the host.
- **Container mode is declared, not verified.** From inside, the broker can't prove the boundary,
  so its receipts say `verified: false`.
- **An agent with its own credentials isn't mediated.** The broker protects only credentials it
  holds. On a Mac, a GitHub credential in your login keychain lets anything running as you push
  directly. Remove it (or run agents as a user without one) and let the broker hold the token. The
  client doctor's direct-push check tells you which case you are in.
- **Dev mode is not isolation.** Mode `none` and in-process use exist for development and demos;
  they are explicit in the config and in every receipt.
- **Resource limits are coarse.** Requests are capped (`max_bundle_mb`, base64 overhead + 4 MB) and
  each connection has a 60 s read timeout, but there is no per-client rate limit, and a bundle's
  compressed size is capped, not its unpacked size.
- **The broker trusts its own host.** Root on the broker's machine controls the broker. Attested
  enclaves are on the roadmap.

## Reason codes (daemon and startup)

| Code | When |
|---|---|
| `broker_not_isolated` | the client runs as the broker's user or as root, or its uid can't be read |
| `client_not_allowed` | the client's uid is not in `isolation.clients` |
| `unauthorized` | TCP without the right bearer token |
| `request_malformed` | not one JSON object `{"op", "args": {...}}`, or a bundle that isn't base64 |
| `request_too_large` | the request line exceeds the limit |
| `unknown_op` | an op the daemon doesn't serve (`release` included, on purpose) |
| `broker_error` | an internal error; the daemon keeps serving |
| `broker_key_exposed` | startup: the key isn't owned by the broker or is readable by others |
| `broker_credentials_exposed` | startup: a token file isn't owned by the broker or is readable by others |
| `broker_state_writable` | startup: config, registry, ledger, receipts, state dir or socket dir writable by others |
| `source_path_not_allowed` | a proposal named a path on the agent's disk instead of sending a bundle |
| `bundle_too_large` | the bundle exceeds `max_bundle_mb` |

## Verified on Linux

**Two-user selftest** (`scripts/isolation_selftest.sh`, run as root in a `python:3.12-slim`
container, 2026-10-01; the users are created by the script, every key is a throwaway):

```
Synthe isolation selftest: Linux 6.10.14-linuxkit, Python 3.12.14, git version 2.47.3
users: synthe-broker=10002 synthe-agent=10003 synthe-other=10004

PASS  broker doctor: key 0600 and owned by the broker, state not writable by others
PASS  broker is serving on a unix socket as synthe-broker
      agent> cat broker.key.json: Permission denied
PASS  agent cannot read the broker's key
PASS  agent cannot rewrite the ledger
      agent> git push: exit 1, error: remote unpack failed: unable to create temporary object directory
PASS  agent cannot push to the remote itself
PASS  the remote has no feature/direct
      agent> doctor: PASS  broker isolation: the broker runs as uid 10002 (kernel-checked); this agent is uid 10003
      agent> doctor: PASS  direct push: this user cannot write the repository behind 'origin'
PASS  agent doctor: every check passes (exit 0)
PASS  hello: separate-user, verified, broker uid != agent uid
PASS  agent claims the handoff over the socket: ACCEPT
PASS  out-of-scope commit (README.md): denied path_outside_scope
PASS  in-scope commit: executed
PASS  receipt: via unix, separate-user, verified: true, uids differ
PASS  receipt: the commits arrived as a git bundle
PASS  the remote's feature/selftest is the agent's commit
      receipt #2: executed, via unix, isolation separate-user verified=True broker_uid=10002 peer_uid=10003, bundle sha256:b060b304e...
PASS  a client running as the broker's user: broker_not_isolated
PASS  a client running as root: broker_not_isolated
PASS  a user outside the clients list: client_not_allowed
PASS  receipt chain verifies against the broker's registered key (2 receipts)
PASS  the agent can check the chain over the socket

SELFTEST PASS
```

To reproduce on a Mac with Docker:

```bash
docker run --rm --user root --entrypoint bash -v "$PWD":/repo:ro synthe-broker:0.6 /repo/scripts/isolation_selftest.sh
```

**systemd** (`deploy/linux/systemd_test.sh`: Debian bookworm, systemd 252 as PID 1, `install.sh`
run as an operator would, then an agent user pushing through the hardened unit):

```
PASS  broker doctor as synthe: ok
PASS  systemd started the broker; socket at /run/synthe/broker.sock
PASS  the broker process runs as synthe (pid 208)
PASS  unit: NoNewPrivileges, ProtectSystem=strict, ProtectHome
PASS  /var/lib/synthe is 0700 synthe
PASS  the broker key is 0600 synthe
PASS  agent1 cannot read the key: Permission denied
      agent1> doctor: PASS  broker isolation: the broker runs as uid 997 (kernel-checked); this agent is uid 1000
      agent1> doctor: PASS  direct push: this user cannot write the repository behind 'origin'
PASS  agent1 claims through the socket: ACCEPT
PASS  agent1's push: executed by the systemd broker
PASS  receipt: separate-user, verified, uids differ
PASS  the remote has agent1's commit
PASS  a root client: broker_not_isolated

SYSTEMD TEST PASS
```

**Container** (`deploy/docker/smoke_test.py`: Docker 28.3.2, linux/arm64; the agent on the host
with no keys, the broker in the container as `synthe`):

```
PASS  broker answers hello over tcp on 127.0.0.1
PASS  hello: isolation 'container' (declared by the operator, not verifiable from inside)
PASS  no bearer token: unauthorized
PASS  a wrong bearer token: unauthorized
PASS  broker doctor inside the container: key 0600, state private
PASS  broker runs as the unprivileged user 'synthe'
PASS  agent claims the handoff over tcp: ACCEPT
PASS  agent proposes a push (bundle over tcp): executed
PASS  receipt: via tcp, isolation container, commits from a bundle
PASS  the container's remote has feature/x at the agent's commit
PASS  receipt chain verifies (1 receipt)

SMOKE TEST PASS
```
