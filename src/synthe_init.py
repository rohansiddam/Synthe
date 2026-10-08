#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""synthe-init: set up Synthe for an OpenClaw agent on this machine, and say honestly how strong it is.

  synthe-init setup --repo-url URL --branches 'agent/*' --allowed-paths 'src/**,tests/**'
                    [--github-token-file FILE] [--approver NAME] [--agent openclaw]
                    [--home ~/.synthe] [--no-openclaw] [--yes]
  synthe-init doctor [--home ~/.synthe] [--repo PATH] [--json]
  synthe-init serve  [--home ~/.synthe]          (dev isolation: run the broker in the foreground)

`setup` writes, under --home (default ~/.synthe):
  approver.key.json   your approver key, sealed under a passphrase you type (never plaintext)
  approver.pub.json   its public half
  broker/             the commit broker: its key, broker.json, registry.json and the GitHub token
                      (moved there, 0600; never printed, never put in argv)
  setup-report.json   what was set up and every check, with no secrets in it
and wires OpenClaw: the Synthe MCP server (without the approval tool: the agent never approves), the
synthe-barrier plugin (blocks direct pushes) and the synthe skill. OpenClaw asks you to confirm the
plugin unless you pass --yes.

`doctor` reports one of three enforcement levels, with every failing check and its fix:
  ADVISORY   the agent can still push or approve on its own; Synthe is a checker it may use
  GUARDED    direct pushes are blocked and the agent holds no credentials it could see, but the broker
             runs as your own user (dev isolation), so the agent could read the broker's key and token
  ENFORCED   the broker runs as another OS user (or a container the agent can't enter), the approver
             key needs your passphrase, and the agent has no way to push or approve on its own

Isolation on a Mac without Docker: run the broker as its own user with
  sudo deploy/macos/install.sh --agent-user "$USER"
(you type the sudo password; Synthe never does), then `synthe-init doctor`.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_crypto as sc  # noqa: E402
import synthe_ui as sui  # noqa: E402
import synthe_sign as ss  # noqa: E402

BROKER_ID = "synthe-broker"
MCP_NAME = "synthe-local"
PLUGIN_ID = "synthe-barrier"
FORBIDDEN_PATHS = [".github/**", "**/*.key.json", "**/.env", "**/*.pem"]
DEFAULT_MAX_TTL_HOURS = 72          # scenario S22: a handoff is a bearer token while it lives
DEFAULT_PUSHES_PER_DAY = 20         # study F02 (lite): a ceiling on what one agent can push in a day
LEVELS = ("ADVISORY", "GUARDED", "ENFORCED")


# ---- where things are ---------------------------------------------------------------

def integration_dir() -> Path | None:
    """The OpenClaw plugin and skill: next to the source tree, or installed under share/synthe."""
    here = Path(__file__).resolve().parent
    for candidate in (here.parent / "integrations" / "openclaw", Path(sys.prefix) / "share" / "synthe" / "openclaw"):
        if (candidate / "plugin" / "openclaw.plugin.json").exists() and (candidate / "skill" / "synthe" / "SKILL.md").exists():
            return candidate
    return None


def find_openclaw() -> str | None:
    found = shutil.which("openclaw")
    if found:
        return found
    candidates = sorted(glob.glob(os.path.expanduser("~/.nvm/versions/node/*/bin/openclaw")))
    return candidates[-1] if candidates else None


class OpenClaw:
    """The openclaw CLI, with its own bin directory on PATH (it may live under an nvm Node)."""

    def __init__(self, binary: str, env: dict | None = None):
        self.binary = binary
        self.env = {**os.environ, **(env or {}),
                    "PATH": f"{Path(binary).parent}{os.pathsep}{(env or os.environ).get('PATH', os.environ.get('PATH', ''))}"}

    def run(self, *args, interactive: bool = False) -> subprocess.CompletedProcess:
        if interactive:  # let OpenClaw ask the person at the keyboard
            return subprocess.run([self.binary, *args], env=self.env, text=True, timeout=600)
        return subprocess.run([self.binary, *args], env=self.env, capture_output=True, text=True, timeout=600)

    def config_path(self) -> Path:
        if self.env.get("OPENCLAW_CONFIG_PATH"):
            return Path(self.env["OPENCLAW_CONFIG_PATH"])
        state = self.env.get("OPENCLAW_STATE_DIR")
        if state:
            return Path(state) / "openclaw.json"
        home = self.env.get("OPENCLAW_HOME") or os.path.expanduser("~")
        return Path(home) / ".openclaw" / "openclaw.json"


# ---- setup --------------------------------------------------------------------------

def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # O_CREAT's mode only applies to a new file; an existing one keeps its mode otherwise
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def approver_public_key(home: Path, approver: str, passphrase: str | None = None, prompt=ss.prompt_passphrase) -> dict:
    """The approver's public key. Creates the key, sealed under a passphrase, if there is none yet.
    A plaintext approver key is refused: an agent running as you could read it and approve itself."""
    key_path, pub_path = home / "approver.key.json", home / "approver.pub.json"
    if key_path.exists():
        body = json.loads(key_path.read_text())
        if not ss.is_encrypted(body):
            raise ss.KeyFileError(f"{key_path} holds a plaintext key; encrypt it first: synthe-sign protect {key_path}")
        if pub_path.exists():
            return json.loads(pub_path.read_text())
        secret = ss.decrypt_key(body, passphrase if passphrase is not None else prompt("Approver passphrase: "))
        pub = {"kid": body["kid"], "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}
    else:
        secret = sc.generate_secret()
        meta = {"agent": approver, "kid": f"{approver}-approver-1", "alg": sc.ALG}
        sealed = ss.encrypt_key(meta, secret, passphrase if passphrase is not None else ss.new_passphrase(prompt))
        _write_private(key_path, json.dumps(sealed, indent=2) + "\n")
        pub = {"kid": meta["kid"], "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}
    pub_path.write_text(json.dumps(pub, indent=2) + "\n")
    return pub


def _check_scope(branches: list, allowed_paths: list) -> None:
    if not branches or any(b in ("*", "**", "main", "master") for b in branches):
        raise SystemExit("--branches: agents land on their own branches and a human merges; "
                         "'main', 'master' and '*' are refused (try 'agent/*')")
    if not allowed_paths:
        raise SystemExit("--allowed-paths: give at least one glob, e.g. 'src/**'")


def build_registry(approver: str, approver_pub: dict, agent: str, allowed_paths: list,
                   broker_pub: dict | None = None) -> dict:
    """You (approver and sender), the agent (receiver, fail-closed policy) and, once known, the broker."""
    agents = {approver: {"role": "approver and sender", "kind": "human", "keys": [approver_pub]},
              agent: {"role": "receiver", "kind": "agent", "keys": [], "policy": {
                  "allowed_tools": ["read_repo", "edit_files", "run_tests", "git_push"],
                  "forbidden": ["force_push"], "approval_required_for": ["git_push"],
                  "trusted_approvers": [approver], "budget": {"tokens": 500000, "usd": 25, "minutes": 240},
                  "require_signatures": True, "require_signed_approvals": True, "require_planned_actions": True,
                  "max_ttl_hours": DEFAULT_MAX_TTL_HOURS,
                  "allowed_paths": allowed_paths, "forbidden_paths": FORBIDDEN_PATHS,
                  "defaults": {"owned_paths": allowed_paths, "output_schema": "synthe.commit.v1",
                               "budget": {"tokens": 200000, "usd": 10, "minutes": 120}}}}}
    if broker_pub is not None:
        agents[BROKER_ID] = {"role": "commit broker", "kind": "service", "keys": [broker_pub]}
    return {"agents": agents}


def write_setup(home: Path, info: dict) -> None:
    """HOME/setup.json: which broker and workspace this machine uses (no secrets), for the other commands."""
    (home / "setup.json").write_text(json.dumps(info, indent=2) + "\n")


def read_setup(home: Path) -> dict:
    """setup.json, or the dev layout of a setup made before setup.json existed."""
    try:
        return json.loads((home / "setup.json").read_text())
    except (OSError, json.JSONDecodeError):
        b = home / "broker"
        return {"mode": "dev", "broker": f"unix://{home / 'broker.sock'}", "registry": str(b / "registry.json"),
                "broker_config": str(b / "broker.json"), "workspace": str(b / "workspace")}


def readable(branches: list) -> dict:
    """The agent reads the repo through the broker (synthe_client clone/sync), so its account needs no
    GitHub credential at all, even for a private repo: the base branch and its own branches."""
    return {"readable": True, "readable_refs": ["main", "master", *branches]}


def write_broker(home: Path, *, repo_url: str, branches: list, allowed_paths: list, approver: str,
                 approver_pub: dict, agent: str, token_file: Path | None, isolation: str = "none") -> dict:
    """The broker's directory (dev isolation by default). Returns a summary with no secrets in it."""
    _check_scope(branches, allowed_paths)
    b = home / "broker"
    if (b / "broker.json").exists():
        raise SystemExit(f"{b} already holds a broker; move it aside to set up a new one")
    for d in ("keys", "workspace", "state"):
        (b / d).mkdir(parents=True, exist_ok=True)
    os.chmod(b, 0o700)
    secret = sc.generate_secret()
    kid = f"{BROKER_ID}-1"
    _write_private(b / "keys" / f"{BROKER_ID}.key.json",
                   json.dumps({"agent": BROKER_ID, "kid": kid, "alg": sc.ALG, "private_key": sc.b64u(secret)}, indent=2) + "\n")
    remote = {"url": repo_url, "branches": branches, **readable(branches)}
    if token_file is not None:
        token = token_file.expanduser().read_text().strip()
        if not token:
            raise SystemExit(f"{token_file} is empty")
        _write_private(b / "github.token", token + "\n")
        remote["token_file"] = "github.token"
    config = {"broker_id": BROKER_ID, "receiver": agent,
              "key": f"keys/{BROKER_ID}.key.json", "registry": "registry.json",
              "ledger": "ledger.sqlite3", "receipts": "receipts.jsonl", "workspace": "workspace", "state_dir": "state",
              "source_roots": [], "isolation": {"mode": isolation},
              "effects": {"git_push": {"max_commits": 200, "require_approval_commit_pin": True,
                                       "remotes": {"origin": remote}}}}
    (b / "broker.json").write_text(json.dumps(config, indent=2) + "\n")
    broker_pub = {"kid": kid, "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}
    (b / "registry.json").write_text(json.dumps(build_registry(approver, approver_pub, agent, allowed_paths,
                                                               broker_pub), indent=2) + "\n")
    write_setup(home, {"mode": "dev", "broker": f"unix://{home / 'broker.sock'}", "registry": str(b / "registry.json"),
                       "broker_config": str(b / "broker.json"), "workspace": str(b / "workspace"),
                       "remote": {"url": repo_url, "branches": branches}, "receiver": agent})
    return {"broker_dir": str(b), "isolation": isolation, "repo_url": repo_url, "branches": branches,
            "allowed_paths": allowed_paths, "approver": approver, "agent": agent, "token_file": token_file is not None,
            "max_ttl_hours": DEFAULT_MAX_TTL_HOURS}


def broker_address(home: Path) -> str:
    return read_setup(home).get("broker") or f"unix://{home / 'broker.sock'}"


# ---- ENFORCED on macOS: the broker as its own user ------------------------------------

MACOS_STATE = Path("/var/db/synthe")
MACOS_SOCKET = "unix:///var/db/synthe-run/broker.sock"
MACOS_WORKSPACE = Path("/Users/Shared/Synthe/workspace")


GITHUB_TOKEN_PREFIXES = ("github_pat_", "ghp_", "gho_", "ghu_", "ghs_")
OPENCLAW_VERSION = "2026.9.8"  # the version the plugin and these steps were verified with


def prompt_token(stage: Path, repo_url: str, read=None) -> Path:
    """Ask for the GitHub token at the terminal, hidden, and keep it only in the 0700 stage folder
    until the admin step installs it for the broker and deletes this copy. Never echoed, never on
    the clipboard path that broke the first real run."""
    import getpass
    read = read or (lambda: getpass.getpass("GitHub token for the broker (hidden; paste, then Return): "))
    stage.mkdir(parents=True, exist_ok=True)
    os.chmod(stage, 0o700)
    path = stage / "github.token"
    _write_private(path, read().strip() + "\n")
    try:
        check_token_file(path, repo_url)
    except SystemExit:
        path.unlink(missing_ok=True)
        raise
    return path


def prepare(home: Path, *, repo_url: str, branches: list, allowed_paths: list, agent_account: str,
            approver: str, python: str, script_path: Path, node: Path = Path("/opt/homebrew/bin/node")) -> Path:
    """What an agent may do for you: check everything that can be checked without a secret, then
    write the one command you run (finish-setup.sh). It asks for your passphrase, your GitHub token
    and your Mac password, in that order. No secret passes through here."""
    _check_scope(branches, allowed_paths)
    problems = []
    if sys.platform != "darwin":
        problems.append("this setup is for macOS")
    if os.geteuid() == 0:
        problems.append("run prepare as yourself, not root")
    if agent_account == approver:
        problems.append(f"the agent's account must not be yours ({approver}): your account's GitHub login "
                        f"would let the agent push. Pick another name, e.g. openclaw")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", agent_account or ""):
        problems.append(f"{agent_account!r} is not a valid macOS account name")
    if not node.exists():
        problems.append(f"Node isn't at {node}: run `brew install node` (the agent's account needs it for OpenClaw)")
    if not shutil.which("git"):
        problems.append("git is missing: run `xcode-select --install`")
    root = source_root()
    if problems:
        raise SystemExit("can't prepare yet:\n  - " + "\n  - ".join(problems))
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    q = lambda v: "'" + str(v).replace("'", "'\\''") + "'"  # noqa: E731
    finish = home / "finish-setup.sh"
    finish.write_text(f"""#!/bin/bash
# Finish setting up Synthe (written by synthe-init prepare; holds no secret). Run it yourself, in a
# terminal: it asks for your approval passphrase, your GitHub token (hidden) and your Mac password.
set -euo pipefail
cd {q(root)}
{q(python)} {q(script_path)} setup --isolation macos-user --repo-url {q(repo_url)} \\
    --branches {q(",".join(branches))} --allowed-paths {q(",".join(allowed_paths))} \\
    --agent-user {q(agent_account)} --github-token-prompt --no-openclaw --home {q(home)}
echo
echo "Now the one admin step (your Mac password):"
sudo bash {q(home / "enforce-macos.sh")}
""")
    os.chmod(finish, 0o700)
    return finish




def check_token_file(token_file: Path, repo_url: str) -> None:
    """Refuse a token file that can't work, before anything is installed. The first real run saved the
    setup command itself into the token file (the clipboard held the command, not the token); GitHub
    only said 'Invalid username or token' after the approval. Never prints the file's contents."""
    try:
        token = token_file.read_text().strip()
    except OSError:
        token = ""
    if not token:
        raise SystemExit(f"{token_file} is missing or empty")
    if "github.com" in repo_url and (not token.startswith(GITHUB_TOKEN_PREFIXES) or any(c.isspace() for c in token)):
        raise SystemExit(f"{token_file} doesn't hold a GitHub token (one starts with github_pat_ and has no "
                         f"spaces). Save the token again: the file may hold something else from your clipboard.")


def source_root() -> Path:
    """The Synthe source directory (it holds deploy/macos/install.sh and src/): next to this file in a
    checkout or an editable install, else the directory you run synthe-init from."""
    for c in (Path(__file__).resolve().parent.parent, Path.cwd()):
        if (c / "deploy" / "macos" / "install.sh").is_file() and (c / "src" / "synthe_commit.py").is_file():
            return c
    raise SystemExit("run synthe-init setup from the Synthe source directory (the one with deploy/macos/install.sh)")


def base_python() -> str | None:
    """The interpreter behind the environment running setup. It already built a working venv, so the
    system venv gets the same one (on a clean Mac the installer picked a different, broken Homebrew
    Python). None if it lives in a home folder: the broker's hidden user couldn't run it from there."""
    p = getattr(sys, "_base_executable", None) or sys.executable
    if not p or not os.path.isabs(p) or os.path.realpath(p).startswith("/Users/"):
        return None
    return p


def stage_macos(home: Path, *, repo_url: str, branches: list, allowed_paths: list, approver: str,
                approver_pub: dict, agent: str, agent_user: str, token_file: Path | None, repo_root: Path,
                workspace: Path = MACOS_WORKSPACE, base_python: str | None = "auto") -> Path:
    """Everything the one sudo step needs, prepared as you: the registry and config to merge into the
    broker (which deploy/macos/install.sh creates as the hidden user _synthe), a workspace both you
    and the broker can read, setup.json, and the script to run with sudo. Returns the script's path.
    No secret is copied: the script reads the token file you named, as root, and installs it 0600."""
    _check_scope(branches, allowed_paths)
    if base_python == "auto":
        base_python = globals()["base_python"]()
    if token_file is not None:
        token_file = token_file.expanduser().resolve()
        check_token_file(token_file, repo_url)
    installer = repo_root / "deploy" / "macos" / "install.sh"
    if not installer.exists():
        raise SystemExit(f"no installer at {installer}: run synthe-init from a Synthe checkout")
    stage = home / "macos-stage"
    stage.mkdir(parents=True, exist_ok=True)
    os.chmod(stage, 0o700)
    (stage / "registry.json").write_text(json.dumps(build_registry(approver, approver_pub, agent, allowed_paths),
                                                    indent=2) + "\n")
    remote = {"url": repo_url, "branches": branches, **({"token_file": "github.token"} if token_file else {}),
              **readable(branches)}
    (stage / "config-patch.json").write_text(json.dumps({"workspace": str(workspace), "remote": remote,
                                                          "receiver": agent},
                                                        indent=2) + "\n")
    workspace.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace, 0o755)  # the broker (_synthe) reads task files here; it never writes them
    write_setup(home, {"mode": "macos-user", "broker": MACOS_SOCKET, "registry": str(stage / "registry.json"),
                       "broker_config": str(MACOS_STATE / "broker.json"), "workspace": str(workspace),
                       "remote": {"url": repo_url, "branches": branches}, "receiver": agent})
    q = lambda v: "'" + str(v).replace("'", "'\\''") + "'"  # noqa: E731  (single-quote for the shell)
    script = home / "enforce-macos.sh"
    script.write_text(f"""#!/bin/bash
# Make Synthe ENFORCED on this Mac: the commit broker runs as its own hidden user, _synthe, so an
# agent running as {agent_user} can't read its key or the GitHub token. Run once, with sudo:
#     sudo bash {script}
# It runs deploy/macos/install.sh, merges the config synthe-init staged, installs the token (never
# printed), checks the broker and starts it. Written by synthe-init; holds no secret.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || {{ echo "run it with sudo: sudo bash $0" >&2; exit 2; }}
REPO={q(repo_root)}
AGENT_USER={q(agent_user)}
STAGE={q(stage)}
TOKEN={q(token_file) if token_file else "''"}
TOKEN_STAGED={1 if token_file is not None and token_file.parent == stage.resolve() else 0}
STATE={q(MACOS_STATE)}
APP=/Library/Synthe
BPY="$APP/venv/bin/python"
PLIST=/Library/LaunchDaemons/com.synthe.broker.plist

APPROVER="${{SUDO_USER:-}}"
SEPARATE=0
if [ -n "$APPROVER" ] && [ "$APPROVER" != root ] && [ "$AGENT_USER" != "$APPROVER" ]; then SEPARATE=1; fi
if [ "$SEPARATE" = 1 ] && ! id -u "$AGENT_USER" >/dev/null 2>&1; then
  # The agent gets its own macOS account: no GitHub login, no approver key, nothing of yours to read.
  sysadminctl -addUser "$AGENT_USER" -fullName "Synthe agent ($AGENT_USER)" \\
    -password "$(openssl rand -base64 24)" -home "/Users/$AGENT_USER" >/dev/null 2>&1
  createhomedir -c -u "$AGENT_USER" >/dev/null 2>&1 || true
  echo "Created the macOS account $AGENT_USER for the agent (use: sudo -iu $AGENT_USER)."
fi

cd /  # _synthe runs steps below and can't enter a home folder (found on a clean Mac)
"$REPO/deploy/macos/install.sh" --agent-user "$AGENT_USER"{" --python " + q(base_python) if base_python else ""}
"$BPY" "$APP/src/synthe_init.py" apply-config --state "$STATE" --stage "$STAGE"
if [ -n "$TOKEN" ]; then install -o _synthe -g _synthe -m 600 "$TOKEN" "$STATE/github.token"; fi
if [ "$TOKEN_STAGED" = 1 ]; then rm -f "$TOKEN"; TOKEN=''; fi  # a prompted token: the broker has its copy now
chown _synthe:_synthe "$STATE/registry.json" "$STATE/broker.json"
chmod 600 "$STATE/registry.json" "$STATE/broker.json"
sudo -u _synthe env HOME="$STATE" "$BPY" "$APP/src/synthe_commit.py" doctor --config "$STATE/broker.json"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"

if [ "$SEPARATE" = 1 ]; then
  chmod 700 "/Users/$APPROVER"  # other accounts, the agent's included, can't browse yours
  bash "$REPO/deploy/macos/add-agent-user.sh" --agent-user "$AGENT_USER" --approver-user "$APPROVER"
  cd /  # the agent's account can't enter yours; don't start its processes there
  AS_AGENT=(sudo -u "$AGENT_USER" -H env "PATH=/Users/$AGENT_USER/.local/bin:/opt/homebrew/bin:/usr/bin:/bin")
  if [ ! -x "/Users/$AGENT_USER/.local/bin/openclaw" ]; then
    echo "Installing OpenClaw {OPENCLAW_VERSION} for $AGENT_USER..."
    "${{AS_AGENT[@]}}" npm install -g -q {q("openclaw@" + OPENCLAW_VERSION)} --prefix "/Users/$AGENT_USER/.local"
  fi
  "${{AS_AGENT[@]}}" "$APP/venv/bin/synthe-init" agent-setup --yes
  # git finds remote helpers on PATH: with git-remote-synthe there, a plain `git push` in the agent's clone
  # (whose origin is Synthe) becomes a proposal, for any agent or tool, not only OpenClaw.
  "${{AS_AGENT[@]}}" mkdir -p "/Users/$AGENT_USER/.local/bin"
  "${{AS_AGENT[@]}}" ln -sf "$APP/venv/bin/git-remote-synthe" "/Users/$AGENT_USER/.local/bin/git-remote-synthe"
  # The gateway (where the plugin acts) runs as the agent's account, started by launchd: nobody has to
  # keep a window open. It restarts if it stops; its log is in the agent's home.
  GW_PLIST=/Library/LaunchDaemons/com.synthe.openclaw-gateway.plist
  cat > "$GW_PLIST" <<GWEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.synthe.openclaw-gateway</string>
  <key>UserName</key><string>$AGENT_USER</string>
  <key>ProgramArguments</key><array>
    <string>/Users/$AGENT_USER/.local/bin/openclaw</string><string>gateway</string><string>run</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>HOME</key><string>/Users/$AGENT_USER</string>
    <key>PATH</key><string>/Users/$AGENT_USER/.local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>
  <key>WorkingDirectory</key><string>/Users/$AGENT_USER</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Users/$AGENT_USER/.openclaw/gateway.log</string>
  <key>StandardOutPath</key><string>/Users/$AGENT_USER/.openclaw/gateway.log</string>
</dict></plist>
GWEOF
  chown root:wheel "$GW_PLIST"
  chmod 644 "$GW_PLIST"
  plutil -lint "$GW_PLIST" >/dev/null
  launchctl bootout system "$GW_PLIST" 2>/dev/null || true
  launchctl bootstrap system "$GW_PLIST" \\
    || echo "(couldn't start the gateway service; start it yourself: sudo -iu $AGENT_USER, then openclaw gateway run)"
  CLONE="/Users/$AGENT_USER/repo"
  # Through the broker: the agent's account has no GitHub credential, not even to read (private repos too).
  [ -d "$CLONE/.git" ] || "${{AS_AGENT[@]}}" "$APP/venv/bin/synthe-client" --broker {q(MACOS_SOCKET)} clone "$CLONE" >/dev/null \\
    || echo "(couldn't clone through the broker; see: sudo -iu $AGENT_USER, then synthe-client clone ~/repo)"
  echo
  "${{AS_AGENT[@]}}" "$APP/venv/bin/synthe-init" doctor --repo "$CLONE" || true
  echo
  echo "Last step, yours: give OpenClaw its model. Its gateway (where the plugin acts) is already running."
  echo "  sudo -iu $AGENT_USER"
  echo '  export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH" && openclaw onboard'
  echo '  export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH" && cd ~/repo && openclaw tui'
else
  echo
  echo "The broker runs as _synthe (uid $(id -u _synthe)). Next, as yourself:"
  echo "  synthe-init doctor --repo PATH/TO/YOUR/CLONE        (expect ENFORCED)"
  [ -n "$TOKEN" ] && echo "  rm $TOKEN        (the broker holds its own copy now)" || true
fi
""")
    os.chmod(script, 0o700)
    return script


def apply_config(state: Path, stage: Path) -> dict:
    """Run by the sudo script, as root: merge the staged registry and config into the broker's state.
    The broker's public key comes from its own key file, so the registry names the right broker."""
    cfg_path, key_path = state / "broker.json", state / "keys" / f"{BROKER_ID}.key.json"
    cfg = json.loads(cfg_path.read_text())
    key = json.loads(key_path.read_text())
    broker_pub = {"kid": key["kid"], "alg": sc.ALG,
                  "public_key": sc.b64u(sc.public_key(sc.unb64u(key["private_key"])))}
    registry = json.loads((stage / "registry.json").read_text())
    registry["agents"][BROKER_ID] = {"role": "commit broker", "kind": "service", "keys": [broker_pub]}
    patch = json.loads((stage / "config-patch.json").read_text())
    if (cfg.get("isolation") or {}).get("mode") != "user":
        raise SystemExit(f"{cfg_path}: isolation mode is not 'user'; refusing to change it")
    cfg["workspace"] = patch["workspace"]
    cfg["receiver"] = patch["receiver"]
    cfg["ledger"] = "ledger.sqlite3"
    git_push = cfg.setdefault("effects", {}).setdefault("git_push", {})
    git_push.update({"max_commits": 200, "require_approval_commit_pin": True, "remotes": {"origin": patch["remote"]}})
    _write_private(state / "registry.json", json.dumps(registry, indent=2) + "\n")
    _write_private(cfg_path, json.dumps(cfg, indent=2) + "\n")
    return {"broker_kid": broker_pub["kid"], "workspace": cfg["workspace"], "remote": patch["remote"]["url"]}


def apply_registry(state: Path, stage: Path) -> dict:
    """Run as root by deploy/macos/upgrade.sh: install the staged registry (a new approval key, say)
    without touching the broker's config. The broker's own entry always comes from its key file."""
    key = json.loads((state / "keys" / f"{BROKER_ID}.key.json").read_text())
    registry = json.loads((stage / "registry.json").read_text())
    registry.setdefault("agents", {})[BROKER_ID] = {
        "role": "commit broker", "kind": "service",
        "keys": [{"kid": key["kid"], "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(sc.unb64u(key["private_key"])))}]}
    _write_private(state / "registry.json", json.dumps(registry, indent=2) + "\n")
    return {"approval_keys": {n: [k.get("kid") for k in a.get("keys", [])] for n, a in registry["agents"].items()
                              if a.get("kind") == "human"}}


def add_approval_key(registry_path: Path, entry: dict) -> str:
    """Append an approval key (e.g. Touch ID's ES256 key) to the one human approver's entry. Returns the
    approver's id. The existing keys stay: the passphrase key is the fallback."""
    registry = json.loads(registry_path.read_text())
    humans = [n for n, a in (registry.get("agents") or {}).items() if (a or {}).get("kind") == "human"]
    if len(humans) != 1:
        raise SystemExit(f"{registry_path} has {len(humans)} human approvers; add the key by hand")
    keys = registry["agents"][humans[0]].setdefault("keys", [])
    if any(k.get("kid") == entry["kid"] for k in keys):
        raise SystemExit(f"{registry_path} already has a key named {entry['kid']}")
    keys.append(entry)
    mode = registry_path.stat().st_mode & 0o777
    registry_path.write_text(json.dumps(registry, indent=2) + "\n")
    os.chmod(registry_path, mode)
    return humans[0]


def touchid_setup(home: Path) -> int:
    """Make a Touch ID approval key and register it next to the passphrase key."""
    import synthe_touchid as st
    ui = sui.UI()
    print(ui.header("touch id"))
    setup = read_setup(home)
    reg = Path(setup.get("registry") or home / "broker" / "registry.json")
    if not reg.is_file():
        raise SystemExit(f"no registry at {reg}: run synthe-init setup first")
    registry = json.loads(reg.read_text())
    humans = [n for n, a in (registry.get("agents") or {}).items() if (a or {}).get("kind") == "human"]
    if len(humans) != 1:
        raise SystemExit(f"{reg} has {len(humans)} human approvers; this sets up one")
    try:
        entry = st.enroll(home, humans[0], source_root())
    except st.TouchIDError as e:
        raise SystemExit(f"Touch ID can't be set up: {e}")
    add_approval_key(reg, entry)
    print(ui.check("PASS", "touch id key", f"{entry['kid']}: made in this Mac's Secure Enclave; it signs only "
                                          f"after a Touch ID check with today's fingerprints", 16))
    print(ui.check("PASS", "registered", f"next to your passphrase key (the fallback) in {reg}", 16))
    if setup.get("mode") == "macos-user":
        print("\nOne admin step makes the broker accept it (it also updates the installed Synthe code):")
        print(ui.cmd(f"sudo bash {source_root() / 'deploy' / 'macos' / 'upgrade.sh'}") if ui.color
              else f"\n  sudo bash {source_root() / 'deploy' / 'macos' / 'upgrade.sh'}\n")
    print("\nThen synthe-approve asks for your finger instead of your passphrase "
          "(synthe-approve --passphrase still uses the passphrase key).")
    return 0


def wire_openclaw(oc: OpenClaw, home: Path, assume_yes: bool) -> list:
    """Add the MCP server, the plugin and the skill to OpenClaw. Returns [(step, ok, detail)]."""
    integ = integration_dir()
    if integ is None:
        return [("openclaw files", False, "the OpenClaw plugin and skill were not found next to this install")]
    mcp = shutil.which("synthe-mcp") or str(Path(sys.executable).parent / "synthe-mcp")
    steps = []

    def step(name, *args, interactive=False):
        r = oc.run(*args, interactive=interactive)
        lines = [] if interactive else (r.stderr or r.stdout or "").strip().splitlines()
        steps.append((name, r.returncode == 0, lines[-1][:200] if lines else ""))
        return r.returncode == 0

    oc.run("mcp", "unset", MCP_NAME)  # re-running setup replaces our own entry, nothing else
    mcp_args = ["mcp", "add", MCP_NAME, "--command", mcp, "--arg", "--broker-url",
                "--arg", broker_address(home)]
    receiver = read_setup(home).get("receiver")
    if receiver:
        mcp_args += ["--arg", "--as-receiver", "--arg", receiver]
    step("mcp server", *mcp_args, "--no-probe")
    step("mcp tool filter", "mcp", "tools", MCP_NAME, "--exclude", "synthe_submit_approval")
    install = ["plugins", "install", "-l", str(integ / "plugin")]
    if assume_yes:
        install += ["--force", "--accept-capabilities"]
    step("barrier plugin", *install, interactive=not assume_yes)
    step("plugin broker address", "config", "set", f"plugins.entries.{PLUGIN_ID}.config.brokerSocket", broker_address(home))
    # The status line ("a push waits for your approval") is a before_prompt_build hook, which OpenClaw
    # blocks for non-bundled plugins unless they're allowed conversation access (seen live, 2026-10-07).
    step("plugin status line", "config", "set", f"plugins.entries.{PLUGIN_ID}.hooks.allowConversationAccess", "true")
    step("skill", "skills", "install", str(integ / "skill" / "synthe"), "--force")
    return steps


def configure_gateway(oc) -> list:
    """The gateway is where the plugin acts (embedded `tui --local` skips it): local only, loopback,
    token auth. An existing token is kept, so re-running doesn't log anyone out."""
    import secrets
    steps = []
    for name, key, value in (("gateway mode", "gateway.mode", "local"), ("gateway bind", "gateway.bind", "loopback"),
                             ("gateway auth", "gateway.auth.mode", "token")):
        r = oc.run("config", "set", key, value)
        steps.append((name, r.returncode == 0, (r.stderr or "").strip()[-200:]))
    have = oc.run("config", "get", "gateway.auth.token")
    if have.returncode != 0 or not (have.stdout or "").strip():
        r = oc.run("config", "set", "gateway.auth.token", secrets.token_hex(24))
        steps.append(("gateway token", r.returncode == 0, ""))
    return steps


def agent_setup(home: Path, oc, agent: str, assume_yes: bool) -> int:
    """The agent's own macOS account (a different user from the approver): point OpenClaw at the
    separate-user broker. This account gets no approver key and no GitHub token; it only proposes."""
    if (home / "approver.key.json").exists():
        raise SystemExit(f"{home} holds an approver key: run agent-setup in the agent's own account, not yours")
    if oc is None:
        raise SystemExit("OpenClaw was not found in this account; install it here first")
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    write_setup(home, {"mode": "macos-user", "role": "agent", "broker": MACOS_SOCKET,
                       "workspace": str(MACOS_WORKSPACE), "receiver": agent})
    steps = wire_openclaw(oc, home, assume_yes) + configure_gateway(oc)
    ui = sui.UI()
    print(ui.header("agent setup"))
    print_wiring(ui, steps)
    print_next(ui, [("Check the level in this account (expect ENFORCED)",
                     f"synthe-init doctor --home {home} --repo ~/repo")])
    return 0 if all(ok for _, ok, _ in steps) else 1


# ---- doctor -------------------------------------------------------------------------

def _json(r: subprocess.CompletedProcess):
    try:
        return json.loads(r.stdout)
    except (json.JSONDecodeError, TypeError):
        return None


def openclaw_checks(oc: OpenClaw | None) -> list:
    out = []

    def add(status, check, detail):
        out.append({"status": status, "check": check, "detail": detail})

    if oc is None:
        add("WARN", "openclaw", "the openclaw CLI was not found; nothing blocks an OpenClaw agent's direct pushes")
        return out
    ins = _json(oc.run("plugins", "inspect", PLUGIN_ID, "--runtime", "--json")) or {}
    plugin = ins.get("plugin") or {}
    hooks = {h.get("name") for h in ins.get("typedHooks") or []}
    if plugin.get("status") == "loaded" and plugin.get("enabled") and "before_tool_call" in hooks:
        add("PASS", "barrier plugin", "synthe-barrier is loaded and blocks direct pushes (before_tool_call)")
        # Seen live (2026-10-07): through the gateway it blocked every push; in `openclaw tui --local` /
        # `openclaw chat` (embedded) it never ran, and only the wall (no credential) stopped the pushes.
        add("WARN", "barrier plugin mode", "it acts only through the OpenClaw gateway (setup runs it as a service; "
                                           "connect with openclaw tui); `tui --local` and `chat` skip it, "
                                           "leaving only the wall")
    else:
        add("FAIL", "barrier plugin", f"synthe-barrier is not loaded and active (status {plugin.get('status')!r}); "
                                      f"run synthe-init setup again")
    skill = _json(oc.run("skills", "info", "synthe", "--json")) or {}
    skill = skill.get("skill", skill)
    add("PASS" if skill.get("eligible") else "WARN", "synthe skill",
        "the synthe skill is installed and eligible" if skill.get("eligible") else "the synthe skill is missing or ineligible")
    show = _json(oc.run("mcp", "show", MCP_NAME, "--json"))
    add("PASS" if show else "FAIL", "mcp server", f"OpenClaw has the {MCP_NAME} MCP server" if show
        else f"OpenClaw has no {MCP_NAME} MCP server; run synthe-init setup again")
    try:
        cfg = json.loads(oc.config_path().read_text())
    except (OSError, json.JSONDecodeError):
        cfg = {}
    github = (cfg.get("tools") or {}).get("github")
    per_agent = [a for a, v in ((cfg.get("agents") or {}).get("entries") or {}).items()
                 if isinstance(v, dict) and (v.get("tools") or {}).get("github")]
    if github or per_agent:
        add("FAIL", "openclaw github identity", "OpenClaw gives agents a GitHub identity (tools.github): an agent "
                                                "could publish around Synthe; remove it from OpenClaw's config")
    else:
        add("PASS", "openclaw github identity", "OpenClaw gives agents no GitHub identity of its own")
    return out


def host_checks(home: Path) -> list:
    out = []

    def add(status, check, detail):
        out.append({"status": status, "check": check, "detail": detail})

    key = home / "approver.key.json"
    agent_only = read_setup(home).get("role") == "agent"
    if agent_only and not key.exists():
        add("PASS", "approver key", "this is the agent's account and holds no approver key: approvals are signed "
                                    "in the approver's own account")
    elif not key.exists():
        add("FAIL", "approver key", f"no approver key at {key}; run synthe-init setup")
    else:
        try:
            sealed = ss.is_encrypted(json.loads(key.read_text()))
        except (OSError, json.JSONDecodeError):
            sealed = False
        add("PASS" if sealed else "FAIL", "approver key",
            "your approver key needs your passphrase to sign" if sealed else
            f"{key} is plaintext: an agent running as you could read it and approve itself "
            f"(synthe-sign protect {key})")
    if shutil.which("gh") and subprocess.run(["gh", "auth", "status"], capture_output=True).returncode == 0:
        add("FAIL", "gh login", "the GitHub CLI is logged in as this user, so an agent running as you can push "
                                "or merge with it: gh auth logout")
    if subprocess.run(["git", "config", "--global", "--get", "credential.helper"], capture_output=True,
                      text=True).stdout.strip():
        add("WARN", "git credential helper", "git has a credential helper (keychain or store): saved GitHub "
                                             "credentials let anything running as you push; remove them for github.com")
    return out


def level(checks: list) -> str:
    fails = {c["check"] for c in checks if c["status"] == "FAIL"}
    iso = [c["status"] for c in checks if c["check"] == "broker isolation"]
    # PASS = a separate OS user, kernel-checked. WARN = a declared container, a wall only if this user
    # can't control the container runtime (else it can enter the container and read the keys).
    runtime = any(c["check"] == "container runtime" for c in checks)
    isolation_ok = bool(iso) and "FAIL" not in iso and ("PASS" in iso or not runtime)
    guard_fails = fails - {"broker isolation"}
    if not fails and isolation_ok:
        return "ENFORCED"
    if not guard_fails and any(c["check"] == "barrier plugin" and c["status"] == "PASS" for c in checks):
        return "GUARDED"
    return "ADVISORY"


def run_doctor(home: Path, oc: OpenClaw | None, repo: str | None = None, broker: str | None = None) -> dict:
    import synthe_client as scl
    checks = host_checks(home)
    try:
        client = scl.BrokerClient(broker or broker_address(home))
        checks += scl.doctor(client, repo=repo, git_remote="origin" if repo else None)
    except scl.BrokerError as e:
        checks.append({"status": "FAIL", "check": "broker isolation", "detail": f"no broker answers: {e}"})
    checks += openclaw_checks(oc)
    return {"level": level(checks), "checks": checks}


LEVEL_MEANING = {
    "ADVISORY": "The agent can still push or approve on its own. Synthe is a checker it may use.",
    "GUARDED": "Direct pushes are blocked and the agent holds no credentials, but the broker runs as your own "
               "user, so the agent could read its key and token. For ENFORCED, run the broker as its own user "
               "(synthe-init prepare, then finish-setup).",
    "ENFORCED": "The agent can't push or approve on its own: only the broker pushes, after your "
                "passphrase-signed approval.",
}


def print_next(ui, steps: list) -> None:
    """Numbered next steps; each command on its own line, so it's easy to copy."""
    print("\n" + ui.c("Next", "brand", bold=True) if ui.color else "\nNext:")
    for i, (text, command) in enumerate(steps, 1):
        if ui.color:
            print(ui.step(i, text))
            if command:
                print(ui.cmd(command))
        else:
            print(f"  {i}. {text}" + (f":  {command}" if command else ""))


def print_wiring(ui, steps: list) -> None:
    for name, ok, detail in steps:
        if ui.color:
            print(ui.check("PASS" if ok else "FAIL", f"OpenClaw {name}", detail if not ok else "", 28))
        else:
            print(f"  {'ok ' if ok else 'FAILED'}  OpenClaw {name}" + (f": {detail}" if detail and not ok else ""))


def print_report(report: dict, ui=None) -> None:
    ui = ui or sui.UI()
    lvl, checks = report["level"], report["checks"]
    if not ui.color:  # plain: the same lines agents and scripts have always read
        print(f"\nEnforcement level: {lvl}")
        print("  " + LEVEL_MEANING[lvl])
        for c in checks:
            print(ui.check(c["status"], c["check"], c["detail"]))
        return
    counts = {k: sum(c["status"] == k for c in checks) for k in ("PASS", "WARN", "FAIL")}
    tally = "  ".join(ui.c(f"{n} {word}", role) for n, word, role in
                      ((counts["PASS"], "passed", "ok"),
                       (counts["WARN"], "warning" if counts["WARN"] == 1 else "warnings", "warn"),
                       (counts["FAIL"], "failed", "bad")) if n)
    print()
    print(ui.banner([ui.c("synthe", "brand", bold=True) + "  " + ui.c("doctor", "muted"), "",
                     ui.level(lvl), tally]))
    print()
    print("  " + LEVEL_MEANING[lvl])
    print("  " + ui.rule(70))
    width = max(len(c["check"]) for c in checks) + 2 if checks else 20
    order = {"FAIL": 0, "WARN": 1, "PASS": 2}
    for c in sorted(checks, key=lambda c: order.get(c["status"], 3)):  # what to fix first, first
        print(ui.check(c["status"], c["check"], c["detail"], width))
    print()


# ---- CLI ----------------------------------------------------------------------------

def _csv(s: str) -> list:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Set up Synthe for an OpenClaw agent, and check how strong it is.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="create keys, the broker and the OpenClaw wiring")
    s.add_argument("--repo-url", required=True, help="the repo the broker pushes to (https://… or a path)")
    s.add_argument("--branches", default="agent/*", help="comma-separated branch patterns the agent may push")
    s.add_argument("--allowed-paths", required=True, help="comma-separated globs the agent may change, e.g. 'src/**'")
    s.add_argument("--github-token-file", help="a file holding a fine-grained token (Contents: write) for the repo")
    s.add_argument("--approver", default=os.environ.get("USER") or "human", help="your name as approver")
    s.add_argument("--agent", default="openclaw", help="the agent's id")
    s.add_argument("--home", default="~/.synthe")
    s.add_argument("--isolation", choices=["dev", "macos-user"], default="dev",
                   help="dev: the broker runs as you (GUARDED at best). macos-user: prepare the one sudo step "
                        "that runs it as its own user (ENFORCED)")
    s.add_argument("--agent-user", default=os.environ.get("USER"), help="macos-user: the macOS user OpenClaw runs as")
    s.add_argument("--github-token-prompt", action="store_true",
                   help="ask for the GitHub token at the terminal (hidden) instead of reading a file")
    s.add_argument("--no-openclaw", action="store_true", help="don't change OpenClaw's configuration")
    s.add_argument("--yes", action="store_true", help="install the OpenClaw plugin without OpenClaw asking you")
    ab = sub.add_parser("about", help="what Synthe is (with the logo's intro)")
    ab.add_argument("--style", choices=["lock", "draw", "spin"], default="lock", help="which intro to play")
    pr = sub.add_parser("prepare", help="(safe for an agent) check this Mac and write the one command you run "
                                        "to finish setup")
    pr.add_argument("--repo-url", required=True)
    pr.add_argument("--branches", default="agent/*")
    pr.add_argument("--allowed-paths", required=True)
    pr.add_argument("--agent-account", default="openclaw", help="the macOS account the agent runs as (created if missing)")
    pr.add_argument("--home", default="~/.synthe")
    d = sub.add_parser("doctor", help="report the enforcement level and every check")
    d.add_argument("--home", default="~/.synthe")
    d.add_argument("--repo", help="the agent's repo, to test whether it can push on its own")
    d.add_argument("--broker", help="broker address (default unix://HOME/broker.sock)")
    d.add_argument("--json", action="store_true")
    v = sub.add_parser("serve", help="run the broker in the foreground (dev isolation: as your own user)")
    v.add_argument("--home", default="~/.synthe")
    g = sub.add_parser("agent-setup", help="in the agent's own macOS account: wire OpenClaw to the separate-user "
                                           "broker (no keys, no token)")
    g.add_argument("--home", default="~/.synthe")
    g.add_argument("--agent", default="openclaw", help="the agent's id (the broker's receiver)")
    g.add_argument("--yes", action="store_true", help="install the OpenClaw plugin without OpenClaw asking you")
    t = sub.add_parser("touchid", help="approve with Touch ID: make a Secure Enclave key and register it")
    t.add_argument("--home", default="~/.synthe")
    r = sub.add_parser("apply-registry", help=argparse.SUPPRESS)  # run by deploy/macos/upgrade.sh, as root
    r.add_argument("--state", required=True)
    r.add_argument("--stage", required=True)
    c = sub.add_parser("apply-config", help=argparse.SUPPRESS)  # run by enforce-macos.sh, as root
    c.add_argument("--state", required=True)
    c.add_argument("--stage", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "about":  # needs no setup, no --home, no OpenClaw
        ui = sui.UI()
        lines = [*ui.wordmark(), "", ui.c(sui.PROMISE, "muted"), "", ui.c("synthe.live", "brand")]
        if not sui.intro(ui, lines, style=a.style):
            print(ui.banner(lines))
        return 0
    if a.cmd == "apply-config":  # runs as root with no --home and no OpenClaw
        print(json.dumps(apply_config(Path(a.state), Path(a.stage)), indent=2))
        return 0
    if a.cmd == "apply-registry":  # runs as root with no --home and no OpenClaw
        print(json.dumps(apply_registry(Path(a.state), Path(a.stage)), indent=2))
        return 0
    if a.cmd == "touchid":
        return touchid_setup(Path(a.home).expanduser())
    home = Path(a.home).expanduser()
    oc_bin = find_openclaw()
    oc = OpenClaw(oc_bin) if oc_bin else None

    if a.cmd == "prepare":
        finish = prepare(home, repo_url=a.repo_url, branches=_csv(a.branches), allowed_paths=_csv(a.allowed_paths),
                         agent_account=a.agent_account, approver=os.environ.get("USER") or "",
                         python=sys.executable, script_path=Path(__file__).resolve())
        ui = sui.UI()
        print(ui.header("prepare"))
        print(ui.check("PASS", "this Mac is ready", "macOS, Node, git, the source folder, the scope", 20))
        print("\nAsk the person at this Mac to run this in their own terminal:")
        print(ui.cmd(f"bash {finish}") if ui.color else f"\n  bash {finish}\n")
        print(("\n" if ui.color else "") + "It asks for their approval passphrase, the GitHub token (hidden) and their "
              "Mac password.\n" + ui.c("Never ask for or handle any of those yourself.", "warn", bold=True))
        return 0

    if a.cmd == "agent-setup":
        return agent_setup(home, oc, a.agent, a.yes)

    if a.cmd == "serve":
        cfg = home / "broker" / "broker.json"
        if not cfg.exists():
            raise SystemExit(f"no broker at {cfg}; run synthe-init setup first")
        import synthe_commit as cm
        return cm.main(["serve", "--config", str(cfg), "--socket", str(home / "broker.sock")])

    if a.cmd == "doctor":
        report = run_doctor(home, oc, a.repo, a.broker)
        if home.exists():
            path = home / "setup-report.json"
            try:
                saved = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                saved = {}
            path.write_text(json.dumps({**saved, "doctor": report}, indent=2) + "\n")
        print(json.dumps(report, indent=2)) if a.json else print_report(report)
        return 0

    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    ui = sui.UI()
    if ui.color:
        lines = [*ui.wordmark(), "", ui.kv("setup", str(home), 6).strip()]
        if not sui.intro(ui, lines, style="spin"):  # once, at the start of an interactive setup
            print(ui.banner(lines))
        print()
    else:
        print(f"Setting up Synthe in {home}")
    token = Path(a.github_token_file).expanduser() if a.github_token_file else None
    # Everything that can fail without you is checked before you choose a passphrase.
    _check_scope(_csv(a.branches), _csv(a.allowed_paths))
    if token is not None:
        check_token_file(token, a.repo_url)
    root = source_root() if a.isolation == "macos-user" else None
    if a.github_token_prompt:
        if a.isolation != "macos-user":
            raise SystemExit("--github-token-prompt is for --isolation macos-user")
        token = prompt_token(home / "macos-stage", a.repo_url)
    pub = approver_public_key(home, a.approver)
    script = None
    if a.isolation == "macos-user":
        script = stage_macos(home, repo_url=a.repo_url, branches=_csv(a.branches),
                             allowed_paths=_csv(a.allowed_paths), approver=a.approver, approver_pub=pub,
                             agent=a.agent, agent_user=a.agent_user, token_file=token, repo_root=root)
        summary = {"isolation": "macos-user", "script": str(script), "repo_url": a.repo_url}
    else:
        summary = write_broker(home, repo_url=a.repo_url, branches=_csv(a.branches),
                               allowed_paths=_csv(a.allowed_paths), approver=a.approver, approver_pub=pub,
                               agent=a.agent, token_file=token)
        if token:
            print(f"  The broker now holds the GitHub token. Delete {token} (it is still a plaintext copy).")
    steps = []
    if not a.no_openclaw:
        if oc is None:
            print("  OpenClaw not found: skipping its wiring (install it, then run synthe-init setup again)")
        else:
            steps = wire_openclaw(oc, home, a.yes)
            print_wiring(ui, steps)
    report = {"setup": summary, "openclaw": [{"step": n, "ok": ok} for n, ok, _ in steps]}
    (home / "setup-report.json").write_text(json.dumps(report, indent=2) + "\n")
    approve = f"SYNTHE_BROKER={MACOS_SOCKET if script else broker_address(home)} synthe-approve"
    task = 'synthe-task new "what to do" --branch agent/<name>'
    if script is not None and a.github_token_prompt:  # finish-setup runs the admin step next, by itself
        print(("\n" if ui.color else "") + ui.check("PASS", "your key and the token are staged",
                                                  "nothing secret left your account", 34))
        return 0
    if script is not None:
        print_next(ui, [("Run the one admin step (it asks for your Mac password)", f"sudo bash {script}"),
                        ("Check the level (expect ENFORCED)", "synthe-init doctor --repo PATH/TO/YOUR/CLONE"),
                        ("Give OpenClaw a task", task), ("Approve its push after reading the diff", approve)])
        return 0
    print_next(ui, [("Start the broker (dev isolation, as you)", f"synthe-init serve --home {home}"),
                    ("Check the level", "synthe-init doctor --repo PATH/TO/YOUR/CLONE"),
                    ("Give OpenClaw a task", task), ("Approve its push after reading the diff", approve)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
