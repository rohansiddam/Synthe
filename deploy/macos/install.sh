#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
# Install the Synthe commit broker as a hidden system user on macOS (launchd).
#
#   sudo deploy/macos/install.sh --agent-user "$USER" [--python /opt/homebrew/bin/python3]
#   sudo deploy/macos/install.sh --uninstall [--purge]
#
# Creates the hidden user and group `_synthe` (uid/gid below 500), copies the
# code to /Library/Synthe/src (root-owned), makes /Library/Synthe/venv with
# `cryptography`, creates the broker key and config in /var/db/synthe (0700,
# owned by _synthe) with isolation mode "user" and clients = [AGENT_USER], and
# installs /Library/LaunchDaemons/com.synthe.broker.plist. The plist is world-
# readable, so it never holds a token: the GitHub token goes in a 0600 file
# only _synthe can read. It does NOT start the broker (steps printed at the end).
#
# UNTESTED until Rishab runs it (it needs sudo). docs/ISOLATION.md has the
# checks to run afterwards.
set -euo pipefail

LABEL=com.synthe.broker
PLIST=/Library/LaunchDaemons/$LABEL.plist
STATE=/var/db/synthe
RUN=/var/db/synthe-run           # socket dir: 0755, writable only by _synthe
APP=/Library/Synthe
AGENT_USER= PY= UNINSTALL=0 PURGE=0
while [ $# -gt 0 ]; do
  case $1 in
    --agent-user) AGENT_USER=$2; shift 2 ;;
    --python) PY=$2; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(uname -s)" = Darwin ] || { echo "macOS only" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: it creates a system user and a LaunchDaemon" >&2; exit 2; }

if [ "$UNINSTALL" = 1 ]; then
  launchctl bootout system "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  rm -rf "$APP" "$RUN"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$STATE"   # the broker key, ledger and receipts: gone for good
    dscl . -delete /Users/_synthe 2>/dev/null || true
    dscl . -delete /Groups/_synthe 2>/dev/null || true
    echo "uninstalled and purged (key, ledger, receipts and the _synthe user deleted)"
  else
    echo "uninstalled; kept $STATE (key, ledger, receipts) and the _synthe user. --purge removes them."
  fi
  exit 0
fi

[ -n "$AGENT_USER" ] || { echo "--agent-user USER is required (the macOS user your agents run as)" >&2; exit 2; }
id -u "$AGENT_USER" >/dev/null 2>&1 || { echo "no such user: $AGENT_USER" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")/../.." && pwd)
# Steps below run as _synthe, which can't enter a home folder (found on a clean Mac: a PermissionError
# from the user's checkout). Run from / so no step depends on where sudo was started.
cd /
# A Python that can really build the venv: 3.10+ with a working pyexpat (a version check alone picked
# a broken Homebrew 3.14 on macOS 26.1). An explicit --python is checked the same way.
if [ -n "$PY" ]; then
  PY=$(bash "$HERE/deploy/macos/find-python.sh" --check "$PY") || exit 2
else
  PY=$(bash "$HERE/deploy/macos/find-python.sh") || exit 2
fi
command -v git >/dev/null || { echo "needs git (xcode-select --install)" >&2; exit 2; }

# 1. hidden user + group _synthe, with a free id below 500
if ! dscl . -read /Users/_synthe >/dev/null 2>&1; then
  used=$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}' | sort -n -u)
  ID=
  for i in $(seq 480 -1 400); do grep -qx "$i" <<<"$used" || { ID=$i; break; }; done
  [ -n "$ID" ] || { echo "no free uid/gid between 400 and 480" >&2; exit 1; }
  dscl . -create /Groups/_synthe
  dscl . -create /Groups/_synthe PrimaryGroupID "$ID"
  dscl . -create /Groups/_synthe RealName "Synthe broker"
  dscl . -create /Users/_synthe
  dscl . -create /Users/_synthe UniqueID "$ID"
  dscl . -create /Users/_synthe PrimaryGroupID "$ID"
  dscl . -create /Users/_synthe UserShell /usr/bin/false
  dscl . -create /Users/_synthe NFSHomeDirectory "$STATE"
  dscl . -create /Users/_synthe RealName "Synthe broker"
  dscl . -create /Users/_synthe IsHidden 1
  dscl . -create /Users/_synthe Password '*'
fi

# 2. code (root-owned) and a venv with cryptography
install -d -o root -g wheel -m 755 "$APP" "$APP/src"
install -o root -g wheel -m 644 "$HERE"/src/*.py "$HERE"/src/*.html "$APP/src/"
# Reuse the venv only if it works: a half-built one (no pip, from a broken Python) stayed forever.
if ! { [ -x "$APP/venv/bin/python" ] && "$APP/venv/bin/python" -m pip --version >/dev/null 2>&1; }; then
  rm -rf "$APP/venv"
  "$PY" -m venv "$APP/venv"
fi
"$APP/venv/bin/pip" install -q --upgrade cryptography
BPY=$APP/venv/bin/python

# 3. the broker's state (0700) and socket dir (0755), owned by _synthe
install -d -o _synthe -g _synthe -m 700 "$STATE"
install -d -o _synthe -g _synthe -m 755 "$RUN"
sudo -u _synthe env HOME="$STATE" "$BPY" "$APP/src/synthe_commit.py" init --dir "$STATE" --isolation user >/dev/null 2>&1 \
  || { echo "broker init failed" >&2; exit 1; }
sudo -u _synthe env HOME="$STATE" "$BPY" - "$STATE/broker.json" "$AGENT_USER" <<'PYEOF'
import json, sys
path, agent = sys.argv[1], sys.argv[2]
cfg = json.load(open(path))
cfg.setdefault("isolation", {"mode": "user"})["clients"] = [agent]
json.dump(cfg, open(path, "w"), indent=2)
PYEOF

# 4. the LaunchDaemon (no secrets in it)
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>UserName</key><string>_synthe</string>
  <key>GroupName</key><string>_synthe</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BPY</string>
    <string>$APP/src/synthe_commit.py</string>
    <string>serve</string>
    <string>--config</string><string>$STATE/broker.json</string>
    <string>--socket</string><string>$RUN/broker.sock</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>$STATE</string>
    <key>PYTHONDONTWRITEBYTECODE</key><string>1</string>
  </dict>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardErrorPath</key><string>$STATE/broker.log</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null

cat <<EOF

Installed (not started). The broker's key and config are in $STATE (owned by _synthe, 0700).
Its public key (add it to your registry under agents.synthe-broker.keys):
$(sudo -u _synthe env HOME="$STATE" "$BPY" "$APP/src/synthe_commit.py" init --dir "$STATE" 2>/dev/null)

Next (each line is one command):
  1. registry:     sudo install -o _synthe -g _synthe -m 600 registry.json $STATE/registry.json
  2. GitHub token: sudo -u _synthe sh -c 'umask 077; cat > $STATE/github.token'    (paste the token, then Ctrl-D)
  3. remote:       sudo -u _synthe nano $STATE/broker.json    and set effects.git_push.remotes, e.g.
                   "synthe": {"url": "https://github.com/rohansiddam/Synthe.git", "branches": ["feature/*"],
                              "token_file": "github.token"}
  4. check:        sudo -u _synthe $BPY $APP/src/synthe_commit.py doctor --config $STATE/broker.json
  5. start:        sudo launchctl bootstrap system $PLIST
Then, as $AGENT_USER:
  export SYNTHE_BROKER=unix://$RUN/broker.sock
  python3 $APP/src/synthe_client.py doctor --repo PATH/TO/REPO --git-remote origin
  (it FAILs "direct push" while $AGENT_USER still has its own GitHub credentials in the keychain)
EOF
