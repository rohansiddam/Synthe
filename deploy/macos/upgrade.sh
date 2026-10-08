#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Upgrade an ENFORCED macOS install to this checkout, and apply staged registry changes.
#
#   cd <your Synthe checkout> && git pull && sudo bash deploy/macos/upgrade.sh [--stage DIR]
#
# Copies the code into /Library/Synthe (root-owned), rewrites the launchers the agent's account uses,
# installs the staged registry (for example a Touch ID approval key from `synthe-init touchid`), and
# restarts the broker and, if setup installed it, the agent's OpenClaw gateway. The broker's key,
# config, ledger and receipts stay as they are. Holds no secret.
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "macOS only" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo: sudo bash $0" >&2; exit 2; }

APP=/Library/Synthe
STATE=/var/db/synthe
HERE=$(cd "$(dirname "$0")/../.." && pwd)
STAGE=
while [ $# -gt 0 ]; do
  case $1 in
    --stage) STAGE=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
if [ -z "$STAGE" ]; then
  [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || { echo "run it with sudo from your own account, or pass --stage" >&2; exit 2; }
  STAGE="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | awk '{print $2}')/.synthe/macos-stage"
fi
cd /   # _synthe can't enter a home folder (a clean-Mac finding)
[ -x "$APP/venv/bin/python" ] && [ -d "$APP/src" ] || { echo "no Synthe install at $APP: run setup first" >&2; exit 2; }
[ -f "$STAGE/registry.json" ] || { echo "no staged registry at $STAGE/registry.json" >&2; exit 2; }
[ -f "$HERE/src/synthe_commit.py" ] || { echo "run this from a Synthe checkout" >&2; exit 2; }
BPY="$APP/venv/bin/python"

# 1. the code, root-owned, readable by the broker and the agent
install -o root -g wheel -m 644 "$HERE"/src/*.py "$HERE"/src/*.html "$APP/src/"
if [ -d "$APP/integrations/openclaw" ]; then
  rm -rf "$APP/integrations/openclaw"
  cp -R "$HERE/integrations/openclaw" "$APP/integrations/openclaw"
  rm -rf "$APP/integrations/openclaw/tests"
  chown -R root:wheel "$APP/integrations"
  chmod -R u=rwX,go=rX "$APP/integrations"
fi
for name in init mcp task client; do
  printf '#!/bin/sh\nexec %s %s "$@"\n' "$BPY" "$APP/src/synthe_$name.py" > "$APP/venv/bin/synthe-$name"
done
printf '#!/bin/sh\nexec %s %s "$@"\n' "$BPY" "$APP/src/synthe_git_remote.py" > "$APP/venv/bin/git-remote-synthe"
for f in "$APP"/venv/bin/synthe-init "$APP"/venv/bin/synthe-mcp "$APP"/venv/bin/synthe-task \
         "$APP"/venv/bin/synthe-client "$APP"/venv/bin/git-remote-synthe; do
  chown root:wheel "$f"; chmod 755 "$f"
done

# 2. the staged registry (approval keys); the broker's own entry comes from its key file
"$BPY" "$APP/src/synthe_init.py" apply-registry --state "$STATE" --stage "$STAGE"
chown _synthe:_synthe "$STATE/registry.json"
chmod 600 "$STATE/registry.json"

# 3. restart what runs the new code, then check the broker
launchctl kickstart -k system/com.synthe.broker
if launchctl print system/com.synthe.openclaw-gateway >/dev/null 2>&1; then
  launchctl kickstart -k system/com.synthe.openclaw-gateway
fi
sleep 2
sudo -u _synthe env HOME="$STATE" "$BPY" "$APP/src/synthe_commit.py" doctor --config "$STATE/broker.json"
echo
echo "Upgraded $APP from $HERE. Check the level from the agent's account: synthe-init doctor --repo ~/repo"
