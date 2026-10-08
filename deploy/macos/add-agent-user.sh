#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
# Let a separate macOS user run the agent (OpenClaw) against an installed Synthe broker, so the agent's
# account holds no GitHub credentials and no approver key. Run after install.sh / enforce-macos.sh:
#
#   sudo bash deploy/macos/add-agent-user.sh --agent-user openclaw --approver-user "$SUDO_USER"
#
# It adds both users to the broker's clients (the approver needs the socket for synthe-approve), gives
# the broker its shared workspace (it writes signed tasks there through submit_task), copies the OpenClaw
# plugin and skill to /Library/Synthe/integrations (root-owned, readable by the agent user), puts
# synthe-init and synthe-mcp launchers in /Library/Synthe/venv/bin, and restarts the broker.
# It holds no secret and never touches the token or any key.
set -euo pipefail

STATE=/var/db/synthe
APP=/Library/Synthe
BPY=$APP/venv/bin/python
PLIST=/Library/LaunchDaemons/com.synthe.broker.plist
WORKSPACE=/Users/Shared/Synthe/workspace
AGENT_USER= APPROVER_USER=
while [ $# -gt 0 ]; do
  case $1 in
    --agent-user) AGENT_USER=$2; shift 2 ;;
    --approver-user) APPROVER_USER=$2; shift 2 ;;
    --workspace) WORKSPACE=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 2; }
[ -n "$AGENT_USER" ] && [ -n "$APPROVER_USER" ] || { echo "--agent-user and --approver-user are required" >&2; exit 2; }
[ "$AGENT_USER" != "$APPROVER_USER" ] || { echo "the agent and the approver must be different users" >&2; exit 2; }
for u in "$AGENT_USER" "$APPROVER_USER" _synthe; do id -u "$u" >/dev/null 2>&1 || { echo "no such user: $u" >&2; exit 2; }; done
[ -x "$BPY" ] && [ -f "$STATE/broker.json" ] || { echo "no installed broker: run install.sh first" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")/../.." && pwd)

# 1. both users may connect; nobody else
sudo -u _synthe env HOME="$STATE" "$BPY" - "$STATE/broker.json" "$APPROVER_USER" "$AGENT_USER" <<'PYEOF'
import json, os, sys
path, users = sys.argv[1], sys.argv[2:]
cfg = json.load(open(path))
cfg.setdefault("isolation", {"mode": "user"})["clients"] = users
fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
with os.fdopen(fd, "w") as fh:
    json.dump(cfg, fh, indent=2)
PYEOF

# 2. the broker owns the shared workspace; everyone may read the signed tasks in it
install -d -m 755 "$(dirname "$WORKSPACE")"
install -d -o _synthe -g _synthe -m 755 "$WORKSPACE"
chown -R _synthe:_synthe "$WORKSPACE"

# 3. the OpenClaw plugin and skill, and launchers, where the agent user can read them
install -o root -g wheel -m 644 "$HERE"/src/*.py "$HERE"/src/*.html "$APP/src/"
rm -rf "$APP/integrations"
mkdir -p "$APP/integrations"
cp -R "$HERE/integrations/openclaw" "$APP/integrations/openclaw"
rm -rf "$APP/integrations/openclaw/tests"
chown -R root:wheel "$APP/integrations"
chmod -R u=rwX,go=rX "$APP/integrations"
for name in init mcp task client; do
  printf '#!/bin/sh\nexec %s %s "$@"\n' "$BPY" "$APP/src/synthe_$name.py" > "$APP/venv/bin/synthe-$name"
  chown root:wheel "$APP/venv/bin/synthe-$name"
  chmod 755 "$APP/venv/bin/synthe-$name"
done

# 4. publish the broker's public key (root-owned, world-readable) so anyone can verify its receipts
"$BPY" - "$STATE/registry.json" "$(dirname "$WORKSPACE")/broker.pub.json" <<'PYEOF'
import json, sys
reg = json.load(open(sys.argv[1]))
pub = {"broker": "synthe-broker", **reg["agents"]["synthe-broker"]["keys"][0]}
pub = {k: pub[k] for k in ("broker", "kid", "alg", "public_key")}
open(sys.argv[2], "w").write(json.dumps(pub, indent=2) + "\n")
PYEOF
chown root:wheel "$(dirname "$WORKSPACE")/broker.pub.json"
chmod 644 "$(dirname "$WORKSPACE")/broker.pub.json"

# 5. restart the broker with the new client list
sudo -u _synthe env HOME="$STATE" "$BPY" "$APP/src/synthe_commit.py" doctor --config "$STATE/broker.json"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
echo
echo "The broker accepts $APPROVER_USER (approves) and $AGENT_USER (proposes)."
echo "Next, in $AGENT_USER's account:  $APP/venv/bin/synthe-init agent-setup"
