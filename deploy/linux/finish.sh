#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
# Human-invoked only: finish a fresh systemd install using synthe-init's staged public configuration.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo 'run the generated enforce-linux.sh with sudo' >&2; exit 2; }
[ "$#" -eq 8 ] || { echo 'expected staged setup arguments' >&2; exit 2; }
STAGE=$1 AGENT_USER=$2 APPROVER=$3 AGENT_KIND=$4 RECEIVER=$5 TOKEN=$6 TOKEN_STAGED=$7
# The final reserved argument pins the installer interface version.
[ "$8" = v1 ] || { echo 'unsupported setup version' >&2; exit 2; }
[[ "$AGENT_USER" =~ ^[a-z_][a-z0-9_-]{0,30}$ && "$APPROVER" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || exit 2
case "$AGENT_USER:$APPROVER" in root:*|synthe:*|_synthe:*|*:root|*:synthe|*:_synthe) exit 2;; esac
[ "$AGENT_USER" != "$APPROVER" ] && [ "${SUDO_USER:-}" = "$APPROVER" ] || { echo 'separate human and agent accounts required' >&2; exit 2; }
case "$AGENT_KIND" in openclaw|none) ;; *) exit 2;; esac
HERE=$(cd "$(dirname "$0")/../.." && pwd)
STATE=/var/lib/synthe APP=/opt/synthe SHARED=/var/lib/synthe-shared
[ ! -e "$STATE/broker.json" ] || { echo 'existing broker: use a reviewed upgrade, not fresh setup' >&2; exit 2; }
command -v systemctl >/dev/null
id -u "$APPROVER" >/dev/null
id -u "$AGENT_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$AGENT_USER"
AGENT_HOME=$(getent passwd "$AGENT_USER" | cut -d: -f6)
APPROVER_HOME=$(getent passwd "$APPROVER" | cut -d: -f6)
[[ "$AGENT_HOME" = /home/* && "$APPROVER_HOME" = /home/* && "$AGENT_HOME" != "$APPROVER_HOME" ]] || exit 2
# No agent sudo rights, Docker socket or inherited publish credentials may be present; doctor must verify.
chmod 700 "$APPROVER_HOME" "$AGENT_HOME"
cd /
bash "$HERE/deploy/linux/install.sh" --agent-user "$AGENT_USER"
BPY=$APP/venv/bin/python
"$BPY" "$APP/src/synthe_init.py" apply-config --state "$STATE" --stage "$STAGE"
[ -z "$TOKEN" ] || install -o synthe -g synthe -m 600 "$TOKEN" "$STATE/github.token"
if [ "$TOKEN_STAGED" = 1 ] && [ "$TOKEN" = "$STAGE/github.token" ]; then rm -f -- "$TOKEN"; fi
chown synthe:synthe "$STATE/registry.json" "$STATE/broker.json"
chmod 600 "$STATE/registry.json" "$STATE/broker.json"
install -d -m 755 "$SHARED"
install -d -o synthe -g synthe -m 755 "$SHARED/workspace"
install -d -o "$APPROVER" -m 755 "$SHARED/inbox"
install -d -m 755 "$APP/bin" "$APP/integrations"
cp -R "$HERE/integrations/openclaw" "$APP/integrations/"
chmod -R go-w "$APP/integrations"
for name in init mcp task client approve verify; do
  printf '#!/bin/sh\nexec /opt/synthe/venv/bin/python /opt/synthe/src/synthe_%s.py "$@"\n' "$name" > "$APP/bin/synthe-$name"
  chmod 755 "$APP/bin/synthe-$name"
done
printf '#!/bin/sh\nexec /opt/synthe/venv/bin/python /opt/synthe/src/synthe_git_remote.py "$@"\n' > "$APP/bin/git-remote-synthe"
chmod 755 "$APP/bin/git-remote-synthe"
runuser -u synthe -- env HOME="$STATE" "$BPY" "$APP/src/synthe_commit.py" doctor --config "$STATE/broker.json"
systemctl enable --now synthe-broker
AS_AGENT=(runuser -u "$AGENT_USER" -- env "HOME=$AGENT_HOME" "PATH=$APP/bin:$AGENT_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin")
# BEGIN broker readiness: Type=simple does not mean the socket is listening yet.
BROKER_READY=0
for attempt in {1..40}; do
  if "${AS_AGENT[@]}" "$BPY" -c 'import pwd, sys; sys.path.insert(0, "/opt/synthe/src"); from synthe_client import BrokerClient; BrokerClient("unix:///run/synthe/broker.sock", timeout=1, expected_broker_uid=pwd.getpwnam("synthe").pw_uid).call("hello")' >/dev/null 2>&1; then
    BROKER_READY=1
    break
  fi
  sleep 0.25
done
[ "$BROKER_READY" = 1 ] || { echo 'broker not ready; setup stopped before clone; inspect synthe-broker.service before continuing' >&2; exit 1; }
# END broker readiness
if [ "$AGENT_KIND" = openclaw ]; then
  "${AS_AGENT[@]}" npm install -g -q openclaw@2026.9.8 --prefix "$AGENT_HOME/.local"
fi
"${AS_AGENT[@]}" "$APP/bin/synthe-init" agent-setup --agent "$RECEIVER" --agent-kind "$AGENT_KIND" --yes
if [ "$AGENT_KIND" = openclaw ]; then
  sed -e "s|@AGENT@|$AGENT_USER|g" -e "s|@HOME@|$AGENT_HOME|g" "$HERE/deploy/linux/openclaw-gateway.service" > /etc/systemd/system/synthe-openclaw.service
  chmod 644 /etc/systemd/system/synthe-openclaw.service
  systemctl daemon-reload
  systemctl enable --now synthe-openclaw
fi
"${AS_AGENT[@]}" "$APP/bin/synthe-client" --broker unix:///run/synthe/broker.sock clone "$AGENT_HOME/repo"
"${AS_AGENT[@]}" git -C "$AGENT_HOME/repo" config synthe.inbox "$SHARED/inbox"
"${AS_AGENT[@]}" "$APP/bin/synthe-init" doctor --repo "$AGENT_HOME/repo"
echo 'Installed, not certified: review doctor as the agent and check its account has no sudo/docker/GitHub authority.'
echo "Agent terminal: sudo -iu $AGENT_USER; export PATH=/opt/synthe/bin:\$HOME/.local/bin:\$PATH"
