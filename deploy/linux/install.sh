#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
# Install the Synthe commit broker as its own OS user on Linux (systemd).
#
#   sudo deploy/linux/install.sh --agent-user AGENT_USER [--no-venv] [--no-systemd]
#
# Creates the system user `synthe`, copies the code to /opt/synthe/src (root-
# owned, so neither the broker nor an agent can change it), makes a venv with
# `cryptography` (constant-time Ed25519), creates the broker key and config in
# /var/lib/synthe (0700, owned by synthe) with isolation mode "user" and
# clients = [AGENT_USER], and installs the systemd unit. It does NOT start the
# broker: add the registry and the GitHub token first (printed at the end).
set -euo pipefail

AGENT_USER= VENV=1 SYSTEMD=1
while [ $# -gt 0 ]; do
  case $1 in
    --agent-user) AGENT_USER=$2; shift 2 ;;
    --no-venv) VENV=0; shift ;;
    --no-systemd) SYSTEMD=0; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: it creates a system user" >&2; exit 2; }
[ -n "$AGENT_USER" ] || { echo "--agent-user USER is required (the OS user your agents run as)" >&2; exit 2; }
id -u "$AGENT_USER" >/dev/null 2>&1 || { echo "no such user: $AGENT_USER" >&2; exit 2; }
[ "$AGENT_USER" != synthe ] && [ "$AGENT_USER" != root ] || { echo "agents must not run as synthe or root" >&2; exit 2; }
command -v python3 >/dev/null && command -v git >/dev/null || { echo "needs python3 (3.10+) and git" >&2; exit 2; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "needs Python 3.10+" >&2; exit 2; }

HERE=$(cd "$(dirname "$0")/../.." && pwd)
STATE=/var/lib/synthe

id -u synthe >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin synthe
install -d -o root -g root -m 755 /opt/synthe /opt/synthe/src
install -o root -g root -m 644 "$HERE"/src/*.py "$HERE"/src/*.html /opt/synthe/src/
PY=$(command -v python3)
if [ "$VENV" = 1 ]; then
  [ -x /opt/synthe/venv/bin/python ] || python3 -m venv /opt/synthe/venv
  /opt/synthe/venv/bin/pip install -q --upgrade cryptography
  PY=/opt/synthe/venv/bin/python
fi
install -d -o synthe -g synthe -m 700 "$STATE"
runuser -u synthe -- env HOME="$STATE" "$PY" /opt/synthe/src/synthe_commit.py init --dir "$STATE" --isolation user >/dev/null 2>&1 \
  || { echo "broker init failed" >&2; exit 1; }
runuser -u synthe -- env HOME="$STATE" "$PY" - "$STATE/broker.json" "$AGENT_USER" <<'PYEOF'
import json, sys
path, agent = sys.argv[1], sys.argv[2]
cfg = json.load(open(path))
cfg.setdefault("isolation", {"mode": "user"})["clients"] = [agent]
json.dump(cfg, open(path, "w"), indent=2)
PYEOF
chmod 600 "$STATE/broker.json"

if [ "$SYSTEMD" = 1 ]; then
  unit=/etc/systemd/system/synthe-broker.service
  sed "s|/opt/synthe/venv/bin/python|$PY|" "$HERE/deploy/linux/synthe-broker.service" > "$unit"
  chmod 644 "$unit"
  systemctl daemon-reload
fi

cat <<EOF

Installed. The broker key and config are in $STATE (owned by synthe, 0700).
Its public key (add it to your registry under agents.synthe-broker.keys):
$(runuser -u synthe -- env HOME="$STATE" "$PY" /opt/synthe/src/synthe_commit.py init --dir "$STATE" 2>/dev/null)

Next, as root:
  1. registry:      install -o synthe -g synthe -m 600 registry.json $STATE/registry.json
  2. GitHub token:  runuser -u synthe -- sh -c 'umask 077; cat > $STATE/github.token'   (paste, Ctrl-D)
  3. remote:        edit $STATE/broker.json, effects.git_push.remotes, e.g.
                    "synthe": {"url": "https://github.com/OWNER/REPO.git", "branches": ["feature/*"],
                               "token_file": "github.token"}
  4. check:         runuser -u synthe -- $PY /opt/synthe/src/synthe_commit.py doctor --config $STATE/broker.json
  5. start:         systemctl enable --now synthe-broker
Then, as $AGENT_USER (holding no GitHub credentials):
  export SYNTHE_BROKER=unix:///run/synthe/broker.sock
  python3 /opt/synthe/src/synthe_client.py doctor --repo YOUR_REPO --git-remote origin
EOF
