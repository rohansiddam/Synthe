#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
# The live red team, unattended: scripts/redteam_live.py against a real install under systemd, in a throwaway
# container. Three OS users, as on a real machine: `synthe` runs the broker (deploy/linux/install.sh, the
# hardened unit), `agent1` is the agent and runs every attack, `human` is the person, whose three steps (approve
# the swap, approve the control push, revoke the red-team lane) a process running as `human` does on request.
# Throwaway keys only; a local bare repository stands in for GitHub. Every row of docs/REDTEAM.md runs, the
# OS-wall rows included (the agent can't read the broker's token or keys or the person's key).
#
#   deploy/linux/redteam_test.sh [OUT_DIR]     (needs docker; runs a --privileged container)
#
# Writes OUT_DIR/redteam-report.json (default ./redteam-out). Exit 0 only when no row FAILs.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=$(mkdir -p "${1:-redteam-out}" && cd "${1:-redteam-out}" && pwd)
IMAGE=synthe-systemd-test:bookworm
NAME=synthe-redteam-$(date +%s)

docker build -q -t "$IMAGE" - >/dev/null <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv python3 python3-venv git ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
docker run -d --name "$NAME" --privileged --tmpfs /run --tmpfs /run/lock -v "$PWD":/repo:ro -v "$OUT":/out \
  "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

docker exec -i "$NAME" bash -s <<'INNER'
set -euo pipefail
systemctl is-system-running --wait >/dev/null 2>&1 || true
as() { local u=$1; shift; runuser -u "$u" -- env -i PATH=/usr/bin:/bin HOME="$(getent passwd "$u" | cut -d: -f6)" "$@"; }
useradd --create-home --shell /bin/bash agent1
useradd --create-home --shell /bin/bash human
chmod 700 /home/agent1 /home/human

echo "--- install.sh (the broker as synthe)"
bash /repo/deploy/linux/install.sh --agent-user agent1 | sed -n '1,2p'
PY=/opt/synthe/venv/bin/python
RT=/repo/scripts/redteam_live.py

echo "--- the world: the person's key and setup, registry, config, a stand-in GitHub"
mkdir -p /srv/git
"$PY" /repo/scripts/redteam_world.py --src /opt/synthe/src --remote-url /srv/git/remote.git > /tmp/world.json
chown synthe:synthe /srv/git
as synthe git init -q --bare -b main /srv/git/remote.git
seed=$(as synthe mktemp -d)
as synthe sh -c 'cd "$1" && git init -q -b main && mkdir src && echo "print(1)" > src/app.py && git add -A &&
  git -c user.name=seed -c user.email=seed@x.invalid commit -qm init && git push -q /srv/git/remote.git HEAD:main &&
  echo hello > src/hello.md && git add -A && git -c user.name=seed -c user.email=seed@x.invalid commit -qm hello &&
  git push -q /srv/git/remote.git HEAD:refs/heads/agent/hello3' _ "$seed"
rm -rf "$seed"
chmod -R a+rX,go-w /srv/git
# Test only: the stand-in remote is a local path, and ProtectSystem=strict makes /srv read-only for the service.
mkdir -p /etc/systemd/system/synthe-broker.service.d
printf '[Service]\nReadWritePaths=/srv/git\n' > /etc/systemd/system/synthe-broker.service.d/test-local-remote.conf
systemctl daemon-reload
systemctl enable --now synthe-broker >/dev/null 2>&1
for _ in $(seq 50); do [ -S /run/synthe/broker.sock ] && break; sleep 0.2; done
test -S /run/synthe/broker.sock || { journalctl -u synthe-broker --no-pager -o cat | tail -20; exit 1; }
for u in agent1 human; do as "$u" git config --global --add safe.directory /srv/git/remote.git; done
as agent1 git clone -q /srv/git/remote.git /home/agent1/repo

echo "--- step 1, the person: sign the red-team tasks and the self-issue lane"
as human "$PY" "$RT" tasks --home /home/human/.synthe --inbox /var/lib/synthe-shared/inbox --test-key

echo "--- step 2, the agent: every attack; the person answers the three pauses from their own account"
install -d -o agent1 -m 755 /srv/pipe/req
install -d -o human -m 755 /srv/pipe/done
as human "$PY" "$RT" human --pipe /srv/pipe --home /home/human/.synthe --broker unix:///run/synthe/broker.sock \
  --test-key > /tmp/human.log 2>&1 &
HUMAN=$!
PUB=$(python3 -c 'import json; print(json.load(open("/tmp/world.json"))["broker_pub"])')
set +e
as agent1 "$PY" "$RT" attack --broker unix:///run/synthe/broker.sock --broker-pub "$PUB" \
  --repo /home/agent1/repo --remote /srv/git/remote.git --receiver openclaw \
  --inbox /var/lib/synthe-shared/inbox --approver-home /home/human --state /var/lib/synthe \
  --registry /var/lib/synthe-shared/registry.pub.json --human-pipe /srv/pipe --report /tmp/redteam-report.json \
  --mcp-cmd "$PY /opt/synthe/src/synthe_mcp.py --broker-url unix:///run/synthe/broker.sock --as-receiver openclaw"
CODE=$?
set -e
kill "$HUMAN" 2>/dev/null || true
echo "--- the person's process"
sed 's/^/  /' /tmp/human.log
cp /tmp/redteam-report.json /out/redteam-report.json 2>/dev/null || true
echo "--- broker journal (last lines)"
journalctl -u synthe-broker --no-pager -o cat | grep -v '^$' | tail -6 | sed 's/^/  /'
[ "$CODE" -eq 0 ] && echo "RED TEAM PASS" || { echo "RED TEAM FAIL (exit $CODE)"; exit 1; }
INNER
