#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
# Verify deploy/linux end to end under real systemd, in a throwaway container:
# install.sh as an operator would run it, the hardened unit started by systemd,
# and an agent user pushing through /run/synthe/broker.sock. Throwaway keys only.
#
#   deploy/linux/systemd_test.sh        (needs docker; runs a --privileged container)
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE=synthe-systemd-test:bookworm
NAME=synthe-systemd-$(date +%s)

docker build -q -t "$IMAGE" - >/dev/null <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv python3 python3-venv git ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
docker run -d --name "$NAME" --privileged --tmpfs /run --tmpfs /run/lock -v "$PWD":/repo:ro "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

docker exec -i "$NAME" bash -s <<'INNER'
set -euo pipefail
FAILS=0
check() { local n=$1; shift; if "$@"; then echo "PASS  $n"; else echo "FAIL  $n"; FAILS=$((FAILS + 1)); fi; }
jtrue() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if eval(sys.argv[2]) else 1)' "$1" "$2"; }
as() { local u=$1; shift; runuser -u "$u" -- env -i PATH=/usr/bin:/bin HOME="$(getent passwd "$u" | cut -d: -f6)" "$@"; }

systemctl is-system-running --wait >/dev/null 2>&1 || true
echo "systemd $(systemctl --version | head -1 | cut -d' ' -f2), $(python3 --version), $(git --version)"
useradd --create-home --shell /bin/bash agent1

echo "--- install.sh"
bash /repo/deploy/linux/install.sh --agent-user agent1 | sed -n '1,4p'

# the operator's part: a registry, a remote, a handoff (throwaway keys)
mkdir -p /srv/git /srv/handoff
python3 /repo/scripts/selftest_world.py --src /opt/synthe/src --broker-dir /var/lib/synthe \
  --remote-name origin --remote-url /srv/git/remote.git --packet /srv/handoff/packet.json --clients agent1
chown -R synthe:synthe /var/lib/synthe /srv/git
chmod 600 /var/lib/synthe/registry.json
chmod 644 /srv/handoff/packet.json
as synthe git init -q --bare -b main /srv/git/remote.git
seed=$(as synthe mktemp -d)
as synthe sh -c 'cd "$1" && git init -q -b main && mkdir src && echo "print(1)" > src/app.py && git add -A &&
  git -c user.name=seed -c user.email=seed@x.invalid commit -qm init && git push -q /srv/git/remote.git HEAD:main' _ "$seed"
rm -rf "$seed"
chmod -R a+rX,go-w /srv/git
# Test only: the stand-in remote is a local path, and ProtectSystem=strict makes
# /srv read-only for the service. A real remote is https and needs no override.
mkdir -p /etc/systemd/system/synthe-broker.service.d
printf '[Service]\nReadWritePaths=/srv/git\n' > /etc/systemd/system/synthe-broker.service.d/test-local-remote.conf
systemctl daemon-reload

as synthe /opt/synthe/venv/bin/python /opt/synthe/src/synthe_commit.py doctor --config /var/lib/synthe/broker.json > /tmp/doctor.json || true
check "broker doctor as synthe: ok" jtrue /tmp/doctor.json 'd["ok"]'
systemctl enable --now synthe-broker >/dev/null 2>&1
for _ in $(seq 50); do [ -S /run/synthe/broker.sock ] && break; sleep 0.2; done
check "systemd started the broker; socket at /run/synthe/broker.sock" test -S /run/synthe/broker.sock
pid=$(systemctl show -p MainPID --value synthe-broker)
check "the broker process runs as synthe (pid $pid)" test "$(ps -o user= -p "$pid")" = synthe
check "unit: NoNewPrivileges, ProtectSystem=strict, ProtectHome" test \
  "$(systemctl show -p NoNewPrivileges -p ProtectSystem -p ProtectHome --value synthe-broker | tr '\n' ' ')" = "yes strict yes "
check "/var/lib/synthe is 0700 synthe" test "$(stat -c '%a %U' /var/lib/synthe)" = "700 synthe"
check "the broker key is 0600 synthe" test "$(stat -c '%a %U' /var/lib/synthe/keys/synthe-broker.key.json)" = "600 synthe"
out=$(as agent1 cat /var/lib/synthe/keys/synthe-broker.key.json 2>&1 || true)
check "agent1 cannot read the key: ${out##*: }" grep -q "Permission denied" <<<"$out"

C=(python3 /opt/synthe/src/synthe_client.py --broker unix:///run/synthe/broker.sock)
as agent1 git config --global --add safe.directory /srv/git/remote.git
as agent1 git clone -q /srv/git/remote.git /home/agent1/repo
as agent1 sh -c 'cd ~/repo && echo "print(2)" > src/app.py && git -c user.name=a -c user.email=a@x.invalid commit -qam v2'
as agent1 "${C[@]}" doctor --repo /home/agent1/repo --git-remote origin | sed 's/^/      agent1> doctor: /'
as agent1 "${C[@]}" claim /srv/handoff/packet.json > /home/agent1/claim.json || true
chown agent1: /home/agent1/claim.json
check "agent1 claims through the socket: ACCEPT" jtrue /home/agent1/claim.json 'd["decision"] == "ACCEPT"'
as agent1 "${C[@]}" push --packet /srv/handoff/packet.json --claim-token-file /home/agent1/claim.json \
  --action push_branch --remote origin --branch feature/selftest --repo /home/agent1/repo > /tmp/push.json || true
check "agent1's push: executed by the systemd broker" jtrue /tmp/push.json 'd["decision"] == "executed"'
check "receipt: separate-user, verified, uids differ" jtrue /tmp/push.json \
  'd["isolation"]["mode"] == "separate-user" and d["isolation"]["verified"] is True and d["isolation"]["broker_uid"] != d["isolation"]["peer_uid"]'
check "the remote has agent1's commit" test "$(git --git-dir /srv/git/remote.git rev-parse refs/heads/feature/selftest)" = \
  "$(as agent1 git -C /home/agent1/repo rev-parse HEAD)"
python3 /opt/synthe/src/synthe_client.py --broker unix:///run/synthe/broker.sock hello > /tmp/root.json || true
check "a root client: broker_not_isolated" jtrue /tmp/root.json 'd["error"]["code"] == "broker_not_isolated"'
echo "--- journal"
journalctl -u synthe-broker --no-pager -o cat | grep -v '^$' | tail -8 | sed 's/^/  /'
echo
[ "$FAILS" -eq 0 ] && echo "SYSTEMD TEST PASS" || { echo "SYSTEMD TEST FAIL ($FAILS)"; exit 1; }
INNER
