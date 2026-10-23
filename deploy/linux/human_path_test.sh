#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-ALv2
# Walk the human Linux path end to end under real systemd, in a throwaway container: an approver
# account with sudo runs `synthe-init prepare` and `finish-setup.sh` (passphrase, hidden token prompt,
# sudo password, all typed at a real terminal by expect), the broker runs as `synthe` from the systemd
# unit, the agent account `worker` gets no credential, a signed task becomes a plain `git push`
# proposal, the approver reads the diff and approves with the passphrase, and the broker pushes.
# Then scripts/redteam_live.py attacks the install from the agent's account.
#
#   deploy/linux/human_path_test.sh     (needs docker; runs a --privileged container)
#
# The remote is a local bare repo: no GitHub, no real credential. The hidden token prompt gets a
# placeholder string, which a local remote never uses. Throwaway keys and passphrases only.
# SYNTHE_TEST_IMAGE / SYNTHE_TEST_DOCKER_ARGS: as in systemd_test.sh (the image also needs sudo and expect).
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE=${SYNTHE_TEST_IMAGE:-synthe-human-path-test:bookworm}
NAME=synthe-human-$(date +%s)

[ -n "${SYNTHE_TEST_IMAGE:-}" ] || docker build -q -t "$IMAGE" - >/dev/null <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv python3 python3-venv git ca-certificates procps sudo expect \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
# shellcheck disable=SC2086
docker run -d ${SYNTHE_TEST_DOCKER_ARGS:-} --name "$NAME" --privileged --tmpfs /run --tmpfs /run/lock -v "$PWD":/repo:ro "$IMAGE" >/dev/null
[ -n "${SYNTHE_TEST_KEEP:-}" ] || trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT  # SYNTHE_TEST_KEEP=1: keep it to debug

docker exec -i "$NAME" bash -s <<'INNER'
set -euo pipefail
umask 022  # what a login shell gets; docker exec may start with 000
FAILS=0
check() { local n=$1; shift; if "$@"; then echo "PASS  $n"; else echo "FAIL  $n"; FAILS=$((FAILS + 1)); fi; }
as() { local u=$1; shift; runuser -u "$u" -- env -i PATH=/opt/synthe/bin:/usr/bin:/bin HOME="$(getent passwd "$u" | cut -d: -f6)" USER="$u" TERM=dumb "$@"; }
PASS='correct horse battery staple'  # throwaway approval passphrase
REMOTE=/srv/git/remote.git

systemctl is-system-running --wait >/dev/null 2>&1 || true
echo "systemd $(systemctl --version | head -1 | cut -d' ' -f2), $(python3 --version), $(git --version), $(. /etc/os-release; echo "$PRETTY_NAME")"

# The human: an ordinary account that can sudo with its own password.
useradd --create-home --shell /bin/bash -G sudo alice
echo 'alice:alice-sudo-pw' | chpasswd

# The stand-in remote: a local bare repo with main and an existing agent branch (for the rewrite attack).
mkdir -p /srv/git
git init -q --bare -b main "$REMOTE"
# Test only: readable by every account, like the public repo the macOS live run used. The broker's unit
# runs with UMask=0077, so the refs it pushes here are 0600 and others would read them as absent.
# (core.sharedRepository is no use: it sets setgid on new directories, which RestrictSUIDSGID refuses.)
printf '#!/bin/sh\nchmod -R a+rX .\n' > "$REMOTE/hooks/post-receive"
chmod 755 "$REMOTE/hooks/post-receive"
seed=/srv/seed  # not /tmp: systemd may still be mounting it
git init -q -b main "$seed"
mkdir "$seed/src"
echo 'print("hello")' > "$seed/src/app.py"
echo '# demo' > "$seed/README.md"
git -C "$seed" add -A
git -C "$seed" -c user.name=seed -c user.email=seed@x.invalid commit -qm init
git -C "$seed" push -q "$REMOTE" HEAD:main
git -C "$seed" checkout -q -b agent/hello3
echo hello > "$seed/src/hello.md"
git -C "$seed" add -A
git -C "$seed" -c user.name=seed -c user.email=seed@x.invalid commit -qm hello
git -C "$seed" push -q "$REMOTE" agent/hello3
rm -rf "$seed"
has_hello3() { git --git-dir "$REMOTE" rev-parse -q --verify refs/heads/agent/hello3 >/dev/null; }
check "seed: the remote has main and agent/hello3" has_hello3
# Test only: the remote is a local path. The broker (and the agent's read-only ls-remote) read a repo
# they don't own, and ProtectSystem=strict makes /srv read-only for the service. A real remote is https.
git config --system --add safe.directory "$REMOTE"
mkdir -p /etc/systemd/system/synthe-broker.service.d
printf '[Service]\nReadWritePaths=/srv/git\n' > /etc/systemd/system/synthe-broker.service.d/test-local-remote.conf

echo "--- alice: install and prepare (no secrets)"
git clone -q /repo /home/alice/synthe && chown -R alice:alice /home/alice/synthe
as alice bash -c 'cd ~/synthe && python3 -m venv ~/synthe-venv && ~/synthe-venv/bin/pip install -q --disable-pip-version-check .'
as alice bash -c 'cd ~/synthe && ~/synthe-venv/bin/synthe-init prepare --agent-kind none --agent-account worker \
  --repo-url /srv/git/remote.git --branches "agent/*" --allowed-paths "src/**"' | sed 's/^/  /'

echo "--- alice: bash ~/.synthe/finish-setup.sh (passphrase twice, placeholder token, sudo password)"
cat > /tmp/finish.exp <<'EXP'
set timeout 900
spawn bash /home/alice/.synthe/finish-setup.sh
expect {
  -re "New passphrase.*: $" { send "$env(PASS)\r"; exp_continue }
  -re "Type it again: $" { send "$env(PASS)\r"; exp_continue }
  -re "GitHub token.*: $" { send "local-remote-placeholder-not-a-credential\r"; exp_continue }
  -re "password for alice: $" { send "alice-sudo-pw\r"; exp_continue }
  timeout { puts "expect: timed out"; exit 124 }
  eof
}
exit [lindex [wait] 3]
EXP
chmod 644 /tmp/finish.exp
set +e; as alice PASS="$PASS" expect /tmp/finish.exp > /tmp/finish.log 2>&1; code=$?; set -e
sed -n '/Enforcement level/,$p' /tmp/finish.log | sed 's/^/  /'
check "finish-setup.sh exits 0" test "$code" = 0
check "finish.sh's own doctor, as worker: ENFORCED" grep -q "Enforcement level: ENFORCED" /tmp/finish.log
check "the staged token copy is gone from alice's account" test ! -e /home/alice/.synthe/linux-stage/github.token
pid=$(systemctl show -p MainPID --value synthe-broker)
check "systemd runs the broker as synthe (pid $pid)" test "$(ps -o user= -p "$pid")" = synthe
check "the broker's public key is published root-owned 0644" test "$(stat -c '%a %U' /var/lib/synthe-shared/broker.pub.json)" = "644 root"
# The broker, and only the broker, may write the remote from here on.
chown -R synthe:synthe "$REMOTE"

echo "--- worker: the wall"
out=$(as worker cat /var/lib/synthe/github.token 2>&1 || true)
check "worker cannot read the broker's token" grep -q "Permission denied" <<<"$out"
out=$(as worker cat /var/lib/synthe/keys/synthe-broker.key.json 2>&1 || true)
check "worker cannot read the broker's key" grep -q "Permission denied" <<<"$out"
out=$(as worker cat /home/alice/.synthe/approver.key.json 2>&1 || true)
check "worker cannot read the approver's key" grep -q "Permission denied" <<<"$out"
check "worker has no passwordless sudo" bash -c '! runuser -u worker -- sudo -n true 2>/dev/null'
as worker bash -c 'cd ~/repo && synthe-init doctor --repo ~/repo' > /tmp/doctor.txt
check "doctor as worker after setup: ENFORCED" grep -q "Enforcement level: ENFORCED" /tmp/doctor.txt

echo "--- alice: sign a task"
cat > /tmp/task.exp <<'EXP'
set timeout 120
spawn /home/alice/synthe-venv/bin/synthe-task new "Add a greeting function" --branch agent/first-push
expect {
  -re "assphrase.*: $" { send "$env(PASS)\r"; exp_continue }
  timeout { puts "expect: timed out"; exit 124 }
  eof
}
exit [lindex [wait] 3]
EXP
chmod 644 /tmp/task.exp
check "synthe-task new (passphrase)" as alice PASS="$PASS" expect /tmp/task.exp

echo "--- worker: commit and plain git push"
as worker bash -c 'cd ~/repo && git checkout -q -b agent/first-push && printf "def greet(name):\n    return f\"hello, {name}\"\n" >> src/app.py &&
  git -c user.name=worker -c user.email=worker@x.invalid commit -qam "Add a greeting function"'
commit=$(as worker git -C /home/worker/repo rev-parse HEAD)
as worker bash -c 'cd ~/repo && git push 2>&1' | sed 's/^/  worker> /'
check "after git push: proposed, not on the remote" bash -c "! git --git-dir $REMOTE rev-parse -q --verify refs/heads/agent/first-push"
set +e; as worker git -C /home/worker/repo push "$REMOTE" HEAD:refs/heads/agent/direct > /tmp/direct.txt 2>&1; code=$?; set -e
check "worker's direct push to the remote fails (exit $code)" bash -c "[ $code -ne 0 ] && ! git --git-dir $REMOTE rev-parse -q --verify refs/heads/agent/direct"

echo "--- alice: synthe-approve --passphrase (read the diff, approve)"
cat > /tmp/approve.exp <<'EXP'
set timeout 120
set env(SYNTHE_BROKER) unix:///run/synthe/broker.sock
spawn /home/alice/synthe-venv/bin/synthe-approve --passphrase
expect {
  -re {\[v\] view[^>]*> $} { send "v\r"; exp_continue }
  -re {\[a\] approve once[^>]*> $} { send "a\r"; exp_continue }
  -re "assphrase.*: $" { send "$env(PASS)\r"; exp_continue }
  timeout { puts "expect: timed out"; exit 124 }
  eof
}
exit [lindex [wait] 3]
EXP
chmod 644 /tmp/approve.exp
set +e; as alice PASS="$PASS" expect /tmp/approve.exp > /tmp/approve.log 2>&1; code=$?; set -e
sed -n '/Approving as/,$p' /tmp/approve.log | sed 's/^/  /'
check "synthe-approve exits 0" test "$code" = 0
check "the remote has exactly the approved commit ${commit:0:12}" test "$(git --git-dir $REMOTE rev-parse refs/heads/agent/first-push)" = "$commit"

echo "--- receipts: verify with the published key only"
install -d -m 755 /tmp/audit && cp /var/lib/synthe/receipts.jsonl /tmp/audit/ && chmod 644 /tmp/audit/receipts.jsonl
as alice /home/alice/synthe-venv/bin/synthe-verify /tmp/audit/receipts.jsonl --key /var/lib/synthe-shared/broker.pub.json | sed 's/^/  /'
check "synthe-verify: VERIFIED" as alice /home/alice/synthe-venv/bin/synthe-verify /tmp/audit/receipts.jsonl --key /var/lib/synthe-shared/broker.pub.json
python3 - /tmp/audit/receipts.jsonl /tmp/audit/tampered.jsonl <<'PYEOF'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
rows[0]["decision"] = "denied" if rows[0]["decision"] != "denied" else "executed"
open(sys.argv[2], "w").write("".join(json.dumps(r) + "\n" for r in rows))
PYEOF
chmod 644 /tmp/audit/tampered.jsonl
check "synthe-verify on an edited copy: NOT VERIFIED (exit 1)" bash -c \
  'runuser -u alice -- /home/alice/synthe-venv/bin/synthe-verify /tmp/audit/tampered.jsonl --key /var/lib/synthe-shared/broker.pub.json >/dev/null; [ $? -eq 1 ]'

echo "--- live red team: scripts/redteam_live.py"
check "agent/hello3 is still on the remote (the rewrite target)" has_hello3
install -o root -g root -m 644 /home/alice/synthe/scripts/redteam_live.py /var/lib/synthe-shared/redteam_live.py
cat > /tmp/rt-tasks.exp <<'EXP'
set timeout 120
spawn /home/alice/synthe-venv/bin/python /home/alice/synthe/scripts/redteam_live.py tasks
expect {
  -re "assphrase.*: $" { send "$env(PASS)\r"; exp_continue }
  timeout { puts "expect: timed out"; exit 124 }
  eof
}
exit [lindex [wait] 3]
EXP
chmod 644 /tmp/rt-tasks.exp
check "redteam_live.py tasks (alice, passphrase)" as alice PASS="$PASS" expect /tmp/rt-tasks.exp
# Two terminals: the agent attacks; at its two pauses, alice uses synthe-approve as REDTEAM.md says.
cat > /tmp/rt-attack.exp <<'EXP'
set timeout 600
set as_alice {runuser -u alice -- env -i PATH=/usr/bin:/bin HOME=/home/alice USER=alice TERM=dumb SYNTHE_BROKER=unix:///run/synthe/broker.sock /home/alice/synthe-venv/bin/synthe-approve --passphrase --id}
spawn runuser -u worker -- env -i PATH=/opt/synthe/bin:/usr/bin:/bin HOME=/home/worker USER=worker TERM=dumb \
  /opt/synthe/venv/bin/python /var/lib/synthe-shared/redteam_live.py attack --repo /home/worker/repo \
  --remote /srv/git/remote.git --approver-home /home/alice
set agent $spawn_id
expect -i $agent -re {--id '([^']+)'\s+Read the diff} {} timeout { puts "expect: timed out"; exit 124 }
set swap $expect_out(1,string)
expect -i $agent "Press Enter here when done" {} timeout { puts "expect: timed out"; exit 124 }
# Window A: open the swap proposal (version A) and leave it at the prompt.
eval spawn $as_alice [list $swap]
set human $spawn_id
expect -i $human -re {\[a\] approve once[^>]*> $} {} timeout { puts "expect: timed out"; exit 124 }
send -i $agent "\r"
expect -i $agent -re {--id '([^']+)'\s+=====} {} timeout { puts "expect: timed out"; exit 124 }
set control $expect_out(1,string)
expect -i $agent "Press Enter here when done" {} timeout { puts "expect: timed out"; exit 124 }
# Back in window A: approve version A after the agent swapped in B.
send -i $human "a\r"
expect -i $human -re "assphrase.*: $" {} timeout { puts "expect: timed out"; exit 124 }
send -i $human "$env(PASS)\r"
expect -i $human eof {} timeout { puts "expect: timed out"; exit 124 }
# Then the control push.
eval spawn $as_alice [list $control]
set human2 $spawn_id
expect {
  -i $human2 -re {\[v\] view[^>]*> $} { send -i $human2 "v\r"; exp_continue }
  -i $human2 -re {\[a\] approve once[^>]*> $} { send -i $human2 "a\r"; exp_continue }
  -i $human2 -re "assphrase.*: $" { send -i $human2 "$env(PASS)\r"; exp_continue }
  -i $human2 eof {}
  timeout { puts "expect: timed out"; exit 124 }
}
send -i $agent "\r"
expect -i $agent eof {} timeout { puts "expect: timed out"; exit 124 }
exit [lindex [wait -i $agent] 3]
EXP
chmod 644 /tmp/rt-attack.exp
set +e; PASS="$PASS" expect /tmp/rt-attack.exp > /tmp/rt-attack.log 2>&1; code=$?; set -e
grep -E "Nothing pushed yet|^  (PASS|FAIL|skip) |passed, " /tmp/rt-attack.log | tr -d "\r" | sed 's/^/  /'
check "red team: no FAIL row (exit $code)" test "$code" = 0
[ "$code" = 0 ] || tail -40 /tmp/rt-attack.log | tr -d "\r" | sed "s/^/  attack.log> /"
check "red team: the swap was refused at approval (Nothing pushed yet)" grep -q "Nothing pushed yet" /tmp/rt-attack.log
cp /home/worker/synthe-redteam-report.json /tmp/redteam-report.json 2>/dev/null || true

echo
[ "$FAILS" -eq 0 ] && echo "HUMAN PATH TEST PASS" || { echo "HUMAN PATH TEST FAIL ($FAILS)"; exit 1; }
INNER
# SYNTHE_TEST_REPORT=PATH keeps the red team's own JSON report, exactly as redteam_live.py wrote it.
[ -z "${SYNTHE_TEST_REPORT:-}" ] || docker cp "$NAME":/tmp/redteam-report.json "$SYNTHE_TEST_REPORT"
