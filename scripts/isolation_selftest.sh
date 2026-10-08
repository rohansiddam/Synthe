#!/usr/bin/env bash
# Synthe broker isolation: the real two-user proof. Linux only, run as root.
#
#   sudo scripts/isolation_selftest.sh          (KEEP=1 keeps the users and files)
#
# It creates three OS users:
#   synthe-broker  holds the broker key, registry, ledger and receipts, and is
#                  the only user that can write the "GitHub" stand-in (a bare repo)
#   synthe-agent   the coding agent: can read the repo, holds no credentials
#   synthe-other   a third user, not on the broker's clients list
# starts the broker as synthe-broker on a unix socket (isolation mode "user"),
# and checks the wall from both sides. Every key is a throwaway generated here
# and nothing leaves this machine. Prints PASS/FAIL per check, then
# "SELFTEST PASS" (exit 0) or "SELFTEST FAIL" (exit 1).
set -euo pipefail

[ "$(uname -s)" = Linux ] || { echo "Linux only (useradd, runuser, SO_PEERCRED)" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root: it creates OS users" >&2; exit 2; }
for tool in runuser useradd userdel getent git python3; do
  command -v "$tool" >/dev/null || { echo "needs $tool" >&2; exit 2; }
done

HERE=$(cd "$(dirname "$0")/.." && pwd)
PY=$(command -v python3)
BROKER=synthe-broker AGENT=synthe-agent OTHER=synthe-other
WORK=$(mktemp -d /tmp/synthe-selftest.XXXXXX)
chmod 755 "$WORK"
CREATED=()
BPID=

cleanup() {
  [ -n "$BPID" ] && kill "$BPID" 2>/dev/null || true
  local uid p
  uid=$(id -u "$BROKER" 2>/dev/null) || uid=
  for p in /proc/[0-9]*; do  # the broker itself (no pkill in slim images)
    [ -n "$uid" ] && [ "$(stat -c %u "$p" 2>/dev/null)" = "$uid" ] && kill "${p#/proc/}" 2>/dev/null || true
  done
  sleep 0.2
  if [ "${KEEP:-0}" = 1 ]; then
    echo "kept: $WORK and users ${CREATED[*]+${CREATED[*]}}"
    return
  fi
  rm -rf "$WORK"
  for u in ${CREATED[@]+"${CREATED[@]}"}; do userdel -r "$u" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

for u in "$BROKER" "$AGENT" "$OTHER"; do
  if ! id -u "$u" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/sh "$u"
    CREATED+=("$u")
  fi
done

# Run as another user with a clean environment: nothing inherited from root.
as() {
  local u=$1; shift
  runuser -u "$u" -- env -i PATH="$PATH" HOME="$(getent passwd "$u" | cut -d: -f6)" LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 GIT_CONFIG_NOSYSTEM=1 "$@"
}

FAILS=0
check() {  # check NAME CMD...
  local name=$1; shift
  if "$@"; then printf 'PASS  %s\n' "$name"; else printf 'FAIL  %s\n' "$name"; FAILS=$((FAILS + 1)); fi
}
jtrue() {  # jtrue FILE EXPR: EXPR over the JSON in FILE (as d) is true
  "$PY" -c 'import json, sys; d = json.load(open(sys.argv[1])); sys.exit(0 if eval(sys.argv[2]) else 1)' "$1" "$2"
}

echo "Synthe isolation selftest: $(uname -sr), $("$PY" --version), $(git --version)"
echo "users: $BROKER=$(id -u "$BROKER") $AGENT=$(id -u "$AGENT") $OTHER=$(id -u "$OTHER")"
echo

# ---- the world: code (world-readable), broker state (broker only), handoff -----
cp -r "$HERE/src" "$WORK/src"
rm -rf "$WORK/src/__pycache__"
chmod -R a+rX,go-w "$WORK/src"
SRC=$WORK/src
mkdir -m 755 "$WORK/handoff" "$WORK/github" "$WORK/run"
mkdir -m 700 "$WORK/broker" "$WORK/agent"

"$PY" "$HERE/scripts/selftest_world.py" --src "$SRC" --broker-dir "$WORK/broker" --remote-url "$WORK/github/remote.git" \
  --packet "$WORK/handoff/packet.json" --new-broker-key --clients "$AGENT"
chmod 644 "$WORK/handoff/packet.json"
chown -R "$BROKER:" "$WORK/broker" "$WORK/github" "$WORK/run"
chmod 600 "$WORK/broker/broker.key.json"
chown "$AGENT:" "$WORK/agent"

# "GitHub": a bare repo only the broker can write; everyone can read it.
REMOTE=$WORK/github/remote.git
as "$BROKER" git init -q --bare -b main "$REMOTE"
SEED=$(as "$BROKER" mktemp -d)
as "$BROKER" sh -c 'cd "$1" && git init -q -b main && mkdir src && echo "print(1)" > src/app.py &&
  echo "# app" > README.md && git add -A && git -c user.name=seed -c user.email=seed@selftest.invalid \
  commit -qm init && git push -q "$2" HEAD:main' _ "$SEED" "$REMOTE"
rm -rf "$SEED"
chmod -R a+rX,go-w "$WORK/github"

# The agent: a read-only clone (like a GitHub clone without push rights).
REPO=$WORK/agent/repo
as "$AGENT" git config --global user.name builder-agent
as "$AGENT" git config --global user.email agent@selftest.invalid
as "$AGENT" git config --global --add safe.directory "$REMOTE"  # reading another user's repo
as "$AGENT" git clone -q "$REMOTE" "$REPO"

# ---- the broker, as its own user -------------------------------------------------
SOCK=$WORK/run/broker.sock
CFG=$WORK/broker/broker.json
as "$BROKER" "$PY" "$SRC/synthe_commit.py" doctor --config "$CFG" > "$WORK/doctor-broker.json" || true
check "broker doctor: key 0600 and owned by the broker, state not writable by others" \
  jtrue "$WORK/doctor-broker.json" 'd["ok"]'
runuser -u "$BROKER" -- env -i PATH="$PATH" HOME="$(getent passwd "$BROKER" | cut -d: -f6)" LANG=C.UTF-8 \
  PYTHONDONTWRITEBYTECODE=1 GIT_CONFIG_NOSYSTEM=1 \
  "$PY" "$SRC/synthe_commit.py" serve --config "$CFG" --socket "$SOCK" 2> "$WORK/broker.log" &
BPID=$!
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
check "broker is serving on a unix socket as $BROKER" test -S "$SOCK"
CLIENT=("$PY" "$SRC/synthe_client.py" --broker "unix://$SOCK")

# ---- 1. the agent can't touch the broker's secrets or state ------------------------
out=$(as "$AGENT" cat "$WORK/broker/broker.key.json" 2>&1 || true)
echo "      agent> cat broker.key.json: ${out##*: }"
check "agent cannot read the broker's key" grep -q "Permission denied" <<<"$out"
out=$(as "$AGENT" sh -c 'echo "{}" > "$1"' _ "$WORK/broker/ledger.json" 2>&1 || true)
check "agent cannot rewrite the ledger" grep -q "Permission denied" <<<"$out"

# ---- 2. the agent can't push on its own ------------------------------------------
as "$AGENT" sh -c 'cd "$1" && echo "print(2)" > src/direct.py && git add -A && git commit -qm direct' _ "$REPO"
out=$(as "$AGENT" git -C "$REPO" push origin HEAD:refs/heads/feature/direct 2>&1) && rc=0 || rc=$?
echo "      agent> git push: exit $rc, $(grep -m1 -iE 'permission|denied|error' <<<"$out" || true)"
check "agent cannot push to the remote itself" test "$rc" -ne 0
check "the remote has no feature/direct" \
  test -z "$(as "$BROKER" git --git-dir "$REMOTE" rev-parse -q --verify refs/heads/feature/direct || true)"
as "$AGENT" git -C "$REPO" reset -q --hard HEAD~1

as "$AGENT" "${CLIENT[@]}" doctor --repo "$REPO" --git-remote origin > "$WORK/doctor-agent.txt" 2>&1 && rc=0 || rc=$?
sed 's/^/      agent> doctor: /' "$WORK/doctor-agent.txt"
check "agent doctor: every check passes (exit $rc)" test "$rc" -eq 0

# ---- 3. the agent claims and proposes through the socket ----------------------------
as "$AGENT" "${CLIENT[@]}" hello > "$WORK/hello.json"
check "hello: separate-user, verified, broker uid != agent uid" jtrue "$WORK/hello.json" \
  'd["isolation"]["mode"] == "separate-user" and d["isolation"]["verified"] is True and d["isolation"]["broker_uid"] != d["isolation"]["peer_uid"]'
as "$AGENT" "${CLIENT[@]}" claim "$WORK/handoff/packet.json" > "$WORK/agent/claim.json" || true
chown "$AGENT:" "$WORK/agent/claim.json"
chmod 600 "$WORK/agent/claim.json"
check "agent claims the handoff over the socket: ACCEPT" jtrue "$WORK/agent/claim.json" 'd["decision"] == "ACCEPT"'
PUSH=(push --packet "$WORK/handoff/packet.json" --claim-token-file "$WORK/agent/claim.json"
      --action push_branch --remote github --branch feature/selftest --repo "$REPO")

as "$AGENT" sh -c 'cd "$1" && echo "# changed" > README.md && git commit -qam readme' _ "$REPO"
as "$AGENT" "${CLIENT[@]}" "${PUSH[@]}" > "$WORK/denied.json" || true
check "out-of-scope commit (README.md): denied path_outside_scope" jtrue "$WORK/denied.json" \
  'd["decision"] == "denied" and d["reasons"][0]["code"] == "path_outside_scope"'
as "$AGENT" git -C "$REPO" reset -q --hard HEAD~1

as "$AGENT" sh -c 'cd "$1" && echo "print(3)" > src/app.py && git commit -qam v2' _ "$REPO"
SHA=$(as "$AGENT" git -C "$REPO" rev-parse HEAD)
as "$AGENT" "${CLIENT[@]}" "${PUSH[@]}" > "$WORK/executed.json" || true
check "in-scope commit: executed" jtrue "$WORK/executed.json" 'd["decision"] == "executed"'
check "receipt: via unix, separate-user, verified: true, uids differ" jtrue "$WORK/executed.json" \
  'd["via"] == "unix" and d["isolation"]["mode"] == "separate-user" and d["isolation"]["verified"] is True and d["isolation"]["broker_uid"] != d["isolation"]["peer_uid"]'
check "receipt: the commits arrived as a git bundle" jtrue "$WORK/executed.json" \
  'd["commits_from"].startswith("bundle sha256:")'
check "the remote's feature/selftest is the agent's commit" \
  test "$(as "$BROKER" git --git-dir "$REMOTE" rev-parse refs/heads/feature/selftest)" = "$SHA"
"$PY" - "$WORK/executed.json" <<'PYEOF' || true
import json, sys
d = json.load(open(sys.argv[1]))
i = d.get("isolation") or {}
print(f"      receipt #{d.get('seq')}: {d.get('decision')}, via {d.get('via')}, isolation {i.get('mode')} "
      f"verified={i.get('verified')} broker_uid={i.get('broker_uid')} peer_uid={i.get('peer_uid')}, "
      f"{str(d.get('commits_from'))[:23]}...")
PYEOF

# ---- 4. clients that could read the keys are refused --------------------------------
as "$BROKER" "${CLIENT[@]}" hello > "$WORK/r-broker.json" || true
check "a client running as the broker's user: broker_not_isolated" \
  jtrue "$WORK/r-broker.json" 'd["error"]["code"] == "broker_not_isolated"'
"${CLIENT[@]}" hello > "$WORK/r-root.json" || true
check "a client running as root: broker_not_isolated" \
  jtrue "$WORK/r-root.json" 'd["error"]["code"] == "broker_not_isolated"'
as "$OTHER" "${CLIENT[@]}" hello > "$WORK/r-other.json" || true
check "a user outside the clients list: client_not_allowed" \
  jtrue "$WORK/r-other.json" 'd["error"]["code"] == "client_not_allowed"'

# ---- 5. the receipt chain verifies -----------------------------------------------------
as "$BROKER" "$PY" "$SRC/synthe_commit.py" receipts verify --config "$CFG" > "$WORK/chain.json" || true
check "receipt chain verifies against the broker's registered key (2 receipts)" \
  jtrue "$WORK/chain.json" 'd["ok"] and d["count"] == 2 and not d["errors"]'
as "$AGENT" "${CLIENT[@]}" receipts > "$WORK/chain-agent.json" || true
check "the agent can check the chain over the socket" jtrue "$WORK/chain-agent.json" 'd["ok"] and d["count"] == 2'

echo
echo "broker log:"
sed 's/^/  /' "$WORK/broker.log"
echo
if [ "$FAILS" -eq 0 ]; then echo "SELFTEST PASS"; else echo "SELFTEST FAIL ($FAILS failed)"; exit 1; fi
