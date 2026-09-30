#!/usr/bin/env bash
# Entrypoint for the Handoff Contract Check GitHub Action.
#
# Runs the vendored Handoff Contract v0.1 validator (checker/handoff_check.py,
# python3 stdlib only, no network) against one handoff packet.
#
#   exit 0 -> ACCEPT: the receiving agent may start work.
#   exit 1 -> REJECT: prints the failure state + reason(s) and fails the step.
#
# The raw checker exits 2 on reject; this wrapper normalizes any non-zero
# checker exit to 1 so CI sees a clean pass/fail.
#
# Configured via environment variables (set by action.yml):
#   HANDOFF_PACKET    path to the handoff packet JSON (required)
#   HANDOFF_REGISTRY  path to the agent registry JSON (optional)
#   HANDOFF_LEDGER    path to an idempotency ledger JSON (optional)
#   HANDOFF_WORKSPACE workspace root for artifact existence/hash checks (optional)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

packet="${HANDOFF_PACKET:-}"
registry="${HANDOFF_REGISTRY:-}"
ledger="${HANDOFF_LEDGER:-}"
workspace="${HANDOFF_WORKSPACE:-}"

if [[ -z "$packet" ]]; then
  echo "::error::Handoff check: no packet path provided (set the 'packet' input)."
  exit 1
fi

args=("$packet")
[[ -n "$registry" ]] && args+=(--registry "$registry")
[[ -n "$ledger" ]] && args+=(--ledger "$ledger")
[[ -n "$workspace" ]] && args+=(--workspace "$workspace")

output="$(python3 "$SCRIPT_DIR/handoff_check.py" "${args[@]}")"
code=$?
echo "$output"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  if [[ $code -eq 0 ]]; then
    echo "decision=ACCEPT" >> "$GITHUB_OUTPUT"
  else
    echo "decision=REJECT" >> "$GITHUB_OUTPUT"
  fi
fi

if [[ $code -eq 0 ]]; then
  echo "Handoff ACCEPTED - safe for the receiver to start work."
  exit 0
fi

summary="$(printf '%s' "$output" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    rs = d.get("reasons", [])
    print("; ".join("%s: %s" % (r.get("state", "?"), r.get("message", "")) for r in rs)
          or "validation failed")
except Exception:
    print("validation failed")
')"
echo "::error::Handoff REJECTED - $summary"
exit 1
