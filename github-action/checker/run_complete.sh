#!/usr/bin/env bash
# Completion entrypoint for the Handoff Contract Check GitHub Action.
#
# Run this AFTER the receiving agent's effect is real (phase: complete).
# Flips the packet's idempotency-key entry in the ledger from RESERVED to
# COMPLETED, so a later replay of the same key is rejected as a terminal
# duplicate. The Action's cache-save step (which runs after this script,
# even on failure) is what persists the flip across runs -- in v0.2 the
# single save happened before the effect, so a local --complete was never
# persisted by the Action; the phase split fixes that.
#
#   exit 0 -> COMPLETED recorded (or already COMPLETED: idempotent no-op).
#   exit 1 -> no RESERVED entry to complete, or no ledger: fails the step.
#
# Configured via environment variables (set by action.yml):
#   HANDOFF_PACKET    path to the handoff packet JSON (required)
#   HANDOFF_LEDGER    path to the idempotency ledger JSON (required here)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

packet="${HANDOFF_PACKET:-}"
ledger="${HANDOFF_LEDGER:-}"

if [[ -z "$packet" ]]; then
  echo "::error::Handoff complete: no packet path provided (set the 'packet' input)."
  exit 1
fi
if [[ -z "$ledger" ]]; then
  echo "::error::Handoff complete: no ledger path provided (set the 'ledger' input or use the managed ledger)."
  exit 1
fi

output="$(python3 "$SCRIPT_DIR/handoff_check.py" "$packet" --ledger "$ledger" --complete)"
code=$?
echo "$output"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  if [[ $code -eq 0 ]]; then
    echo "decision=COMPLETED" >> "$GITHUB_OUTPUT"
  else
    echo "decision=REJECT" >> "$GITHUB_OUTPUT"
  fi
fi

if [[ $code -eq 0 ]]; then
  echo "Handoff COMPLETED - claim closed; replays of this key are terminal duplicates."
  exit 0
fi

echo "::error::Handoff completion failed - no RESERVED claim was completed (see output above)."
exit 1
