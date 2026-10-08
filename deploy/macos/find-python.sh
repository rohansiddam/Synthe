#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Print the path of a Python that can actually build Synthe's environments, or explain why none can.
#
#   bash deploy/macos/find-python.sh              the first working candidate
#   bash deploy/macos/find-python.sh --check PY   PY itself, or why it won't do
#
# "Working" means 3.10 or newer AND able to load pyexpat. A founder's clean-Mac run (2026-10-07,
# macOS 26.1) found Homebrew's Python 3.14.8 and 3.12 installed but broken: pyexpat couldn't load a
# libexpat symbol, so platform.mac_ver() came back empty and `python3 -m venv` died in ensurepip.
# A version check alone picked the broken one, twice. Candidates can be overridden for tests with
# SYNTHE_PY_CANDIDATES (space-separated).
set -uo pipefail

works() {
  [ -x "$1" ] && "$1" -c 'import sys, pyexpat, ensurepip, venv; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1
}

if [ "${1:-}" = --check ]; then
  PY=${2:?--check needs a path}
  if works "$PY"; then echo "$PY"; exit 0; fi
  echo "$PY can't build a Python environment here (it needs 3.10+ with a working pyexpat and ensurepip)." >&2
  exit 1
fi

CANDIDATES=${SYNTHE_PY_CANDIDATES:-"
  /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12
  /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.10
  /usr/local/bin/python3 /usr/local/bin/python3.13 /usr/local/bin/python3.12
  /Library/Frameworks/Python.framework/Versions/Current/bin/python3
  /usr/bin/python3"}
broken=()
for c in $CANDIDATES; do
  [ -x "$c" ] || continue
  if works "$c"; then echo "$c"; exit 0; fi
  broken+=("$c")
done
{
  echo "No working Python 3.10+ found."
  if [ ${#broken[@]} -gt 0 ]; then
    echo "These are installed but can't build an environment (too old, or pyexpat won't load): ${broken[*]}"
    echo "Homebrew's newest Python can need a newer macOS than this one: update macOS, or try"
    echo "  brew install python@3.13"
    echo "or install Python from https://www.python.org/downloads/macos/ and run this again."
  else
    echo "Install one: brew install python"
  fi
} >&2
exit 1
