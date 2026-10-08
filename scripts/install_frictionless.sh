#!/usr/bin/env bash
# Frictionless one-liner install for Synthe
# Run via: curl -sSL https://synthe.live/install | bash

set -e

echo "=> Synthe: Starting frictionless installation..."

# 1. Install dependencies
echo "=> Checking Homebrew dependencies (python, node, git)..."
if ! command -v brew &> /dev/null; then
    echo "Homebrew is required but not installed. Please install it first:"
    echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
    exit 1
fi
brew install -q python node git

# 2. Clone the repository to a hidden setup folder
SYNTHE_SRC="$HOME/.synthe-source"
echo "=> Cloning Synthe repository to $SYNTHE_SRC..."
if [ -d "$SYNTHE_SRC" ]; then
    rm -rf "$SYNTHE_SRC"
fi
git clone -q https://github.com/rohansiddam/Synthe "$SYNTHE_SRC"
cd "$SYNTHE_SRC"

# 3. Find correct Python and build venv
echo "=> Setting up Python environment..."
PY=$(bash deploy/macos/find-python.sh)
if [ -z "$PY" ]; then
    echo "No working Python 3.10+ found. Synthe needs a valid Python installation."
    exit 1
fi
"$PY" -m venv ~/synthe-venv
~/synthe-venv/bin/pip install -q .

echo "=================================================="
echo "Synthe core installed successfully!"
echo "=================================================="

# 4. If interactive, prompt for repo URL and run prepare immediately
REPO_URL=""
if [ -t 0 ]; then
    echo ""
    read -rp "Enter the GitHub repository URL for your agent (e.g. https://github.com/YOU/REPO.git): " REPO_URL
fi

if [ -n "$REPO_URL" ]; then
    echo "=> Preparing Synthe for $REPO_URL..."
    ~/synthe-venv/bin/synthe-init prepare --repo-url "$REPO_URL" --allowed-paths 'src/**'
    echo ""
    read -rp "Run finish-setup.sh now to enforce the barrier? [Y/n] " CONFIRM
    if [[ "$CONFIRM" =~ ^[Nn] ]]; then
        echo "Run it whenever you are ready: bash ~/.synthe/finish-setup.sh"
    else
        bash ~/.synthe/finish-setup.sh
    fi
else
    echo "To finish setup and enforce the commit barrier, run:"
    echo ""
    echo "  ~/synthe-venv/bin/synthe-init prepare --repo-url <YOUR_REPO_URL> --allowed-paths 'src/**'"
    echo "  bash ~/.synthe/finish-setup.sh"
fi
