#!/usr/bin/env bash
# Frictionless one-liner install for Synthe
# Run via: curl -sSL https://synthe.live/install | bash

set -e

if [ "$EUID" -eq 0 ]; then
    echo "Synthe installer should not be run as root/sudo directly."
    echo "Please run as your regular user: curl -sSL https://synthe.live/install | bash"
    exit 1
fi

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

# Symlink executables to ~/.local/bin and export PATH
mkdir -p "$HOME/.local/bin"
for bin in synthe-init synthe-mcp synthe-approve synthe-task synthe-client synthe-verify git-remote-synthe; do
    if [ -f "$HOME/synthe-venv/bin/$bin" ]; then
        ln -sf "$HOME/synthe-venv/bin/$bin" "$HOME/.local/bin/$bin"
        if [ -w /usr/local/bin ]; then
            ln -sf "$HOME/synthe-venv/bin/$bin" "/usr/local/bin/$bin" 2>/dev/null || true
        fi
    fi
done

for profile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
    if [ -f "$profile" ] && ! grep -q '\.local/bin' "$profile"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$profile"
    fi
done
export PATH="$HOME/.local/bin:$HOME/synthe-venv/bin:$PATH"

echo "=================================================="
echo "Synthe core installed successfully!"
echo "=================================================="

# 4. If interactive, prompt for repo URL and run prepare immediately
REPO_URL=""
if [ -r /dev/tty ]; then
    echo ""
    read -rp "Enter the GitHub repository URL for your agent (e.g. https://github.com/YOU/REPO.git): " REPO_URL < /dev/tty
elif [ -t 0 ]; then
    echo ""
    read -rp "Enter the GitHub repository URL for your agent (e.g. https://github.com/YOU/REPO.git): " REPO_URL
fi

if [ -n "$REPO_URL" ]; then
    echo "=> Preparing Synthe for $REPO_URL..."
    "$HOME/synthe-venv/bin/synthe-init" prepare --repo-url "$REPO_URL" --allowed-paths 'src/**'
    echo ""
    CONFIRM=""
    if [ -r /dev/tty ]; then
        read -rp "Run finish-setup.sh now to enforce the barrier? [Y/n] " CONFIRM < /dev/tty
    elif [ -t 0 ]; then
        read -rp "Run finish-setup.sh now to enforce the barrier? [Y/n] " CONFIRM
    fi
    if [[ "$CONFIRM" =~ ^[Nn] ]]; then
        echo "Run it whenever you are ready: bash ~/.synthe/finish-setup.sh"
    else
        bash ~/.synthe/finish-setup.sh
    fi
else
    echo "To finish setup and enforce the commit barrier, run:"
    echo ""
    echo "  synthe-init prepare --repo-url <YOUR_REPO_URL> --allowed-paths 'src/**'"
    echo "  bash ~/.synthe/finish-setup.sh"
fi

echo ""
echo "=================================================="
echo "Enable Synthe in your agent framework:"
echo ""
echo "  • Claude Code:"
echo "      claude plugin marketplace add rohansiddam/Synthe"
echo "      claude plugin install synthe@synthe"
echo ""
echo "  • OpenClaw:"
echo "      openclaw plugins install @synthelive/openclaw-synthe-barrier"
echo "=================================================="
