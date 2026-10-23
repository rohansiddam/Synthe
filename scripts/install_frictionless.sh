#!/usr/bin/env bash
# Frictionless one-liner install for Synthe
# Run via: curl -sSL https://synthe.live/install | bash

set -euo pipefail

# Default to a fixed release. Overrides must also name a stable release tag.
readonly SYNTHE_RELEASE_TAG="${SYNTHE_REF:-v0.7.1}"
if [[ ! "$SYNTHE_RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "SYNTHE_REF must name a release tag such as v0.7.1."
    exit 1
fi
if [ "${SYNTHE_EXPECTED_COMMIT+x}" = x ] && [[ ! "$SYNTHE_EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "SYNTHE_EXPECTED_COMMIT must be a full 40-character lowercase commit SHA."
    exit 1
fi

if [ "$EUID" -eq 0 ]; then
    echo "Synthe installer should not be run as root/sudo directly."
    echo "Please run as your regular user: curl -sSL https://synthe.live/install | bash"
    exit 1
fi

echo "=> Synthe: Starting frictionless installation..."

# Git must already be available: verify source before installing dependencies.
if ! command -v git &> /dev/null; then
    echo "Git is required to verify the release before installing dependencies. Install Git, then retry."
    exit 1
fi

# Ignore replacement refs and local fsmonitor/hooks while inspecting a checkout.
synthe_git() {
    git --no-replace-objects -c core.fsmonitor=false -c core.hooksPath=/dev/null "$@"
}

SYNTHE_SRC="$HOME/.synthe-source"
readonly SYNTHE_REPO="https://github.com/rohansiddam/Synthe"
move_aside() {
    local backup="$SYNTHE_SRC.backup" index=0
    while [ -e "$backup" ] || [ -L "$backup" ]; do
        index=$((index + 1))
        backup="$SYNTHE_SRC.backup.$index"
    done
    echo "Source checkout cannot be reused: $1"
    echo "Nothing was moved. To keep it and retry, run this exact command:"
    printf '  mv -i -- %q %q\n' "$SYNTHE_SRC" "$backup"
    exit 1
}

# 1. Clone the requested tag, or inspect an existing checkout without resetting it.
if [ -e "$SYNTHE_SRC" ] || [ -L "$SYNTHE_SRC" ]; then
    [ -d "$SYNTHE_SRC" ] && [ ! -L "$SYNTHE_SRC" ] && [ ! -L "$SYNTHE_SRC/.git" ] \
        || move_aside "the path is not a regular checkout directory"
    SOURCE_ROOT=$(synthe_git -C "$SYNTHE_SRC" rev-parse --show-toplevel 2>/dev/null) \
        || move_aside "the directory is not a Git checkout"
    [ "$SOURCE_ROOT" = "$(cd "$SYNTHE_SRC" && pwd -P)" ] \
        || move_aside "the directory is inside a different checkout"
    # The URL as configured: `remote get-url` applies url.*.insteadOf rewrites (often https -> ssh),
    # which made a rerun refuse a correct checkout.
    SOURCE_REMOTE=$(synthe_git -C "$SYNTHE_SRC" config --get remote.origin.url 2>/dev/null) \
        || move_aside "origin is missing"
    [ "$SOURCE_REMOTE" = "$SYNTHE_REPO" ] || [ "$SOURCE_REMOTE" = "$SYNTHE_REPO.git" ] \
        || move_aside "origin is not the public Synthe repository"
    echo "=> Checking existing Synthe checkout at $SYNTHE_SRC..."
else
    echo "=> Cloning Synthe $SYNTHE_RELEASE_TAG to $SYNTHE_SRC..."
    synthe_git clone -q --depth 1 --branch "$SYNTHE_RELEASE_TAG" "$SYNTHE_REPO" "$SYNTHE_SRC"
    synthe_git -C "$SYNTHE_SRC" checkout -q --detach "refs/tags/$SYNTHE_RELEASE_TAG"
fi

INSTALLED_COMMIT=$(synthe_git -C "$SYNTHE_SRC" rev-parse --verify 'HEAD^{commit}') \
    || move_aside "HEAD is not a commit"
TAG_COMMIT=$(synthe_git -C "$SYNTHE_SRC" rev-parse --verify "refs/tags/$SYNTHE_RELEASE_TAG^{commit}" 2>/dev/null) \
    || move_aside "the requested release tag is missing"
[ "$INSTALLED_COMMIT" = "$TAG_COMMIT" ] || move_aside "HEAD is not at $SYNTHE_RELEASE_TAG"
if [ "${SYNTHE_EXPECTED_COMMIT+x}" = x ] && [ "$INSTALLED_COMMIT" != "$SYNTHE_EXPECTED_COMMIT" ]; then
    echo "Release commit mismatch for $SYNTHE_RELEASE_TAG: expected $SYNTHE_EXPECTED_COMMIT, found $INSTALLED_COMMIT."
    echo "Stopped before installing any dependencies. The checkout was preserved for inspection."
    exit 1
fi
SOURCE_STATUS=$(synthe_git -C "$SYNTHE_SRC" status --porcelain --untracked-files=all --ignored) \
    || move_aside "Git could not verify the working tree"
[ -z "$SOURCE_STATUS" ] || move_aside "the checkout has changed, untracked or ignored files"
echo "=> Installing Synthe $SYNTHE_RELEASE_TAG at $INSTALLED_COMMIT"

# 2. Dependencies are installed only after the tag and optional commit pin pass.
echo "=> Checking Homebrew dependencies (python, node, git)..."
if ! command -v brew &> /dev/null; then
    echo "Homebrew is required but not installed. Please install it first:"
    echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
    exit 1
fi
brew install -q python node git

# Build from the verified commit in a temporary directory. pip's build/egg-info
# files must not dirty the preserved checkout and break the next clean rerun.
SYNTHE_BUILD=$(mktemp -d "${TMPDIR:-/tmp}/synthe-install.XXXXXXXX")
trap 'rm -rf -- "$SYNTHE_BUILD"' EXIT
synthe_git -C "$SYNTHE_SRC" archive --format=tar "$INSTALLED_COMMIT" | tar -xf - -C "$SYNTHE_BUILD"
cd "$SYNTHE_BUILD"

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
    read -rp "Enter the GitHub repository URL for your agent (e.g. https://github.com/YOU/REPO.git): " REPO_URL < /dev/tty 2>/dev/null || true
elif [ -t 0 ]; then
    echo ""
    read -rp "Enter the GitHub repository URL for your agent (e.g. https://github.com/YOU/REPO.git): " REPO_URL
fi

if [ -n "$REPO_URL" ]; then
    echo "=> Preparing Synthe for $REPO_URL..."
    "$HOME/synthe-venv/bin/synthe-init" prepare --repo-url "$REPO_URL" --allowed-paths 'src/**'
    echo "Review the generated setup script, then run the admin step in your own terminal:"
    echo "  bash ~/.synthe/finish-setup.sh"
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
