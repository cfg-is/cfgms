#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# install-cfg.sh — Install the cfg CLI binary on Linux and macOS.
#
# Copies the cfg binary to a directory on PATH. Defaults to /usr/local/bin when
# running as root; falls back to ~/.local/bin for non-root callers. If the
# fallback directory is not already on PATH, a hint is printed.
#
# Usage:
#   bash scripts/install-cfg.sh [--prefix <dir>]
#
# Flags:
#   --prefix <dir>   Install directory (default: /usr/local/bin or ~/.local/bin)
#
# Examples:
#   sudo bash scripts/install-cfg.sh
#   bash scripts/install-cfg.sh --prefix ~/.local/bin
#   bash scripts/install-cfg.sh --prefix /opt/homebrew/bin

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_SRC="$REPO_ROOT/bin/cfg"

# ── Argument parsing ──────────────────────────────────────────────────────────

PREFIX=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ── Resolve install prefix ────────────────────────────────────────────────────

if [[ -z "$PREFIX" ]]; then
    if [[ "$EUID" -eq 0 ]]; then
        PREFIX="/usr/local/bin"
    else
        PREFIX="$HOME/.local/bin"
    fi
fi

# ── Validate source binary ────────────────────────────────────────────────────

if [[ ! -f "$BIN_SRC" ]]; then
    echo "Error: cfg binary not found at $BIN_SRC" >&2
    echo "Run 'make build-cli' first." >&2
    exit 1
fi

# ── Create prefix directory if absent ────────────────────────────────────────

if [[ ! -d "$PREFIX" ]]; then
    install -d "$PREFIX"
fi

# ── Install binary ────────────────────────────────────────────────────────────

install -m 755 "$BIN_SRC" "$PREFIX/cfg"

echo "cfg installed to $PREFIX/cfg"

# ── PATH hint for ~/.local/bin ────────────────────────────────────────────────

if [[ "$PREFIX" == "$HOME/.local/bin" ]]; then
    case ":${PATH}:" in
        *":$PREFIX:"*) ;;
        *)
            echo ""
            echo "Note: $PREFIX is not on your PATH."
            echo "Add it by running:"
            echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
            echo "Or for zsh:"
            echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc && source ~/.zshrc"
            ;;
    esac
fi
