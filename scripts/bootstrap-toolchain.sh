#!/usr/bin/env bash
#
# Installs a Rust toolchain **inside this repository**.
#
# Nothing is written outside the project folder: rustup's home and cargo's home
# both live under .toolchain/, and the install never edits your shell profile
# (--no-modify-path). Afterwards, run `source scripts/env.sh` in every shell
# that builds AuraPass.
#
#   scripts/bootstrap-toolchain.sh
#   source scripts/env.sh
#   cargo build --release --workspace
#
# Set AURAPASS_TOOLCHAIN to pick a different channel or a pinned version, e.g.
#   AURAPASS_TOOLCHAIN=1.85.0 scripts/bootstrap-toolchain.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="${AURAPASS_TOOLCHAIN:-stable}"

export RUSTUP_HOME="$ROOT/.toolchain/rustup"
export CARGO_HOME="$ROOT/.toolchain/cargo"

mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"

if [ -x "$ROOT/.toolchain/cargo/bin/cargo" ] && "$ROOT/.toolchain/cargo/bin/rustup" toolchain list 2>/dev/null | grep -q "$TOOLCHAIN"; then
  echo "Toolchain $TOOLCHAIN is already installed in .toolchain/."
else
  RUSTUP_INIT="$ROOT/.toolchain/rustup-init"
  if [ ! -x "$RUSTUP_INIT" ]; then
    echo "Downloading rustup-init into .toolchain/"
    if command -v curl > /dev/null 2>&1; then
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$RUSTUP_INIT"
    elif command -v wget > /dev/null 2>&1; then
      wget -qO "$RUSTUP_INIT" https://sh.rustup.rs
    else
      echo "aurapass: need curl or wget to download rustup-init" >&2
      exit 1
    fi
    chmod +x "$RUSTUP_INIT"
  fi

  echo "Installing toolchain $TOOLCHAIN into .toolchain/"
  "$RUSTUP_INIT" -y \
    --no-modify-path \
    --profile minimal \
    --default-toolchain "$TOOLCHAIN" \
    --component rustfmt clippy
fi

echo
echo "Done. In this and every future shell:"
echo
echo "    source scripts/env.sh"
echo "    cargo build --release --workspace"
echo
"$CARGO_HOME/bin/rustc" --version 2>/dev/null || true
