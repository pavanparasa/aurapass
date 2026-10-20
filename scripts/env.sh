#!/usr/bin/env bash
# AuraPass build environment.
# Everything (rustup, cargo home, target dir) lives INSIDE this repository so
# that building aurapass never touches files outside the project folder.
#
#   source scripts/env.sh
#
# Optional: point AURAPASS_TOOLCHAIN elsewhere if you already have Rust.
set -u

AURAPASS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export AURAPASS_ROOT

export RUSTUP_HOME="${RUSTUP_HOME:-$AURAPASS_ROOT/.toolchain/rustup}"
export CARGO_HOME="${CARGO_HOME:-$AURAPASS_ROOT/.toolchain/cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AURAPASS_ROOT/target}"
export PATH="$CARGO_HOME/bin:$PATH"

if ! command -v cargo >/dev/null 2>&1; then
  echo "aurapass: cargo not found. Run scripts/bootstrap-toolchain.sh first." >&2
fi

# Deterministic, offline-friendly builds.
export CARGO_NET_RETRY="${CARGO_NET_RETRY:-5}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
