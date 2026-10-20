#!/usr/bin/env bash
# Capture AuraPass screens with the in-app harness (development aid).
#
#   scripts/shoot.sh [modal ...]
#
# With no arguments it shoots the locked window and the main window; otherwise
# it shoots the main window with the named dialog open. PNGs land in
# /tmp/opencode/shots/.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/env.sh"

OUT="${AURAPASS_SHOT_DIR:-/tmp/opencode/shots}"
FIXTURE="${AURAPASS_SHOT_FIXTURE:-/tmp/aurapass-shot}"
mkdir -p "$OUT"

BIN="$CARGO_TARGET_DIR/debug/aurapass-desktop"
[ -x "$BIN" ] || { echo "build the gui first: cargo build -p aurapass-gui" >&2; exit 1; }

unset AURAPASS_SHOT_VAULT AURAPASS_SHOT_PASSWORD AURAPASS_SHOT_MODAL

shoot() { # name, vault?, modal?
  local name="$1" vault="$2" modal="${3:-}"
  local ppm="$OUT/$name.ppm"
  export AURAPASS_CONFIG_DIR="$FIXTURE/config"
  unset AURAPASS_SHOT_VAULT AURAPASS_SHOT_PASSWORD AURAPASS_SHOT_MODAL
  [ -n "$vault" ] && export AURAPASS_SHOT_VAULT="$vault"
  [ -n "$vault" ] && export AURAPASS_SHOT_PASSWORD="$(cat "$FIXTURE/pw")"
  [ -n "$modal" ] && export AURAPASS_SHOT_MODAL="$modal"
  AURAPASS_SHOT="$ppm" timeout 90 "$BIN" >"$OUT/$name.log" 2>&1
  python3 - "$ppm" "$OUT/$name.png" <<'PY'
import sys
from PIL import Image
Image.open(sys.argv[1]).save(sys.argv[2])
PY
  echo "  $OUT/$name.png"
}

VAULT="$FIXTURE/demo.aurapass"

if [ "$#" -eq 0 ]; then
  shoot locked ""
  shoot main "$VAULT"
else
  for modal in "$@"; do
    if [ "$modal" = "locked" ]; then
      shoot locked ""
    else
      shoot "$modal" "$VAULT" "$modal"
    fi
  done
fi
