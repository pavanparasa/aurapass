#!/usr/bin/env bash
# Measure what the desktop app actually costs in memory.
#
#   scripts/mem.sh [vault] [password-file]
#
# Reports resident set size (RSS) and proportional set size (PSS) for the two
# states that matter: locked (nothing decrypted, the window on the unlock card)
# and unlocked (a vault open, the main window drawn). PSS is the honest number:
# it counts shared pages, such as libc and the font files, at their true share.
#
# With no arguments it uses the fixture vault under /tmp/aurapass-shot. Passing
# a vault and a password file measures a real one. The app is asked to hold the
# window open through the same capture harness `scripts/shoot.sh` uses; nothing
# here is set by the shipped package.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/env.sh"

FIXTURE="${AURAPASS_SHOT_FIXTURE:-/tmp/aurapass-shot}"
VAULT="${1:-$FIXTURE/demo.aurapass}"
PWFILE="${2:-$FIXTURE/pw}"
SETTLE="${AURAPASS_MEM_SETTLE:-10}"
BIN="$CARGO_TARGET_DIR/release/aurapass-desktop"

[ -x "$BIN" ] || { echo "build it first: cargo build --release -p aurapass-gui" >&2; exit 1; }

sample() { # pid
    local rss pss thr gl
    rss=$(awk '/^VmRSS:/{print $2}' "/proc/$1/status")
    pss=$(awk '/^Pss:/{print $2}' "/proc/$1/smaps_rollup")
    thr=$(awk '/^Threads:/{print $2}' "/proc/$1/status")
    gl=$(grep -ciE 'libGL|libEGL|mesa|swrast|libvulkan' "/proc/$1/maps")
    printf 'RSS %5d MB   PSS %5d MB   threads %-3s GPU-driver mappings %s\n' \
        $((rss / 1024)) $((pss / 1024)) "$thr" "$gl"
}

measure() { # label, vault?, password?
    local label="$1" vault="${2:-}" password="${3:-}"
    local dir
    dir="$(mktemp -d)"
    printf '{"version":1,"vaults":[],"bridge":{"enabled":false,"port":8974,"token":"","require_gui":true,"lock_on_disconnect":false},"theme":"light","window":{"width":1180.0,"height":760.0,"maximized":false},"onboarded":true,"last_directory":null,"tray_enabled":true,"close_to_tray":true,"tray_icon_dark":false}\n' >"$dir/config.json"

    local env_args=(AURAPASS_CONFIG_DIR="$dir")
    if [ -n "$vault" ]; then
        env_args+=(
            AURAPASS_SHOT="$dir/hold.ppm"
            AURAPASS_SHOT_HOLD=1
            AURAPASS_SHOT_VAULT="$vault"
            AURAPASS_SHOT_PASSWORD="$password"
            AURAPASS_SHOT_MODAL=main
        )
    fi

    env "${env_args[@]}" "$BIN" >/dev/null 2>&1 &
    local pid=$!
    sleep "$SETTLE"
    if ! kill -0 "$pid" 2>/dev/null; then
        printf '%-28s failed to stay up\n' "$label"
    else
        printf '%-28s %s\n' "$label" "$(sample "$pid")"
    fi
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    rm -rf "$dir"
}

printf '%s\n' "aurapass-desktop, $(date +%Y-%m-%d), settled ${SETTLE}s"
measure "locked, idle"
if [ -r "$VAULT" ] && [ -r "$PWFILE" ]; then
    measure "unlocked, idle" "$VAULT" "$(cat "$PWFILE")"
else
    echo "no vault at $VAULT — skipping the unlocked measurement" >&2
fi
