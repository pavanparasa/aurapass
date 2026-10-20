#!/usr/bin/env bash
#
# Builds the AuraPass Debian package.
#
#   packaging/build-deb.sh                 build, stage and package
#   packaging/build-deb.sh --no-build      reuse the release binaries as-is
#   packaging/build-deb.sh --no-extensions skip the browser-extension packages
#
# The result is dist/aurapass_<version>_<arch>.deb. Everything is staged inside
# the repository (target/deb/) and nothing outside the project folder is
# touched.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUILD=1
EXTENSIONS=1
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --no-extensions) EXTENSIONS=0 ;;
    -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '  %s\n' "$*"; }
fail() { printf 'aurapass: %s\n' "$*" >&2; exit 1; }

command -v dpkg-deb > /dev/null 2>&1 || fail "dpkg-deb is required to build a .deb"

# shellcheck source=../scripts/env.sh
source "$ROOT/scripts/env.sh"

VERSION="$(awk '/^\[workspace\.package\]/{f=1} f && /^version[[:space:]]*=/{gsub(/[" ]/,"",$3); print $3; exit}' Cargo.toml)"
ARCH="$(dpkg --print-architecture)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/release"
STAGE="$ROOT/target/deb/aurapass_${VERSION}_${ARCH}"
OUT_DIR="$ROOT/dist"
OUT="$OUT_DIR/aurapass_${VERSION}_${ARCH}.deb"

[ -n "$VERSION" ] || fail "could not read the workspace version from Cargo.toml"

BINARIES=(aurapass aurapass-desktop aurapass-bridge)

# ------------------------------------------------------------------- build

if [ "$BUILD" = 1 ]; then
  echo "Building release binaries"
  cargo build --release --workspace
fi

for binary in "${BINARIES[@]}"; do
  [ -x "$TARGET_DIR/$binary" ] || fail "missing $TARGET_DIR/$binary (run without --no-build)"
done

if [ "$EXTENSIONS" = 1 ]; then
  echo "Building browser extensions"
  "$ROOT/extensions/build.sh" --zip > /dev/null
fi

# ------------------------------------------------------------------- stage

echo "Staging $STAGE"
rm -rf "$STAGE"
mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/share/applications" \
  "$STAGE/usr/share/aurapass/extensions" \
  "$STAGE/usr/share/doc/aurapass" \
  "$STAGE/usr/share/icons/hicolor/scalable/apps" \
  "$STAGE/usr/share/icons/hicolor/128x128/apps" \
  "$STAGE/usr/share/man/man1" \
  "$STAGE/usr/share/mime/packages"

for binary in "${BINARIES[@]}"; do
  install -m 0755 "$TARGET_DIR/$binary" "$STAGE/usr/bin/$binary"
done
say "installed ${#BINARIES[@]} binaries"

install -m 0644 packaging/aurapass.desktop "$STAGE/usr/share/applications/aurapass.desktop"
install -m 0644 packaging/aurapass.svg "$STAGE/usr/share/icons/hicolor/scalable/apps/aurapass.svg"
install -m 0644 extensions/shared/icons/icon128.png \
  "$STAGE/usr/share/icons/hicolor/128x128/apps/aurapass.png"
install -m 0644 packaging/aurapass-vault.xml "$STAGE/usr/share/mime/packages/aurapass-vault.xml"
say "installed desktop entry, icons and MIME type"

for page in packaging/man/*.1; do
  [ -e "$page" ] || continue
  install -m 0644 "$page" "$STAGE/usr/share/man/man1/$(basename "$page")"
done
gzip -9n -f "$STAGE"/usr/share/man/man1/*.1 2>/dev/null || true

install -m 0644 packaging/debian/copyright "$STAGE/usr/share/doc/aurapass/copyright"

# A short changelog so lintian is happier and users can see what changed.
{
  printf 'aurapass (%s) unstable; urgency=medium\n\n' "$VERSION"
  printf '  * Initial packaged release.\n\n'
  printf ' -- pa1 <pa1@aurapass.invalid>  %s\n' \
    "$(date -u '+%a, %d %b %Y %H:%M:%S +0000')"
} > "$STAGE/usr/share/doc/aurapass/changelog"
gzip -9n -f "$STAGE/usr/share/doc/aurapass/changelog"

if [ "$EXTENSIONS" = 1 ]; then
  # Ship the packages (zip for store upload / unzipping, xpi for Firefox) and
  # the unpacked trees, so "Load unpacked" works straight from
  # /usr/share/aurapass/extensions/chromium without unzipping anything.
  #
  # The signed .crx is deliberately not installed: Chrome rejects a locally
  # built CRX with CRX_REQUIRED_PROOF_MISSING, so shipping it only invites
  # users to hit a dead end. It stays in dist/ for enterprise deployments.
  for pkg in "$OUT_DIR"/aurapass-chromium-*.zip \
             "$OUT_DIR"/aurapass-firefox-*.zip "$OUT_DIR"/aurapass-firefox-*.xpi; do
    [ -e "$pkg" ] || continue
    install -m 0644 "$pkg" "$STAGE/usr/share/aurapass/extensions/$(basename "$pkg")"
  done
  for target in chromium firefox; do
    [ -d "$ROOT/extensions/$target" ] || continue
    rm -rf "$STAGE/usr/share/aurapass/extensions/$target"
    cp -r "$ROOT/extensions/$target" "$STAGE/usr/share/aurapass/extensions/$target"
  done
  find "$STAGE/usr/share/aurapass/extensions/chromium" \
       "$STAGE/usr/share/aurapass/extensions/firefox" -type f -exec chmod 0644 {} +
  find "$STAGE/usr/share/aurapass/extensions/chromium" \
       "$STAGE/usr/share/aurapass/extensions/firefox" -type d -exec chmod 0755 {} +
  say "bundled browser extensions (packages + unpacked)"
fi

install -m 0755 packaging/debian/postinst "$STAGE/DEBIAN/postinst"
install -m 0755 packaging/debian/postrm "$STAGE/DEBIAN/postrm"

SIZE="$(du -sk "$STAGE/usr" | cut -f1)"

# Ask the binaries themselves which glibc they need, so the Depends line stays
# honest whether they were built on Ubuntu 24.04 or an older Debian.
LIBC_MIN="2.35"
if command -v readelf > /dev/null 2>&1; then
  found="$(for binary in "${BINARIES[@]}"; do
    readelf --version-info "$TARGET_DIR/$binary" 2>/dev/null \
      | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/^GLIBC_//'
  done | sort -uV | tail -1)"
  [ -n "$found" ] && LIBC_MIN="$found"
fi

sed -e "s/@VERSION@/$VERSION/" \
    -e "s/@ARCH@/$ARCH/" \
    -e "s/@SIZE@/$SIZE/" \
    -e "s/@LIBC@/$LIBC_MIN/" \
    packaging/debian/control.in > "$STAGE/DEBIAN/control"

# ------------------------------------------------------------------ package

# Normalise modes so the archive is not at the mercy of the build umask.
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE/usr" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE"/usr/bin/* "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/postrm"
chmod 0644 "$STAGE/DEBIAN/control"

mkdir -p "$OUT_DIR"
rm -f "$OUT"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" > /dev/null

echo
say "built $OUT"
dpkg-deb --info "$OUT" | sed -n 's/^/    /p'
echo
say "installed size: $(du -sh "$STAGE/usr" | cut -f1)"
say "contents:"
dpkg-deb --contents "$OUT" | awk '{print "    " $1, $6}'
