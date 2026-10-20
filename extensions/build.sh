#!/usr/bin/env bash
#
# Assembles the browser extensions.
#
# `extensions/shared/` is the whole extension — one implementation, tested
# against the real bridge by `tools/test-bridge.mjs`. The only per-browser
# difference is the manifest, so this script copies the shared sources into
# `extensions/chromium/` and `extensions/firefox/` next to their manifest and
# checks that every file the manifest mentions is actually present.
#
# Usage:
#   extensions/build.sh            assemble and validate
#   extensions/build.sh --zip      also write dist/aurapass-<browser>.zip
#   extensions/build.sh --test     also run the crypto/interop test suites

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED="$ROOT/shared"
DIST="$(cd "$ROOT/.." && pwd)/dist"
TARGETS=(chromium firefox)

ZIP=0
TEST=0
for arg in "$@"; do
  case "$arg" in
    --zip) ZIP=1 ;;
    --test) TEST=1 ;;
    -h|--help)
      sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '  %s\n' "$*"; }

# ---------------------------------------------------------------- assemble

for target in "${TARGETS[@]}"; do
  dir="$ROOT/$target"
  echo "Assembling $target"
  rm -rf "$dir/lib" "$dir/icons"
  mkdir -p "$dir/lib" "$dir/icons"
  cp "$SHARED"/lib/*.js "$dir/lib/"
  cp "$SHARED"/*.js "$dir/"
  cp "$SHARED"/*.html "$dir/"
  cp "$SHARED"/*.css "$dir/"
  cp "$SHARED"/icons/*.png "$dir/icons/"
  say "copied $(find "$dir" -type f | wc -l) files"
done

# ---------------------------------------------------------------- validate

echo "Checking syntax"
for target in "${TARGETS[@]}"; do
  while IFS= read -r file; do
    node --check "$file"
  done < <(find "$ROOT/$target" -name '*.js' | sort)
  say "$target ok"
done

echo "Validating manifests"
for target in "${TARGETS[@]}"; do
  dir="$ROOT/$target"
  node --input-type=module -e '
    import { readFileSync, existsSync } from "node:fs";
    const dir = process.argv[1];
    const manifest = JSON.parse(readFileSync(`${dir}/manifest.json`, "utf8"));
    const problems = [];
    if (manifest.manifest_version !== 3) problems.push("manifest_version must be 3");
    if (!manifest.name || !manifest.version) problems.push("name/version missing");
    const referenced = [];
    const walk = (value) => {
      if (typeof value === "string") {
        if (/\.(js|html|css|png)$/.test(value)) referenced.push(value);
        return;
      }
      if (Array.isArray(value)) return value.forEach(walk);
      if (value && typeof value === "object") Object.values(value).forEach(walk);
    };
    walk(manifest);
    for (const file of referenced) {
      if (!existsSync(`${dir}/${file}`)) problems.push(`missing file: ${file}`);
    }
    if (manifest.background?.service_worker && manifest.background?.scripts) {
      problems.push("manifest sets both service_worker and scripts");
    }
    for (const entry of manifest.content_scripts || []) {
      for (const file of entry.js || []) {
        if (!existsSync(`${dir}/${file}`)) problems.push(`missing content script: ${file}`);
      }
    }
    // Every relative import must point at a real file.
    const stack = ["background.js", "popup.js", "options.js", "content.js"];
    const seen = new Set();
    while (stack.length) {
      const file = stack.pop();
      if (seen.has(file)) continue;
      seen.add(file);
      if (!existsSync(`${dir}/${file}`)) continue;
      const source = readFileSync(`${dir}/${file}`, "utf8");
      // Drop comments so JSDoc examples like `from "./lib/bridge.js"` are not
      // mistaken for real imports; `://` in URLs is left alone.
      const stripped = source
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/(^|[^:\w])\/\/[^\n]*/gm, "$1");
      for (const match of stripped.matchAll(/from\s+[\u0027"]([^\u0027"]+)[\u0027"]/g)) {
        const base = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "";
        let target = match[1].replace(/^\.\//, "");
        if (base) target = `${base}/${target}`;
        if (!existsSync(`${dir}/${target}`)) problems.push(`${file} imports missing ${target}`);
        else stack.push(target);
      }
    }
    if (problems.length) {
      console.error(`  FAIL ${dir.split("/").pop()}`);
      for (const problem of problems) console.error(`       ${problem}`);
      process.exit(1);
    }
    console.log(`  ok   ${manifest.name} ${manifest.version} (${dir.split("/").pop()})`);
  ' "$dir"
done

# ---------------------------------------------------------------- test

if [ "$TEST" = 1 ]; then
  echo "Running extension tests"
  node "$ROOT/tools/test-crypto.mjs"
fi

# ---------------------------------------------------------------- package

if [ "$ZIP" = 1 ]; then
  echo "Packaging"
  mkdir -p "$DIST"
  version="$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$ROOT/chromium/manifest.json")"
  for target in "${TARGETS[@]}"; do
    out="$DIST/aurapass-$target-$version.zip"
    rm -f "$out"
    if command -v zip > /dev/null 2>&1; then
      (cd "$ROOT/$target" && zip -qr "$out" . -x '.*')
    else
      python3 - "$ROOT/$target" "$out" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for root, _dirs, files in os.walk(src):
        for name in files:
            path = os.path.join(root, name)
            zf.write(path, os.path.relpath(path, src))
PY
    fi
    say "$out"
  done

  # Firefox installs a .xpi: the same zip under the name the browser expects.
  xpi="$DIST/aurapass-firefox-$version.xpi"
  cp "$DIST/aurapass-firefox-$version.zip" "$xpi"
  say "$xpi"

  # Chrome/Chromium use the signed CRX3 container. The key is the extension's
  # identity, so it is kept in packaging/keys/ and reused for every release.
  if command -v openssl > /dev/null 2>&1; then
    python3 "$ROOT/../packaging/pack-crx.py" \
      --dir "$ROOT/chromium" \
      --key "$ROOT/../packaging/keys/aurapass-chromium.pem" \
      --out "$DIST/aurapass-chromium-$version.crx"
  else
    say "openssl not found - skipping the .crx (the .zip loads unpacked)"
  fi
fi

echo "Done."
