#!/usr/bin/env bash
# Builds the Malo desktop client with the bundled local server (sidecar).
#
#   ./build-client.sh                      release installers for this OS
#   ./build-client.sh --bundles deb        only some installer types (comma-separated)
#   ./build-client.sh --no-bundle          just the app binary, no installers
#   ./build-client.sh --debug              debug build (faster, larger, unoptimized)
#   ./build-client.sh --target <triple>    cross-compile (the Rust target must be installed)
#
# Installer types: appimage, deb, rpm (Linux); app, dmg (macOS); msi, nsis (Windows).
set -euo pipefail

cd "$(dirname "$0")"

debug=false
bundles=""
no_bundle=false
target=""

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug) debug=true ;;
    --bundles) bundles="${2:?--bundles needs a list, e.g. deb,appimage}"; shift ;;
    --no-bundle) no_bundle=true ;;
    --target) target="${2:?--target needs a Rust target triple}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if $no_bundle && [[ -n "$bundles" ]]; then
  echo "Use either --bundles or --no-bundle, not both." >&2
  exit 2
fi

for tool in node npm cargo rustc; do
  command -v "$tool" >/dev/null || { echo "Missing $tool. Install Node.js and Rust first." >&2; exit 1; }
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if [[ ! -d node_modules ]]; then
  step "Installing npm packages"
  npm ci
fi

# The app ships malo-server inside it; Tauri expects it at src-tauri/binaries/malo-server-<triple>.
step "Building the bundled server${target:+ for $target}"
sidecar_args=()
$debug && sidecar_args+=(--debug)
[[ -n "$target" ]] && sidecar_args+=(--target "$target")
# ${a[@]+...}: bash 3.2 (macOS) treats an empty array as unset under set -u.
node scripts/build-sidecar.mjs ${sidecar_args[@]+"${sidecar_args[@]}"}

# tauri build also builds the web UI first (beforeBuildCommand: npm run build).
step "Building the desktop app"
tauri_args=()
$debug && tauri_args+=(--debug)
[[ -n "$target" ]] && tauri_args+=(--target "$target")
if $no_bundle; then
  tauri_args+=(--no-bundle)
elif [[ -n "$bundles" ]]; then
  tauri_args+=(--bundles "$bundles")
fi
npx tauri build ${tauri_args[@]+"${tauri_args[@]}"}

profile=$($debug && echo debug || echo release)
out="target${target:+/$target}/$profile"
step "Done"
if $no_bundle; then
  for bin in "$out/malo" "$out/malo.exe"; do
    if [[ -f "$bin" ]]; then echo "App binary: $bin"; fi
  done
else
  echo "Installers in $out/bundle/:"
  find "$out/bundle" -maxdepth 2 \( -type f \( -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' \
    -o -name '*.dmg' -o -name '*.msi' -o -name '*.exe' \) -o -type d -name '*.app' \) -print 2>/dev/null | sort
fi
