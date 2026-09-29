#!/usr/bin/env bash
# Package CyberCipher into the canonical Linux tar.gz release.
#
# Usage: ./scripts/package-linux.sh [version]
#   version defaults to the version in apps/cybercipher-gui/tauri.conf.json.
#
# Produces: CyberCipher-v<version>-linux-x86_64.tar.gz (+ .sha256)
#
# Requirements (build host): Node.js + npm (frontend build), Rust toolchain,
# Tauri Linux system deps (libwebkit2gtk-4.1-dev libgtk-3-dev
# libayatana-appindicator3-dev librsvg2-dev).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(python -c "import json;print(json.load(open('apps/cybercipher-gui/tauri.conf.json'))['version'])")"
fi

ARTIFACT="CyberCipher-v${VERSION}-linux-x86_64"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/CyberCipher"
mkdir -p "$PKG/share/icons"

echo "==> Building frontend (ui/)"
npm --prefix ui ci --no-audit --no-fund
npm --prefix ui run build

echo "==> Building release binaries"
cargo build --release -p cybercipher-gui -p cybercipher-cli

echo "==> Assembling $ARTIFACT"
# GUI binary: produced as target/release/cybercipher-gui (package name);
# shipped as CyberCipher (the productName).
cp target/release/cybercipher-gui "$PKG/CyberCipher"
cp target/release/cybercipher "$PKG/cybercipher"
chmod 755 "$PKG/CyberCipher" "$PKG/cybercipher"

cp distribution/install-desktop.sh "$PKG/"
cp distribution/uninstall-desktop.sh "$PKG/"
chmod 755 "$PKG/install-desktop.sh" "$PKG/uninstall-desktop.sh"

cp apps/cybercipher-gui/icons/128x128.png "$PKG/share/icons/cybercipher.png"
cp apps/cybercipher-gui/icons/32x32.png "$PKG/share/icons/cybercipher-32.png"
cp LICENSE-MIT LICENSE-APACHE "$PKG/"
cp distribution/README.txt "$PKG/"

echo "==> Creating tar.gz"
tar -czf "$ARTIFACT.tar.gz" -C "$STAGE" CyberCipher
sha256sum "$ARTIFACT.tar.gz" > "$ARTIFACT.tar.gz.sha256"

echo "==> Smoke test: extraction + CLI KAT"
SMOKE="$(mktemp -d)"
tar -xzf "$ARTIFACT.tar.gz" -C "$SMOKE"
test -x "$SMOKE/CyberCipher/CyberCipher"
test -x "$SMOKE/CyberCipher/cybercipher"
KAT="$("$SMOKE/CyberCipher/cybercipher" run --op sha256 -- "abc")"
EXPECTED="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
if [[ "$KAT" != "$EXPECTED" ]]; then
  echo "KAT FAILED: sha256(abc) = $KAT" >&2
  exit 1
fi
rm -rf "$SMOKE"

echo "==> Done: $ARTIFACT.tar.gz"
