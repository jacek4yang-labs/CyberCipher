#!/usr/bin/env bash
# Install CyberCipher desktop integration for the current user (no sudo).
# Idempotent: running it again updates the existing entries.
set -euo pipefail

APP_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
APPLICATIONS="$DATA_HOME/applications"
ICONS="$DATA_HOME/icons/hicolor/256x256/apps"

if [[ ! -x "$APP_DIR/CyberCipher" ]]; then
  echo "error: $APP_DIR/CyberCipher not found or not executable" >&2
  exit 1
fi

mkdir -p "$APPLICATIONS" "$ICONS"

# Icon (idempotent copy).
if [[ -f "$APP_DIR/share/icons/cybercipher.png" ]]; then
  cp -f "$APP_DIR/share/icons/cybercipher.png" "$ICONS/cybercipher.png"
fi

# Desktop entry.
cat > "$APPLICATIONS/cybercipher.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=CyberCipher
Comment=Crypto, decode, analyze, solve.
Exec=$APP_DIR/CyberCipher
Icon=cybercipher
Terminal=false
Categories=Development;Security;Utility;
Keywords=crypto;ctf;encoding;decode;
DESKTOP

chmod 644 "$APPLICATIONS/cybercipher.desktop" "$ICONS/cybercipher.png" 2>/dev/null || true

echo "Desktop entry installed: $APPLICATIONS/cybercipher.desktop"
echo "Launch CyberCipher from your application menu or:"
echo "  $APP_DIR/CyberCipher"
echo
echo "Optional CLI symlink:"
echo "  mkdir -p ~/.local/bin && ln -sfn $APP_DIR/cybercipher ~/.local/bin/cybercipher"
