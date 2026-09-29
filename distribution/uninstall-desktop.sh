#!/usr/bin/env bash
# Remove CyberCipher desktop integration for the current user.
# Never touches user data (~/.config, ~/.cache, ~/.local/share/cybercipher)
# or the installation directory itself.
set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
rm -f "$DATA_HOME/applications/cybercipher.desktop"
rm -f "$DATA_HOME/icons/hicolor/256x256/apps/cybercipher.png"
echo "Desktop integration removed."
echo "User data (recipes, settings) was kept:"
echo "  ~/.config/cybercipher  ~/.cache/cybercipher  ~/.local/share/cybercipher"
echo "The installation directory was kept — remove it manually if desired."
