CyberCipher — Crypto, decode, analyze, solve.
==============================================

Thank you for downloading CyberCipher, a local-first cryptography and CTF
workbench. Everything runs on your machine: no telemetry, no accounts, no
network access required.

RUNNING
-------
No installation is required — extraction alone is enough:

  ~/Applications/CyberCipher/CyberCipher     (graphical workbench)
  ~/Applications/CyberCipher/cybercipher     (command line)

Example:

  ~/Applications/CyberCipher/cybercipher run --op sha256 -- "abc"
  ~/Applications/CyberCipher/cybercipher auto "ZmxhZ3tleGFtcGxlfQ=="

Optional command-line symlink:

  mkdir -p ~/.local/bin
  ln -sfn ~/Applications/CyberCipher/cybercipher ~/.local/bin/cybercipher

DESKTOP INTEGRATION (optional)
------------------------------
  ./install-desktop.sh

creates a menu entry and icon for the current user (no sudo, idempotent).
Remove it any time with:

  ./uninstall-desktop.sh

SYSTEM REQUIREMENTS
-------------------
CyberCipher ships as native dynamically linked Linux binaries (built on
Ubuntu 22.04, x86_64). Runtime requires the standard Tauri/WebKitGTK
libraries, which are present on Linux Mint 21+ and most desktop distros:

  libwebkit2gtk-4.1, libgtk-3, libayatana-appindicator3, librsvg-2,
  libglib2.0, libcairo2, libpango — install via your package manager if a
  launch attempt reports a missing .so (e.g. on Debian/Ubuntu/Mint:
  sudo apt install libwebkit2gtk-4.1-0 libgtk-3-0).

No Node.js, Rust, Python, or Java is required at runtime.

USER DATA (XDG)
---------------
Your recipes and settings live outside the application directory, so
upgrading is a simple folder replacement:

  ~/.config/cybercipher/          (saved recipes, settings)
  ~/.cache/cybercipher/           (caches)
  ~/.local/share/cybercipher/     (future local state)

UPGRADING
---------
Download the new tar.gz, extract it over (or replace)
~/Applications/CyberCipher/ — your data in the XDG directories is kept.

LICENSE
-------
Dual-licensed under MIT (LICENSE-MIT) or Apache-2.0 (LICENSE-APACHE), at
your option. Third-party notice: built with RustCrypto crates and
Tauri/WebKitGTK; see the repository for the full dependency list.

https://github.com/jacek4yang-labs/CyberCipher
