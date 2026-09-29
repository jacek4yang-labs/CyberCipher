# Cutting a CyberCipher release

## Canonical artifact

`CyberCipher-vX.Y.Z-linux-x86_64.tar.gz` (+ `.sha256`), extracted under
`~/Applications/`. This is the only canonical Linux release format;
AppImage is an optional future artifact, not the release path.

## Build baseline

Release binaries are built on **ubuntu-22.04** runners: the oldest widely
deployed glibc (2.35) among supported Mint/Ubuntu LTS baselines, so the
dynamic binaries run on Mint 21+ and later without recompilation. The
binaries remain dynamically linked against WebKitGTK/GTK3 — this is
documented honestly in the packaged README.txt; we do not claim static
portability.

## Procedure

1. Bump `version` in `apps/cybercipher-gui/tauri.conf.json` and the
   workspace `Cargo.toml` if needed; commit via PR.
2. Tag: `git tag v0.1.0 && git push origin v0.1.0`.
3. The `Release` workflow builds the frontend + release binaries, runs
   `scripts/package-linux.sh` (which includes an extraction + CLI KAT smoke
   test), and uploads the tar.gz + sha256 as artifacts.
4. Verify the smoke job is green, then publish the GitHub Release with the
   artifacts (done manually or by adding release publishing later — the
   workflow does not publish automatically).

## Smoke test requirements (enforced by the release workflow)

- `CyberCipher/CyberCipher` and `CyberCipher/cybercipher` exist and are
  executable after extraction.
- `cybercipher --help` exits 0.
- A deterministic CLI known-answer test passes
  (sha256("abc") = ba7816bf...5ad).
- `ldd` output of the GUI binary is recorded (dynamic dependencies are
  expected and documented, not hidden).

## Local packaging

`./scripts/package-linux.sh [version]` performs the same build + package +
smoke steps on any Linux host with Node, Rust, and the Tauri system deps.

## Upgrade model

User state lives in XDG directories (`~/.config/cybercipher`,
`~/.cache/cybercipher`, `~/.local/share/cybercipher`) — never inside the
application folder. Upgrading is therefore: extract the new tar over
`~/Applications/CyberCipher/`.
