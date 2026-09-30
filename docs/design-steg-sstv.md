# Design: Steg + SSTV integration into CyberCipher

Status: accepted contract for Lane A (steg core), Lane B (sstv-auto),
Lane C (structure/carving/frames), Lane D (QR + Stego Lab), Lane F (stereo/
combine/pixel UX). Reference commits: StegSolver `c14bfa9`, sstv-auto
`f626d50` (both MIT, see `compatibility/stegsolver.toml` and
`compatibility/sstv-auto.toml`).

## Hard invariants

1. **No Java, ever.** StegSolver is a behavioral/source reference. The final
   `CyberCipher-vX.Y.Z-linux-x86_64.tar.gz` must not contain or require a JVM,
   JavaFX, or Maven. No Java in normal CI once fixtures are pinned.
2. **No subprocesses.** sstv-auto and slowrx are Rust libraries; they are
   compiled in, not invoked. sstv-auto modules migrate in-tree (option 1);
   slowrx stays a pinned crates.io dependency (`slowrx = "=0.5.3"`),
   re-evaluated for vendoring at 1.0.
3. **Runtime needs no Python/Node/Rust toolchain.** symphonia (audio) and
   image/rustfft are pure-Rust, statically linked.
4. **Engine is the product.** All capabilities register in the
   OperationRegistry with typed errors, provenance, resource bounds and cost
   classes; the GUI is replaceable.

## Workspace layout

```
crates/
  cybercipher-media/    # shared image types + bounded decode/encode
  cybercipher-steg/     # transforms, extraction, Auto LSB (structure/QR land
                        # here in later lanes, own modules)
  cybercipher-sstv/     # sstv-auto modules migrated (audio/dsp/modes/vis/
                        # sync/raster/synth/autodetect/backend/score/pipeline/
                        # report), lib-only, strict lints preserved
```

Three crates, not micro-crates; media exists so steg and sstv share one image
representation (`RgbaImage { width, height, argb: Vec<u32> }`, non-premultiplied
`0xAARRGBB` layout identical to upstream, optional palette + indices) and one
bounded decode path.

## cybercipher-media contract

```rust
pub struct RgbaImage { width: u32, height: u32, argb: Vec<u32>, has_alpha: bool,
                      indexed: Option<IndexedData> }   // palette: Vec<u32>, indices: Vec<u32>
pub struct DecodeLimits { max_file_bytes: u64 /* default 256 MiB */,
                          max_pixels: u64 /* default 64 MiPx */ }
pub fn decode(bytes: &[u8], limits: &DecodeLimits) -> Result<RgbaImage, MediaError>;
pub fn encode_png(&RgbaImage) -> Result<Vec<u8>, MediaError>;
```

- Caps are enforced **before** allocation; header dimensions are untrusted
  (checked against both caps and buffer math overflow).
- Indexed sources keep palette + indices (random palette map needs them).
- `MediaError` converts into `OperationError` at the registry boundary.
- Blob plumbing reuses the existing Value/DataRef/blob infrastructure.

## cybercipher-steg: Lane A contracts (bit-exact)

**Transforms** (`transforms.rs`) — catalog order is API:

| idx | meaning | semantic |
|----:|---------|----------|
| 0 | original | pass-through (alpha preserved) |
| 1 | invert | `argb ^ 0xFFFFFF`, opaque |
| 2..9 | alpha planes 7..0 | `((p >>> 24+plane) & 1)` -> `0xFFFFFFFF : 0xFF000000` |
| 10..17 | red planes 7..0 | shift 16 |
| 18..25 | green planes 7..0 | shift 8 |
| 26..33 | blue planes 7..0 | shift 0 |
| 34..37 | full a/r/g/b | mask; legacy quirk: `v >>>= 8` when mask reaches alpha |
| 38..40 | random maps 1..3 | Java `Random(0x5EED0001+variant-1)`; component map `c' = ((c*cm)^cx)+ca` per channel; palette map over palette entries for indexed sources |
| 41 | gray pixels | white where `r == g == b` |

Every computed output is forced opaque (`0xFF000000 | (v & 0xFFFFFF)`),
mirroring legacy TYPE_INT_RGB. **Java `Random` must be reproduced**: 48-bit LCG
`seed = (seed * 0x5DEECE66D + 0xB) & ((1<<48)-1)`, `nextInt(256) = (seed >>> 40)
as u8`, called in the order bm, ba, bx, gm, ga, gx, rm, ra, rx (component map)
or r, g, b per palette entry (palette map). This is engine code with a doc
comment explaining why (golden parity), not test-only code.

**Extraction** (`extract.rs`) — `ExtractionOptions { plane_mask: u32,
order: RgbOrder, lsb_first: bool, row_first: bool, invert_bits: bool }`:
- plane bit `channel_ordinal*8 + plane` (ordinal ALPHA=0, RED=1, GREEN=2,
  BLUE=3 — matches upstream plane space),
- visit order: ALPHA first, then the RGB permutation (legacy codes 1=RGB ..
  6=BGR),
- inside a channel: planes 7→0 when MSB-first, 0→7 when LSB-first,
- traversal row-first or column-first, ROI clamped up front,
- `invert_bits` = `!pixel` before reading,
- bits pack MSB-first into bytes; trailing partial byte is zero-padded,
- bounded: `extract_bounded(roi, options, max_bytes) -> { data, total_bytes,
  truncated }`; cancellation checked per row (ExecutionContext).

**Auto LSB** (`auto_lsb.rs`):
- Fast/Deep enumerations exactly as upstream (`fast_scan_options(has_alpha)`,
  `deep_scan_options`); keep them as data, not loops-of-loops, so the candidate
  list is inspectable and testable.
- Phase 1 prefix limit 64 KiB; per candidate: `{ options, score, reason,
  payload_type, preview(≤64 KiB), total_bytes, truncated }`.
- Scoring table ported verbatim (98 CTF flag / 100 strong magic / 95 BMP≥14B /
  94 shebang / 92 JSON+XML / 90·86·80 text tiers / 72·45 base64 / 65 partial-
  printable + unverified-MZ / 30 structured binary / 20 binary / 15 high-
  entropy noise / 10 unclassified / 5 low variation / 1 uniform). Detectors
  MUST reuse `cybercipher-codec::fileinfo` magic + `cybercipher_core::util`
  entropy — one scoring system, no fork. CTF flag regex from upstream:
  `(?i)(flag|ctf|steg|key|secret|pico|htb|thm)\{[\x20-\x7e]{1,128}\}` scanned
  in the first 16 KiB.
- Dedup: `fingerprint + total_bytes` (+ options when truncated); rank score
  desc. Phase 2 full extraction only on explicit apply.

**Registry ops** (registered from `register_all`): `image_info`,
`image_decode_png` (blob→blob+meta), `image_transform` (op with transform index
param), `image_extract_bits`, `auto_lsb_scan` (CostClass::Solver, deadline +
cancellation), plus per-op provenance naming StegSolver semantics. Transforms
are CostClass::Instant (auto-bake friendly); scans are Solver; anything SSTV is
Heavy.

**Golden parity tests**: deterministic synthetic fixtures (port the concept of
upstream `SyntheticImage`), plus expected pixel arrays pinned as hex in the
repo, transcribed from the LegacyReference semantics (tests-only oracle). If a
discrepancy with upstream is ever discovered, the fixture + a comment win —
never a silent behavioral drift.

## cybercipher-sstv: Lane B contract

- Migrate sstv-auto modules preserving file-level separation and names:
  `audio, dsp, modes, vis, sync, raster, synth, autodetect, backend, score,
  pipeline, report`. Keep the crate-level lint block
  (`unsafe_code = forbid`, deny unwrap/expect/panic/todo/unimplemented
  outside tests).
- Replace path-based boundaries with byte-blob based ones: `audio::load_bytes`
  wrapping symphonia's in-memory probing; `pipeline` exposes a function taking
  bytes + `Options` and returning `Outcome` (report + PNG bytes). The upstream
  `main.rs` CLI does NOT migrate.
- Preserve: mode data-driven geometry (same definitions drive extract+synth+
  score), VIS-parity-is-hint-only, blind sync-period inference, automatic
  frequency-offset + clock-rate recovery, inverse-model candidate ranking,
  Robot24/36 ambiguity honesty, noise/degenerate rejection, cancellation and
  bounds (max decoded seconds/samples, bounded FFT working set).
- Tests: migrate the 142 upstream tests; synthetic WAV fixtures via hound as
  dev-dependency only; no large challenge audio in the repo.
- New registry op: `sstv_decode` (CostClass::Heavy) returning a structured
  report + image blob.

## Lane C (structure/carving/frames), Lane D (QR), Lane F (stereo/combine)

- `structure.rs`: strict bounds-checked PNG chunk / JPEG segment / GIF block /
  BMP header analyzers with trailing-data carving (offset, size, preview,
  detected magic via fileinfo). Fuzz-style truncation tests mandatory.
- `frames.rs`: lazy frame access with bounded cache (GIF first).
- `qr.rs`: rxing (primary — ZXing parity: 1D+2D, Structured Append,
  inverted/rotated/rescaled fallbacks) or rqrr (QR-only fallback); bytes-first
  payload model (raw bytes / text-if-valid / metadata), never auto-opens
  payloads.
- `stereo.rs`: shifted-XOR with right-edge wrap + edge-hold variant +
  `best_offset` scan (step sampling, offsets 1..w/2, smallest offset wins
  ties, cancellable).
- `combine.rs`: 13 modes with Java-int-wraparound arithmetic pinned by tests
  (XOR/OR/AND/ADD/SUB/MUL whole-int; per-channel ADD/SUB/MUL; LIGHTEST/
  DARKEST; INTERLACE rows h×2 / cols w×2 on size intersection; mismatched
  sizes → max-size canvas, missing pixels = transparent black input).

## GUI integration (later lane, after engines land)

- **Stego Lab**: central viewport (zoom/pan/fit/1:1, pixel readout, ROI),
  left transform list with prev/next/next-in-group, right tabs Info / Extract
  / Auto LSB / QR / Structure / Stereo / Combine / Frames / Pixel. Generation-ID
  cancellation for transform stepping; decode once; bounded caches.
- **SSTV Lab**: drag-drop audio, optional channel/forced-mode/blind toggles,
  progress stages, evidence panel (VIS/parity/sync chain/offset/clock),
  ranked candidates with previews, actions: Open in Stego Lab / Save PNG /
  Inspect Report. All DSP async, UI never blocked.
- Cross-tool flows (registry-level, also usable headless via CLI):
  image → transform/extract → Workbench; Auto LSB → Auto Decode; appended
  bytes → Auto Decode; QR bytes → Auto Decode; SSTV → PNG → Stego Lab.

## Acceptance flows (regression fixtures where practical)

A PNG → bit plane reveals hidden visual data · B PNG → Auto LSB → ZIP magic →
extract → Workbench · C PNG → appended bytes → Auto Decode → flag ·
D QR binary payload → exact raw bytes → Save/Auto Decode · E stereogram →
auto offset → depth result · F two images XOR → recovered message ·
G SSTV WAV → auto mode → image · H SSTV stripped-VIS → blind detection →
image · I SSTV with offset/drift → corrected → image · J SSTV → PNG →
Auto LSB → bytes → Auto Decode → flag.

## PR sequence

1. `feat(steg): Rust image core + StegSolve-compatible transforms/extraction`
   (media + steg core + golden tests) — Lane A PR-1
2. `feat(steg): bounded Auto LSB scanner` — Lane A PR-2
3. `feat(sstv): migrate sstv-auto core library` — Lane B PR-1
4. `feat(sstv): blob bridge + Tauri commands` — Lane B PR-2
5. structure/carving + frames — Lane C
6. QR/barcode + Stego Lab UI — Lane D
7. SSTV Lab UI + handoff — Lane B PR-3
8. stereo + combine + pixel UX — Lane F

## Provenance & license

Both upstreams are MIT. Preserve copyright notices for directly reused code
(sstv-auto modules), add PROVENANCE.md entries: repository, commit, what was
migrated vs reimplemented, and the StegSolve lineage note for the transform
catalog.
