import { create } from "zustand";
import { api, formatInvokeError, type BakeResponse } from "./api";
import { useStore } from "./store";

/**
 * Hard cap of the image_extract_bits op
 * (crates/cybercipher-steg/src/ops.rs MAX_EXTRACT_BYTES).
 */
export const MAX_EXTRACT_BYTES = 16 * 1024 * 1024;

/** Engine defaults for auto_lsb_scan (ops.rs param specs). */
const DEFAULT_MAX_CANDIDATES = 50;
const DEFAULT_PREFIX_BYTES = 65_536;

/** Bounded number of cached transform PNGs (decode-once, op-per-index). */
const TRANSFORM_CACHE_LIMIT = 16;

/** image_info JSON output (crates/cybercipher-steg/src/ops.rs image_info_op). */
export interface StegoImageInfo {
  width: number;
  height: number;
  pixel_count: number;
  has_alpha: boolean;
  indexed: { palette_entries: number } | null;
  estimated_bytes: number;
}

/**
 * One auto_lsb_scan candidate (ops.rs candidate_json; snake_case serde).
 * Mirrors the shape used by the SSTV Lab — same registry op.
 */
export interface StegoCandidate {
  settings: {
    description: string;
    config: string;
    plane_mask: string;
    argb_mask: string;
    order: string;
    order_code: number;
    lsb_first: boolean;
    row_first: boolean;
    invert_bits: boolean;
  };
  score: number;
  reason: string;
  payload_type: string;
  payload_type_id: number;
  preview_hex: string;
  preview_bytes: number;
  total_bytes: number;
  truncated: boolean;
  fingerprint: string;
}

/** image_extract_bits JSON report header (first line of its Bytes output). */
export interface StegoExtractHeader {
  total_bytes?: number;
  truncated?: boolean;
  settings?: string;
}

/** Result of one extraction: header report plus the extracted bytes. */
export interface StegoExtractResult {
  header: StegoExtractHeader | null;
  data: Uint8Array;
}

/**
 * image_extract_appended JSON report header (first line of its Bytes output;
 * fields mirror structure.rs image_extract_appended_op).
 */
export interface StegoAppendedHeader {
  format?: string;
  complete?: boolean;
  present?: boolean;
  offset?: number;
  size?: number;
  magic?: Record<string, unknown> | null;
  preview_bytes?: number;
  strings?: string[];
  emitted_bytes?: number;
  truncated?: boolean;
  max_bytes?: number;
}

/** Result of one appended-data carve: header report plus the carved bytes. */
export interface StegoAppendedResult {
  header: StegoAppendedHeader | null;
  data: Uint8Array;
}

/** One catalog entry, hard-coded to match transforms::catalog() exactly. */
export interface StegoTransformDef {
  index: number;
  group: string;
  label: string;
}

/**
 * The 42-transform catalog in StegSolve order
 * (crates/cybercipher-steg/src/transforms.rs CATALOG):
 * 0 original, 1 invert, 2..9 alpha planes 7..0, 10..17 red, 18..25 green,
 * 26..33 blue, 34..37 full channels, 38..40 random colour maps, 41 gray.
 */
export const TRANSFORM_CATALOG: StegoTransformDef[] = [
  { index: 0, group: "Original", label: "Original" },
  { index: 1, group: "Original", label: "Invert" },
  ...(["Alpha", "Red", "Green", "Blue"] as const).flatMap((channel, c) =>
    [7, 6, 5, 4, 3, 2, 1, 0].map((plane) => ({
      index: 2 + c * 8 + (7 - plane),
      group: `${channel} planes`,
      label: `${channel} plane ${plane}`,
    })),
  ),
  { index: 34, group: "Channels", label: "Full alpha" },
  { index: 35, group: "Channels", label: "Full red" },
  { index: 36, group: "Channels", label: "Full green" },
  { index: 37, group: "Channels", label: "Full blue" },
  { index: 38, group: "Random colour maps", label: "Random colour map 1" },
  { index: 39, group: "Random colour maps", label: "Random colour map 2" },
  { index: 40, group: "Random colour maps", label: "Random colour map 3" },
  { index: 41, group: "Gray pixels", label: "Gray pixels" },
];

/** Groups in catalog order, with their first index (for group navigation). */
export const TRANSFORM_GROUPS: { name: string; first: number }[] = (() => {
  const groups: { name: string; first: number }[] = [];
  for (const def of TRANSFORM_CATALOG) {
    const existing = groups.find((g) => g.name === def.group);
    if (existing) continue;
    groups.push({ name: def.group, first: def.index });
  }
  return groups;
})();

/**
 * Plane-space channel groups for the extraction mask:
 * bit `ordinal * 8 + plane` of the u32 plane mask selects that plane
 * (crates/cybercipher-steg/src/extract.rs ExtractionOptions::bit_for).
 */
export const PLANE_CHANNELS: { ordinal: number; name: string; symbol: string }[] = [
  { ordinal: 0, name: "Alpha", symbol: "a" },
  { ordinal: 1, name: "Red", symbol: "r" },
  { ordinal: 2, name: "Green", symbol: "g" },
  { ordinal: 3, name: "Blue", symbol: "b" },
];

/** Legacy RGB order codes 1..=6 (extract.rs RgbOrder::legacy_code). */
export const RGB_ORDERS: { code: number; label: string }[] = [
  { code: 1, label: "RGB" },
  { code: 2, label: "RBG" },
  { code: 3, label: "GRB" },
  { code: 4, label: "GBR" },
  { code: 5, label: "BRG" },
  { code: 6, label: "BGR" },
];

/** Op default: RGB bit 0 (ops.rs plane_mask_param default "01010100"). */
const DEFAULT_PLANE_MASK = 0x01010100;

/** Tabs of the Stego Lab page. */
export type StegoTab = "transform" | "extract" | "autolsb" | "structure";

let bakeCounter = 0;

/**
 * Run a single-op recipe through the same `bake` command the Workbench uses,
 * with the original image bytes (base64) as the input. `auto_bake: false`
 * means RunMode::Manual, so Solver-cost ops (auto_lsb_scan) run — they are
 * skipped in Auto mode by the engine's cost gate.
 */
function runSingleOp(
  opId: string,
  params: Record<string, string | number | boolean>,
  imageBase64: string,
): Promise<BakeResponse> {
  bakeCounter += 1;
  return api.bake({
    recipe: {
      version: 1,
      nodes: [{ id: "n1", op: opId, enabled: true, params }],
    },
    input_text: imageBase64,
    input_encoding: "base64",
    auto_bake: false,
    run_id: `stego-lab-${bakeCounter}`,
  });
}

/**
 * Split a header-line transport output (base64): a JSON report header line
 * followed by the raw payload bytes (the engine's established carrier).
 */
export function splitHeaderPayload(base64: string): { header: unknown; data: Uint8Array } {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const newline = bytes.indexOf(0x0a);
  if (newline < 0) return { header: null, data: bytes };
  let header: unknown = null;
  try {
    header = JSON.parse(new TextDecoder().decode(bytes.subarray(0, newline)));
  } catch {
    header = null;
  }
  return { header, data: bytes.subarray(newline + 1) };
}

/** Split image_extract_bits output (base64) into its JSON header and payload. */
function splitExtractOutput(base64: string): StegoExtractResult {
  const { header, data } = splitHeaderPayload(base64);
  return { header: header === null ? null : (header as StegoExtractHeader), data };
}

/** Base64 of raw bytes (op input carries binary as base64). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/**
 * Builds the `roi` op parameter from the four optional fields: "" (whole
 * image) unless all four are filled; the UI says so explicitly.
 */
export function roiString(x: string, y: string, w: string, h: string): string {
  const parts = [x.trim(), y.trim(), w.trim(), h.trim()];
  if (parts.some((p) => p === "")) return "";
  return parts.join(",");
}

/** Decoded byte length of a base64 string (no full decode). */
export function base64ByteLength(base64: string): number {
  const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((base64.length * 3) / 4) - padding);
}

/** Container formats the structure analyzers understand (structure.rs). */
export type StructureFormat = "png" | "jpeg" | "gif" | "bmp";

/** Registry op ids of the per-format structure analyzers. */
export type StructureOpId = `${StructureFormat}_structure`;

/**
 * Sniff the container magic from the first bytes of a base64 payload
 * (structure.rs detect_format: PNG signature, JPEG FFD8, GIF87a/89a, BM).
 * Decodes at most 24 base64 characters, never the whole payload.
 */
export function sniffImageFormat(base64: string): StructureFormat | null {
  let bin: string;
  try {
    bin = atob(base64.slice(0, 24));
  } catch {
    return null;
  }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const startsWith = (signature: number[]) => signature.every((b, i) => bytes[i] === b);
  if (startsWith([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
  if (startsWith([0xff, 0xd8])) return "jpeg";
  if (bin.startsWith("GIF87a") || bin.startsWith("GIF89a")) return "gif";
  if (bin.startsWith("BM")) return "bmp";
  return null;
}

export interface StegoStore {
  // Tab selection (persists while the session lives, like the PKI Lab).
  tab: StegoTab;
  setTab: (tab: StegoTab) => void;

  // Input (original image bytes — every op re-invokes with the same bytes).
  fileName: string | null;
  fileSize: number | null;
  fileBase64: string | null;
  loadFile: (file: File) => Promise<void>;
  /** Cross-tool handoff: load image bytes (base64, e.g. an SSTV PNG) as the active image. */
  loadFromBytes: (name: string, base64: string) => void;
  clearFile: () => void;

  // Image info (image_info op, run once per loaded file).
  infoBusy: boolean;
  infoError: string | null;
  info: StegoImageInfo | null;

  // Transform viewer (image_transform op on the original bytes, cached).
  transformIndex: number;
  transformCache: Record<number, string>;
  transformCacheOrder: number[];
  transformBusy: boolean;
  transformError: string | null;
  transformErrorIndex: number | null;
  setTransformIndex: (index: number) => void;
  ensureTransform: () => Promise<void>;

  // Extract tab (image_extract_bits op on the original bytes).
  planeMask: number;
  order: number;
  lsbFirst: boolean;
  rowFirst: boolean;
  invertBits: boolean;
  roiX: string;
  roiY: string;
  roiW: string;
  roiH: string;
  maxBytes: number;
  setPlaneBit: (bit: number, selected: boolean) => void;
  setOrder: (order: number) => void;
  setLsbFirst: (v: boolean) => void;
  setRowFirst: (v: boolean) => void;
  setInvertBits: (v: boolean) => void;
  setRoi: (field: "x" | "y" | "w" | "h", value: string) => void;
  setMaxBytes: (v: number) => void;
  extractBusy: boolean;
  extractError: string | null;
  extractResult: StegoExtractResult | null;
  runExtract: () => Promise<void>;

  // Auto LSB tab (auto_lsb_scan op, apply via image_extract_bits).
  scanBusy: boolean;
  scanError: string | null;
  candidates: StegoCandidate[] | null;
  applyBusy: boolean;
  applyError: string | null;
  applied: StegoExtractResult | null;
  runScan: (deep: boolean) => Promise<void>;
  applyCandidate: (candidate: StegoCandidate) => Promise<void>;

  // Structure tab (png/jpeg/gif/bmp_structure + image_extract_appended ops).
  structureBusy: boolean;
  structureError: string | null;
  structureOp: StructureOpId | null;
  structureReport: unknown | null;
  structureOpen: boolean;
  setStructureOpen: (open: boolean) => void;
  runStructure: () => Promise<void>;
  appendedMaxBytes: number;
  setAppendedMaxBytes: (v: number) => void;
  appendedBusy: boolean;
  appendedError: string | null;
  appendedResult: StegoAppendedResult | null;
  runAppended: () => Promise<void>;

  // Handoff to the Workbench (binary travels as base64 input).
  sendToWorkbench: (base64: string) => void;
  /** Handoff to Auto Analyze (binary travels as base64 input, scan auto-runs). */
  sendToAutoDecode: (base64: string) => void;
}

export const useStegoStore = create<StegoStore>((set, get) => {
  const resetResults = () =>
    set({
      info: null,
      infoBusy: false,
      infoError: null,
      transformCache: {},
      transformCacheOrder: [],
      transformBusy: false,
      transformError: null,
      transformErrorIndex: null,
      extractBusy: false,
      extractError: null,
      extractResult: null,
      scanBusy: false,
      scanError: null,
      candidates: null,
      applyBusy: false,
      applyError: null,
      applied: null,
      structureBusy: false,
      structureError: null,
      structureOp: null,
      structureReport: null,
      appendedBusy: false,
      appendedError: null,
      appendedResult: null,
    });

  /**
   * True when the loaded file changed since an op captured its input — the
   * op's result is stale and must not land (the file switch already reset
   * the busy flags it would clear).
   */
  const superseded = (startBase64: string) => get().fileBase64 !== startBase64;

  /** Inserts a transform PNG into the bounded cache, evicting oldest first. */
  const cacheTransform = (index: number, pngBase64: string) => {
    const cache = { ...get().transformCache, [index]: pngBase64 };
    const order = get().transformCacheOrder.filter((i) => i !== index);
    order.push(index);
    while (order.length > TRANSFORM_CACHE_LIMIT) {
      const victimPosition = order.findIndex((i) => i !== get().transformIndex);
      if (victimPosition < 0) break;
      const victim = order.splice(victimPosition, 1)[0];
      delete cache[victim];
    }
    set({ transformCache: cache, transformCacheOrder: order });
  };

  /**
   * Shared loader for files and cross-tool handoffs: sets the active image
   * bytes and runs image_info once for the new image.
   */
  const loadImageBytes = async (name: string, base64: string, size: number) => {
    set({ fileName: name, fileSize: size, fileBase64: null });
    resetResults();
    set({ fileBase64: base64 });
    // Image info runs once per loaded image.
    set({ infoBusy: true });
    try {
      const resp = await runSingleOp("image_info", {}, base64);
      if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
      if (resp.blocked_at !== null) {
        throw new Error(`run stopped at stage ${resp.blocked_at}`);
      }
      const out = resp.output;
      if (out === null || out.kind !== "json") {
        throw new Error("image_info returned no report");
      }
      if (superseded(base64)) return;
      set({ info: out.value as StegoImageInfo, infoBusy: false });
    } catch (e) {
      if (superseded(base64)) return;
      set({ infoBusy: false, infoError: e instanceof Error ? e.message : String(e) });
    }
  };

  return {
    tab: "transform",
    setTab: (tab) => set({ tab }),

    fileName: null,
    fileSize: null,
    fileBase64: null,
    loadFile: async (file) => {
      try {
        const buf = await file.arrayBuffer();
        await loadImageBytes(file.name, bytesToBase64(new Uint8Array(buf)), file.size);
      } catch (e) {
        set({
          fileName: null,
          fileSize: null,
          infoError: `could not read file: ${e instanceof Error ? e.message : String(e)}`,
        });
      }
    },
    loadFromBytes: (name, base64) => {
      void loadImageBytes(name, base64, base64ByteLength(base64));
    },
    clearFile: () => {
      set({ fileName: null, fileSize: null, fileBase64: null });
      resetResults();
    },

    infoBusy: false,
    infoError: null,
    info: null,

    transformIndex: 0,
    transformCache: {},
    transformCacheOrder: [],
    transformBusy: false,
    transformError: null,
    transformErrorIndex: null,
    setTransformIndex: (index) =>
      set({ transformIndex: index, transformError: null, transformErrorIndex: null }),
    ensureTransform: async () => {
      const {
        fileBase64,
        transformIndex: index,
        transformCache,
        transformBusy,
        transformErrorIndex,
      } = get();
      if (!fileBase64 || transformCache[index] !== undefined || transformBusy) return;
      // A failed index is not retried until the index or file changes.
      if (transformErrorIndex === index) return;
      set({ transformBusy: true, transformError: null });
      try {
        const resp = await runSingleOp("image_transform", { transform: index }, fileBase64);
        if (superseded(fileBase64)) return;
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        if (out === null || out.kind !== "bytes") {
          throw new Error("image_transform returned no PNG payload");
        }
        cacheTransform(index, out.base64);
        set({ transformBusy: false });
      } catch (e) {
        if (superseded(fileBase64)) return;
        set({
          transformBusy: false,
          transformError: e instanceof Error ? e.message : String(e),
          transformErrorIndex: index,
        });
      }
    },

    planeMask: DEFAULT_PLANE_MASK,
    order: 1,
    lsbFirst: false,
    rowFirst: true,
    invertBits: false,
    roiX: "",
    roiY: "",
    roiW: "",
    roiH: "",
    maxBytes: 65_536,
    setPlaneBit: (bit, selected) => {
      const bitValue = 2 ** bit;
      const mask = selected
        ? (get().planeMask | bitValue) >>> 0
        : (get().planeMask & ~bitValue) >>> 0;
      set({ planeMask: mask });
    },
    setOrder: (order) => set({ order }),
    setLsbFirst: (lsbFirst) => set({ lsbFirst }),
    setRowFirst: (rowFirst) => set({ rowFirst }),
    setInvertBits: (invertBits) => set({ invertBits }),
    setRoi: (field, value) => set(field === "x" ? { roiX: value } : field === "y" ? { roiY: value } : field === "w" ? { roiW: value } : { roiH: value }),
    setMaxBytes: (maxBytes) => set({ maxBytes }),
    extractBusy: false,
    extractError: null,
    extractResult: null,
    runExtract: async () => {
      const {
        fileBase64,
        extractBusy,
        planeMask,
        order,
        lsbFirst,
        rowFirst,
        invertBits,
        roiX,
        roiY,
        roiW,
        roiH,
        maxBytes,
      } = get();
      if (extractBusy || !fileBase64) return;
      set({ extractBusy: true, extractError: null, extractResult: null });
      try {
        const clampedMax = Math.min(Math.max(Math.trunc(maxBytes) || 0, 1), MAX_EXTRACT_BYTES);
        const resp = await runSingleOp(
          "image_extract_bits",
          {
            plane_mask: planeMask.toString(16).padStart(8, "0"),
            order,
            lsb_first: lsbFirst,
            row_first: rowFirst,
            invert_bits: invertBits,
            roi: roiString(roiX, roiY, roiW, roiH),
            max_bytes: clampedMax,
          },
          fileBase64,
        );
        if (superseded(fileBase64)) return;
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        if (out === null || out.kind !== "bytes") {
          throw new Error("image_extract_bits returned no byte payload");
        }
        set({ extractBusy: false, extractResult: splitExtractOutput(out.base64) });
      } catch (e) {
        if (superseded(fileBase64)) return;
        set({
          extractBusy: false,
          extractError: e instanceof Error ? e.message : String(e),
        });
      }
    },

    scanBusy: false,
    scanError: null,
    candidates: null,
    applyBusy: false,
    applyError: null,
    applied: null,
    runScan: async (deep) => {
      const { fileBase64, scanBusy } = get();
      if (scanBusy || !fileBase64) return;
      set({
        scanBusy: true,
        scanError: null,
        candidates: null,
        applied: null,
        applyError: null,
      });
      try {
        // Param defaults mirror crates/cybercipher-steg/src/ops.rs.
        const resp = await runSingleOp(
          "auto_lsb_scan",
          { deep, roi: "", max_candidates: DEFAULT_MAX_CANDIDATES, prefix_bytes: DEFAULT_PREFIX_BYTES },
          fileBase64,
        );
        if (superseded(fileBase64)) return;
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        const found =
          out !== null && out.kind === "json" && Array.isArray(out.value)
            ? (out.value as StegoCandidate[])
            : [];
        set({ scanBusy: false, candidates: found });
      } catch (e) {
        if (superseded(fileBase64)) return;
        set({ scanBusy: false, scanError: e instanceof Error ? e.message : String(e) });
      }
    },
    applyCandidate: async (candidate) => {
      const { fileBase64, applyBusy } = get();
      if (applyBusy || !fileBase64) return;
      set({ applyBusy: true, applyError: null, applied: null });
      try {
        // Phase 2: the full extraction with the candidate's settings.
        const maxBytes = Math.min(Math.max(candidate.total_bytes, 1), MAX_EXTRACT_BYTES);
        const resp = await runSingleOp(
          "image_extract_bits",
          {
            plane_mask: candidate.settings.plane_mask,
            order: candidate.settings.order_code,
            lsb_first: candidate.settings.lsb_first,
            row_first: candidate.settings.row_first,
            invert_bits: candidate.settings.invert_bits,
            roi: "",
            max_bytes: maxBytes,
          },
          fileBase64,
        );
        if (superseded(fileBase64)) return;
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        if (out === null || out.kind !== "bytes") {
          throw new Error("image_extract_bits returned no byte payload");
        }
        set({ applyBusy: false, applied: splitExtractOutput(out.base64) });
      } catch (e) {
        if (superseded(fileBase64)) return;
        set({ applyBusy: false, applyError: e instanceof Error ? e.message : String(e) });
      }
    },

    structureBusy: false,
    structureError: null,
    structureOp: null,
    structureReport: null,
    structureOpen: false,
    setStructureOpen: (structureOpen) => set({ structureOpen }),
    runStructure: async () => {
      const { fileBase64, structureBusy } = get();
      if (structureBusy || !fileBase64) return;
      // The per-format analyzers walk raw container bytes; pick the op by magic.
      const format = sniffImageFormat(fileBase64);
      if (format === null) {
        set({
          structureBusy: false,
          structureError:
            "not a PNG/JPEG/GIF/BMP container — the structure analyzers walk raw file bytes",
          structureOp: null,
          structureReport: null,
        });
        return;
      }
      const opId: StructureOpId = `${format}_structure`;
      set({ structureBusy: true, structureError: null, structureReport: null, structureOp: opId });
      try {
        const resp = await runSingleOp(opId, {}, fileBase64);
        if (superseded(fileBase64)) return;
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        if (out === null || out.kind !== "json") {
          throw new Error(`${opId} returned no report`);
        }
        set({ structureBusy: false, structureReport: out.value });
      } catch (e) {
        if (superseded(fileBase64)) return;
        set({ structureBusy: false, structureError: e instanceof Error ? e.message : String(e) });
      }
    },

    appendedMaxBytes: 65_536,
    setAppendedMaxBytes: (appendedMaxBytes) => set({ appendedMaxBytes }),
    appendedBusy: false,
    appendedError: null,
    appendedResult: null,
    runAppended: async () => {
      const { fileBase64, appendedBusy, appendedMaxBytes } = get();
      if (appendedBusy || !fileBase64) return;
      set({ appendedBusy: true, appendedError: null, appendedResult: null });
      try {
        const clampedMax = Math.min(Math.max(Math.trunc(appendedMaxBytes) || 0, 1), MAX_EXTRACT_BYTES);
        const resp = await runSingleOp(
          "image_extract_appended",
          { max_bytes: clampedMax },
          fileBase64,
        );
        if (superseded(fileBase64)) return;
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        if (out === null || out.kind !== "bytes") {
          throw new Error("image_extract_appended returned no byte payload");
        }
        const { header, data } = splitHeaderPayload(out.base64);
        set({
          appendedBusy: false,
          appendedResult: {
            header: header === null ? null : (header as StegoAppendedHeader),
            data,
          },
        });
      } catch (e) {
        if (superseded(fileBase64)) return;
        set({ appendedBusy: false, appendedError: e instanceof Error ? e.message : String(e) });
      }
    },

    sendToWorkbench: (base64) => {
      const workbench = useStore.getState();
      workbench.setInputText(base64);
      workbench.setInputEncoding("base64");
      workbench.setPage("workbench");
      void workbench.bake(false);
    },

    sendToAutoDecode: (base64) => {
      useStore.getState().sendToAutoDecode(base64);
    },
  };
});
