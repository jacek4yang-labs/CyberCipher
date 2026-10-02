import { create } from "zustand";
import {
  api,
  formatInvokeError,
  type BakeResponse,
  type SstvDecodeResult,
  type SstvImage,
  type SstvModeInfo,
} from "./api";
import { useStore } from "./store";
import { useStegoStore } from "./stegoStore";

/** Channel override accepted by sstv_decode_audio: named choices or a zero-based index. */
export type SstvChannelKind = "auto" | "mono" | "left" | "right" | "index";

/**
 * Hard cap the engine enforces on max_duration_seconds
 * (crates/cybercipher-sstv/src/ops.rs MAX_DURATION_SECONDS_CAP).
 */
export const SSTV_MAX_SECONDS_CAP = 300;

/** Engine default for max_candidates (command layer passes it when unset). */
const DEFAULT_MAX_CANDIDATES = 5;

/** Hard cap of the image_extract_bits op (crates/cybercipher-steg/src/ops.rs). */
const MAX_EXTRACT_BYTES = 16 * 1024 * 1024;

/** One auto_lsb_scan candidate (ops.rs candidate_json; snake_case serde). */
export interface LsbCandidate {
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
export interface ExtractHeader {
  total_bytes?: number;
  truncated?: boolean;
  settings?: string;
}

/** Result of applying one candidate: header report plus the extracted bytes. */
export interface ExtractResult {
  header: ExtractHeader | null;
  data: Uint8Array;
}

/** Per-image Auto LSB state, keyed by the image's detection_index. */
export interface LsbRun {
  busy: boolean;
  error: string | null;
  deep: boolean;
  candidates: LsbCandidate[] | null;
  applyBusy: boolean;
  applyError: string | null;
  applied: ExtractResult | null;
}

function emptyLsbRun(): LsbRun {
  return {
    busy: false,
    error: null,
    deep: false,
    candidates: null,
    applyBusy: false,
    applyError: null,
    applied: null,
  };
}

let bakeCounter = 0;

/**
 * Run a single-op recipe through the same `bake` command the Workbench uses,
 * with the SSTV image (base64 PNG) as the base64 input. `auto_bake: false`
 * means RunMode::Manual, so Solver-cost ops (auto_lsb_scan) run — they are
 * skipped in Auto mode by the engine's cost gate.
 */
function runSingleOp(
  opId: string,
  params: Record<string, string | number | boolean>,
  pngBase64: string,
): Promise<BakeResponse> {
  bakeCounter += 1;
  return api.bake({
    recipe: {
      version: 1,
      nodes: [{ id: "n1", op: opId, enabled: true, params }],
    },
    input_text: pngBase64,
    input_encoding: "base64",
    auto_bake: false,
    run_id: `sstv-lab-${bakeCounter}`,
  });
}

/** Split image_extract_bits output (base64) into its JSON header and payload. */
function splitExtractOutput(base64: string): ExtractResult {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const newline = bytes.indexOf(0x0a);
  if (newline < 0) return { header: null, data: bytes };
  let header: ExtractHeader | null = null;
  try {
    header = JSON.parse(new TextDecoder().decode(bytes.subarray(0, newline))) as ExtractHeader;
  } catch {
    header = null;
  }
  return { header, data: bytes.subarray(newline + 1) };
}

/** Base64 of raw bytes (the Workbench input carries binary as base64). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export interface SstvStore {
  // Mode metadata (from sstv_modes, loaded once).
  modes: SstvModeInfo[];
  modesError: string | null;
  loadModes: () => Promise<void>;

  // Input.
  fileName: string | null;
  fileSize: number | null;
  fileBytes: Uint8Array | null;
  loadFile: (file: File) => Promise<void>;
  clearFile: () => void;

  channelKind: SstvChannelKind;
  channelIndex: number;
  forcedMode: string;
  blind: boolean;
  maxSeconds: number;
  setChannelKind: (v: SstvChannelKind) => void;
  setChannelIndex: (v: number) => void;
  setForcedMode: (v: string) => void;
  setBlind: (v: boolean) => void;
  setMaxSeconds: (v: number) => void;

  // Decode.
  decoding: boolean;
  decodeError: string | null;
  result: SstvDecodeResult | null;
  reportOpen: boolean;
  setReportOpen: (open: boolean) => void;
  decode: () => Promise<void>;

  // Per-image Auto LSB runs and applies.
  lsbRuns: Record<number, LsbRun>;
  setLsbDeep: (detectionIndex: number, deep: boolean) => void;
  runAutoLsb: (image: SstvImage, deep: boolean) => Promise<void>;
  applyCandidate: (image: SstvImage, candidate: LsbCandidate) => Promise<void>;

  // Handoff to the Workbench (binary travels as base64 input).
  sendToWorkbench: (base64: string) => void;
  /** Handoff to Auto Analyze (binary travels as base64 input, scan auto-runs). */
  sendToAutoDecode: (base64: string) => void;
  /** Handoff to the Stego Lab: a decoded PNG becomes the active Stego image. */
  openInStegoLab: (image: SstvImage) => void;
}

export const useSstvStore = create<SstvStore>((set, get) => {
  const setLsbRun = (index: number, patch: Partial<LsbRun>) => {
    const current = get().lsbRuns[index] ?? emptyLsbRun();
    set({ lsbRuns: { ...get().lsbRuns, [index]: { ...current, ...patch } } });
  };

  return {
    modes: [],
    modesError: null,
    loadModes: async () => {
      if (get().modes.length > 0) return;
      try {
        const modes = await api.sstvModes();
        set({ modes, modesError: null });
      } catch (e) {
        set({ modesError: formatInvokeError(e) });
      }
    },

    fileName: null,
    fileSize: null,
    fileBytes: null,
    loadFile: async (file) => {
      set({
        fileName: file.name,
        fileSize: file.size,
        fileBytes: null,
        result: null,
        decodeError: null,
        lsbRuns: {},
      });
      try {
        const buf = await file.arrayBuffer();
        set({ fileBytes: new Uint8Array(buf) });
      } catch (e) {
        set({
          fileName: null,
          fileSize: null,
          decodeError: `could not read file: ${e instanceof Error ? e.message : String(e)}`,
        });
      }
    },
    clearFile: () =>
      set({
        fileName: null,
        fileSize: null,
        fileBytes: null,
        result: null,
        decodeError: null,
        lsbRuns: {},
      }),

    channelKind: "auto",
    channelIndex: 0,
    forcedMode: "",
    blind: true,
    maxSeconds: 90,
    setChannelKind: (channelKind) => set({ channelKind }),
    setChannelIndex: (channelIndex) => set({ channelIndex }),
    setForcedMode: (forcedMode) => set({ forcedMode }),
    setBlind: (blind) => set({ blind }),
    setMaxSeconds: (maxSeconds) => set({ maxSeconds }),

    decoding: false,
    decodeError: null,
    result: null,
    reportOpen: false,
    setReportOpen: (reportOpen) => set({ reportOpen }),
    decode: async () => {
      const { fileBytes, decoding, channelKind, channelIndex, forcedMode, blind, maxSeconds } =
        get();
      if (decoding || !fileBytes) return;
      set({ decoding: true, decodeError: null, lsbRuns: {} });
      try {
        const result = await api.sstvDecodeAudio(Array.from(fileBytes), {
          channel: channelKind === "index" ? String(channelIndex) : channelKind,
          forced_mode: forcedMode.trim() !== "" ? forcedMode.trim() : null,
          blind,
          max_duration_seconds: Math.min(Math.max(Math.trunc(maxSeconds), 1), SSTV_MAX_SECONDS_CAP),
          max_candidates: DEFAULT_MAX_CANDIDATES,
        });
        set({ result, reportOpen: false });
      } catch (e) {
        set({ decodeError: formatInvokeError(e) });
      } finally {
        set({ decoding: false });
      }
    },

    lsbRuns: {},
    setLsbDeep: (detectionIndex, deep) => setLsbRun(detectionIndex, { deep }),
    runAutoLsb: async (image, deep) => {
      if (get().lsbRuns[image.detection_index]?.busy) return;
      setLsbRun(image.detection_index, {
        busy: true,
        error: null,
        deep,
        candidates: null,
        applied: null,
        applyError: null,
      });
      try {
        // Param defaults mirror crates/cybercipher-steg/src/ops.rs.
        const resp = await runSingleOp(
          "auto_lsb_scan",
          { deep, roi: "", max_candidates: 50, prefix_bytes: 65_536 },
          image.png_base64,
        );
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        const candidates =
          out !== null && out.kind === "json" && Array.isArray(out.value)
            ? (out.value as LsbCandidate[])
            : [];
        setLsbRun(image.detection_index, { busy: false, candidates });
      } catch (e) {
        setLsbRun(image.detection_index, {
          busy: false,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    },
    applyCandidate: async (image, candidate) => {
      const run = get().lsbRuns[image.detection_index];
      if (run?.applyBusy) return;
      setLsbRun(image.detection_index, { applyBusy: true, applyError: null, applied: null });
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
          image.png_base64,
        );
        if (resp.report.error) throw new Error(formatInvokeError(resp.report.error));
        if (resp.blocked_at !== null) {
          throw new Error(`run stopped at stage ${resp.blocked_at}`);
        }
        const out = resp.output;
        if (out === null || out.kind !== "bytes") {
          throw new Error("image_extract_bits returned no byte payload");
        }
        setLsbRun(image.detection_index, {
          applyBusy: false,
          applied: splitExtractOutput(out.base64),
        });
      } catch (e) {
        setLsbRun(image.detection_index, {
          applyBusy: false,
          applyError: e instanceof Error ? e.message : String(e),
        });
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

    openInStegoLab: (image) => {
      // The mandatory SSTV → Stego Lab flow: the decoded PNG (base64) is
      // loaded in-memory as the Stego Lab's active image, no temp files.
      useStegoStore.getState().loadFromBytes(
        `sstv-${image.detection_index + 1}-${image.mode_slug}.png`,
        image.png_base64,
      );
      useStore.getState().setPage("stego-lab");
    },
  };
});
