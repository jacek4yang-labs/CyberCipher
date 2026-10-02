import { create } from "zustand";
import {
  api,
  type AssistHit,
  type AssistResult,
  type AutoCandidate,
  type BakeResponse,
  type ExecutionReport,
  type InputStats,
  type OperationInfo,
  type ParamSpec,
  type ParamValue,
  type RecipeNode,
  type RecipeV1,
  type RsaAnalyzerReport,
  type ValuePayload,
} from "./api";

export type Page =
  | "workbench"
  | "rsa-lab"
  | "pki-lab"
  | "sstv-lab"
  | "stego-lab"
  | "auto"
  | "recipes"
  | "settings";

/** Scalar RSA key-material fields editable in the lab form. */
export const RSA_FIELD_KEYS = [
  "n",
  "e",
  "c",
  "d",
  "p",
  "q",
  "phi",
  "dp",
  "dq",
  "qinv",
] as const;

export type RsaFieldKey = (typeof RSA_FIELD_KEYS)[number];

export type RsaFields = Record<RsaFieldKey, string>;

export const DEFAULT_RSA_FIELDS: RsaFields = {
  n: "",
  e: "65537",
  c: "",
  d: "",
  p: "",
  q: "",
  phi: "",
  dp: "",
  dq: "",
  qinv: "",
};

/**
 * Local display-only parse of a decimal / 0x-hex big-integer input, mirroring
 * the backend's `parse_big_value`. Returns:
 * - `{ ok: true, value }` for a valid integer,
 * - `null` for empty input (nothing entered),
 * - `{ ok: false, error }` for malformed input.
 */
export function parseRsaIntInput(
  text: string,
): { ok: true; value: bigint } | { ok: false; error: string } | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  const cleaned = trimmed.replace(/\s+/g, "");
  const isHex = /^0[xX][0-9a-fA-F]+$/.test(cleaned);
  const isDec = /^[0-9]+$/.test(cleaned);
  if (!isHex && !isDec) {
    return {
      ok: false,
      error: /^0[xX]/.test(cleaned) ? "not a valid hex integer" : "not a valid decimal integer",
    };
  }
  try {
    return { ok: true, value: BigInt(cleaned) };
  } catch {
    return { ok: false, error: "not a valid integer" };
  }
}

/** Keys allowed in the advanced JSON box (backend rejects anything else). */
const RSA_ADVANCED_KEYS = new Set(["hint", "plaintext_hint", "sets", "ns", "moduli"]);

/** Validate + build the `params` payload for rsa_analyze, or an error message. */
export function buildRsaParams(
  fields: RsaFields,
  advancedJson: string,
): { params: Record<string, unknown> } | { error: string } {
  const params: Record<string, unknown> = {};
  for (const key of RSA_FIELD_KEYS) {
    const parsed = parseRsaIntInput(fields[key]);
    if (parsed === null) continue;
    if (!parsed.ok) return { error: `${key}: ${parsed.error}` };
    params[key] = fields[key].trim();
  }
  const adv = advancedJson.trim();
  if (adv !== "") {
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(adv);
    } catch (e) {
      return { error: `advanced JSON: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (typeof parsedJson !== "object" || parsedJson === null || Array.isArray(parsedJson)) {
      return { error: "advanced JSON must be an object" };
    }
    for (const [k, v] of Object.entries(parsedJson as Record<string, unknown>)) {
      if (!RSA_ADVANCED_KEYS.has(k.toLowerCase())) {
        return { error: `advanced JSON: unknown key \`${k}\` (allowed: hint, sets, ns)` };
      }
      params[k] = v;
    }
  }
  return { params };
}

let runCounter = 0;
let nodeCounter = 0;
let latestRunId = "";

function defaultParamValue(spec: ParamSpec): ParamValue {
  const d = spec.default;
  if ("str" in d) return d.str;
  if ("int" in d) return d.int;
  if ("bool" in d) return d.bool;
  return d.float;
}

/** Build recipe nodes from an auto candidate, overlaying the per-step
 * parameter overrides the engine recorded (e.g. strict=false on the relaxed
 * hex/base64 steps) over the operation defaults. */
function nodesFromCandidate(
  candidate: AutoCandidate,
  opsById: Record<string, OperationInfo>,
): Array<{ id: string; op: string; enabled: boolean; params: Record<string, ParamValue> }> {
  nodeCounter = 0;
  return candidate.path.map((opId, i) => {
    nodeCounter += 1;
    const op = opsById[opId];
    const params = initParams(op);
    const overrides = candidate.step_params?.[i];
    if (overrides) {
      for (const [key, value] of Object.entries(overrides)) {
        if (typeof value === "boolean") params[key] = value;
        else if (typeof value === "number") params[key] = value;
        else if (typeof value === "string") params[key] = value;
      }
    }
    return { id: `n${nodeCounter}`, op: opId, enabled: true, params };
  });
}

function initParams(op: OperationInfo | undefined): Record<string, ParamValue> {
  const params: Record<string, ParamValue> = {};
  if (op) for (const p of op.params) params[p.key] = defaultParamValue(p);
  return params;
}

export interface Store {
  ready: boolean;
  page: Page;
  ops: OperationInfo[];
  opsById: Record<string, OperationInfo>;
  recipe: RecipeNode[];
  inputText: string;
  inputEncoding: "utf8" | "hex" | "base64" | "decimal";
  output: ValuePayload | null;
  report: ExecutionReport | null;
  inputStats: InputStats | null;
  autoCandidates: AutoCandidate[];
  /** Alternate decodes (from the last empty-recipe Bake) as one-click chips. */
  bakeAlternates: Array<{ index: number; label: string }>;
  autoRunning: boolean;
  autoBake: boolean;
  baking: boolean;
  lastError: string | null;
  theme: "dark" | "light";
  saveDialogOpen: boolean;
  loadError: string | null;

  // RSA attack lab
  rsaFields: RsaFields;
  rsaAdvancedJson: string;
  rsaBudgetMs: number;
  rsaReport: RsaAnalyzerReport | null;
  rsaRunning: boolean;
  rsaLastError: string | null;

  // Crypto assist panel (Auto Analyze page)
  assistCiphertext: string;
  assistEncoding: Store["inputEncoding"];
  assistKeyCandidate: string;
  assistIvHex: string;
  assistHint: string;
  assistResult: AssistResult | null;
  assistRunning: boolean;
  assistError: string | null;
  /**
   * Honesty note shown in the Workbench after "Apply as Recipe" when the hit
   * used an IV the recipe input cannot express yet (carved first/last block).
   */
  assistRecipeNote: string | null;

  init: () => Promise<void>;
  setPage: (p: Page) => void;
  setTheme: (t: "dark" | "light") => void;
  setAutoBake: (v: boolean) => void;
  setInputText: (t: string) => void;
  setInputEncoding: (e: Store["inputEncoding"]) => void;

  setRsaField: (key: RsaFieldKey, value: string) => void;
  setRsaAdvancedJson: (json: string) => void;
  setRsaBudgetMs: (ms: number) => void;
  runRsa: (solve: boolean) => Promise<void>;
  applyRsaReportParams: () => void;
  resetRsaLab: () => void;

  setAssistCiphertext: (t: string) => void;
  setAssistEncoding: (e: Store["inputEncoding"]) => void;
  setAssistKeyCandidate: (t: string) => void;
  setAssistIvHex: (t: string) => void;
  setAssistHint: (t: string) => void;
  runCryptoAssist: () => Promise<void>;
  applyAssistHit: (hit: AssistHit) => void;
  dismissAssistRecipeNote: () => void;

  addOp: (opId: string, atIndex?: number) => void;
  removeOp: (nodeId: string) => void;
  duplicateOp: (nodeId: string) => void;
  moveOp: (nodeId: string, toIndex: number) => void;
  toggleEnabled: (nodeId: string) => void;
  setParam: (nodeId: string, key: string, value: ParamValue) => void;

  bake: (manual: boolean) => Promise<void>;
  setSaveDialogOpen: (open: boolean) => void;
  saveRecipe: (name: string) => Promise<void>;
  loadRecipeByName: (name: string) => Promise<void>;
  importRecipeJson: (json: string) => boolean;
  outputToInput: () => void;
  swapInputOutput: () => void;
  runAuto: () => Promise<void>;
  applyAutoCandidate: (index: number) => void;
  /** Switch the applied decode to one of the Bake alternates. */
  applyBakeAlternate: (index: number) => void;
  dismissBakeNote: () => void;
  /** Cross-tool handoff: bytes (base64) become the input and Auto Analyze runs. */
  sendToAutoDecode: (base64: string) => void;
}

export const useStore = create<Store>((set, get) => ({
  ready: false,
  page: "workbench",
  ops: [],
  opsById: {},
  recipe: [],
  inputText: "",
  inputEncoding: "utf8",
  output: null,
  report: null,
  inputStats: null,
  autoCandidates: [],
  bakeAlternates: [],
  autoRunning: false,
  autoBake: true,
  baking: false,
  lastError: null,
  theme: "dark",
  saveDialogOpen: false,
  loadError: null,

  rsaFields: { ...DEFAULT_RSA_FIELDS },
  rsaAdvancedJson: "",
  rsaBudgetMs: 10000,
  rsaReport: null,
  rsaRunning: false,
  rsaLastError: null,

  assistCiphertext: "",
  assistEncoding: "hex",
  assistKeyCandidate: "",
  assistIvHex: "",
  assistHint: "",
  assistResult: null,
  assistRunning: false,
  assistError: null,
  assistRecipeNote: null,

  init: async () => {
    const ops = await api.listOperations();
    const opsById: Record<string, OperationInfo> = {};
    for (const op of ops) opsById[op.id] = op;
    const theme = (localStorage.getItem("cc-theme") as "dark" | "light") || "dark";
    set({ ops, opsById, ready: true, theme });
    document.documentElement.dataset.theme = theme;
    // Auto-bake the (empty) initial state once to populate status.
    void get().bake(false);
  },

  setPage: (page) => set({ page }),
  setTheme: (theme) => {
    localStorage.setItem("cc-theme", theme);
    document.documentElement.dataset.theme = theme;
    set({ theme });
  },
  setAutoBake: (autoBake) => {
    set({ autoBake });
    if (autoBake) void get().bake(false);
  },

  setInputText: (inputText) => set({ inputText }),
  setInputEncoding: (inputEncoding) => set({ inputEncoding }),

  setRsaField: (key, value) =>
    set({ rsaFields: { ...get().rsaFields, [key]: value } }),

  setRsaAdvancedJson: (rsaAdvancedJson) => set({ rsaAdvancedJson }),

  setRsaBudgetMs: (rsaBudgetMs) => set({ rsaBudgetMs }),

  runRsa: async (solve) => {
    const { rsaFields, rsaAdvancedJson, rsaBudgetMs, rsaRunning } = get();
    if (rsaRunning) return;
    const built = buildRsaParams(rsaFields, rsaAdvancedJson);
    if ("error" in built) {
      set({ rsaLastError: built.error });
      return;
    }
    set({ rsaRunning: true, rsaLastError: null });
    try {
      const report = await api.rsaAnalyze({
        params: built.params,
        solve,
        budget_ms: rsaBudgetMs,
      });
      set({ rsaReport: report });
    } catch (e) {
      set({ rsaLastError: String(e) });
    } finally {
      set({ rsaRunning: false });
    }
  },

  applyRsaReportParams: () => {
    const { rsaReport } = get();
    if (!rsaReport) return;
    const fields: RsaFields = { ...DEFAULT_RSA_FIELDS };
    const advanced: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(rsaReport.params)) {
      const lower = key.toLowerCase();
      if (lower === "hint" || lower === "plaintext_hint") {
        advanced.hint = value;
      } else if (lower === "sets" || lower === "ns" || lower === "moduli") {
        advanced[lower === "moduli" ? "ns" : lower] = value;
      } else if ((RSA_FIELD_KEYS as readonly string[]).includes(lower)) {
        fields[lower as RsaFieldKey] = typeof value === "string" ? value : String(value);
      }
    }
    const advancedJson = Object.keys(advanced).length > 0 ? JSON.stringify(advanced, null, 2) : "";
    set({ rsaFields: fields, rsaAdvancedJson: advancedJson });
  },

  resetRsaLab: () =>
    set({
      rsaFields: { ...DEFAULT_RSA_FIELDS },
      rsaAdvancedJson: "",
      rsaReport: null,
      rsaLastError: null,
    }),

  setAssistCiphertext: (assistCiphertext) => set({ assistCiphertext }),

  setAssistEncoding: (assistEncoding) => set({ assistEncoding }),

  setAssistKeyCandidate: (assistKeyCandidate) => set({ assistKeyCandidate }),

  setAssistIvHex: (assistIvHex) => set({ assistIvHex }),

  setAssistHint: (assistHint) => set({ assistHint }),

  runCryptoAssist: async () => {
    const {
      assistCiphertext,
      assistEncoding,
      assistKeyCandidate,
      assistIvHex,
      assistHint,
      assistRunning,
    } = get();
    if (assistRunning) return;
    if (!assistCiphertext.trim()) {
      set({ assistError: "paste the ciphertext to analyze first" });
      return;
    }
    if (!assistKeyCandidate.trim()) {
      set({ assistError: "enter a key candidate — the assist searches around what you give it, it does not brute-force keys" });
      return;
    }
    set({ assistRunning: true, assistError: null });
    try {
      const result = await api.cryptoAssist({
        ciphertext_text: assistCiphertext,
        ciphertext_encoding: assistEncoding,
        key_candidate: assistKeyCandidate,
        iv_hex: assistIvHex.trim() !== "" ? assistIvHex : null,
        hint: assistHint.trim() !== "" ? assistHint : null,
      });
      set({ assistResult: result });
    } catch (e) {
      set({ assistError: String(e) });
    } finally {
      set({ assistRunning: false });
    }
  },

  applyAssistHit: (hit) => {
    const { opsById, assistCiphertext, assistEncoding } = get();
    const aesOp = opsById["aes-decrypt"];
    if (!aesOp) return;

    // Build the recipe the same way applyAutoCandidate/importRecipeJson do:
    // fresh ids, default params from the op spec, then explicit overrides.
    nodeCounter = 0;
    const nodes: RecipeNode[] = [];

    // Input-decode step so the Workbench bytes match the assist's ciphertext.
    const decodeOpId: string | null =
      assistEncoding === "hex"
        ? "from-hex"
        : assistEncoding === "base64"
          ? "from-base64"
          : assistEncoding === "decimal"
            ? "from-decimal"
            : null; // utf8 input needs no decode op
    const decodeOp = decodeOpId ? opsById[decodeOpId] : undefined;
    if (decodeOpId && decodeOp) {
      nodeCounter += 1;
      nodes.push({
        id: `n${nodeCounter}`,
        op: decodeOpId,
        enabled: true,
        params: initParams(decodeOp),
      });
    }

    // aes-decrypt with the hit's resolved parameters (key and IV as hex).
    nodeCounter += 1;
    const params = initParams(aesOp);
    params.key = hit.key_hex;
    params.key_encoding = "hex";
    params.mode = hit.mode;
    if (hit.mode !== "ecb") {
      params.iv = hit.iv_hex;
      params.iv_encoding = "hex";
    }
    params.padding = hit.padding ?? "none";
    nodes.push({ id: `n${nodeCounter}`, op: "aes-decrypt", enabled: true, params });

    // Keep it honest: no registry op can carve an IV block out of the input
    // yet, so say exactly what the user must do with the input themselves.
    let assistRecipeNote: string | null = null;
    if (hit.iv_source === "first_block") {
      assistRecipeNote =
        "Crypto Assist recipe: the IV was carved from the FIRST 16 bytes of the ciphertext (no op can trim that block yet). Feed aes-decrypt the ciphertext WITHOUT its leading IV block — drop the first 16 bytes (e.g. the first 32 hex characters) from the input to reproduce the assist preview.";
    } else if (hit.iv_source === "last_block") {
      assistRecipeNote =
        "Crypto Assist recipe: the IV was carved from the LAST 16 bytes of the ciphertext (no op can trim that block yet). Feed aes-decrypt the ciphertext WITHOUT its trailing IV block — drop the last 16 bytes from the input to reproduce the assist preview.";
    }

    set({
      recipe: nodes,
      inputText: assistCiphertext,
      inputEncoding: assistEncoding,
      page: "workbench",
      assistRecipeNote,
    });
    void get().bake(false);
  },

  dismissAssistRecipeNote: () => set({ assistRecipeNote: null }),

  addOp: (opId, atIndex) => {
    const op = get().opsById[opId];
    if (!op) return;
    nodeCounter += 1;
    const node: RecipeNode = {
      id: `n${nodeCounter}`,
      op: opId,
      enabled: true,
      params: initParams(op),
    };
    const recipe = [...get().recipe];
    recipe.splice(atIndex ?? recipe.length, 0, node);
    set({ recipe });
  },

  removeOp: (nodeId) => set({ recipe: get().recipe.filter((n) => n.id !== nodeId) }),

  duplicateOp: (nodeId) => {
    const recipe = [...get().recipe];
    const idx = recipe.findIndex((n) => n.id === nodeId);
    if (idx < 0) return;
    nodeCounter += 1;
    const src = recipe[idx];
    recipe.splice(idx + 1, 0, {
      ...src,
      id: `n${nodeCounter}`,
      params: { ...src.params },
    });
    set({ recipe });
  },

  moveOp: (nodeId, toIndex) => {
    const recipe = [...get().recipe];
    const from = recipe.findIndex((n) => n.id === nodeId);
    if (from < 0) return;
    const [node] = recipe.splice(from, 1);
    recipe.splice(Math.max(0, Math.min(toIndex, recipe.length)), 0, node);
    set({ recipe });
  },

  toggleEnabled: (nodeId) =>
    set({
      recipe: get().recipe.map((n) =>
        n.id === nodeId ? { ...n, enabled: !n.enabled } : n,
      ),
    }),

  setParam: (nodeId, key, value) =>
    set({
      recipe: get().recipe.map((n) =>
        n.id === nodeId ? { ...n, params: { ...n.params, [key]: value } } : n,
      ),
    }),

  bake: async (manual) => {
    const { recipe, inputText, inputEncoding } = get();
    // One-interface bake: an explicit Bake click with an EMPTY recipe runs
    // Auto Decode first and applies the best confident chain as the recipe,
    // so multi-layer encodings unwrap on the same Bake button instead of
    // requiring the Auto Analyze page. Auto-bake (typing) never triggers
    // this — it would run the bounded-but-nontrivial search per keystroke.
    if (manual && recipe.length === 0 && inputText.trim() !== "") {
      try {
        const cands = await api.autoAnalyze({
          input_text: inputText,
          input_encoding: inputEncoding,
        });
        // One-shot result: among confident candidates tied within a small
        // score margin, take the DEEPEST chain — it unwraps the most layers
        // so the output is the terminal payload, not an intermediate layer.
        // A top flag-pattern hit still wins (nothing reaches its score).
        const top = cands.length ? Math.max(...cands.map((c) => c.score)) : 0;
        const best =
          cands
            .filter((c) => c.confident && c.score >= top - 0.05)
            .sort((a, b) => b.path.length - a.path.length)[0] ?? cands[0];
        if (best && best.path.length > 0) {
          const { opsById } = get();
          const nodes = nodesFromCandidate(best, opsById);
          // Keep every confident candidate reachable: the recipe panel shows
          // alternates as one-click chips so the user can switch decodes.
          const seen = new Set<string>();
          const alternates = cands
            .filter((c) => c.confident && c.path.length > 0)
            .filter((c) => {
              const key = c.path.join(">");
              if (seen.has(key)) return false;
              seen.add(key);
              return true;
            })
            .slice(0, 6)
            .map((c) => ({
              index: cands.indexOf(c),
              label: `${c.path.join(" → ")} (${Math.round(c.score * 100)}%)`,
            }));
          set({
            recipe: nodes,
            autoCandidates: cands,
            bakeAlternates: alternates,
            assistRecipeNote: `Auto decoded: ${best.path.join(" → ")} (${Math.round(best.score * 100)}% confident) — applied as recipe`,
          });
          return void get().bake(manual);
        }
        set({
          assistRecipeNote:
            "Auto Analyze found no confident decoding for this input — inspect the full candidate list on the Auto Analyze page.",
        });
      } catch {
        // Auto decode unavailable/failed: fall through to the plain bake,
        // which reports the empty-recipe outcome as usual.
      }
    }
    runCounter += 1;
    const runId = `run-${runCounter}`;
    latestRunId = runId;
    set({ baking: true });
    try {
      const payload: RecipeV1 = {
        version: 1,
        nodes: recipe.map((n) => ({
          id: n.id,
          op: n.op,
          enabled: n.enabled,
          params: n.params,
        })),
      };
      const resp = await api.bake({
        recipe: payload,
        input_text: inputText,
        input_encoding: inputEncoding,
        auto_bake: manual ? false : get().autoBake,
        run_id: runId,
      });
      if (latestRunId !== runId) return; // superseded by a newer run
      applyResponse(set, resp);
    } catch (e) {
      if (latestRunId !== runId) return;
      set({ lastError: String(e) });
    } finally {
      if (latestRunId === runId) set({ baking: false });
    }
  },

  setSaveDialogOpen: (saveDialogOpen) => set({ saveDialogOpen }),

  saveRecipe: async (name) => {
    const { recipe } = get();
    const payload: RecipeV1 = {
      version: 1,
      nodes: recipe.map((n) => ({
        id: n.id,
        op: n.op,
        enabled: n.enabled,
        params: n.params,
      })),
    };
    await api.saveRecipe({ name, recipe: payload });
    set({ saveDialogOpen: false });
  },

  loadRecipeByName: async (name) => {
    try {
      const recipe = await api.loadRecipe(name);
      nodeCounter = 0;
      const nodes = recipe.nodes.map((n) => {
        nodeCounter += 1;
        return { ...n, id: `n${nodeCounter}` };
      });
      set({ recipe: nodes, page: "workbench", loadError: null });
      void get().bake(false);
    } catch (e) {
      set({ loadError: String(e) });
    }
  },

  importRecipeJson: (json) => {
    try {
      const parsed = JSON.parse(json) as RecipeV1;
      if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.nodes)) return false;
      nodeCounter = 0;
      const nodes = parsed.nodes.map((n) => {
        nodeCounter += 1;
        return { ...n, id: `n${nodeCounter}` };
      });
      set({ recipe: nodes, page: "workbench" });
      void get().bake(false);
      return true;
    } catch {
      return false;
    }
  },

  runAuto: async () => {
    const { inputText, inputEncoding } = get();
    set({ autoRunning: true });
    try {
      const candidates = await api.autoAnalyze({
        input_text: inputText,
        input_encoding: inputEncoding,
      });
      set({ autoCandidates: candidates });
    } catch (e) {
      set({ lastError: String(e) });
    } finally {
      set({ autoRunning: false });
    }
  },

  applyAutoCandidate: (index) => {
    const { autoCandidates, opsById } = get();
    const candidate = autoCandidates[index];
    if (!candidate) return;
    const nodes = nodesFromCandidate(candidate, opsById);
    set({ recipe: nodes, page: "workbench" });
    void get().bake(false);
  },

  applyBakeAlternate: (index) => {
    get().applyAutoCandidate(index);
  },

  dismissBakeNote: () => set({ assistRecipeNote: null, bakeAlternates: [] }),

  sendToAutoDecode: (base64) => {
    // Same input buffer the Workbench bakes (auto-bake picks the change up on
    // mount), then Auto Analyze runs on it immediately; old candidates go.
    set({ inputText: base64, inputEncoding: "base64", autoCandidates: [], page: "auto" });
    void get().runAuto();
  },

  outputToInput: () => {
    const { output } = get();
    if (!output) return;
    if (output.kind === "text") {
      set({ inputText: output.text, inputEncoding: "utf8" });
    } else if (output.kind === "bytes") {
      set({ inputText: output.base64, inputEncoding: "base64" });
    } else if (output.kind === "json") {
      set({ inputText: JSON.stringify(output.value, null, 2), inputEncoding: "utf8" });
    } else if (output.kind === "integer_list") {
      set({ inputText: output.items.join(" "), inputEncoding: "decimal" });
    }
  },

  swapInputOutput: () => {
    const { output } = get();
    if (!output) return;
    const prevInput = { text: get().inputText, encoding: get().inputEncoding };
    if (output.kind === "text") set({ inputText: output.text, inputEncoding: "utf8" });
    else if (output.kind === "bytes") set({ inputText: output.base64, inputEncoding: "base64" });
    else if (output.kind === "json")
      set({ inputText: JSON.stringify(output.value, null, 2), inputEncoding: "utf8" });
    else if (output.kind === "integer_list")
      set({ inputText: output.items.join(" "), inputEncoding: "decimal" });
    // The previous input becomes the output view (best effort, local only).
    set({ output: makePayloadFromInput(prevInput.text) });
  },
}));

function makePayloadFromInput(text: string): ValuePayload {
  return { kind: "text", text, size: text.length, entropy: 0 };
}

function applyResponse(
  set: (partial: Partial<Store>) => void,
  resp: BakeResponse,
) {
  set({
    output: resp.output,
    report: resp.report,
    lastError: resp.report.error ? resp.report.error.message : null,
  });
}

/** Debounce helper for auto bake. */
export function debounce<A extends unknown[]>(fn: (...args: A) => void, ms: number) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return (...args: A) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}
