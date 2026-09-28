import { create } from "zustand";
import {
  api,
  type BakeResponse,
  type ExecutionReport,
  type InputStats,
  type OperationInfo,
  type ParamSpec,
  type ParamValue,
  type RecipeNode,
  type RecipeV1,
  type ValuePayload,
} from "./api";

export type Page = "workbench" | "recipes" | "settings";

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
  autoBake: boolean;
  baking: boolean;
  lastError: string | null;
  theme: "dark" | "light";
  saveDialogOpen: boolean;
  loadError: string | null;

  init: () => Promise<void>;
  setPage: (p: Page) => void;
  setTheme: (t: "dark" | "light") => void;
  setAutoBake: (v: boolean) => void;
  setInputText: (t: string) => void;
  setInputEncoding: (e: Store["inputEncoding"]) => void;

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
  autoBake: true,
  baking: false,
  lastError: null,
  theme: "dark",
  saveDialogOpen: false,
  loadError: null,

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
