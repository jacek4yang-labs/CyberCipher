// Typed wrappers around the Tauri IPC surface. These mirror the Rust types
// in cybercipher-core / cybercipher-engine; keep them in sync.

import { invoke } from "@tauri-apps/api/core";

export type Category =
  | "encoding"
  | "byte_operation"
  | "crypto"
  | "hash"
  | "mac"
  | "kdf"
  | "public_key"
  | "classical"
  | "analysis"
  | "compression"
  | "serialization"
  | "file"
  | "utility";

export type CostClass = "instant" | "interactive" | "heavy" | "solver" | "external";
export type Security = "modern" | "legacy" | "broken" | "hazmat" | "neutral";
export type ValueKind = "bytes" | "text" | "integer" | "integer_list" | "json" | "list" | "null";
export type ParamKind = "text" | "text_area" | "integer" | "float" | "boolean" | "options" | "encoding";

export interface ParamOption {
  value: string;
  label: string;
}

export interface ParamSpec {
  key: string;
  label: string;
  kind: ParamKind;
  default: { str: string } | { int: number } | { bool: boolean } | { float: number };
  optional: boolean;
  hint: string;
  options: ParamOption[];
}

export interface Provenance {
  standard: string;
  implementation: string;
  test_vectors: string;
}

export interface OperationInfo {
  id: string;
  name: string;
  description: string;
  category: Category;
  input_kinds: ValueKind[];
  output_kind: ValueKind;
  params: ParamSpec[];
  cost: CostClass;
  security: Security;
  deterministic: boolean;
  reversible: boolean;
  aliases: string[];
  tags: string[];
  provenance: Provenance;
}

export type ParamValue = string | number | boolean;

export interface RecipeNode {
  id: string;
  op: string;
  enabled: boolean;
  params: Record<string, ParamValue>;
}

export interface RecipeV1 {
  version: 1;
  nodes: RecipeNode[];
  edges?: { from: string; to: string }[];
}

export type ErrorKind =
  | "invalid_param"
  | "invalid_input"
  | "decode"
  | "key_error"
  | "length_mismatch"
  | "unsupported"
  | "cancelled"
  | "budget_exceeded"
  | "internal";

export interface OperationError {
  kind: ErrorKind;
  message: string;
  parameter?: string;
  expected?: string;
  actual?: string;
  details?: string;
}

export type StageStatus = "ok" | "cached" | "skipped" | "error";

export interface StageReport {
  node_id: string;
  op_id: string;
  op_name: string;
  status: StageStatus;
  kind: string;
  size: number;
  duration_us: number;
  error: OperationError | null;
}

export interface ExecutionReport {
  stages: StageReport[];
  error: OperationError | null;
  blocked_at: string | null;
  cached_stages: number;
  duration_us: number;
}

export type ValuePayload =
  | { kind: "text"; text: string; size: number; entropy: number }
  | {
      kind: "bytes";
      base64: string;
      text_lossy: string;
      is_utf8: boolean;
      size: number;
      entropy: number;
    }
  | { kind: "json"; value: unknown; size: number }
  | { kind: "integer_list"; items: string[]; count: number }
  | { kind: "list"; count: number; preview: string[] }
  | { kind: "null" };

export interface BakeResponse {
  report: ExecutionReport;
  output: ValuePayload | null;
  blocked_at: string | null;
}

export interface InputStats {
  size: number;
  entropy: number;
  printable_ratio: number;
}

export interface RecipeMeta {
  name: string;
  op_count: number;
  modified: string;
}

export interface AutoCandidate {
  score: number;
  confident: boolean;
  path: string[];
  evidence: string[];
  kind: string;
  size: number;
  preview: string;
  is_utf8: boolean;
  flag_like: string | null;
}

export interface CmdError {
  kind: string;
  message: string;
}

// ---------------------------------------------------------- RSA attack lab ----

/** Mirrors cybercipher_attack::AttackStatus (serde snake_case). */
export type RsaAttackStatus = "applicable" | "not_applicable" | "success" | "failed";

/** Mirrors cybercipher_attack::AttackCost. */
export type RsaAttackCost = "instant" | "fast" | "slow";

/** Recovered plaintext with human-readable interpretations. */
export interface RsaPlaintext {
  m_hex: string;
  m_decimal: string;
  /** Big-endian byte encoding of m, as lowercase hex pairs. */
  bytes_be: string;
  utf8?: string;
  flag_like?: string;
}

/** One attack's diagnostic result. */
export interface RsaAttackOutcome {
  id: string;
  name: string;
  status: RsaAttackStatus;
  cost: RsaAttackCost;
  message: string;
  details?: string;
  plaintext?: RsaPlaintext;
}

/** Mirrors cybercipher_attack::AnalyzerReport. */
export interface RsaAnalyzerReport {
  findings: RsaAttackOutcome[];
  /** Working parameter set after enrichments (0x-hex string values). */
  params: Record<string, unknown>;
  plaintext?: RsaPlaintext;
}

export interface RsaAnalyzeRequest {
  /** Parameter object: decimal or 0x-hex strings, optional sets/ns/hint. */
  params: Record<string, unknown>;
  solve: boolean;
  budget_ms: number;
}

export const api = {
  listOperations: () => invoke<OperationInfo[]>("list_operations"),

  bake: (request: {
    recipe: RecipeV1;
    input_text: string;
    input_encoding: string;
    auto_bake: boolean;
    run_id: string;
  }) => invoke<BakeResponse>("bake", { request }),

  cancelRun: (runId: string) => invoke<void>("cancel_run", { runId }),

  inputStats: (input: { text: string; encoding: string }) =>
    invoke<InputStats>("input_stats", { input }),

  autoAnalyze: (request: { input_text: string; input_encoding: string }) =>
    invoke<AutoCandidate[]>("auto_analyze", { request }),

  saveRecipe: (request: { name: string; recipe: RecipeV1 }) =>
    invoke<RecipeMeta>("save_recipe", { request }),

  loadRecipe: (name: string) => invoke<RecipeV1>("load_recipe", { name }),

  listSavedRecipes: () => invoke<RecipeMeta[]>("list_saved_recipes"),

  deleteRecipe: (name: string) => invoke<void>("delete_recipe", { name }),

  rsaAnalyze: (request: RsaAnalyzeRequest) =>
    invoke<RsaAnalyzerReport>("rsa_analyze", { request }),
};
