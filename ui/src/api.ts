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
  /** Parameter overrides per step (aligned with path); absent for default runs. */
  step_params?: Array<Record<string, unknown> | null>;
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

// ---------------------------------------------------------- crypto assist ----

/** Mirrors cybercipher_attack::assist::KeyInterpretation (serde snake_case). */
export type AssistKeyInterpretation = "utf8" | "hex" | "base64";

/** Mirrors cybercipher_attack::assist::Mode (serde snake_case). */
export type AssistMode = "ecb" | "cbc" | "ctr" | "cfb" | "ofb";

/** Mirrors cybercipher_attack::assist::Padding (serde snake_case). */
export type AssistPadding = "pkcs7" | "none" | "zero" | "iso7816";

/** Mirrors cybercipher_attack::assist::IvSource (serde snake_case). */
export type AssistIvSource = "explicit" | "first_block" | "last_block" | "zero";

/** Mirrors cybercipher_attack::assist::AssistHit (serde snake_case). */
export interface AssistHit {
  rank: number;
  score: number;
  confident: boolean;
  cipher: string;
  key_length: number;
  key_interpretation: AssistKeyInterpretation;
  /** Resolved key material as lowercase hex pairs. */
  key_hex: string;
  mode: AssistMode;
  /** null for stream modes (CTR/CFB/OFB), which have no padding concept. */
  padding: AssistPadding | null;
  iv_source: AssistIvSource;
  /** The IV actually used, as lowercase hex pairs (empty for ECB). */
  iv_hex: string;
  /** Bounded lossy plaintext preview produced by the engine. */
  preview: string;
  evidence: string[];
}

/** Mirrors cybercipher_attack::assist::AssistResult (serde snake_case). */
export interface AssistResult {
  hits: AssistHit[];
  candidates_tried: number;
  candidates_pruned: number;
  deadline_ms: number;
  timed_out: boolean;
}

/** Mirrors the GUI's crypto_assist command request. */
export interface AssistRequest {
  ciphertext_text: string;
  /** utf8 | hex | base64 | decimal (same set as the Workbench input). */
  ciphertext_encoding: string;
  key_candidate: string;
  /** Optional explicit IV as hex. */
  iv_hex?: string | null;
  /** Optional known-plaintext hint that boosts matching hits. */
  hint?: string | null;
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

  autoAnalyze: (request: {
    input_text: string;
    input_encoding: string;
    /** Optional key material — enables structural keyed decryption in the beam. */
    key_text?: string;
    key_encoding?: string;
    /** Optional IV for CBC keyed candidates. */
    iv_text?: string;
    iv_encoding?: string;
    /** Optional known-plaintext hint that boosts matching candidates. */
    hint?: string;
  }) => invoke<AutoCandidate[]>("auto_analyze", { request }),

  saveRecipe: (request: { name: string; recipe: RecipeV1 }) =>
    invoke<RecipeMeta>("save_recipe", { request }),

  loadRecipe: (name: string) => invoke<RecipeV1>("load_recipe", { name }),

  listSavedRecipes: () => invoke<RecipeMeta[]>("list_saved_recipes"),

  deleteRecipe: (name: string) => invoke<void>("delete_recipe", { name }),

  rsaAnalyze: (request: RsaAnalyzeRequest) =>
    invoke<RsaAnalyzerReport>("rsa_analyze", { request }),

  cryptoAssist: (request: AssistRequest) =>
    invoke<AssistResult>("crypto_assist", { request }),

  // ------------------------------------------------------------- PKI lab ----

  pkiInspectKey: (material: string, hint?: string | null) =>
    invoke<PkiKeyReport>("pki_inspect_key", { material, hint }),

  pkiRsaKeygen: (bits: number) =>
    invoke<PkiRsaKeygenResult>("pki_rsa_keygen", { request: { bits } }),

  pkiRsaEncrypt: (request: PkiRsaEncryptRequest) =>
    invoke<PkiRsaEncryptResult>("pki_rsa_encrypt", { request }),

  pkiRsaDecrypt: (request: PkiRsaDecryptRequest) =>
    invoke<PkiRsaDecryptResult>("pki_rsa_decrypt", { request }),

  pkiRsaSign: (request: PkiRsaSignRequest) =>
    invoke<PkiRsaSignResult>("pki_rsa_sign", { request }),

  pkiRsaVerify: (request: PkiRsaVerifyRequest) =>
    invoke<SignatureVerifyResult>("pki_rsa_verify", { request }),

  pkiEccKeygen: (curve: string) =>
    invoke<PkiEccKeygenResult>("pki_ecc_keygen", { request: { curve } }),

  pkiEcdsaSign: (request: PkiEcdsaSignRequest) =>
    invoke<PkiEcdsaSignResult>("pki_ecdsa_sign", { request }),

  pkiEcdsaVerify: (request: PkiEcdsaVerifyRequest) =>
    invoke<PkiEcdsaVerifyResult>("pki_ecdsa_verify", { request }),

  pkiEcdh: (request: { curve: string; private_hex: string; peer_public_hex: string }) =>
    invoke<PkiSharedSecretResult>("pki_ecdh", { request }),

  pkiEd25519Sign: (request: { private_hex: string; data_text: string; data_encoding: string }) =>
    invoke<PkiSignatureHexResult>("pki_ed25519_sign", { request }),

  pkiEd25519Verify: (request: {
    public_hex: string;
    data_text: string;
    data_encoding: string;
    signature_hex: string;
  }) => invoke<PkiEd25519VerifyResult>("pki_ed25519_verify", { request }),

  pkiX25519: (request: { private_hex: string; peer_public_hex: string }) =>
    invoke<PkiSharedSecretResult>("pki_x25519", { request }),

  pkiSm2Keygen: () => invoke<PkiSm2KeygenResult>("pki_sm2_keygen"),

  pkiSm2Sign: (request: {
    private_hex: string;
    data_text: string;
    data_encoding: string;
    user_id?: string | null;
  }) => invoke<PkiSm2SignResult>("pki_sm2_sign", { request }),

  pkiSm2Verify: (request: {
    public_hex: string;
    data_text: string;
    data_encoding: string;
    signature_hex: string;
    user_id?: string | null;
  }) => invoke<PkiSm2VerifyResult>("pki_sm2_verify", { request }),

  pkiSm2Encrypt: (request: {
    public_hex: string;
    plaintext_text: string;
    plaintext_encoding: string;
  }) => invoke<PkiSm2EncryptResult>("pki_sm2_encrypt", { request }),

  pkiSm2Decrypt: (request: {
    private_hex: string;
    ciphertext_text: string;
    ciphertext_encoding: string;
  }) => invoke<PkiSm2DecryptResult>("pki_sm2_decrypt", { request }),

  pkiCertInspect: (material: string) =>
    invoke<PkiCertReport>("pki_cert_inspect", { request: { material } }),

  // ------------------------------------------------------------- SSTV lab ----

  sstvDecodeAudio: (bytes: number[], options: SstvDecodeOptions) =>
    invoke<SstvDecodeResult>("sstv_decode_audio", { bytes, options }),

  sstvModes: () => invoke<SstvModeInfo[]>("sstv_modes"),
};

// -------------------------------------------------------------- PKI lab ----
// Mirrors the serde types in apps/cybercipher-gui/src/pki_commands.rs and the
// engine structs in crates/cybercipher-pki; keep them in sync.

/** One label/value row of a key or certificate report. */
export interface PkiField {
  label: string;
  value: string;
  multiline: boolean;
}

/** Binary result: lowercase hex is canonical, UTF-8 rendering when valid. */
export interface PkiBytes {
  hex: string;
  utf8?: string;
  size: number;
}

/** Unified key-inspection report from pki_inspect_key. */
export interface PkiKeyReport {
  kind: "rsa" | "ec" | "ed25519" | "x25519" | "sm2";
  curve?: string;
  is_private: boolean;
  bit_length?: number;
  source_format: string;
  summary: string;
  public_fields: PkiField[];
  private_fields: PkiField[];
  encodings: PkiField[];
  alternatives: string[];
}

/** Mirrors the engine's RsaKeyMaterial (hex components). */
export interface RsaKeyMaterial {
  n: string;
  e: string;
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qinv: string;
}

export interface PkiRsaKeygenResult {
  private_pem: string;
  public_pem: string;
  private_pkcs1_pem: string;
  public_pkcs1_pem: string;
  report: PkiKeyReport;
}

export interface PkiRsaEncryptRequest {
  key_pem: string;
  scheme: "oaep" | "pkcs1v15";
  hash?: string | null;
  label?: string | null;
  plaintext_text: string;
  plaintext_encoding: string;
}

export interface PkiRsaEncryptResult {
  ciphertext: PkiBytes;
  scheme: string;
  hash?: string;
}

export interface PkiRsaDecryptRequest {
  key_pem: string;
  scheme: "oaep" | "pkcs1v15";
  hash?: string | null;
  label?: string | null;
  ciphertext_text: string;
  ciphertext_encoding: string;
}

export interface PkiRsaDecryptResult {
  plaintext: PkiBytes;
}

export interface PkiRsaSignRequest {
  key_pem: string;
  scheme: "pkcs1v15" | "pss";
  hash: string;
  salt_len?: string | null;
  data_text: string;
  data_encoding: string;
}

export interface PkiRsaSignResult {
  signature: PkiBytes;
  scheme: string;
  digest: string;
  salt_len?: string;
}

export interface PkiRsaVerifyRequest {
  key_pem: string;
  scheme: "pkcs1v15" | "pss";
  hash: string;
  salt_len?: string | null;
  data_text: string;
  data_encoding: string;
  signature_text: string;
}

/** Mirrors cybercipher_pki::SignatureVerifyResult. */
export interface SignatureVerifyResult {
  valid: boolean;
  reason?: string;
  scheme: string;
  digest: string;
  salt_len?: number;
}

export interface PkiEccKeygenResult {
  curve: string;
  private_hex: string;
  public_compressed_hex: string;
  public_uncompressed_hex: string;
  private_pkcs8_pem: string;
  public_spki_pem: string;
  report: PkiKeyReport;
}

export interface PkiEcdsaSignRequest {
  curve: string;
  private_hex: string;
  digest: string;
  format?: string | null;
  nonce?: string | null;
  data_text: string;
  data_encoding: string;
}

export interface PkiEcdsaSignResult {
  signature_hex: string;
  curve: string;
  digest: string;
  format: string;
  nonce: string;
}

export interface PkiEcdsaVerifyRequest {
  curve: string;
  public_hex: string;
  digest: string;
  format?: string | null;
  data_text: string;
  data_encoding: string;
  signature_hex: string;
}

/** Mirrors cybercipher_pki::EcdsaVerifyResult. */
export interface PkiEcdsaVerifyResult {
  valid: boolean;
  reason?: string;
  curve: string;
  digest: string;
  signature_format: string;
}

export interface PkiSharedSecretResult {
  shared_secret_hex: string;
}

export interface PkiSignatureHexResult {
  signature_hex: string;
}

/** Mirrors cybercipher_pki::Ed25519VerifyResult. */
export interface PkiEd25519VerifyResult {
  valid: boolean;
  reason?: string;
}

/** Mirrors cybercipher_pki::Sm2KeyPair. */
export interface Sm2KeyPair {
  private_hex: string;
  public_compressed_hex: string;
  public_uncompressed_hex: string;
}

export interface PkiSm2KeygenResult extends Sm2KeyPair {
  report: PkiKeyReport;
}

export interface PkiSm2SignResult {
  signature_hex: string;
  user_id: string;
}

/** Mirrors cybercipher_pki::Sm2VerifyResult. */
export interface PkiSm2VerifyResult {
  valid: boolean;
  reason?: string;
  user_id: string;
}

export interface PkiSm2EncryptResult {
  ciphertext: PkiBytes;
}

export interface PkiSm2DecryptResult {
  plaintext: PkiBytes;
}

export interface PkiCertReport {
  object_type: "certificate" | "csr" | "crl";
  pem_label?: string;
  der_hex: string;
  certificate?: CertificateInspection;
  csr?: CsrInspection;
  crl?: CrlInspection;
  asn1_tree: Asn1Node[];
}

/** Mirrors cybercipher_pki::RdnEntry. */
export interface RdnEntry {
  oid: string;
  name?: string;
  value: string;
}

/** Mirrors cybercipher_pki::PublicKeyInfoInspection. */
export interface PublicKeyInfoInspection {
  algorithm: string;
  algorithm_oid: string;
  key_type: string;
  bit_length?: number;
  curve?: string;
  public_key_hex?: string;
}

/** Mirrors cybercipher_pki::ExtensionSummary. */
export interface ExtensionSummary {
  oid: string;
  name?: string;
  critical: boolean;
}

/** Mirrors cybercipher_pki::BasicConstraintsInspection. */
export interface BasicConstraintsInspection {
  ca: boolean;
  path_len?: number;
}

/** Mirrors cybercipher_pki::CertificateInspection. */
export interface CertificateInspection {
  version: number;
  version_label: string;
  serial_hex: string;
  signature_algorithm: string;
  signature_algorithm_oid: string;
  issuer: RdnEntry[];
  subject: RdnEntry[];
  not_before: string;
  not_after: string;
  public_key: PublicKeyInfoInspection;
  fingerprint_sha256: string;
  fingerprint_sha1: string;
  extensions: ExtensionSummary[];
  subject_alt_names: string[];
  key_usage: string[];
  extended_key_usage: string[];
  basic_constraints?: BasicConstraintsInspection;
  subject_key_identifier?: string;
  authority_key_identifier?: string;
  summary: string;
}

/** Mirrors cybercipher_pki::AttributeSummary. */
export interface AttributeSummary {
  oid: string;
  name?: string;
  value_count: number;
}

/** Mirrors cybercipher_pki::CsrInspection. */
export interface CsrInspection {
  version: number;
  subject: RdnEntry[];
  public_key: PublicKeyInfoInspection;
  signature_algorithm: string;
  signature_algorithm_oid: string;
  attributes: AttributeSummary[];
  signature_verified: boolean | null;
  verification_note: string;
  summary: string;
}

/** Mirrors cybercipher_pki::RevokedEntry. */
export interface RevokedEntry {
  serial_hex: string;
  revocation_date: string;
}

/** Mirrors cybercipher_pki::CrlInspection. */
export interface CrlInspection {
  issuer: RdnEntry[];
  this_update: string;
  next_update?: string;
  signature_algorithm: string;
  signature_algorithm_oid: string;
  revoked: RevokedEntry[];
  revoked_count: number;
  crl_number_hex?: string;
  summary: string;
}

/** Mirrors cybercipher_pki::Asn1Class. */
export type Asn1Class = "universal" | "application" | "context" | "private";

/** Mirrors cybercipher_pki::Asn1Value (tagged union). */
export type Asn1Value =
  | { type: "integer"; value: string; hex: string }
  | { type: "boolean"; value: boolean }
  | { type: "null" }
  | { type: "object_identifier"; dotted: string; name?: string }
  | { type: "utf8_string"; text: string }
  | { type: "printable_string"; text: string }
  | { type: "ia5_string"; text: string }
  | { type: "numeric_string"; text: string }
  | { type: "visible_string"; text: string }
  | { type: "utc_time"; text: string }
  | { type: "generalized_time"; text: string }
  | { type: "bit_string"; hex: string; unused_bits: number }
  | { type: "octet_string"; hex: string }
  | { type: "raw"; hex: string };

/** Mirrors cybercipher_pki::Asn1Node. */
export interface Asn1Node {
  tag_class: Asn1Class;
  tag_number: number;
  tag_name?: string;
  constructed: boolean;
  offset: number;
  header_len: number;
  value_offset: number;
  value_len: number;
  total_len: number;
  value?: Asn1Value;
  children: Asn1Node[];
  hex_preview?: string;
}

// -------------------------------------------------------------- SSTV lab ----
// Mirrors the serde types in apps/cybercipher-gui/src/sstv_commands.rs and the
// engine structs in crates/cybercipher-sstv (report.rs); keep them in sync.

/** Mirrors sstv_commands.rs SstvDecodeOptions (serde field names, snake_case). */
export interface SstvDecodeOptions {
  /** auto | mono | left | right | zero-based channel index (as a string). */
  channel: string;
  /** Slug or display name; null/blank means automatic detection. */
  forced_mode?: string | null;
  /** Allow blind sync-period inference when the VIS header is absent. */
  blind: boolean;
  /** Reject audio longer than this (engine clamps to 1..=300 s). */
  max_duration_seconds: number;
  /** Ranked candidates decoded at full resolution (engine clamps to 1..=20). */
  max_candidates: number;
}

/** Mirrors sstv_commands.rs SstvImage. */
export interface SstvImage {
  /** Index into report.detections. */
  detection_index: number;
  mode_slug: string;
  mode_name: string;
  width: number;
  height: number;
  /** PNG byte count before base64. */
  size: number;
  /** Base64-encoded PNG bytes, data-URL ready. */
  png_base64: string;
}

/** Mirrors sstv_commands.rs SstvDecodeResult. */
export interface SstvDecodeResult {
  /** The complete run report (crates/cybercipher-sstv/src/report.rs). */
  report: SstvReport;
  /** Decoded images, best first, aligned with report.detections. */
  images: SstvImage[];
  /** Always null: decoded bytes never touch disk in the command layer. */
  report_path: string | null;
}

/** Mirrors sstv_commands.rs SstvModeInfo. */
export interface SstvModeInfo {
  slug: string;
  name: string;
  vis_code: number;
  family: string;
  palette: string;
  width: number;
  height: number;
  /** Total transmitted image duration, seconds (excludes the VIS header). */
  image_seconds: number;
}

/**
 * The engine's full run report (crates/cybercipher-sstv/src/report.rs), as a
 * loose shape: every documented field is optional so the UI degrades
 * gracefully when the engine omits one.
 */
export interface SstvReport {
  tool_version?: string;
  audio?: SstvReportAudio;
  hypotheses_evaluated?: number;
  detections?: SstvReportDetection[];
  warnings?: string[];
  /** Image metadata appended by decode_bounded (aligned with detections). */
  images?: SstvReportImageMeta[];
  [key: string]: unknown;
}

/** Mirrors report.rs AudioReport. */
export interface SstvReportAudio {
  input?: string;
  duration_seconds?: number;
  analysis_rate_hz?: number;
  source_channels?: number;
  selected_channel?: string;
  normalized_peak?: number;
}

/** Mirrors report.rs Detection. */
export interface SstvReportDetection {
  mode?: string;
  mode_slug?: string;
  vis_code?: number;
  /** vis | vis-parity-failed | sync-period | forced. */
  detected_by?: string;
  confidence?: number;
  signal_agreement?: number;
  coverage?: number;
  complete?: boolean;
  image_start_seconds?: number;
  frequency_offset_hz?: number;
  clock_rate?: number;
  clock_error_percent?: number;
  matched_syncs?: number;
  width?: number;
  height?: number;
  image_quality?: number;
  evidence?: string[];
  /** Other modes that would decode identically without a VIS header. */
  ambiguous_with?: string[];
  output_png?: string;
}

/** Image metadata inside report.images. */
export interface SstvReportImageMeta {
  detection_index?: number;
  format?: string;
  width?: number;
  height?: number;
  bytes?: number;
}

/**
 * Render a rejected `invoke` error as readable text. Tauri rejects with the
 * serialized command error; the PKI commands send the engine's structured
 * OperationError (kind/message/parameter/expected/actual/details).
 */
export function formatInvokeError(e: unknown): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const err = e as Record<string, unknown>;
    if (typeof err.message === "string") {
      const kind = typeof err.kind === "string" ? err.kind : "error";
      let text = `${kind}: ${err.message}`;
      const extra: string[] = [];
      if (typeof err.parameter === "string") extra.push(`parameter=${err.parameter}`);
      if (typeof err.expected === "string") extra.push(`expected ${err.expected}`);
      if (typeof err.actual === "string") extra.push(`got ${err.actual}`);
      if (typeof err.details === "string") extra.push(err.details);
      if (extra.length > 0) text += ` — ${extra.join("; ")}`;
      return text;
    }
  }
  return String(e);
}
