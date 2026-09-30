import { create } from "zustand";
import {
  api,
  formatInvokeError,
  type PkiBytes,
  type PkiCertReport,
  type PkiEccKeygenResult,
  type PkiEcdsaVerifyResult,
  type PkiEd25519VerifyResult,
  type PkiKeyReport,
  type PkiRsaKeygenResult,
  type PkiSm2KeygenResult,
  type PkiSm2SignResult,
  type PkiSm2VerifyResult,
  type SignatureVerifyResult,
} from "./api";

/** Tabs of the PKI Lab page. */
export type PkiTab = "keys" | "rsa" | "ecc" | "sm2" | "certificate";

/** Bit sizes accepted by the engine's RSA keygen (see pki keys::mod). */
export const RSA_KEYGEN_BITS = [1024, 2048, 3072, 4096] as const;

/** Curves accepted by the engine's ECC keygen (see pki ecc::curve). */
export const ECC_CURVES = ["p256", "p384", "ed25519", "x25519"] as const;

/** The engine's default SM2 user ID (GB/T 32918.2 appendix A). */
export const SM2_DEFAULT_USER_ID = "1234567812345678";

/** Hashes the engine accepts for RSA operations (RFC 8017). */
export const RSA_HASHES = ["sha1", "sha256", "sha384", "sha512"] as const;

/** Message-input encodings for byte-oriented fields (text or raw hex). */
export type DataEncoding = "utf8" | "hex";

export interface PkiStore {
  tab: PkiTab;
  setTab: (tab: PkiTab) => void;

  // --------------------------------------------------------------- keys ----
  keysMaterial: string;
  keysHint: string;
  keysReport: PkiKeyReport | null;
  keysBusy: boolean;
  keysError: string | null;
  setKeysMaterial: (v: string) => void;
  setKeysHint: (v: string) => void;
  inspectMaterial: () => Promise<void>;

  // ---------------------------------------------------------------- rsa ----
  rsaBits: number;
  setRsaBits: (bits: number) => void;
  rsaKeygen: PkiRsaKeygenResult | null;
  rsaKeygenBusy: boolean;
  rsaKeygenError: string | null;
  generateRsaKey: () => Promise<void>;

  rsaPublicPem: string;
  rsaPrivatePem: string;
  rsaEncScheme: "oaep" | "pkcs1v15";
  rsaHash: string;
  rsaLabel: string;
  rsaPlaintextText: string;
  rsaPlaintextEnc: DataEncoding;
  rsaCiphertext: PkiBytes | null;
  rsaDecryptCiphertext: string;
  rsaDecryptResult: PkiBytes | null;
  rsaEncBusy: boolean;
  rsaEncError: string | null;
  setRsaPublicPem: (v: string) => void;
  setRsaPrivatePem: (v: string) => void;
  setRsaEncScheme: (v: "oaep" | "pkcs1v15") => void;
  setRsaHash: (v: string) => void;
  setRsaLabel: (v: string) => void;
  setRsaPlaintextText: (v: string) => void;
  setRsaPlaintextEnc: (v: DataEncoding) => void;
  setRsaDecryptCiphertext: (v: string) => void;
  rsaEncrypt: () => Promise<void>;
  rsaDecrypt: () => Promise<void>;

  rsaSignScheme: "pkcs1v15" | "pss";
  rsaSignHash: string;
  rsaSaltLen: string;
  rsaSignDataText: string;
  rsaSignDataEnc: DataEncoding;
  rsaSignature: PkiBytes | null;
  rsaVerifyKeyPem: string;
  rsaVerifySigText: string;
  rsaVerifyVerdict: SignatureVerifyResult | null;
  rsaSignBusy: boolean;
  rsaSignError: string | null;
  rsaVerifyBusy: boolean;
  rsaVerifyError: string | null;
  setRsaSignScheme: (v: "pkcs1v15" | "pss") => void;
  setRsaSignHash: (v: string) => void;
  setRsaSaltLen: (v: string) => void;
  setRsaSignDataText: (v: string) => void;
  setRsaSignDataEnc: (v: DataEncoding) => void;
  setRsaVerifyKeyPem: (v: string) => void;
  setRsaVerifySigText: (v: string) => void;
  rsaSign: () => Promise<void>;
  rsaVerify: () => Promise<void>;

  // ---------------------------------------------------------------- ecc ----
  eccCurve: string;
  eccKeygen: PkiEccKeygenResult | null;
  eccKeygenBusy: boolean;
  eccKeygenError: string | null;
  setEccCurve: (v: string) => void;
  generateEccKey: () => Promise<void>;

  // ECDSA (P-256/P-384 only)
  ecdsaPrivateHex: string;
  ecdsaPublicHex: string;
  ecdsaDataText: string;
  ecdsaDataEnc: DataEncoding;
  ecdsaFormat: "der" | "fixed";
  ecdsaSigHex: string;
  ecdsaSignResult: string | null;
  ecdsaVerifyResult: PkiEcdsaVerifyResult | null;
  ecdsaBusy: boolean;
  ecdsaError: string | null;
  setEcdsaPrivateHex: (v: string) => void;
  setEcdsaPublicHex: (v: string) => void;
  setEcdsaDataText: (v: string) => void;
  setEcdsaDataEnc: (v: DataEncoding) => void;
  setEcdsaFormat: (v: "der" | "fixed") => void;
  setEcdsaSigHex: (v: string) => void;
  runEcdsaSign: () => Promise<void>;
  runEcdsaVerify: () => Promise<void>;

  // ECDH (P-256/P-384 only)
  ecdhPrivateHex: string;
  ecdhPeerHex: string;
  ecdhSecret: string | null;
  ecdhBusy: boolean;
  ecdhError: string | null;
  setEcdhPrivateHex: (v: string) => void;
  setEcdhPeerHex: (v: string) => void;
  runEcdh: () => Promise<void>;

  // Ed25519
  edPrivateHex: string;
  edPublicHex: string;
  edDataText: string;
  edDataEnc: DataEncoding;
  edSigHex: string;
  edSignResult: string | null;
  edVerifyResult: PkiEd25519VerifyResult | null;
  edBusy: boolean;
  edError: string | null;
  setEdPrivateHex: (v: string) => void;
  setEdPublicHex: (v: string) => void;
  setEdDataText: (v: string) => void;
  setEdDataEnc: (v: DataEncoding) => void;
  setEdSigHex: (v: string) => void;
  runEdSign: () => Promise<void>;
  runEdVerify: () => Promise<void>;

  // X25519
  xPrivateHex: string;
  xPeerHex: string;
  xSecret: string | null;
  xBusy: boolean;
  xError: string | null;
  setXPrivateHex: (v: string) => void;
  setXPeerHex: (v: string) => void;
  runX25519: () => Promise<void>;

  // ---------------------------------------------------------------- sm2 ----
  sm2Keygen: PkiSm2KeygenResult | null;
  sm2KeygenBusy: boolean;
  sm2KeygenError: string | null;
  sm2UserId: string;
  sm2PrivateHex: string;
  sm2PublicHex: string;
  sm2DataText: string;
  sm2DataEnc: DataEncoding;
  sm2SigHex: string;
  sm2SignResult: PkiSm2SignResult | null;
  sm2VerifyResult: PkiSm2VerifyResult | null;
  sm2SignBusy: boolean;
  sm2VerifyBusy: boolean;
  sm2SignError: string | null;
  sm2VerifyError: string | null;
  sm2EncPublicHex: string;
  sm2PlaintextText: string;
  sm2PlaintextEnc: DataEncoding;
  sm2Ciphertext: PkiBytes | null;
  sm2DecPrivateHex: string;
  sm2DecCiphertext: string;
  sm2DecResult: PkiBytes | null;
  sm2EncBusy: boolean;
  sm2EncError: string | null;
  setSm2UserId: (v: string) => void;
  setSm2PrivateHex: (v: string) => void;
  setSm2PublicHex: (v: string) => void;
  setSm2DataText: (v: string) => void;
  setSm2DataEnc: (v: DataEncoding) => void;
  setSm2SigHex: (v: string) => void;
  setSm2EncPublicHex: (v: string) => void;
  setSm2PlaintextText: (v: string) => void;
  setSm2PlaintextEnc: (v: DataEncoding) => void;
  setSm2DecPrivateHex: (v: string) => void;
  setSm2DecCiphertext: (v: string) => void;
  generateSm2Key: () => Promise<void>;
  runSm2Sign: () => Promise<void>;
  runSm2Verify: () => Promise<void>;
  runSm2Encrypt: () => Promise<void>;
  runSm2Decrypt: () => Promise<void>;

  // --------------------------------------------------------- certificate ----
  certMaterial: string;
  certReport: PkiCertReport | null;
  certBusy: boolean;
  certError: string | null;
  setCertMaterial: (v: string) => void;
  inspectCert: () => Promise<void>;
}

export const usePkiStore = create<PkiStore>((set, get) => ({
  tab: "keys",
  setTab: (tab) => set({ tab }),

  // --------------------------------------------------------------- keys ----
  keysMaterial: "",
  keysHint: "",
  keysReport: null,
  keysBusy: false,
  keysError: null,
  setKeysMaterial: (keysMaterial) => set({ keysMaterial }),
  setKeysHint: (keysHint) => set({ keysHint }),
  inspectMaterial: async () => {
    if (get().keysBusy) return;
    set({ keysBusy: true, keysError: null });
    try {
      const hint = get().keysHint.trim();
      const report = await api.pkiInspectKey(get().keysMaterial, hint !== "" ? hint : null);
      set({ keysReport: report });
    } catch (e) {
      set({ keysError: formatInvokeError(e) });
    } finally {
      set({ keysBusy: false });
    }
  },

  // ---------------------------------------------------------------- rsa ----
  rsaBits: 2048,
  setRsaBits: (rsaBits) => set({ rsaBits }),
  rsaKeygen: null,
  rsaKeygenBusy: false,
  rsaKeygenError: null,
  generateRsaKey: async () => {
    if (get().rsaKeygenBusy) return;
    set({ rsaKeygenBusy: true, rsaKeygenError: null });
    try {
      const result = await api.pkiRsaKeygen(get().rsaBits);
      set({
        rsaKeygen: result,
        rsaPublicPem: result.public_pem,
        rsaPrivatePem: result.private_pem,
        rsaVerifyKeyPem: result.public_pem,
      });
    } catch (e) {
      set({ rsaKeygenError: formatInvokeError(e) });
    } finally {
      set({ rsaKeygenBusy: false });
    }
  },

  rsaPublicPem: "",
  rsaPrivatePem: "",
  rsaEncScheme: "oaep",
  rsaHash: "sha256",
  rsaLabel: "",
  rsaPlaintextText: "",
  rsaPlaintextEnc: "utf8",
  rsaCiphertext: null,
  rsaDecryptCiphertext: "",
  rsaDecryptResult: null,
  rsaEncBusy: false,
  rsaEncError: null,
  setRsaPublicPem: (rsaPublicPem) => set({ rsaPublicPem }),
  setRsaPrivatePem: (rsaPrivatePem) => set({ rsaPrivatePem }),
  setRsaEncScheme: (rsaEncScheme) => set({ rsaEncScheme }),
  setRsaHash: (rsaHash) => set({ rsaHash }),
  setRsaLabel: (rsaLabel) => set({ rsaLabel }),
  setRsaPlaintextText: (rsaPlaintextText) => set({ rsaPlaintextText }),
  setRsaPlaintextEnc: (rsaPlaintextEnc) => set({ rsaPlaintextEnc }),
  setRsaDecryptCiphertext: (rsaDecryptCiphertext) => set({ rsaDecryptCiphertext }),
  rsaEncrypt: async () => {
    if (get().rsaEncBusy) return;
    set({ rsaEncBusy: true, rsaEncError: null });
    try {
      const label = get().rsaLabel.trim();
      const result = await api.pkiRsaEncrypt({
        key_pem: get().rsaPublicPem,
        scheme: get().rsaEncScheme,
        hash: get().rsaEncScheme === "oaep" ? get().rsaHash : null,
        label: label !== "" ? label : null,
        plaintext_text: get().rsaPlaintextText,
        plaintext_encoding: get().rsaPlaintextEnc,
      });
      // Ciphertext is ready for the decrypt box (hex, the round trip).
      set({
        rsaCiphertext: result.ciphertext,
        rsaDecryptCiphertext: result.ciphertext.hex,
      });
    } catch (e) {
      set({ rsaEncError: formatInvokeError(e) });
    } finally {
      set({ rsaEncBusy: false });
    }
  },
  rsaDecrypt: async () => {
    if (get().rsaEncBusy) return;
    set({ rsaEncBusy: true, rsaEncError: null });
    try {
      const label = get().rsaLabel.trim();
      const result = await api.pkiRsaDecrypt({
        key_pem: get().rsaPrivatePem,
        scheme: get().rsaEncScheme,
        hash: get().rsaEncScheme === "oaep" ? get().rsaHash : null,
        label: label !== "" ? label : null,
        ciphertext_text: get().rsaDecryptCiphertext,
        ciphertext_encoding: "hex",
      });
      set({ rsaDecryptResult: result.plaintext });
    } catch (e) {
      set({ rsaEncError: formatInvokeError(e) });
    } finally {
      set({ rsaEncBusy: false });
    }
  },

  rsaSignScheme: "pkcs1v15",
  rsaSignHash: "sha256",
  rsaSaltLen: "digest",
  rsaSignDataText: "",
  rsaSignDataEnc: "utf8",
  rsaSignature: null,
  rsaVerifyKeyPem: "",
  rsaVerifySigText: "",
  rsaVerifyVerdict: null,
  rsaSignBusy: false,
  rsaSignError: null,
  rsaVerifyBusy: false,
  rsaVerifyError: null,
  setRsaSignScheme: (rsaSignScheme) => set({ rsaSignScheme }),
  setRsaSignHash: (rsaSignHash) => set({ rsaSignHash }),
  setRsaSaltLen: (rsaSaltLen) => set({ rsaSaltLen }),
  setRsaSignDataText: (rsaSignDataText) => set({ rsaSignDataText }),
  setRsaSignDataEnc: (rsaSignDataEnc) => set({ rsaSignDataEnc }),
  setRsaVerifyKeyPem: (rsaVerifyKeyPem) => set({ rsaVerifyKeyPem }),
  setRsaVerifySigText: (rsaVerifySigText) => set({ rsaVerifySigText }),
  rsaSign: async () => {
    if (get().rsaSignBusy) return;
    set({ rsaSignBusy: true, rsaSignError: null });
    try {
      const salt = get().rsaSaltLen.trim();
      const result = await api.pkiRsaSign({
        key_pem: get().rsaPrivatePem,
        scheme: get().rsaSignScheme,
        hash: get().rsaSignHash,
        salt_len: get().rsaSignScheme === "pss" && salt !== "" ? salt : null,
        data_text: get().rsaSignDataText,
        data_encoding: get().rsaSignDataEnc,
      });
      set({
        rsaSignature: result.signature,
        rsaVerifySigText: result.signature.hex,
      });
    } catch (e) {
      set({ rsaSignError: formatInvokeError(e) });
    } finally {
      set({ rsaSignBusy: false });
    }
  },
  rsaVerify: async () => {
    if (get().rsaVerifyBusy) return;
    set({ rsaVerifyBusy: true, rsaVerifyError: null });
    try {
      const salt = get().rsaSaltLen.trim();
      const verdict = await api.pkiRsaVerify({
        key_pem: get().rsaVerifyKeyPem,
        scheme: get().rsaSignScheme,
        hash: get().rsaSignHash,
        salt_len: get().rsaSignScheme === "pss" && salt !== "" ? salt : null,
        data_text: get().rsaSignDataText,
        data_encoding: get().rsaSignDataEnc,
        signature_text: get().rsaVerifySigText,
      });
      set({ rsaVerifyVerdict: verdict });
    } catch (e) {
      set({ rsaVerifyError: formatInvokeError(e) });
    } finally {
      set({ rsaVerifyBusy: false });
    }
  },

  // ---------------------------------------------------------------- ecc ----
  eccCurve: "p256",
  eccKeygen: null,
  eccKeygenBusy: false,
  eccKeygenError: null,
  setEccCurve: (eccCurve) => set({ eccCurve }),
  generateEccKey: async () => {
    if (get().eccKeygenBusy) return;
    set({ eccKeygenBusy: true, eccKeygenError: null });
    try {
      const result = await api.pkiEccKeygen(get().eccCurve);
      // Pre-fill the operation boxes for the generated curve.
      if (result.curve === "p256" || result.curve === "p384") {
        set({
          ecdsaPrivateHex: result.private_hex,
          ecdsaPublicHex: result.public_uncompressed_hex,
          ecdhPrivateHex: result.private_hex,
          ecdhPeerHex: result.public_uncompressed_hex,
        });
      } else if (result.curve === "ed25519") {
        set({
          edPrivateHex: result.private_hex,
          edPublicHex: result.public_compressed_hex,
        });
      } else if (result.curve === "x25519") {
        set({
          xPrivateHex: result.private_hex,
          xPeerHex: result.public_compressed_hex,
        });
      }
      set({ eccKeygen: result });
    } catch (e) {
      set({ eccKeygenError: formatInvokeError(e) });
    } finally {
      set({ eccKeygenBusy: false });
    }
  },

  ecdsaPrivateHex: "",
  ecdsaPublicHex: "",
  ecdsaDataText: "",
  ecdsaDataEnc: "utf8",
  ecdsaFormat: "der",
  ecdsaSigHex: "",
  ecdsaSignResult: null,
  ecdsaVerifyResult: null,
  ecdsaBusy: false,
  ecdsaError: null,
  setEcdsaPrivateHex: (ecdsaPrivateHex) => set({ ecdsaPrivateHex }),
  setEcdsaPublicHex: (ecdsaPublicHex) => set({ ecdsaPublicHex }),
  setEcdsaDataText: (ecdsaDataText) => set({ ecdsaDataText }),
  setEcdsaDataEnc: (ecdsaDataEnc) => set({ ecdsaDataEnc }),
  setEcdsaFormat: (ecdsaFormat) => set({ ecdsaFormat }),
  setEcdsaSigHex: (ecdsaSigHex) => set({ ecdsaSigHex }),
  runEcdsaSign: async () => {
    const { ecdsaBusy, eccCurve } = get();
    if (ecdsaBusy) return;
    set({ ecdsaBusy: true, ecdsaError: null, ecdsaVerifyResult: null });
    try {
      const result = await api.pkiEcdsaSign({
        curve: eccCurve,
        private_hex: get().ecdsaPrivateHex,
        digest: eccCurve === "p384" ? "sha384" : "sha256",
        format: get().ecdsaFormat,
        nonce: null,
        data_text: get().ecdsaDataText,
        data_encoding: get().ecdsaDataEnc,
      });
      set({ ecdsaSignResult: result.signature_hex, ecdsaSigHex: result.signature_hex });
    } catch (e) {
      set({ ecdsaError: formatInvokeError(e) });
    } finally {
      set({ ecdsaBusy: false });
    }
  },
  runEcdsaVerify: async () => {
    const { ecdsaBusy, eccCurve } = get();
    if (ecdsaBusy) return;
    set({ ecdsaBusy: true, ecdsaError: null });
    try {
      const verdict = await api.pkiEcdsaVerify({
        curve: eccCurve,
        public_hex: get().ecdsaPublicHex,
        digest: eccCurve === "p384" ? "sha384" : "sha256",
        format: get().ecdsaFormat,
        data_text: get().ecdsaDataText,
        data_encoding: get().ecdsaDataEnc,
        signature_hex: get().ecdsaSigHex,
      });
      set({ ecdsaVerifyResult: verdict });
    } catch (e) {
      set({ ecdsaError: formatInvokeError(e) });
    } finally {
      set({ ecdsaBusy: false });
    }
  },

  ecdhPrivateHex: "",
  ecdhPeerHex: "",
  ecdhSecret: null,
  ecdhBusy: false,
  ecdhError: null,
  setEcdhPrivateHex: (ecdhPrivateHex) => set({ ecdhPrivateHex }),
  setEcdhPeerHex: (ecdhPeerHex) => set({ ecdhPeerHex }),
  runEcdh: async () => {
    const { ecdhBusy, eccCurve } = get();
    if (ecdhBusy) return;
    set({ ecdhBusy: true, ecdhError: null });
    try {
      const result = await api.pkiEcdh({
        curve: eccCurve,
        private_hex: get().ecdhPrivateHex,
        peer_public_hex: get().ecdhPeerHex,
      });
      set({ ecdhSecret: result.shared_secret_hex });
    } catch (e) {
      set({ ecdhError: formatInvokeError(e) });
    } finally {
      set({ ecdhBusy: false });
    }
  },

  edPrivateHex: "",
  edPublicHex: "",
  edDataText: "",
  edDataEnc: "utf8",
  edSigHex: "",
  edSignResult: null,
  edVerifyResult: null,
  edBusy: false,
  edError: null,
  setEdPrivateHex: (edPrivateHex) => set({ edPrivateHex }),
  setEdPublicHex: (edPublicHex) => set({ edPublicHex }),
  setEdDataText: (edDataText) => set({ edDataText }),
  setEdDataEnc: (edDataEnc) => set({ edDataEnc }),
  setEdSigHex: (edSigHex) => set({ edSigHex }),
  runEdSign: async () => {
    if (get().edBusy) return;
    set({ edBusy: true, edError: null, edVerifyResult: null });
    try {
      const result = await api.pkiEd25519Sign({
        private_hex: get().edPrivateHex,
        data_text: get().edDataText,
        data_encoding: get().edDataEnc,
      });
      set({ edSignResult: result.signature_hex, edSigHex: result.signature_hex });
    } catch (e) {
      set({ edError: formatInvokeError(e) });
    } finally {
      set({ edBusy: false });
    }
  },
  runEdVerify: async () => {
    if (get().edBusy) return;
    set({ edBusy: true, edError: null });
    try {
      const verdict = await api.pkiEd25519Verify({
        public_hex: get().edPublicHex,
        data_text: get().edDataText,
        data_encoding: get().edDataEnc,
        signature_hex: get().edSigHex,
      });
      set({ edVerifyResult: verdict });
    } catch (e) {
      set({ edError: formatInvokeError(e) });
    } finally {
      set({ edBusy: false });
    }
  },

  xPrivateHex: "",
  xPeerHex: "",
  xSecret: null,
  xBusy: false,
  xError: null,
  setXPrivateHex: (xPrivateHex) => set({ xPrivateHex }),
  setXPeerHex: (xPeerHex) => set({ xPeerHex }),
  runX25519: async () => {
    if (get().xBusy) return;
    set({ xBusy: true, xError: null });
    try {
      const result = await api.pkiX25519({
        private_hex: get().xPrivateHex,
        peer_public_hex: get().xPeerHex,
      });
      set({ xSecret: result.shared_secret_hex });
    } catch (e) {
      set({ xError: formatInvokeError(e) });
    } finally {
      set({ xBusy: false });
    }
  },

  // ---------------------------------------------------------------- sm2 ----
  sm2Keygen: null,
  sm2KeygenBusy: false,
  sm2KeygenError: null,
  sm2UserId: SM2_DEFAULT_USER_ID,
  sm2PrivateHex: "",
  sm2PublicHex: "",
  sm2DataText: "",
  sm2DataEnc: "utf8",
  sm2SigHex: "",
  sm2SignResult: null,
  sm2VerifyResult: null,
  sm2SignBusy: false,
  sm2VerifyBusy: false,
  sm2SignError: null,
  sm2VerifyError: null,
  sm2EncPublicHex: "",
  sm2PlaintextText: "",
  sm2PlaintextEnc: "utf8",
  sm2Ciphertext: null,
  sm2DecPrivateHex: "",
  sm2DecCiphertext: "",
  sm2DecResult: null,
  sm2EncBusy: false,
  sm2EncError: null,
  setSm2UserId: (sm2UserId) => set({ sm2UserId }),
  setSm2PrivateHex: (sm2PrivateHex) => set({ sm2PrivateHex }),
  setSm2PublicHex: (sm2PublicHex) => set({ sm2PublicHex }),
  setSm2DataText: (sm2DataText) => set({ sm2DataText }),
  setSm2DataEnc: (sm2DataEnc) => set({ sm2DataEnc }),
  setSm2SigHex: (sm2SigHex) => set({ sm2SigHex }),
  setSm2EncPublicHex: (sm2EncPublicHex) => set({ sm2EncPublicHex }),
  setSm2PlaintextText: (sm2PlaintextText) => set({ sm2PlaintextText }),
  setSm2PlaintextEnc: (sm2PlaintextEnc) => set({ sm2PlaintextEnc }),
  setSm2DecPrivateHex: (sm2DecPrivateHex) => set({ sm2DecPrivateHex }),
  setSm2DecCiphertext: (sm2DecCiphertext) => set({ sm2DecCiphertext }),
  generateSm2Key: async () => {
    if (get().sm2KeygenBusy) return;
    set({ sm2KeygenBusy: true, sm2KeygenError: null });
    try {
      const result = await api.pkiSm2Keygen();
      set({
        sm2Keygen: result,
        sm2PrivateHex: result.private_hex,
        sm2PublicHex: result.public_uncompressed_hex,
        sm2EncPublicHex: result.public_uncompressed_hex,
        sm2DecPrivateHex: result.private_hex,
      });
    } catch (e) {
      set({ sm2KeygenError: formatInvokeError(e) });
    } finally {
      set({ sm2KeygenBusy: false });
    }
  },
  runSm2Sign: async () => {
    if (get().sm2SignBusy) return;
    set({ sm2SignBusy: true, sm2SignError: null, sm2VerifyResult: null });
    try {
      const userId = get().sm2UserId.trim();
      const result = await api.pkiSm2Sign({
        private_hex: get().sm2PrivateHex,
        data_text: get().sm2DataText,
        data_encoding: get().sm2DataEnc,
        user_id: userId !== "" ? userId : null,
      });
      set({ sm2SignResult: result, sm2SigHex: result.signature_hex });
    } catch (e) {
      set({ sm2SignError: formatInvokeError(e) });
    } finally {
      set({ sm2SignBusy: false });
    }
  },
  runSm2Verify: async () => {
    if (get().sm2VerifyBusy) return;
    set({ sm2VerifyBusy: true, sm2VerifyError: null });
    try {
      const userId = get().sm2UserId.trim();
      const verdict = await api.pkiSm2Verify({
        public_hex: get().sm2PublicHex,
        data_text: get().sm2DataText,
        data_encoding: get().sm2DataEnc,
        signature_hex: get().sm2SigHex,
        user_id: userId !== "" ? userId : null,
      });
      set({ sm2VerifyResult: verdict });
    } catch (e) {
      set({ sm2VerifyError: formatInvokeError(e) });
    } finally {
      set({ sm2VerifyBusy: false });
    }
  },
  runSm2Encrypt: async () => {
    if (get().sm2EncBusy) return;
    set({ sm2EncBusy: true, sm2EncError: null });
    try {
      const result = await api.pkiSm2Encrypt({
        public_hex: get().sm2EncPublicHex,
        plaintext_text: get().sm2PlaintextText,
        plaintext_encoding: get().sm2PlaintextEnc,
      });
      set({
        sm2Ciphertext: result.ciphertext,
        sm2DecCiphertext: result.ciphertext.hex,
      });
    } catch (e) {
      set({ sm2EncError: formatInvokeError(e) });
    } finally {
      set({ sm2EncBusy: false });
    }
  },
  runSm2Decrypt: async () => {
    if (get().sm2EncBusy) return;
    set({ sm2EncBusy: true, sm2EncError: null });
    try {
      const result = await api.pkiSm2Decrypt({
        private_hex: get().sm2DecPrivateHex,
        ciphertext_text: get().sm2DecCiphertext,
        ciphertext_encoding: "hex",
      });
      set({ sm2DecResult: result.plaintext });
    } catch (e) {
      set({ sm2EncError: formatInvokeError(e) });
    } finally {
      set({ sm2EncBusy: false });
    }
  },

  // --------------------------------------------------------- certificate ----
  certMaterial: "",
  certReport: null,
  certBusy: false,
  certError: null,
  setCertMaterial: (certMaterial) => set({ certMaterial }),
  inspectCert: async () => {
    if (get().certBusy) return;
    set({ certBusy: true, certError: null });
    try {
      const report = await api.pkiCertInspect(get().certMaterial);
      set({ certReport: report });
    } catch (e) {
      set({ certError: formatInvokeError(e) });
    } finally {
      set({ certBusy: false });
    }
  },
}));
