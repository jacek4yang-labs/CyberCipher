import { useState, type ReactNode } from "react";
import {
  ECC_CURVES,
  RSA_HASHES,
  RSA_KEYGEN_BITS,
  SM2_DEFAULT_USER_ID,
  usePkiStore,
  type DataEncoding,
  type PkiTab,
} from "../pkiStore";
import type {
  Asn1Node,
  Asn1Value,
  CertificateInspection,
  CrlInspection,
  CsrInspection,
  PkiBytes,
  PkiField,
  PkiKeyReport,
  RdnEntry,
} from "../api";

// ---------------------------------------------------------------------------
// Shared pieces (reusing the RSA Lab's value-row / error-banner vocabulary)
// ---------------------------------------------------------------------------

function CopyButton({ text, label = "copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className={`tool-btn rsa-copy${copied ? " copied" : ""}`}
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
      title={`Copy ${label}`}
    >
      {copied ? "copied ✓" : "copy"}
    </button>
  );
}

function CopyRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rsa-value-row">
      <span className="rsa-value-label">{label}</span>
      <pre className="rsa-value">{value}</pre>
      <CopyButton text={value} />
    </div>
  );
}

function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="rsa-error-banner">✗ {error}</div>;
}

function VerdictBanner({ valid, reason }: { valid: boolean; reason?: string }) {
  return (
    <div className={`pki-verdict ${valid ? "ok" : "bad"}`}>
      {valid ? "✓ signature valid" : `✗ signature invalid${reason ? ` — ${reason}` : ""}`}
    </div>
  );
}

function BytesResult({ label, bytes }: { label: string; bytes: PkiBytes }) {
  return (
    <div className="pki-result-block">
      <CopyRow label={`${label} (hex)`} value={bytes.hex} />
      {bytes.utf8 !== undefined && <CopyRow label={`${label} (utf-8)`} value={bytes.utf8} />}
      <div className="dim pki-size-note">{bytes.size} bytes</div>
    </div>
  );
}

/** A labeled text input / textarea row. */
function InputField({
  label,
  hint,
  value,
  onChange,
  rows,
  placeholder,
}: {
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  placeholder?: string;
}) {
  return (
    <div className="pki-field">
      <label>
        {label}
        {hint && <span className="pki-hint"> {hint}</span>}
      </label>
      {rows ? (
        <textarea
          rows={rows}
          spellCheck={false}
          autoComplete="off"
          value={value}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          type="text"
          spellCheck={false}
          autoComplete="off"
          value={value}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </div>
  );
}

/** Message input with the text-or-hex toggle the engine's byte inputs take. */
function DataInput({
  label,
  text,
  encoding,
  onText,
  onEncoding,
  rows = 2,
}: {
  label: string;
  text: string;
  encoding: DataEncoding;
  onText: (v: string) => void;
  onEncoding: (v: DataEncoding) => void;
  rows?: number;
}) {
  return (
    <div className="pki-field">
      <label>
        {label}
        <span className="pki-hint"> bytes as</span>
      </label>
      <div className="pki-data-row">
        {rows > 1 ? (
          <textarea
            rows={rows}
            spellCheck={false}
            autoComplete="off"
            value={text}
            onChange={(e) => onText(e.target.value)}
          />
        ) : (
          <input
            type="text"
            spellCheck={false}
            autoComplete="off"
            value={text}
            onChange={(e) => onText(e.target.value)}
          />
        )}
        <select value={encoding} onChange={(e) => onEncoding(e.target.value as DataEncoding)}>
          <option value="utf8">utf-8</option>
          <option value="hex">hex</option>
        </select>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="pki-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function FieldRows({ fields }: { fields: PkiField[] }) {
  return (
    <>
      {fields.map((f) => (
        <CopyRow key={f.label} label={f.label} value={f.value} />
      ))}
    </>
  );
}

// --------------------------------------------------------- key report ----

function KeyReportView({ report }: { report: PkiKeyReport }) {
  return (
    <div className="pki-report">
      <div className="pki-report-head">
        <span className="pki-kind-chip">{report.kind}</span>
        {report.curve && <span className="pki-kind-chip">{report.curve}</span>}
        <span className={`pki-kind-chip ${report.is_private ? "priv" : "pub"}`}>
          {report.is_private ? "private" : "public"}
        </span>
        {report.bit_length !== undefined && (
          <span className="pki-kind-chip">{report.bit_length} bits</span>
        )}
        <span className="dim pki-src">{report.source_format}</span>
      </div>
      <div className="pki-summary">{report.summary}</div>

      <FieldRows fields={report.public_fields} />
      {report.private_fields.length > 0 && (
        <>
          <div className="pki-subhead dim">private material</div>
          <FieldRows fields={report.private_fields} />
        </>
      )}
      {report.encodings.length > 0 && (
        <>
          <div className="pki-subhead dim">encodings</div>
          <FieldRows fields={report.encodings} />
        </>
      )}
      {report.alternatives.length > 0 && (
        <div className="dim pki-alternatives">
          also a plausible: {report.alternatives.join(", ")}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Keys tab
// ---------------------------------------------------------------------------

function KeysTab() {
  const material = usePkiStore((s) => s.keysMaterial);
  const hint = usePkiStore((s) => s.keysHint);
  const report = usePkiStore((s) => s.keysReport);
  const busy = usePkiStore((s) => s.keysBusy);
  const error = usePkiStore((s) => s.keysError);
  const setMaterial = usePkiStore((s) => s.setKeysMaterial);
  const setHint = usePkiStore((s) => s.setKeysHint);
  const inspect = usePkiStore((s) => s.inspectMaterial);

  return (
    <>
      <Section title="Inspect key material">
        <InputField
          label="hint"
          hint="(optional) restrict raw-hex interpretation: rsa, sm2, p256, …"
          value={hint}
          onChange={setHint}
          placeholder="e.g. p256"
        />
        <InputField
          label="key material"
          hint="PEM, DER hex, JWK, or hex SEC1/scalar"
          value={material}
          onChange={setMaterial}
          rows={8}
          placeholder={"-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----"}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void inspect()} disabled={busy}>
            {busy ? "Inspecting…" : "Inspect"}
          </button>
        </div>
        <ErrorBanner error={error} />
      </Section>
      {report && (
        <Section title="Report">
          <KeyReportView report={report} />
        </Section>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// RSA tab
// ---------------------------------------------------------------------------

function RsaTab() {
  const s = usePkiStore();
  return (
    <>
      <Section title="Keygen">
        <div className="pki-run-row">
          <label className="pki-select-label">
            bits
            <select value={s.rsaBits} onChange={(e) => s.setRsaBits(Number(e.target.value))}>
              {RSA_KEYGEN_BITS.map((bits) => (
                <option key={bits} value={bits}>
                  {bits}
                  {bits === 1024 ? " (legacy)" : ""}
                </option>
              ))}
            </select>
          </label>
          <button className="bake-btn" onClick={() => void s.generateRsaKey()} disabled={s.rsaKeygenBusy}>
            {s.rsaKeygenBusy ? "Generating…" : "Generate keypair"}
          </button>
        </div>
        <ErrorBanner error={s.rsaKeygenError} />
        {s.rsaKeygen && (
          <div className="pki-result-block">
            <CopyRow label="private (PKCS#8)" value={s.rsaKeygen.private_pem} />
            <CopyRow label="public (SPKI)" value={s.rsaKeygen.public_pem} />
            <CopyRow label="private (PKCS#1)" value={s.rsaKeygen.private_pkcs1_pem} />
            <CopyRow label="public (PKCS#1)" value={s.rsaKeygen.public_pkcs1_pem} />
          </div>
        )}
      </Section>

      <Section title="Encrypt / Decrypt (OAEP | PKCS#1 v1.5)">
        <div className="pki-run-row">
          <label className="pki-select-label">
            scheme
            <select
              value={s.rsaEncScheme}
              onChange={(e) => s.setRsaEncScheme(e.target.value as "oaep" | "pkcs1v15")}
            >
              <option value="oaep">OAEP</option>
              <option value="pkcs1v15">PKCS#1 v1.5</option>
            </select>
          </label>
          {s.rsaEncScheme === "oaep" && (
            <>
              <label className="pki-select-label">
                hash
                <select value={s.rsaHash} onChange={(e) => s.setRsaHash(e.target.value)}>
                  {RSA_HASHES.map((h) => (
                    <option key={h} value={h}>
                      {h}
                      {h === "sha1" ? " (legacy)" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <InputField
                label="label"
                hint="(optional, UTF-8)"
                value={s.rsaLabel}
                onChange={s.setRsaLabel}
              />
            </>
          )}
        </div>
        <InputField
          label="public key PEM"
          hint="encrypts; a private key PEM also works (its public half is used)"
          value={s.rsaPublicPem}
          onChange={s.setRsaPublicPem}
          rows={4}
        />
        <DataInput
          label="plaintext"
          text={s.rsaPlaintextText}
          encoding={s.rsaPlaintextEnc}
          onText={s.setRsaPlaintextText}
          onEncoding={s.setRsaPlaintextEnc}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.rsaEncrypt()} disabled={s.rsaEncBusy}>
            {s.rsaEncBusy ? "Encrypting…" : "Encrypt"}
          </button>
        </div>
        <ErrorBanner error={s.rsaEncError} />
        {s.rsaCiphertext && <BytesResult label="ciphertext" bytes={s.rsaCiphertext} />}

        <div className="pki-subhead dim">decrypt</div>
        <InputField
          label="private key PEM"
          value={s.rsaPrivatePem}
          onChange={s.setRsaPrivatePem}
          rows={4}
        />
        <InputField
          label="ciphertext (hex)"
          value={s.rsaDecryptCiphertext}
          onChange={s.setRsaDecryptCiphertext}
          rows={3}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.rsaDecrypt()} disabled={s.rsaEncBusy}>
            {s.rsaEncBusy ? "Decrypting…" : "Decrypt"}
          </button>
        </div>
        {s.rsaDecryptResult && <BytesResult label="plaintext" bytes={s.rsaDecryptResult} />}
      </Section>

      <Section title="Sign / Verify (PKCS#1 v1.5 | PSS)">
        <div className="pki-run-row">
          <label className="pki-select-label">
            scheme
            <select
              value={s.rsaSignScheme}
              onChange={(e) => s.setRsaSignScheme(e.target.value as "pkcs1v15" | "pss")}
            >
              <option value="pkcs1v15">PKCS#1 v1.5</option>
              <option value="pss">PSS</option>
            </select>
          </label>
          <label className="pki-select-label">
            hash
            <select value={s.rsaSignHash} onChange={(e) => s.setRsaSignHash(e.target.value)}>
              {RSA_HASHES.map((h) => (
                <option key={h} value={h}>
                  {h}
                  {h === "sha1" ? " (legacy)" : ""}
                </option>
              ))}
            </select>
          </label>
          {s.rsaSignScheme === "pss" && (
            <InputField
              label="salt"
              hint="digest | zero | bytes"
              value={s.rsaSaltLen}
              onChange={s.setRsaSaltLen}
            />
          )}
        </div>
        <InputField
          label="private key PEM"
          hint="signs"
          value={s.rsaPrivatePem}
          onChange={s.setRsaPrivatePem}
          rows={4}
        />
        <DataInput
          label="data"
          text={s.rsaSignDataText}
          encoding={s.rsaSignDataEnc}
          onText={s.setRsaSignDataText}
          onEncoding={s.setRsaSignDataEnc}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.rsaSign()} disabled={s.rsaSignBusy}>
            {s.rsaSignBusy ? "Signing…" : "Sign"}
          </button>
        </div>
        <ErrorBanner error={s.rsaSignError} />
        {s.rsaSignature && <BytesResult label="signature" bytes={s.rsaSignature} />}

        <div className="pki-subhead dim">verify</div>
        <InputField
          label="key PEM"
          hint="public (a private key PEM also works)"
          value={s.rsaVerifyKeyPem}
          onChange={s.setRsaVerifyKeyPem}
          rows={4}
        />
        <InputField
          label="signature"
          hint="hex or base64"
          value={s.rsaVerifySigText}
          onChange={s.setRsaVerifySigText}
          rows={3}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.rsaVerify()} disabled={s.rsaVerifyBusy}>
            {s.rsaVerifyBusy ? "Verifying…" : "Verify"}
          </button>
        </div>
        <ErrorBanner error={s.rsaVerifyError} />
        {s.rsaVerifyVerdict && (
          <VerdictBanner valid={s.rsaVerifyVerdict.valid} reason={s.rsaVerifyVerdict.reason} />
        )}
      </Section>
    </>
  );
}

// ---------------------------------------------------------------------------
// ECC tab
// ---------------------------------------------------------------------------

function EccTab() {
  const s = usePkiStore();
  const isNist = s.eccCurve === "p256" || s.eccCurve === "p384";
  const requiredDigest = s.eccCurve === "p384" ? "SHA-384" : "SHA-256";

  return (
    <>
      <Section title="Keygen">
        <div className="pki-run-row">
          <label className="pki-select-label">
            curve
            <select value={s.eccCurve} onChange={(e) => s.setEccCurve(e.target.value)}>
              {ECC_CURVES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </label>
          <button className="bake-btn" onClick={() => void s.generateEccKey()} disabled={s.eccKeygenBusy}>
            {s.eccKeygenBusy ? "Generating…" : "Generate keypair"}
          </button>
        </div>
        <ErrorBanner error={s.eccKeygenError} />
        {s.eccKeygen && (
          <div className="pki-result-block">
            <CopyRow label="private (hex)" value={s.eccKeygen.private_hex} />
            {isNist ? (
              <>
                <CopyRow label="public (SEC1 compressed)" value={s.eccKeygen.public_compressed_hex} />
                <CopyRow
                  label="public (SEC1 uncompressed)"
                  value={s.eccKeygen.public_uncompressed_hex}
                />
              </>
            ) : (
              <CopyRow label="public (raw)" value={s.eccKeygen.public_compressed_hex} />
            )}
            <CopyRow label="private (PKCS#8 PEM)" value={s.eccKeygen.private_pkcs8_pem} />
            <CopyRow label="public (SPKI PEM)" value={s.eccKeygen.public_spki_pem} />
          </div>
        )}
      </Section>

      {isNist && (
        <>
          <Section title={`ECDSA sign / verify (P-256/P-384, ${requiredDigest} pairing)`}>
            <InputField
              label="private key (hex)"
              value={s.ecdsaPrivateHex}
              onChange={s.setEcdsaPrivateHex}
            />
            <DataInput
              label="data"
              text={s.ecdsaDataText}
              encoding={s.ecdsaDataEnc}
              onText={s.setEcdsaDataText}
              onEncoding={s.setEcdsaDataEnc}
            />
            <div className="pki-run-row">
              <label className="pki-select-label">
                signature format
                <select
                  value={s.ecdsaFormat}
                  onChange={(e) => s.setEcdsaFormat(e.target.value as "der" | "fixed")}
                >
                  <option value="der">DER</option>
                  <option value="fixed">fixed r||s</option>
                </select>
              </label>
              <button className="bake-btn" onClick={() => void s.runEcdsaSign()} disabled={s.ecdsaBusy}>
                {s.ecdsaBusy ? "Signing…" : "Sign"}
              </button>
            </div>
            <ErrorBanner error={s.ecdsaError} />
            {s.ecdsaSignResult && <CopyRow label="signature (hex)" value={s.ecdsaSignResult} />}

            <div className="pki-subhead dim">verify</div>
            <InputField
              label="public key (hex SEC1)"
              value={s.ecdsaPublicHex}
              onChange={s.setEcdsaPublicHex}
            />
            <InputField
              label="signature (hex)"
              value={s.ecdsaSigHex}
              onChange={s.setEcdsaSigHex}
              rows={3}
            />
            <div className="pki-run-row">
              <button className="bake-btn" onClick={() => void s.runEcdsaVerify()} disabled={s.ecdsaBusy}>
                {s.ecdsaBusy ? "Verifying…" : "Verify"}
              </button>
            </div>
            {s.ecdsaVerifyResult && (
              <VerdictBanner
                valid={s.ecdsaVerifyResult.valid}
                reason={s.ecdsaVerifyResult.reason}
              />
            )}
          </Section>

          <Section title="ECDH shared secret">
            <InputField
              label="private key (hex)"
              value={s.ecdhPrivateHex}
              onChange={s.setEcdhPrivateHex}
            />
            <InputField
              label="peer public key (hex SEC1)"
              value={s.ecdhPeerHex}
              onChange={s.setEcdhPeerHex}
            />
            <div className="pki-run-row">
              <button className="bake-btn" onClick={() => void s.runEcdh()} disabled={s.ecdhBusy}>
                {s.ecdhBusy ? "Deriving…" : "Derive shared secret"}
              </button>
            </div>
            <ErrorBanner error={s.ecdhError} />
            {s.ecdhSecret && <CopyRow label="shared secret (hex)" value={s.ecdhSecret} />}
          </Section>
        </>
      )}

      {s.eccCurve === "ed25519" && (
        <Section title="Ed25519 sign / verify">
          <InputField
            label="private key (hex seed)"
            value={s.edPrivateHex}
            onChange={s.setEdPrivateHex}
          />
          <DataInput
            label="data"
            text={s.edDataText}
            encoding={s.edDataEnc}
            onText={s.setEdDataText}
            onEncoding={s.setEdDataEnc}
          />
          <div className="pki-run-row">
            <button className="bake-btn" onClick={() => void s.runEdSign()} disabled={s.edBusy}>
              {s.edBusy ? "Signing…" : "Sign"}
            </button>
          </div>
          <ErrorBanner error={s.edError} />
          {s.edSignResult && <CopyRow label="signature (hex)" value={s.edSignResult} />}

          <div className="pki-subhead dim">verify</div>
          <InputField label="public key (hex)" value={s.edPublicHex} onChange={s.setEdPublicHex} />
          <InputField
            label="signature (hex)"
            value={s.edSigHex}
            onChange={s.setEdSigHex}
            rows={3}
          />
          <div className="pki-run-row">
            <button className="bake-btn" onClick={() => void s.runEdVerify()} disabled={s.edBusy}>
              {s.edBusy ? "Verifying…" : "Verify"}
            </button>
          </div>
          {s.edVerifyResult && (
            <VerdictBanner valid={s.edVerifyResult.valid} reason={s.edVerifyResult.reason} />
          )}
        </Section>
      )}

      {s.eccCurve === "x25519" && (
        <Section title="X25519 shared secret">
          <InputField
            label="private key (hex)"
            value={s.xPrivateHex}
            onChange={s.setXPrivateHex}
          />
          <InputField
            label="peer public key (hex)"
            value={s.xPeerHex}
            onChange={s.setXPeerHex}
          />
          <div className="pki-run-row">
            <button className="bake-btn" onClick={() => void s.runX25519()} disabled={s.xBusy}>
              {s.xBusy ? "Deriving…" : "Derive shared secret"}
            </button>
          </div>
          <ErrorBanner error={s.xError} />
          {s.xSecret && <CopyRow label="shared secret (hex)" value={s.xSecret} />}
        </Section>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// SM2 tab
// ---------------------------------------------------------------------------

function Sm2Tab() {
  const s = usePkiStore();
  return (
    <>
      <Section title="Keygen (sm2p256v1)">
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.generateSm2Key()} disabled={s.sm2KeygenBusy}>
            {s.sm2KeygenBusy ? "Generating…" : "Generate keypair"}
          </button>
          <span className="dim">raw hex keys only — PKCS#8/SPKI containers for SM2 are not supported yet</span>
        </div>
        <ErrorBanner error={s.sm2KeygenError} />
        {s.sm2Keygen && (
          <div className="pki-result-block">
            <CopyRow label="private (hex)" value={s.sm2Keygen.private_hex} />
            <CopyRow label="public (SEC1 compressed)" value={s.sm2Keygen.public_compressed_hex} />
            <CopyRow label="public (SEC1 uncompressed)" value={s.sm2Keygen.public_uncompressed_hex} />
          </div>
        )}
      </Section>

      <Section title="Sign / verify (SM3 ZA context via user ID)">
        <InputField
          label="user ID"
          hint={`(default ${SM2_DEFAULT_USER_ID})`}
          value={s.sm2UserId}
          onChange={s.setSm2UserId}
        />
        <InputField
          label="private key (hex)"
          value={s.sm2PrivateHex}
          onChange={s.setSm2PrivateHex}
        />
        <DataInput
          label="data"
          text={s.sm2DataText}
          encoding={s.sm2DataEnc}
          onText={s.setSm2DataText}
          onEncoding={s.setSm2DataEnc}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.runSm2Sign()} disabled={s.sm2SignBusy}>
            {s.sm2SignBusy ? "Signing…" : "Sign"}
          </button>
        </div>
        <ErrorBanner error={s.sm2SignError} />
        {s.sm2SignResult && (
          <>
            <CopyRow label="signature (hex r||s)" value={s.sm2SignResult.signature_hex} />
            <div className="dim pki-size-note">signed as user ID “{s.sm2SignResult.user_id}”</div>
          </>
        )}

        <div className="pki-subhead dim">verify</div>
        <InputField
          label="public key (hex SEC1)"
          value={s.sm2PublicHex}
          onChange={s.setSm2PublicHex}
        />
        <InputField
          label="signature (hex r||s)"
          value={s.sm2SigHex}
          onChange={s.setSm2SigHex}
          rows={3}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.runSm2Verify()} disabled={s.sm2VerifyBusy}>
            {s.sm2VerifyBusy ? "Verifying…" : "Verify"}
          </button>
        </div>
        <ErrorBanner error={s.sm2VerifyError} />
        {s.sm2VerifyResult && (
          <>
            <VerdictBanner valid={s.sm2VerifyResult.valid} reason={s.sm2VerifyResult.reason} />
            <div className="dim pki-size-note">verified as user ID “{s.sm2VerifyResult.user_id}”</div>
          </>
        )}
      </Section>

      <Section title="Encrypt / decrypt (C1||C3||C2 transport)">
        <InputField
          label="public key (hex SEC1)"
          value={s.sm2EncPublicHex}
          onChange={s.setSm2EncPublicHex}
        />
        <DataInput
          label="plaintext"
          text={s.sm2PlaintextText}
          encoding={s.sm2PlaintextEnc}
          onText={s.setSm2PlaintextText}
          onEncoding={s.setSm2PlaintextEnc}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.runSm2Encrypt()} disabled={s.sm2EncBusy}>
            {s.sm2EncBusy ? "Encrypting…" : "Encrypt"}
          </button>
        </div>
        <ErrorBanner error={s.sm2EncError} />
        {s.sm2Ciphertext && <BytesResult label="ciphertext" bytes={s.sm2Ciphertext} />}

        <div className="pki-subhead dim">decrypt</div>
        <InputField
          label="private key (hex)"
          value={s.sm2DecPrivateHex}
          onChange={s.setSm2DecPrivateHex}
        />
        <InputField
          label="ciphertext (hex)"
          value={s.sm2DecCiphertext}
          onChange={s.setSm2DecCiphertext}
          rows={3}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void s.runSm2Decrypt()} disabled={s.sm2EncBusy}>
            {s.sm2EncBusy ? "Decrypting…" : "Decrypt"}
          </button>
        </div>
        {s.sm2DecResult && <BytesResult label="plaintext" bytes={s.sm2DecResult} />}
      </Section>
    </>
  );
}

// ---------------------------------------------------------------------------
// Certificate tab
// ---------------------------------------------------------------------------

function RdnList({ entries }: { entries: RdnEntry[] }) {
  if (entries.length === 0) return <div className="dim">(empty)</div>;
  return (
    <div className="pki-rdn-list">
      {entries.map((e, i) => (
        <div key={`${e.oid}-${i}`} className="pki-rdn-row">
          <span className="pki-rdn-name">{e.name ?? e.oid}</span>
          <span className="pki-rdn-oid dim">{e.oid}</span>
          <span className="pki-rdn-value">{e.value}</span>
        </div>
      ))}
    </div>
  );
}

function CertificateView({ cert }: { cert: CertificateInspection }) {
  return (
    <div className="pki-report">
      <CopyRow label="summary" value={cert.summary} />
      <div className="pki-facts">
        <span className="pki-kind-chip">{cert.version_label}</span>
        <span className="pki-kind-chip">serial 0x{cert.serial_hex}</span>
        <span className="pki-kind-chip">{cert.signature_algorithm}</span>
      </div>
      <div className="pki-subhead dim">subject</div>
      <RdnList entries={cert.subject} />
      <div className="pki-subhead dim">issuer</div>
      <RdnList entries={cert.issuer} />
      <div className="pki-subhead dim">validity</div>
      <div className="pki-facts">
        <span className="pki-kind-chip">notBefore {cert.not_before}</span>
        <span className="pki-kind-chip">notAfter {cert.not_after}</span>
      </div>
      <div className="pki-subhead dim">public key</div>
      <div className="pki-facts">
        <span className="pki-kind-chip">{cert.public_key.algorithm}</span>
        {cert.public_key.bit_length !== undefined && (
          <span className="pki-kind-chip">{cert.public_key.bit_length} bits</span>
        )}
      </div>
      {cert.public_key.public_key_hex && (
        <CopyRow label="spki bits (hex)" value={cert.public_key.public_key_hex} />
      )}
      <div className="pki-subhead dim">fingerprints</div>
      <CopyRow label="sha-256" value={cert.fingerprint_sha256} />
      <CopyRow label="sha-1" value={cert.fingerprint_sha1} />
      {(cert.basic_constraints ||
        cert.subject_alt_names.length > 0 ||
        cert.key_usage.length > 0 ||
        cert.extended_key_usage.length > 0 ||
        cert.subject_key_identifier ||
        cert.authority_key_identifier) && <div className="pki-subhead dim">extensions</div>}
      {cert.basic_constraints && (
        <div className="pki-facts">
          <span className="pki-kind-chip">
            basicConstraints: CA={String(cert.basic_constraints.ca)}
            {cert.basic_constraints.path_len !== undefined &&
              `, pathlen=${cert.basic_constraints.path_len}`}
          </span>
        </div>
      )}
      {cert.subject_alt_names.length > 0 && (
        <div className="pki-facts">
          <span className="dim">SAN:</span> {cert.subject_alt_names.join(", ")}
        </div>
      )}
      {cert.key_usage.length > 0 && (
        <div className="pki-facts">
          <span className="dim">keyUsage:</span> {cert.key_usage.join(", ")}
        </div>
      )}
      {cert.extended_key_usage.length > 0 && (
        <div className="pki-facts">
          <span className="dim">extKeyUsage:</span> {cert.extended_key_usage.join(", ")}
        </div>
      )}
      {cert.subject_key_identifier && (
        <CopyRow label="SKI" value={cert.subject_key_identifier} />
      )}
      {cert.authority_key_identifier && (
        <CopyRow label="AKI" value={cert.authority_key_identifier} />
      )}
      {cert.extensions.length > 0 && (
        <>
          <div className="pki-subhead dim">all extensions ({cert.extensions.length})</div>
          <div className="pki-rdn-list">
            {cert.extensions.map((ext, i) => (
              <div key={`${ext.oid}-${i}`} className="pki-rdn-row">
                <span className="pki-rdn-name">{ext.name ?? ext.oid}</span>
                <span className="pki-rdn-oid dim">{ext.oid}</span>
                <span className="pki-rdn-value">
                  {ext.critical ? "critical" : "non-critical"}
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function CsrView({ csr }: { csr: CsrInspection }) {
  return (
    <div className="pki-report">
      <CopyRow label="summary" value={csr.summary} />
      <div className="pki-facts">
        <span className="pki-kind-chip">PKCS#10 v{csr.version + 1}</span>
        <span className="pki-kind-chip">{csr.signature_algorithm}</span>
      </div>
      <div className="pki-subhead dim">subject</div>
      <RdnList entries={csr.subject} />
      <div className="pki-subhead dim">public key</div>
      <div className="pki-facts">
        <span className="pki-kind-chip">{csr.public_key.algorithm}</span>
        {csr.public_key.bit_length !== undefined && (
          <span className="pki-kind-chip">{csr.public_key.bit_length} bits</span>
        )}
      </div>
      <div className="pki-subhead dim">self-signature</div>
      <div className={`pki-verdict ${csr.signature_verified === true ? "ok" : csr.signature_verified === false ? "bad" : ""}`}>
        {csr.verification_note}
      </div>
      {csr.attributes.length > 0 && (
        <>
          <div className="pki-subhead dim">attributes</div>
          <div className="pki-rdn-list">
            {csr.attributes.map((a, i) => (
              <div key={`${a.oid}-${i}`} className="pki-rdn-row">
                <span className="pki-rdn-name">{a.name ?? a.oid}</span>
                <span className="pki-rdn-oid dim">{a.oid}</span>
                <span className="pki-rdn-value">{a.value_count} value(s)</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function CrlView({ crl }: { crl: CrlInspection }) {
  return (
    <div className="pki-report">
      <CopyRow label="summary" value={crl.summary} />
      <div className="pki-facts">
        <span className="pki-kind-chip">{crl.signature_algorithm}</span>
        <span className="pki-kind-chip">thisUpdate {crl.this_update}</span>
        {crl.next_update && <span className="pki-kind-chip">nextUpdate {crl.next_update}</span>}
        {crl.crl_number_hex && (
          <span className="pki-kind-chip">cRLNumber 0x{crl.crl_number_hex}</span>
        )}
      </div>
      <div className="pki-subhead dim">issuer</div>
      <RdnList entries={crl.issuer} />
      <div className="pki-subhead dim">revoked serials ({crl.revoked_count})</div>
      {crl.revoked.length === 0 ? (
        <div className="dim">(none)</div>
      ) : (
        <div className="pki-rdn-list">
          {crl.revoked.map((r) => (
            <div key={r.serial_hex} className="pki-rdn-row">
              <span className="pki-rdn-name">serial 0x{r.serial_hex}</span>
              <span className="pki-rdn-value">revoked {r.revocation_date}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function asn1ValueText(value: Asn1Value | undefined): string | null {
  if (!value) return null;
  switch (value.type) {
    case "integer":
      return `${value.value} (0x${value.hex})`;
    case "boolean":
      return String(value.value);
    case "null":
      return "NULL";
    case "object_identifier":
      return value.name ? `${value.dotted} (${value.name})` : value.dotted;
    case "bit_string":
      return `bits: ${value.hex}${value.unused_bits > 0 ? ` (${value.unused_bits} unused)` : ""}`;
    case "octet_string":
    case "raw":
      return value.hex;
    default:
      return value.text;
  }
}

function Asn1NodeView({ node, depth }: { node: Asn1Node; depth: number }) {
  const [open, setOpen] = useState(depth < 2);
  const label = node.tag_name ?? `${node.tag_class} #${node.tag_number}`;
  const valueText = asn1ValueText(node.value);
  const header = `${label} [off 0x${node.offset.toString(16)}, len ${node.value_len}]`;
  return (
    <div className={`pki-asn1-node${depth > 0 ? " nested" : ""}`}>
      {node.children.length > 0 ? (
        <button className="pki-asn1-row" onClick={() => setOpen(!open)} title={open ? "Collapse" : "Expand"}>
          <span className="pki-twist">{open ? "▾" : "▸"}</span>
          <span className="pki-asn1-tag">{header}</span>
          {valueText && <span className="pki-asn1-value">{valueText}</span>}
        </button>
      ) : (
        <div className="pki-asn1-row">
          <span className="pki-twist" />
          <span className="pki-asn1-tag">{header}</span>
          {valueText && <span className="pki-asn1-value">{valueText}</span>}
        </div>
      )}
      {!valueText && node.hex_preview && (
        <div className="pki-asn1-preview dim">{node.hex_preview}</div>
      )}
      {open &&
        node.children.map((child, i) => <Asn1NodeView key={i} node={child} depth={depth + 1} />)}
    </div>
  );
}

function CertTab() {
  const material = usePkiStore((s) => s.certMaterial);
  const report = usePkiStore((s) => s.certReport);
  const busy = usePkiStore((s) => s.certBusy);
  const error = usePkiStore((s) => s.certError);
  const setMaterial = usePkiStore((s) => s.setCertMaterial);
  const inspect = usePkiStore((s) => s.inspectCert);
  const [treeOpen, setTreeOpen] = useState(true);

  return (
    <>
      <Section title="Paste certificate / CSR / CRL">
        <InputField
          label="material"
          hint="PEM, DER hex, or base64 DER"
          value={material}
          onChange={setMaterial}
          rows={8}
          placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}
        />
        <div className="pki-run-row">
          <button className="bake-btn" onClick={() => void inspect()} disabled={busy}>
            {busy ? "Inspecting…" : "Inspect"}
          </button>
        </div>
        <ErrorBanner error={error} />
      </Section>
      {report && (
        <>
          <Section title={`Report — ${report.object_type}${report.pem_label ? ` (${report.pem_label})` : ""}`}>
            {report.certificate && <CertificateView cert={report.certificate} />}
            {report.csr && <CsrView csr={report.csr} />}
            {report.crl && <CrlView crl={report.crl} />}
          </Section>
          <Section title="ASN.1 tree">
            <button className="pki-advanced-toggle" onClick={() => setTreeOpen(!treeOpen)}>
              <span className="pki-twist">{treeOpen ? "▾" : "▸"}</span> DER structure (
              {report.der_hex.length / 2} bytes)
            </button>
            {treeOpen && report.asn1_tree.map((node, i) => <Asn1NodeView key={i} node={node} depth={0} />)}
          </Section>
        </>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const TABS: [PkiTab, string][] = [
  ["keys", "Keys"],
  ["rsa", "RSA"],
  ["ecc", "ECC"],
  ["sm2", "SM2"],
  ["certificate", "Certificate"],
];

export function PkiLabPage() {
  const tab = usePkiStore((s) => s.tab);
  const setTab = usePkiStore((s) => s.setTab);

  return (
    <div className="page pki-page">
      <h2>PKI Lab</h2>
      <p className="dim pki-expl">
        Keys, operations, and X.509 objects from the CyberCipher PKI engine.
        Every result shows the engine's own typed diagnostics — nothing is
        guessed.
      </p>
      <div className="pki-tabs">
        {TABS.map(([id, label]) => (
          <button
            key={id}
            className={`pki-tab${tab === id ? " active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="pki-tab-body">
        {tab === "keys" && <KeysTab />}
        {tab === "rsa" && <RsaTab />}
        {tab === "ecc" && <EccTab />}
        {tab === "sm2" && <Sm2Tab />}
        {tab === "certificate" && <CertTab />}
      </div>
    </div>
  );
}
