import { useEffect, useState } from "react";
import {
  RSA_FIELD_KEYS,
  buildRsaParams,
  parseRsaIntInput,
  useStore,
  type RsaFieldKey,
} from "../store";
import type {
  RsaAnalyzerReport,
  RsaAttackOutcome,
  RsaPlaintext,
} from "../api";

const FIELD_HINTS: Record<RsaFieldKey, string> = {
  n: "modulus",
  e: "public exponent",
  c: "ciphertext",
  d: "private exponent",
  p: "prime factor",
  q: "prime factor",
  phi: "φ(n) = (p−1)(q−1)",
  dp: "d mod p−1",
  dq: "d mod q−1",
  qinv: "q⁻¹ mod p",
};

const BUDGET_CHOICES = [1000, 5000, 10000, 30000, 60000];

const ADVANCED_PLACEHOLDER = `{
  "hint": "flag{…}",
  "sets": [{ "n": "0x…", "e": 65537, "c": "0x…" }],
  "ns": ["0x…", "0x…"]
}`;

export function RsaLabPage() {
  const rsaFields = useStore((s) => s.rsaFields);
  const rsaAdvancedJson = useStore((s) => s.rsaAdvancedJson);
  const rsaBudgetMs = useStore((s) => s.rsaBudgetMs);
  const rsaReport = useStore((s) => s.rsaReport);
  const rsaRunning = useStore((s) => s.rsaRunning);
  const rsaLastError = useStore((s) => s.rsaLastError);
  const setRsaField = useStore((s) => s.setRsaField);
  const setRsaAdvancedJson = useStore((s) => s.setRsaAdvancedJson);
  const setRsaBudgetMs = useStore((s) => s.setRsaBudgetMs);
  const runRsa = useStore((s) => s.runRsa);
  const applyRsaReportParams = useStore((s) => s.applyRsaReportParams);
  const resetRsaLab = useStore((s) => s.resetRsaLab);

  const [advancedOpen, setAdvancedOpen] = useState(false);

  // Live validation so invalid input is visible before anything is sent.
  const built = buildRsaParams(rsaFields, rsaAdvancedJson);
  const buildError = "error" in built ? built.error : null;

  // Ctrl+Enter runs Analyze & Solve while the lab page is open.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        void runRsa(true);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [runRsa]);

  return (
    <div className="page rsa-lab-page">
      <h2>RSA Attack Lab</h2>
      <p className="dim rsa-expl">
        Enter any subset of RSA key material (decimal or 0x-hex). The analyzer
        walks a pipeline of attacks — Wiener, Fermat, common-modulus, Hastad,
        low-e, dp-leak, Pollard p−1 / rho, shared-prime — reporting per-attack
        status and cost. Solve mode enriches the parameters as attacks succeed.
      </p>

      <div className="rsa-layout">
        <section className="rsa-form-col">
          <div className="rsa-form-grid">
            {RSA_FIELD_KEYS.map((key) => (
              <RsaField
                key={key}
                fieldKey={key}
                value={rsaFields[key]}
                onChange={(v) => setRsaField(key, v)}
                invalid={fieldError(buildError, key)}
              />
            ))}
          </div>

          <button
            className="rsa-advanced-toggle"
            onClick={() => setAdvancedOpen(!advancedOpen)}
            title="Additional parameters: known-plaintext hint, extra (n, e, c) sets, extra moduli"
          >
            <span className="rsa-twist">{advancedOpen ? "▾" : "▸"}</span> Advanced
            (hint · sets · ns)
          </button>
          {advancedOpen && (
            <textarea
              className="rsa-advanced"
              spellCheck={false}
              rows={6}
              placeholder={ADVANCED_PLACEHOLDER}
              value={rsaAdvancedJson}
              onChange={(e) => setRsaAdvancedJson(e.target.value)}
            />
          )}

          <div className="rsa-run-row">
            <label className="rsa-budget" title="Wall-clock budget for bounded search attacks">
              budget
              <select
                value={rsaBudgetMs}
                onChange={(e) => setRsaBudgetMs(Number(e.target.value))}
              >
                {BUDGET_CHOICES.map((ms) => (
                  <option key={ms} value={ms}>
                    {ms / 1000}s
                  </option>
                ))}
              </select>
            </label>
            <button
              className="tool-btn"
              onClick={() => void runRsa(false)}
              disabled={rsaRunning || buildError !== null}
              title="Run the attack pipeline in analysis mode (no factorization escalation)"
            >
              {rsaRunning ? "Working…" : "Analyze"}
            </button>
            <button
              className="bake-btn"
              onClick={() => void runRsa(true)}
              disabled={rsaRunning || buildError !== null}
              title="Run with solving enabled — factorization escalation and key enrichment (Ctrl+Enter)"
            >
              {rsaRunning ? "Solving…" : "Analyze & Solve"}
            </button>
            <button
              className="tool-btn"
              onClick={resetRsaLab}
              disabled={rsaRunning}
              title="Clear all parameters and the last report"
            >
              Reset
            </button>
          </div>
          <div className="rsa-run-hint">
            {buildError ? (
              <span className="rsa-build-error">✗ {buildError}</span>
            ) : (
              <span className="dim">Ctrl+Enter = Analyze &amp; Solve · fields accept decimal or 0x-hex</span>
            )}
          </div>

          {rsaLastError && <div className="rsa-error-banner">{rsaLastError}</div>}
        </section>

        <section className="rsa-results-col">
          {rsaReport ? (
            <ReportView report={rsaReport} onUseKey={applyRsaReportParams} />
          ) : (
            <div className="rsa-empty dim">
              No analysis yet. Paste a challenge's parameters and press{" "}
              <b>Analyze</b> — every attack reports what it needs, what it ran,
              and what it found. Nothing is claimed without evidence.
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

/** Extract the per-field part of a build error, if it names this field. */
function fieldError(buildError: string | null, key: RsaFieldKey): string | null {
  if (!buildError) return null;
  if (buildError.startsWith(`${key}:`)) return buildError.slice(key.length + 2);
  return null;
}

function RsaField({
  fieldKey,
  value,
  onChange,
  invalid,
}: {
  fieldKey: RsaFieldKey;
  value: string;
  onChange: (v: string) => void;
  invalid: string | null;
}) {
  const parsed = parseRsaIntInput(value);
  const meta = parsed === null ? null : parsed.ok ? metaFor(parsed.value) : null;
  return (
    <div className={`rsa-field${invalid || (parsed && !parsed.ok) ? " invalid" : ""}`}>
      <label htmlFor={`rsa-${fieldKey}`}>
        {fieldKey} <span className="rsa-field-hint">{FIELD_HINTS[fieldKey]}</span>
      </label>
      <input
        id={`rsa-${fieldKey}`}
        type="text"
        spellCheck={false}
        autoComplete="off"
        placeholder="decimal or 0x…"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <span className="rsa-meta" title={invalid ?? undefined}>
        {invalid ? (
          <span className="rsa-meta-bad">✗ {invalid}</span>
        ) : parsed && !parsed.ok ? (
          <span className="rsa-meta-bad">✗ {parsed.error}</span>
        ) : meta ? (
          <span className="rsa-meta-ok">{meta}</span>
        ) : (
          <span className="rsa-meta-empty">optional</span>
        )}
      </span>
    </div>
  );
}

/** "256 bits · 32 bytes ✓" style summary of a parsed integer. */
function metaFor(value: bigint): string {
  const bits = value.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  return `${bits} bits · ${bytes} B ✓`;
}

// ------------------------------------------------------------- report ----

function ReportView({
  report,
  onUseKey,
}: {
  report: RsaAnalyzerReport;
  onUseKey: () => void;
}) {
  const counts = { success: 0, applicable: 0, failed: 0, not_applicable: 0 };
  for (const f of report.findings) counts[f.status] += 1;

  return (
    <div className="rsa-report">
      {report.plaintext && <PlaintextCard plaintext={report.plaintext} />}

      <div className="rsa-report-head">
        <h3>Findings</h3>
        <span className="dim rsa-counts">
          {report.findings.length} attacks · {counts.success} success ·{" "}
          {counts.applicable} applicable · {counts.failed} failed ·{" "}
          {counts.not_applicable} n/a
        </span>
        <span className="spacer" />
        <button
          className="tool-btn"
          onClick={onUseKey}
          title="Copy the enriched parameters (0x-hex) back into the form on the left"
        >
          ⇐ Use recovered key
        </button>
      </div>

      <div className="rsa-findings">
        {report.findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
      </div>
    </div>
  );
}

function FindingRow({ finding }: { finding: RsaAttackOutcome }) {
  const [open, setOpen] = useState(false);
  const expandable = Boolean(finding.details || finding.plaintext);
  const content = (
    <>
      <span className={`rsa-status st-${finding.status}`}>{finding.status.replace("_", " ")}</span>
      <span className={`rsa-cost c-${finding.cost}`}>{finding.cost}</span>
      <span className="rsa-finding-name">{finding.name}</span>
      <span className="rsa-finding-msg">{finding.message}</span>
      {expandable && <span className="rsa-twist">{open ? "▾" : "▸"}</span>}
    </>
  );
  return (
    <div className={`rsa-finding st-${finding.status}`}>
      {expandable ? (
        <button
          className="rsa-finding-row"
          onClick={() => setOpen(!open)}
          title={open ? "Hide details" : "Show details"}
        >
          {content}
        </button>
      ) : (
        <div className="rsa-finding-row">{content}</div>
      )}
      {open && (
        <div className="rsa-finding-details">
          {finding.details && <pre>{finding.details}</pre>}
          {finding.plaintext && <PlaintextCard plaintext={finding.plaintext} compact />}
        </div>
      )}
    </div>
  );
}

function PlaintextCard({
  plaintext,
  compact = false,
}: {
  plaintext: RsaPlaintext;
  compact?: boolean;
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const doCopy = async (label: string, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 1200);
  };

  return (
    <div className={`rsa-plaintext${compact ? " compact" : ""}`}>
      <div className="rsa-plaintext-head">
        <span className="rsa-plaintext-title">
          {compact ? "recovered plaintext" : "Plaintext recovered"}
        </span>
        <span className="dim">round-trip verified: m^e mod n = c ✓</span>
      </div>
      <ValueRow label="hex" value={plaintext.m_hex} onCopy={() => void doCopy("hex", plaintext.m_hex)} copied={copied === "hex"} />
      <ValueRow
        label="decimal"
        value={plaintext.m_decimal}
        onCopy={() => void doCopy("decimal", plaintext.m_decimal)}
        copied={copied === "decimal"}
      />
      <ValueRow
        label="bytes BE"
        value={plaintext.bytes_be}
        onCopy={() => void doCopy("bytes", plaintext.bytes_be)}
        copied={copied === "bytes"}
      />
      {plaintext.utf8 !== undefined && (
        <ValueRow
          label="utf-8"
          value={plaintext.utf8}
          onCopy={() => void doCopy("utf8", plaintext.utf8 ?? "")}
          copied={copied === "utf8"}
        />
      )}
      {plaintext.flag_like && (
        <div className="rsa-flag-row">
          <div className="flag-hint rsa-flag">🎯 {plaintext.flag_like}</div>
          <button
            className="tool-btn"
            onClick={() => void doCopy("flag", plaintext.flag_like ?? "")}
            title="Copy the flag"
          >
            {copied === "flag" ? "copied ✓" : "copy"}
          </button>
        </div>
      )}
    </div>
  );
}

function ValueRow({
  label,
  value,
  onCopy,
  copied,
}: {
  label: string;
  value: string;
  onCopy: () => void;
  copied: boolean;
}) {
  return (
    <div className="rsa-value-row">
      <span className="rsa-value-label">{label}</span>
      <pre className="rsa-value">{value}</pre>
      <button className="tool-btn rsa-copy" onClick={onCopy} title={`Copy ${label}`}>
        {copied ? "copied ✓" : "copy"}
      </button>
    </div>
  );
}
