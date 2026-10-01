import { useEffect, useMemo, useState, type DragEvent, type ReactNode } from "react";
import {
  MAX_EXTRACT_BYTES,
  PLANE_CHANNELS,
  RGB_ORDERS,
  TRANSFORM_CATALOG,
  TRANSFORM_GROUPS,
  bytesToBase64,
  useStegoStore,
  type StegoCandidate,
  type StegoExtractResult,
  type StegoTab,
} from "../stegoStore";
import { formatSize, toHex } from "../format";

// ---------------------------------------------------------------------------
// Shared pieces (same vocabulary as the SSTV/PKI labs: pki-section rows,
// pki-tab strip, rsa-error-banner diagnostics, pki-kind-chip facts)
// ---------------------------------------------------------------------------

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="pki-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="rsa-error-banner">✗ {error}</div>;
}

function Chips({ items }: { items: (string | null | undefined)[] }) {
  return (
    <div className="pki-facts">
      {items
        .filter((item): item is string => Boolean(item))
        .map((item, i) => (
          <span key={`${item}-${i}`} className="pki-kind-chip">
            {item}
          </span>
        ))}
    </div>
  );
}

/** hex ⇄ lossy-text preview of bounded byte strings (the DataPanel select idiom). */
function BytePreview({ bytes, cap = 2048 }: { bytes: Uint8Array; cap?: number }) {
  const [view, setView] = useState<"hex" | "text">("hex");
  const shown = bytes.length > cap ? bytes.subarray(0, cap) : bytes;
  return (
    <>
      <div className="sstv-preview-row">
        <span className="dim">
          {formatSize(bytes.length)}
          {bytes.length > cap ? ` — showing first ${formatSize(cap)}` : ""}
        </span>
        <select value={view} onChange={(e) => setView(e.target.value as "hex" | "text")}>
          <option value="hex">hex</option>
          <option value="text">text</option>
        </select>
      </div>
      <pre className="sstv-cand-preview">
        {view === "hex" ? toHex(shown) : new TextDecoder("utf-8", { fatal: false }).decode(shown)}
      </pre>
    </>
  );
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : hex.slice(0, hex.length - 1);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function downloadPng(pngBase64: string, fileName: string) {
  const anchor = document.createElement("a");
  anchor.href = `data:image/png;base64,${pngBase64}`;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

/** Copy button with the transient "copied ✓" feedback used by DataPanel. */
function CopyHexButton({ bytes }: { bytes: Uint8Array }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="tool-btn"
      onClick={() => {
        void navigator.clipboard.writeText(toHex(bytes)).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
      title="Copy the full payload as lowercase hex"
    >
      {copied ? "Copied ✓" : "Copy Hex"}
    </button>
  );
}

// ----------------------------------------------------------------- input ----

function ImageInputSection() {
  const fileName = useStegoStore((s) => s.fileName);
  const fileSize = useStegoStore((s) => s.fileSize);
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const loadFile = useStegoStore((s) => s.loadFile);
  const clearFile = useStegoStore((s) => s.clearFile);
  const [dragOver, setDragOver] = useState(false);

  const onDrop = (e: DragEvent<HTMLElement>) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) void loadFile(file);
  };

  return (
    <Section title="Image input">
      <label
        className={`sstv-drop${fileName ? " hasfile" : ""}${dragOver ? " dragover" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
      >
        <input
          type="file"
          accept="image/png,image/jpeg,image/gif,image/bmp,.png,.jpg,.jpeg,.gif,.bmp"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void loadFile(file);
            e.target.value = "";
          }}
        />
        {fileName ? (
          <>
            <div className="sstv-file-name">{fileName}</div>
            <div>
              {fileSize !== null ? formatSize(fileSize) : "?"}
              {fileBase64 ? "" : " — reading…"}
            </div>
            <div className="dim">click to choose a different file, or drop one here</div>
          </>
        ) : (
          <>
            <div>drop an image here, or click to choose</div>
            <div className="dim">PNG, JPEG, GIF, BMP — the engine sniffs the format</div>
          </>
        )}
      </label>
      {fileName && (
        <div className="pki-run-row">
          <button
            className="tool-btn"
            onClick={clearFile}
            title="Clear the image and every result"
          >
            Clear
          </button>
        </div>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ info ----

function InfoRow() {
  const info = useStegoStore((s) => s.info);
  const infoBusy = useStegoStore((s) => s.infoBusy);
  const infoError = useStegoStore((s) => s.infoError);
  const fileName = useStegoStore((s) => s.fileName);
  if (!fileName) return null;
  return (
    <Section title="Image info">
      {infoBusy && <div className="dim">decoding the image header (image_info)…</div>}
      <ErrorBanner error={infoError} />
      {info && (
        <Chips
          items={[
            `${info.width}×${info.height}`,
            `${info.pixel_count.toLocaleString()} px`,
            info.has_alpha ? "alpha channel" : "no alpha",
            info.indexed ? `palette (${info.indexed.palette_entries} entries)` : null,
            `estimated ${formatSize(info.estimated_bytes)} decoded`,
          ]}
        />
      )}
    </Section>
  );
}

// ------------------------------------------------------------- transform ----

function TransformTab() {
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const transformIndex = useStegoStore((s) => s.transformIndex);
  const transformCache = useStegoStore((s) => s.transformCache);
  const transformBusy = useStegoStore((s) => s.transformBusy);
  const transformError = useStegoStore((s) => s.transformError);
  const setTransformIndex = useStegoStore((s) => s.setTransformIndex);
  const ensureTransform = useStegoStore((s) => s.ensureTransform);
  const sendToWorkbench = useStegoStore((s) => s.sendToWorkbench);
  const fileName = useStegoStore((s) => s.fileName);

  // Load-on-demand: every selected index is computed from the ORIGINAL image
  // bytes by the image_transform op and cached in the store.
  useEffect(() => {
    if (!fileBase64) return;
    if (transformCache[transformIndex] !== undefined) return;
    void ensureTransform();
  }, [fileBase64, transformIndex, transformCache, transformBusy, ensureTransform]);

  const def = TRANSFORM_CATALOG[transformIndex];
  const pngBase64 = transformCache[transformIndex];
  const groupPosition = TRANSFORM_GROUPS.findIndex((g) => g.name === def.group);

  const grouped = useMemo(() => {
    const byGroup = new Map<string, typeof TRANSFORM_CATALOG>();
    for (const entry of TRANSFORM_CATALOG) {
      const list = byGroup.get(entry.group) ?? [];
      list.push(entry);
      byGroup.set(entry.group, list);
    }
    return [...byGroup.entries()];
  }, []);

  const step = (delta: number) =>
    setTransformIndex(Math.min(Math.max(transformIndex + delta, 0), TRANSFORM_CATALOG.length - 1));
  const stepGroup = (delta: number) => {
    const next = Math.min(Math.max(groupPosition + delta, 0), TRANSFORM_GROUPS.length - 1);
    setTransformIndex(TRANSFORM_GROUPS[next].first);
  };

  return (
    <Section title="Transform viewer">
      {!fileBase64 ? (
        <div className="rsa-empty dim">
          Load an image to step through the 42 StegSolve-compatible transforms — bit planes,
          inversion, full channels, random colour maps, gray pixels.
        </div>
      ) : (
        <>
          <div className="pki-run-row">
            <button
              className="tool-btn"
              onClick={() => stepGroup(-1)}
              disabled={groupPosition <= 0}
              title="First transform of the previous group"
            >
              ◀ group
            </button>
            <select
              value={def.group}
              onChange={(e) => {
                const group = TRANSFORM_GROUPS.find((g) => g.name === e.target.value);
                if (group) setTransformIndex(group.first);
              }}
              title="Transform group"
            >
              {TRANSFORM_GROUPS.map((g) => (
                <option key={g.name} value={g.name}>
                  {g.name}
                </option>
              ))}
            </select>
            <button
              className="tool-btn"
              onClick={() => stepGroup(1)}
              disabled={groupPosition >= TRANSFORM_GROUPS.length - 1}
              title="First transform of the next group"
            >
              group ▶
            </button>
            <button
              className="tool-btn"
              onClick={() => step(-1)}
              disabled={transformIndex <= 0}
              title="Previous transform"
            >
              ◀
            </button>
            <select
              value={transformIndex}
              onChange={(e) => setTransformIndex(Number.parseInt(e.target.value, 10))}
              title="Transform"
            >
              {grouped.map(([group, entries]) => (
                <optgroup key={group} label={group}>
                  {entries.map((entry) => (
                    <option key={entry.index} value={entry.index}>
                      {entry.index} — {entry.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
            <button
              className="tool-btn"
              onClick={() => step(1)}
              disabled={transformIndex >= TRANSFORM_CATALOG.length - 1}
              title="Next transform"
            >
              ▶
            </button>
            <span className="dim stego-index">
              {transformIndex} / {TRANSFORM_CATALOG.length - 1}
            </span>
          </div>

          <ErrorBanner error={transformError} />
          {transformBusy && (
            <div className="dim sstv-busy-note">
              computing transform {transformIndex} via image_transform — runs to completion on the
              engine side, not cancellable
            </div>
          )}

          {pngBase64 !== undefined && (
            <div className="stego-viewport">
              <img
                src={`data:image/png;base64,${pngBase64}`}
                alt={`transform ${transformIndex} — ${def.label}`}
              />
              <div className="sstv-image-head">
                <span className="pki-kind-chip">{def.label}</span>
                <span className="pki-kind-chip">#{transformIndex}</span>
                <span className="dim">{def.group}</span>
                <span className="spacer" />
                <button
                  className="tool-btn"
                  onClick={() =>
                    downloadPng(
                      pngBase64,
                      `${fileName ?? "image"}-transform-${transformIndex}.png`,
                    )
                  }
                  title="Download the transformed PNG through the browser"
                >
                  Save PNG
                </button>
                <button
                  className="tool-btn"
                  onClick={() => sendToWorkbench(pngBase64)}
                  title="Put the transformed PNG into the Workbench input (base64)"
                >
                  → Workbench
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </Section>
  );
}

// -------------------------------------------------------------- extract ----

function PlaneMaskGrid() {
  const planeMask = useStegoStore((s) => s.planeMask);
  const setPlaneBit = useStegoStore((s) => s.setPlaneBit);
  return (
    <div className="stego-planes">
      <div className="dim stego-planes-note">
        plane mask selects the bit planes to read per pixel — bit{" "}
        <code>channel·8 + plane</code>, 0 = least significant (engine bit order)
      </div>
      <div className="stego-plane-groups">
        {PLANE_CHANNELS.map((channel) => (
          <div key={channel.ordinal} className="stego-plane-group">
            <div className="stego-plane-head">
              {channel.name} <span className="dim">({channel.symbol})</span>
            </div>
            <div className="stego-plane-bits">
              {[0, 1, 2, 3, 4, 5, 6, 7].map((plane) => {
                const bit = channel.ordinal * 8 + plane;
                const checked = ((planeMask >>> bit) & 1) === 1;
                return (
                  <label key={plane} className="pki-select-label stego-plane-bit" title={`${channel.name} plane ${plane} — plane-mask bit ${bit}`}>
                    {plane}
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={(e) => setPlaneBit(bit, e.target.checked)}
                    />
                  </label>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="dim stego-mask-hex">
        mask 0x{planeMask.toString(16).padStart(8, "0")}
      </div>
    </div>
  );
}

function ExtractReport({ result }: { result: StegoExtractResult }) {
  const sendToWorkbench = useStegoStore((s) => s.sendToWorkbench);
  const sendToAutoDecode = useStegoStore((s) => s.sendToAutoDecode);
  return (
    <div className="sstv-applied">
      <div className="sstv-cand-head">
        <span className="pki-kind-chip">
          extracted {formatSize(result.data.length)}
          {result.header?.total_bytes !== undefined
            ? ` of ${formatSize(result.header.total_bytes)}`
            : ""}
        </span>
        {result.header?.truncated && <span className="pki-kind-chip">truncated</span>}
        {result.header?.settings && <span className="pki-kind-chip">{result.header.settings}</span>}
        <span className="spacer" />
        <button
          className="tool-btn"
          onClick={() => sendToWorkbench(bytesToBase64(result.data))}
          title="Put the extracted bytes into the Workbench input (base64)"
        >
          → Workbench
        </button>
        <button
          className="tool-btn"
          onClick={() => sendToAutoDecode(bytesToBase64(result.data))}
          title="Run Auto Analyze on the extracted bytes"
        >
          → Auto Decode
        </button>
        <CopyHexButton bytes={result.data} />
      </div>
      <BytePreview bytes={result.data} />
    </div>
  );
}

function ExtractTab() {
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const order = useStegoStore((s) => s.order);
  const lsbFirst = useStegoStore((s) => s.lsbFirst);
  const rowFirst = useStegoStore((s) => s.rowFirst);
  const invertBits = useStegoStore((s) => s.invertBits);
  const roiX = useStegoStore((s) => s.roiX);
  const roiY = useStegoStore((s) => s.roiY);
  const roiW = useStegoStore((s) => s.roiW);
  const roiH = useStegoStore((s) => s.roiH);
  const maxBytes = useStegoStore((s) => s.maxBytes);
  const setOrder = useStegoStore((s) => s.setOrder);
  const setLsbFirst = useStegoStore((s) => s.setLsbFirst);
  const setRowFirst = useStegoStore((s) => s.setRowFirst);
  const setInvertBits = useStegoStore((s) => s.setInvertBits);
  const setRoi = useStegoStore((s) => s.setRoi);
  const setMaxBytes = useStegoStore((s) => s.setMaxBytes);
  const extractBusy = useStegoStore((s) => s.extractBusy);
  const extractError = useStegoStore((s) => s.extractError);
  const extractResult = useStegoStore((s) => s.extractResult);
  const runExtract = useStegoStore((s) => s.runExtract);

  const roiPartiallyFilled =
    [roiX, roiY, roiW, roiH].some((v) => v.trim() !== "") &&
    [roiX, roiY, roiW, roiH].some((v) => v.trim() === "");

  return (
    <Section title="Extract bits">
      {!fileBase64 ? (
        <div className="rsa-empty dim">
          Load an image to extract a bit stream: pick the channel planes, the RGB visit order and
          traversal, then run the image_extract_bits op.
        </div>
      ) : (
        <>
          <PlaneMaskGrid />

          <div className="pki-run-row">
            <label
              className="pki-select-label"
              title="Colour channel visit order (legacy codes 1..=6); alpha is always visited first"
            >
              RGB order
              <select value={order} onChange={(e) => setOrder(Number.parseInt(e.target.value, 10))}>
                {RGB_ORDERS.map((o) => (
                  <option key={o.code} value={o.code}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <label
              className="pki-select-label"
              title="Visit planes 0..7 (LSB-first) instead of 7..0 (MSB-first) inside each channel"
            >
              LSB-first planes
              <input
                type="checkbox"
                checked={lsbFirst}
                onChange={(e) => setLsbFirst(e.target.checked)}
              />
            </label>
            <label
              className="pki-select-label"
              title="Traverse row by row instead of column by column"
            >
              row-first
              <input
                type="checkbox"
                checked={rowFirst}
                onChange={(e) => setRowFirst(e.target.checked)}
              />
            </label>
            <label
              className="pki-select-label"
              title="Complement every pixel before reading planes"
            >
              invert bits
              <input
                type="checkbox"
                checked={invertBits}
                onChange={(e) => setInvertBits(e.target.checked)}
              />
            </label>
          </div>

          <div className="pki-run-row">
            <label className="pki-select-label" title="Region x (0-based, whole image when blank)">
              ROI x
              <input
                type="number"
                min={0}
                value={roiX}
                onChange={(e) => setRoi("x", e.target.value)}
              />
            </label>
            <label className="pki-select-label" title="Region y">
              y
              <input
                type="number"
                min={0}
                value={roiY}
                onChange={(e) => setRoi("y", e.target.value)}
              />
            </label>
            <label className="pki-select-label" title="Region width">
              w
              <input
                type="number"
                min={0}
                value={roiW}
                onChange={(e) => setRoi("w", e.target.value)}
              />
            </label>
            <label className="pki-select-label" title="Region height">
              h
              <input
                type="number"
                min={0}
                value={roiH}
                onChange={(e) => setRoi("h", e.target.value)}
              />
            </label>
            <label
              className="pki-select-label"
              title="Bounded extraction size; the report's total_bytes is what a full run would produce. Hard cap 16 MiB."
            >
              max bytes
              <input
                type="number"
                min={1}
                max={MAX_EXTRACT_BYTES}
                step={1}
                value={maxBytes}
                onChange={(e) => setMaxBytes(Number(e.target.value))}
              />
            </label>
          </div>
          {roiPartiallyFilled && (
            <div className="dim sstv-busy-note">
              region incomplete — all four values (x, y, w, h) make a region; using the whole image
            </div>
          )}

          <div className="pki-run-row">
            <button
              className="bake-btn"
              onClick={() => void runExtract()}
              disabled={extractBusy}
              title="Run image_extract_bits with these settings on the original image bytes"
            >
              {extractBusy ? "Extracting…" : "Extract bits"}
            </button>
            {extractBusy && (
              <span className="dim sstv-busy-note">
                extraction runs to completion on the engine side — not cancellable
              </span>
            )}
          </div>
          <ErrorBanner error={extractError} />
          {extractResult && <ExtractReport result={extractResult} />}
        </>
      )}
    </Section>
  );
}

// ------------------------------------------------------------- auto LSB ----

function CandidateView({
  rank,
  candidate,
  applyBusy,
  onApply,
}: {
  rank: number;
  candidate: StegoCandidate;
  applyBusy: boolean;
  onApply: () => void;
}) {
  const previewBytes = useMemo(() => hexToBytes(candidate.preview_hex), [candidate.preview_hex]);
  return (
    <div className="sstv-candidate">
      <div className="sstv-cand-head">
        <span className="sstv-cand-score">#{rank}</span>
        <span className="pki-kind-chip">score {candidate.score}</span>
        <span className="pki-kind-chip">{candidate.payload_type}</span>
        {candidate.truncated && <span className="pki-kind-chip">truncated</span>}
        <span className="spacer" />
        <button
          className="tool-btn"
          onClick={onApply}
          disabled={applyBusy}
          title="Run Extract Bits with this candidate's settings on the original image"
        >
          {applyBusy ? "Extracting…" : "Apply"}
        </button>
      </div>
      <div className="dim sstv-cand-config">
        {candidate.settings.config} — {candidate.settings.description}
      </div>
      <div className="dim sstv-cand-reason">{candidate.reason}</div>
      <BytePreview bytes={previewBytes} cap={256} />
      <div className="dim sstv-cand-total">
        full extraction: {formatSize(candidate.total_bytes)}
        {candidate.truncated ? " (scan preview was truncated)" : ""}
      </div>
    </div>
  );
}

function AppliedView({ applied }: { applied: StegoExtractResult }) {
  const sendToWorkbench = useStegoStore((s) => s.sendToWorkbench);
  const sendToAutoDecode = useStegoStore((s) => s.sendToAutoDecode);
  return (
    <div className="sstv-applied">
      <div className="sstv-cand-head">
        <span className="pki-kind-chip">extracted {formatSize(applied.data.length)}</span>
        {applied.header?.settings && (
          <span className="pki-kind-chip">{applied.header.settings}</span>
        )}
        {applied.header?.truncated && <span className="pki-kind-chip">truncated</span>}
        <span className="spacer" />
        <button
          className="tool-btn"
          onClick={() => sendToWorkbench(bytesToBase64(applied.data))}
          title="Put the extracted bytes into the Workbench input (base64)"
        >
          → Workbench
        </button>
        <button
          className="tool-btn"
          onClick={() => sendToAutoDecode(bytesToBase64(applied.data))}
          title="Run Auto Analyze on the extracted bytes"
        >
          → Auto Decode
        </button>
        <CopyHexButton bytes={applied.data} />
      </div>
      <BytePreview bytes={applied.data} />
    </div>
  );
}

function AutoLsbTab() {
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const scanBusy = useStegoStore((s) => s.scanBusy);
  const scanError = useStegoStore((s) => s.scanError);
  const candidates = useStegoStore((s) => s.candidates);
  const applyBusy = useStegoStore((s) => s.applyBusy);
  const applyError = useStegoStore((s) => s.applyError);
  const applied = useStegoStore((s) => s.applied);
  const runScan = useStegoStore((s) => s.runScan);
  const applyCandidate = useStegoStore((s) => s.applyCandidate);

  return (
    <Section title="Auto LSB scan">
      {!fileBase64 ? (
        <div className="rsa-empty dim">
          Load an image to enumerate the StegSolve extraction configurations and rank what comes
          out — flags, file signatures, text, base64.
        </div>
      ) : (
        <>
          <div className="pki-run-row">
            <button
              className="bake-btn"
              onClick={() => void runScan(false)}
              disabled={scanBusy}
              title="Run auto_lsb_scan with the Fast configuration set"
            >
              {scanBusy ? "Scanning…" : "Run Fast Scan"}
            </button>
            <button
              className="bake-btn"
              onClick={() => void runScan(true)}
              disabled={scanBusy}
              title="Run auto_lsb_scan with the Deep configuration set (rarer configurations added)"
            >
              {scanBusy ? "Scanning…" : "Run Deep Scan"}
            </button>
            {scanBusy && (
              <span className="dim sstv-busy-note">
                the scan runs to completion on the engine side — not cancellable
              </span>
            )}
          </div>
          <ErrorBanner error={scanError} />
          {candidates !== null && candidates.length === 0 && (
            <div className="dim">no candidates scored above the empty-extract baseline</div>
          )}
          {candidates !== null && candidates.length > 0 && (
            <div className="sstv-candidates">
              {candidates.map((candidate, i) => (
                <CandidateView
                  key={candidate.fingerprint}
                  rank={i + 1}
                  candidate={candidate}
                  applyBusy={applyBusy}
                  onApply={() => void applyCandidate(candidate)}
                />
              ))}
            </div>
          )}
          <ErrorBanner error={applyError} />
          {applied && <AppliedView applied={applied} />}
        </>
      )}
    </Section>
  );
}

// ----------------------------------------------------------------- page ----

const TABS: [StegoTab, string][] = [
  ["transform", "Transforms"],
  ["extract", "Extract"],
  ["autolsb", "Auto LSB"],
];

export function StegoLabPage() {
  const tab = useStegoStore((s) => s.tab);
  const setTab = useStegoStore((s) => s.setTab);

  return (
    <div className="page stego-page">
      <h2>Stego Lab</h2>
      <p className="dim sstv-expl">
        Steganography workbench over the StegSolve-compatible engine: step through the 42-transform
        catalog, extract bit streams with full control over planes, order and traversal, and let
        Auto LSB rank the likely configurations. Every operation runs in the Rust engine on the
        original image bytes.
      </p>
      <div className="sstv-layout">
        <div className="sstv-input-col">
          <ImageInputSection />
          <InfoRow />
        </div>
        <div className="sstv-results-col">
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
            {tab === "transform" && <TransformTab />}
            {tab === "extract" && <ExtractTab />}
            {tab === "autolsb" && <AutoLsbTab />}
          </div>
        </div>
      </div>
    </div>
  );
}
