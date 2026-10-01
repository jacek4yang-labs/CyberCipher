import { useEffect, useMemo, useState, type DragEvent, type ReactNode } from "react";
import {
  MAX_EXTRACT_BYTES,
  PLANE_CHANNELS,
  RGB_ORDERS,
  TRANSFORM_CATALOG,
  TRANSFORM_GROUPS,
  bytesToBase64,
  useStegoStore,
  type StegoAppendedResult,
  type StegoCandidate,
  type QrHit,
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
function CopyButton({
  text,
  label = "Copy Hex",
  disabled = false,
  disabledTitle,
  title,
}: {
  text: string;
  label?: string;
  disabled?: boolean;
  disabledTitle?: string;
  title?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="tool-btn"
      disabled={disabled}
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
      title={disabled ? disabledTitle : title ?? `Copy ${label.toLowerCase()}`}
    >
      {copied ? "Copied ✓" : label}
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
        <CopyButton text={toHex(result.data)} label="Copy Hex" />
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
        <CopyButton text={toHex(applied.data)} label="Copy Hex" />
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

// ------------------------------------------------------------- structure ----

const STRUCTURE_OP_NAMES: Record<string, string> = {
  png_structure: "PNG Structure",
  jpeg_structure: "JPEG Structure",
  gif_structure: "GIF Structure",
  bmp_structure: "BMP Structure",
};

function AppendedView({ result }: { result: StegoAppendedResult }) {
  const sendToWorkbench = useStegoStore((s) => s.sendToWorkbench);
  const sendToAutoDecode = useStegoStore((s) => s.sendToAutoDecode);
  const header = result.header;
  const magicId =
    typeof header?.magic?.id === "string" ? header.magic.id : null;
  return (
    <div className="sstv-applied">
      <div className="sstv-cand-head">
        {header?.present ? (
          <>
            <span className="pki-kind-chip">
              appended {formatSize(result.data.length)}
              {header.size !== undefined ? ` of ${formatSize(header.size)}` : ""}
            </span>
            {header.offset !== undefined && (
              <span className="pki-kind-chip">
                at 0x{header.offset.toString(16)}
              </span>
            )}
            {magicId && <span className="pki-kind-chip">looks like {magicId}</span>}
            {header.truncated && <span className="pki-kind-chip">truncated</span>}
            <span className="spacer" />
            <button
              className="tool-btn"
              onClick={() => sendToWorkbench(bytesToBase64(result.data))}
              title="Put the carved bytes into the Workbench input (base64)"
            >
              → Workbench
            </button>
            <button
              className="tool-btn"
              onClick={() => sendToAutoDecode(bytesToBase64(result.data))}
              title="Run Auto Analyze on the carved bytes"
            >
              → Auto Decode
            </button>
            <CopyButton text={toHex(result.data)} label="Copy Hex" />
          </>
        ) : (
          <span className="dim">no data after the container's logical end of file</span>
        )}
      </div>
      {header?.strings && header.strings.length > 0 && (
        <div className="dim sstv-cand-reason">
          printable strings: {header.strings.join(" · ")}
        </div>
      )}
      {header?.present && result.data.length > 0 && <BytePreview bytes={result.data} />}
    </div>
  );
}

function StructureTab() {
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const structureBusy = useStegoStore((s) => s.structureBusy);
  const structureError = useStegoStore((s) => s.structureError);
  const structureOp = useStegoStore((s) => s.structureOp);
  const structureReport = useStegoStore((s) => s.structureReport);
  const structureOpen = useStegoStore((s) => s.structureOpen);
  const setStructureOpen = useStegoStore((s) => s.setStructureOpen);
  const runStructure = useStegoStore((s) => s.runStructure);
  const appendedMaxBytes = useStegoStore((s) => s.appendedMaxBytes);
  const setAppendedMaxBytes = useStegoStore((s) => s.setAppendedMaxBytes);
  const appendedBusy = useStegoStore((s) => s.appendedBusy);
  const appendedError = useStegoStore((s) => s.appendedError);
  const appendedResult = useStegoStore((s) => s.appendedResult);
  const runAppended = useStegoStore((s) => s.runAppended);

  // Analyze once per loaded file while the tab is visible; a retry after an
  // error (or a re-run) goes through the button.
  useEffect(() => {
    if (!fileBase64) return;
    if (structureBusy || structureError !== null || structureOp !== null) return;
    void runStructure();
  }, [fileBase64, structureBusy, structureError, structureOp, runStructure]);

  const report = (structureReport ?? null) as Record<string, unknown> | null;
  const reportJson = useMemo(
    () => (structureReport !== null ? JSON.stringify(structureReport, null, 2) : ""),
    [structureReport],
  );
  const appendedFlag = report?.["appended"] as { present?: boolean } | null | undefined;
  const complete = report?.["complete"] === true;
  const truncatedWalk = report?.["truncated"] === true;
  const fileSize = typeof report?.["file_size"] === "number" ? report["file_size"] : null;

  return (
    <>
      <Section title="Container structure">
        {!fileBase64 ? (
          <div className="rsa-empty dim">
            Load a PNG, JPEG, GIF or BMP to walk its raw container bytes: chunks / segments /
            blocks with offsets and CRC validity, header geometry, comments, and the logical end
            of file with appended-data detection.
          </div>
        ) : (
          <>
            <div className="pki-run-row">
              <button
                className="bake-btn"
                onClick={() => void runStructure()}
                disabled={structureBusy}
                title={
                  structureOp
                    ? `Re-run ${STRUCTURE_OP_NAMES[structureOp] ?? structureOp} on the original file bytes`
                    : "Run the matching structure analyzer on the original file bytes"
                }
              >
                {structureBusy ? "Walking…" : structureOp ? "Re-analyze" : "Analyze structure"}
              </button>
              {structureBusy && (
                <span className="dim sstv-busy-note">
                  the walk runs to completion on the engine side — not cancellable
                </span>
              )}
            </div>
            <ErrorBanner error={structureError} />
            {report !== null && (
              <>
                <Chips
                  items={[
                    structureOp ? (STRUCTURE_OP_NAMES[structureOp] ?? structureOp) : null,
                    fileSize !== null ? `file size ${formatSize(fileSize)}` : null,
                    complete ? "walk complete" : "walk incomplete",
                    truncatedWalk ? "report truncated" : null,
                    appendedFlag?.present ? "appended data found" : "no appended data",
                  ]}
                />
                <button
                  className="pki-advanced-toggle"
                  onClick={() => setStructureOpen(!structureOpen)}
                  title="The analyzer's full bounded report, exactly as the engine produced it"
                >
                  <span className="pki-twist">{structureOpen ? "▾" : "▸"}</span> Raw report JSON (
                  {formatSize(reportJson.length)})
                </button>
                {structureOpen && <pre className="sstv-evidence">{reportJson}</pre>}
              </>
            )}
          </>
        )}
      </Section>

      <Section title="Appended data">
        {!fileBase64 ? (
          <div className="rsa-empty dim">
            Carve bytes appended after the container's logical end of file (PNG IEND, JPEG EOI,
            GIF trailer, BMP pixel-array end) with the image_extract_appended op.
          </div>
        ) : (
          <>
            <div className="pki-run-row">
              <label
                className="pki-select-label"
                title="Bounded carve size; the header reports the total appended size and a truncated flag. Hard cap 16 MiB."
              >
                max bytes
                <input
                  type="number"
                  min={1}
                  max={MAX_EXTRACT_BYTES}
                  step={1}
                  value={appendedMaxBytes}
                  onChange={(e) => setAppendedMaxBytes(Number(e.target.value))}
                />
              </label>
              <button
                className="bake-btn"
                onClick={() => void runAppended()}
                disabled={appendedBusy}
                title="Run image_extract_appended on the original file bytes"
              >
                {appendedBusy ? "Carving…" : "Extract appended"}
              </button>
              {appendedBusy && (
                <span className="dim sstv-busy-note">
                  the carve runs to completion on the engine side — not cancellable
                </span>
              )}
            </div>
            <ErrorBanner error={appendedError} />
            {appendedResult && <AppendedView result={appendedResult} />}
          </>
        )}
      </Section>
    </>
  );
}

// -------------------------------------------------------------------- qr ----

function QrHitCard({ hit }: { hit: QrHit }) {
  const sendToWorkbench = useStegoStore((s) => s.sendToWorkbench);
  const sendToAutoDecode = useStegoStore((s) => s.sendToAutoDecode);
  const payloadBytes = useMemo(() => hexToBytes(hit.raw_payload_bytes), [hit.raw_payload_bytes]);
  const hasPayload = payloadBytes.length > 0;
  const bounds = hit.position?.bounds ?? null;
  return (
    <div className="sstv-candidate">
      <div className="sstv-cand-head">
        <span className="pki-kind-chip">{hit.format}</span>
        <span className="pki-kind-chip">{formatSize(hit.payload_length)} payload</span>
        {!hasPayload && (
          <span className="pki-kind-chip" title="A text-only symbol: the decoder emitted no raw payload bytes, so none are invented">
            text-only
          </span>
        )}
        {bounds && (
          <span className="pki-kind-chip">
            at {bounds.x},{bounds.y} · {bounds.width}×{bounds.height}
          </span>
        )}
        <span className="spacer" />
        <CopyButton
          text={hit.decoded_text ?? ""}
          label="Copy Text"
          disabled={hit.decoded_text === undefined}
          disabledTitle="The decoder produced no decoded text for this symbol"
        />
        <CopyButton
          text={toHex(payloadBytes)}
          label="Copy Hex"
          disabled={!hasPayload}
          disabledTitle="No raw payload bytes — text-only symbols carry none"
        />
        <button
          className="tool-btn"
          disabled={!hasPayload}
          onClick={() => sendToWorkbench(bytesToBase64(payloadBytes))}
          title={
            hasPayload
              ? "Put the payload bytes into the Workbench input (base64)"
              : "No raw payload bytes — text-only symbols carry none"
          }
        >
          → Workbench
        </button>
        <button
          className="tool-btn"
          disabled={!hasPayload}
          onClick={() => sendToAutoDecode(bytesToBase64(payloadBytes))}
          title={
            hasPayload
              ? "Run Auto Analyze on the payload bytes"
              : "No raw payload bytes — text-only symbols carry none"
          }
        >
          → Auto Decode
        </button>
      </div>
      {hit.decoded_text !== undefined && (
        <pre className="sstv-cand-preview">{hit.decoded_text}</pre>
      )}
      {hasPayload && <BytePreview bytes={payloadBytes} cap={256} />}
    </div>
  );
}

function QrTab() {
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const qrRoiX = useStegoStore((s) => s.qrRoiX);
  const qrRoiY = useStegoStore((s) => s.qrRoiY);
  const qrRoiW = useStegoStore((s) => s.qrRoiW);
  const qrRoiH = useStegoStore((s) => s.qrRoiH);
  const qrTryInverted = useStegoStore((s) => s.qrTryInverted);
  const qrTryRotations = useStegoStore((s) => s.qrTryRotations);
  const qrTryRescale = useStegoStore((s) => s.qrTryRescale);
  const qrMaxSymbols = useStegoStore((s) => s.qrMaxSymbols);
  const setQrRoi = useStegoStore((s) => s.setQrRoi);
  const setQrTryInverted = useStegoStore((s) => s.setQrTryInverted);
  const setQrTryRotations = useStegoStore((s) => s.setQrTryRotations);
  const setQrTryRescale = useStegoStore((s) => s.setQrTryRescale);
  const setQrMaxSymbols = useStegoStore((s) => s.setQrMaxSymbols);
  const qrBusy = useStegoStore((s) => s.qrBusy);
  const qrError = useStegoStore((s) => s.qrError);
  const qrResult = useStegoStore((s) => s.qrResult);
  const runQrScan = useStegoStore((s) => s.runQrScan);

  const roiPartiallyFilled =
    [qrRoiX, qrRoiY, qrRoiW, qrRoiH].some((v) => v.trim() !== "") &&
    [qrRoiX, qrRoiY, qrRoiW, qrRoiH].some((v) => v.trim() === "");

  return (
    <Section title="QR / barcode scan">
      {!fileBase64 ? (
        <div className="rsa-empty dim">
          Load an image to scan it for QR codes and 1D/2D barcodes: every hit reports the exact
          raw payload bytes, the decoded text when printable, its position and metadata — with
          inverted, rotated and rescaled fallback stages.
        </div>
      ) : (
        <>
          <div className="pki-run-row">
            <label className="pki-select-label" title="Region x (0-based, whole image when blank)">
              ROI x
              <input
                type="number"
                min={0}
                value={qrRoiX}
                onChange={(e) => setQrRoi("x", e.target.value)}
              />
            </label>
            <label className="pki-select-label" title="Region y">
              y
              <input
                type="number"
                min={0}
                value={qrRoiY}
                onChange={(e) => setQrRoi("y", e.target.value)}
              />
            </label>
            <label className="pki-select-label" title="Region width">
              w
              <input
                type="number"
                min={0}
                value={qrRoiW}
                onChange={(e) => setQrRoi("w", e.target.value)}
              />
            </label>
            <label className="pki-select-label" title="Region height">
              h
              <input
                type="number"
                min={0}
                value={qrRoiH}
                onChange={(e) => setQrRoi("h", e.target.value)}
              />
            </label>
            <label
              className="pki-select-label"
              title="Maximum number of reported symbols (engine hard cap 64)"
            >
              max symbols
              <input
                type="number"
                min={1}
                max={64}
                step={1}
                value={qrMaxSymbols}
                onChange={(e) => setQrMaxSymbols(Number(e.target.value))}
              />
            </label>
          </div>
          {roiPartiallyFilled && (
            <div className="dim sstv-busy-note">
              region incomplete — all four values (x, y, w, h) make a region; using the whole image
            </div>
          )}

          <div className="pki-run-row">
            <label
              className="pki-select-label"
              title="Also scans an inverted copy, for light symbols on a dark background"
            >
              try inverted
              <input
                type="checkbox"
                checked={qrTryInverted}
                onChange={(e) => setQrTryInverted(e.target.checked)}
              />
            </label>
            <label
              className="pki-select-label"
              title="Also tries quarter turns when nothing decoded upright"
            >
              try rotations
              <input
                type="checkbox"
                checked={qrTryRotations}
                onChange={(e) => setQrTryRotations(e.target.checked)}
              />
            </label>
            <label
              className="pki-select-label"
              title="Adds rescaled copies (for very small/very large images) and the alternate binarizer when everything else failed"
            >
              try rescale
              <input
                type="checkbox"
                checked={qrTryRescale}
                onChange={(e) => setQrTryRescale(e.target.checked)}
              />
            </label>
          </div>

          <div className="pki-run-row">
            <button
              className="bake-btn"
              onClick={() => void runQrScan()}
              disabled={qrBusy}
              title="Run image_scan_qr on the original image bytes"
            >
              {qrBusy ? "Scanning…" : "Scan"}
            </button>
            {qrBusy && (
              <span className="dim sstv-busy-note">
                the scan runs to completion on the engine side — not cancellable
              </span>
            )}
          </div>
          <ErrorBanner error={qrError} />

          {qrResult && (
            <>
              <Chips
                items={[
                  `${qrResult.symbol_count} symbol${qrResult.symbol_count === 1 ? "" : "s"}`,
                  qrResult.merged_count > 0
                    ? `${qrResult.merged_count} merged Structured Append sequence${qrResult.merged_count === 1 ? "" : "s"}`
                    : null,
                  `scanned ${qrResult.scanned_area.width}×${qrResult.scanned_area.height} at ${qrResult.scanned_area.x},${qrResult.scanned_area.y}`,
                ]}
              />
              {qrResult.notes.length > 0 && (
                <div className="pki-alternatives">notes: {qrResult.notes.join(" · ")}</div>
              )}
              {qrResult.symbol_count === 0 && (
                <div className="dim">
                  no symbol found in the scanned region — for very small or very large images try
                  the rescale fallback
                </div>
              )}
              {qrResult.merged.length > 0 && (
                <>
                  <div className="pki-subhead dim">merged Structured Append sequences</div>
                  {qrResult.merged.map((hit, i) => (
                    <QrHitCard key={`merged-${i}`} hit={hit} />
                  ))}
                </>
              )}
              {qrResult.hits.length > 0 && (
                <>
                  <div className="pki-subhead dim">symbols</div>
                  {qrResult.hits.map((hit, i) => (
                    <QrHitCard key={`hit-${i}`} hit={hit} />
                  ))}
                </>
              )}
            </>
          )}
        </>
      )}
    </Section>
  );
}

// ---------------------------------------------------------------- stereo ----

function StereoTab() {
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const fileName = useStegoStore((s) => s.fileName);
  const stereoOffset = useStegoStore((s) => s.stereoOffset);
  const stereoEdgeHold = useStegoStore((s) => s.stereoEdgeHold);
  const stereoSampleStep = useStegoStore((s) => s.stereoSampleStep);
  const setStereoOffset = useStegoStore((s) => s.setStereoOffset);
  const setStereoEdgeHold = useStegoStore((s) => s.setStereoEdgeHold);
  const setStereoSampleStep = useStegoStore((s) => s.setStereoSampleStep);
  const stereoBusy = useStegoStore((s) => s.stereoBusy);
  const stereoError = useStegoStore((s) => s.stereoError);
  const stereoPng = useStegoStore((s) => s.stereoPng);
  const runStereoShift = useStegoStore((s) => s.runStereoShift);
  const stereoAutoBusy = useStegoStore((s) => s.stereoAutoBusy);
  const stereoAutoError = useStegoStore((s) => s.stereoAutoError);
  const stereoAuto = useStegoStore((s) => s.stereoAuto);
  const runStereoAuto = useStegoStore((s) => s.runStereoAuto);
  const applyStereoAuto = useStegoStore((s) => s.applyStereoAuto);
  const sendToWorkbench = useStegoStore((s) => s.sendToWorkbench);

  return (
    <Section title="Stereo shift">
      {!fileBase64 ? (
        <div className="rsa-empty dim">
          Load an autostereogram to solve it: the shift XORs the image with a horizontally shifted
          copy of itself, revealing the depth map once the shift matches the repeating pattern
          width. Auto-detect scans offsets for the strongest self-similarity.
        </div>
      ) : (
        <>
          <div className="pki-run-row">
            <button
              className="tool-btn"
              onClick={() => setStereoOffset(stereoOffset - 1)}
              disabled={stereoOffset <= 1}
              title="Previous offset"
            >
              ◀
            </button>
            <label
              className="pki-select-label"
              title="Horizontal shift in pixels; the engine wraps values at or beyond the width"
            >
              offset
              <input
                type="number"
                min={1}
                step={1}
                value={stereoOffset}
                onChange={(e) => setStereoOffset(Number(e.target.value))}
              />
            </label>
            <button
              className="tool-btn"
              onClick={() => setStereoOffset(stereoOffset + 1)}
              title="Next offset"
            >
              ▶
            </button>
            <label
              className="pki-select-label"
              title="Clamp the sample at the right edge instead of wrapping, removing the wrap-around seam on the last columns"
            >
              edge hold
              <input
                type="checkbox"
                checked={stereoEdgeHold}
                onChange={(e) => setStereoEdgeHold(e.target.checked)}
              />
            </label>
            <button
              className="bake-btn"
              onClick={() => void runStereoShift()}
              disabled={stereoBusy}
              title="Run image_stereo_shift with this offset on the original image bytes"
            >
              {stereoBusy ? "Shifting…" : "Stereo Shift"}
            </button>
          </div>
          <ErrorBanner error={stereoError} />

          <div className="pki-run-row">
            <label
              className="pki-select-label"
              title="Compare only every Nth row and column during the scan (1 = exhaustive); the scan is O(width² · height / step)"
            >
              sample step
              <input
                type="number"
                min={1}
                step={1}
                value={stereoSampleStep}
                onChange={(e) => setStereoSampleStep(Number(e.target.value))}
              />
            </label>
            <button
              className="bake-btn"
              onClick={() => void runStereoAuto()}
              disabled={stereoAutoBusy}
              title="Run image_stereo_auto: rank offsets 1..width/2 by self similarity, smallest offset wins ties"
            >
              {stereoAutoBusy ? "Scanning…" : "Auto-detect offset"}
            </button>
            {stereoAutoBusy && (
              <span className="dim sstv-busy-note">
                the scan runs to completion on the engine side — not cancellable
              </span>
            )}
          </div>
          <ErrorBanner error={stereoAutoError} />
          {stereoAuto && (
            <div className="sstv-applied">
              <div className="sstv-cand-head">
                <span className="pki-kind-chip">best offset {stereoAuto.best_offset}</span>
                <Chips
                  items={[
                    `sampled every ${stereoAuto.sample_step} px`,
                    `${stereoAuto.width}×${stereoAuto.height}`,
                  ]}
                />
                <span className="spacer" />
                {stereoAuto.best_offset > 0 && (
                  <button
                    className="tool-btn"
                    onClick={applyStereoAuto}
                    title="Set the shift offset to the detected value"
                  >
                    Use offset {stereoAuto.best_offset}
                  </button>
                )}
              </div>
              <div className="dim sstv-cand-reason">{stereoAuto.hint}</div>
            </div>
          )}

          {stereoPng !== null && (
            <div className="stego-viewport">
              <img
                src={`data:image/png;base64,${stereoPng}`}
                alt={`stereo shift at offset ${stereoOffset}`}
              />
              <div className="sstv-image-head">
                <span className="pki-kind-chip">offset {stereoOffset}</span>
                {stereoEdgeHold && <span className="pki-kind-chip">edge hold</span>}
                <span className="spacer" />
                <button
                  className="tool-btn"
                  onClick={() =>
                    downloadPng(stereoPng, `${fileName ?? "image"}-stereo-${stereoOffset}.png`)
                  }
                  title="Download the result PNG through the browser"
                >
                  Save PNG
                </button>
                <button
                  className="tool-btn"
                  onClick={() => sendToWorkbench(stereoPng)}
                  title="Put the result PNG into the Workbench input (base64)"
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

// ---------------------------------------------------------------- frames ----

/** Bounded number of frame metadata rows rendered at once. */
const FRAMES_RENDER_LIMIT = 256;

function FramesTab() {
  const fileBase64 = useStegoStore((s) => s.fileBase64);
  const fileName = useStegoStore((s) => s.fileName);
  const framesInfo = useStegoStore((s) => s.framesInfo);
  const framesBusy = useStegoStore((s) => s.framesBusy);
  const framesError = useStegoStore((s) => s.framesError);
  const runFramesInfo = useStegoStore((s) => s.runFramesInfo);
  const selectedFrame = useStegoStore((s) => s.selectedFrame);
  const frameBusy = useStegoStore((s) => s.frameBusy);
  const frameError = useStegoStore((s) => s.frameError);
  const framePng = useStegoStore((s) => s.framePng);
  const previewFrame = useStegoStore((s) => s.previewFrame);
  const analyzeFrame = useStegoStore((s) => s.analyzeFrame);
  const setTab = useStegoStore((s) => s.setTab);
  const sendToWorkbench = useStegoStore((s) => s.sendToWorkbench);

  // Index once per loaded file while the tab is visible; retry goes through the button.
  useEffect(() => {
    if (!fileBase64) return;
    if (framesBusy || framesError !== null || framesInfo !== null) return;
    void runFramesInfo();
  }, [fileBase64, framesBusy, framesError, framesInfo, runFramesInfo]);

  const frames = framesInfo?.frames ?? [];
  const shown = frames.slice(0, FRAMES_RENDER_LIMIT);

  const analyze = () => {
    analyzeFrame();
    setTab("transform");
  };

  return (
    <Section title="GIF frames">
      {!fileBase64 ? (
        <div className="rsa-empty dim">
          Load an animated GIF to index its frames without decoding pixel data: per-frame region,
          delay, disposal method, transparency and interlace — then preview any frame and analyze
          it with the rest of the Stego Lab.
        </div>
      ) : (
        <>
          <div className="pki-run-row">
            <button
              className="bake-btn"
              onClick={() => void runFramesInfo()}
              disabled={framesBusy}
              title="Re-run image_gif_info on the original file bytes"
            >
              {framesBusy ? "Indexing…" : framesInfo ? "Re-index" : "Index frames"}
            </button>
            {framesBusy && (
              <span className="dim sstv-busy-note">
                the index runs to completion on the engine side — not cancellable
              </span>
            )}
          </div>
          <ErrorBanner error={framesError} />
          {framesInfo && (
            <>
              <Chips
                items={[
                  `screen ${framesInfo.screen.width}×${framesInfo.screen.height}`,
                  `${framesInfo.frame_count} frame${framesInfo.frame_count === 1 ? "" : "s"}`,
                  framesInfo.frames_truncated
                    ? "frame index truncated (engine cap 4096)"
                    : null,
                ]}
              />
              <div className="stego-frames">
                <div className="stego-frame-row stego-frame-head dim">
                  <span>#</span>
                  <span>region</span>
                  <span>delay</span>
                  <span>disposal</span>
                  <span>flags</span>
                  <span />
                </div>
                {shown.map((f) => (
                  <div
                    key={f.index}
                    className={`stego-frame-row${selectedFrame === f.index ? " selected" : ""}`}
                  >
                    <span className="stego-frame-idx">{f.index}</span>
                    <span className="stego-frame-region">
                      {f.left},{f.top} · {f.width}×{f.height}
                    </span>
                    <span>{(f.delay_cs / 100).toFixed(2)} s</span>
                    <span>{f.disposal}</span>
                    <span className="dim">
                      {[
                        f.interlaced ? "interlaced" : null,
                        f.transparent_index !== null && f.transparent_index !== undefined
                          ? `transparent ${f.transparent_index}`
                          : null,
                      ]
                        .filter(Boolean)
                        .join(" · ") || "—"}
                    </span>
                    <button
                      className="tool-btn"
                      disabled={frameBusy}
                      onClick={() => void previewFrame(f.index)}
                      title="Decode and compose this frame as PNG (image_gif_frame)"
                    >
                      {selectedFrame === f.index && frameBusy ? "Decoding…" : "Preview"}
                    </button>
                  </div>
                ))}
              </div>
              {frames.length > shown.length && (
                <div className="dim sstv-cand-total">
                  +{frames.length - shown.length} more frames not listed (render bound{" "}
                  {FRAMES_RENDER_LIMIT})
                </div>
              )}
              <ErrorBanner error={frameError} />
              {framePng !== null && selectedFrame !== null && (
                <div className="stego-viewport">
                  <img
                    src={`data:image/png;base64,${framePng}`}
                    alt={`GIF frame ${selectedFrame}`}
                  />
                  <div className="sstv-image-head">
                    <span className="pki-kind-chip">frame {selectedFrame}</span>
                    <span className="dim">
                      composed onto the logical screen, as a viewer shows it
                    </span>
                    <span className="spacer" />
                    <button
                      className="tool-btn"
                      onClick={analyze}
                      title="Load this frame as the Stego Lab's active image (transforms, extract, QR, …)"
                    >
                      Analyze frame
                    </button>
                    <button
                      className="tool-btn"
                      onClick={() =>
                        downloadPng(framePng, `${fileName ?? "gif"}-frame-${selectedFrame}.png`)
                      }
                      title="Download the frame PNG through the browser"
                    >
                      Save PNG
                    </button>
                    <button
                      className="tool-btn"
                      onClick={() => sendToWorkbench(framePng)}
                      title="Put the frame PNG into the Workbench input (base64)"
                    >
                      → Workbench
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
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
  ["structure", "Structure"],
  ["qr", "QR"],
  ["stereo", "Stereo"],
  ["frames", "Frames"],
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
        Auto LSB rank the likely configurations. Structure, QR/barcode, stereo and GIF-frame tabs
        cover the rest of the container toolkit. Every operation runs in the Rust engine on the
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
            {tab === "structure" && <StructureTab />}
            {tab === "qr" && <QrTab />}
            {tab === "stereo" && <StereoTab />}
            {tab === "frames" && <FramesTab />}
          </div>
        </div>
      </div>
    </div>
  );
}
