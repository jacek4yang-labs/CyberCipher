import { useEffect, useMemo, useState, type DragEvent, type ReactNode } from "react";
import {
  SSTV_MAX_SECONDS_CAP,
  bytesToBase64,
  useSstvStore,
  type ExtractResult,
  type LsbCandidate,
  type LsbRun,
  type SstvChannelKind,
} from "../sstvStore";
import { formatSize, toHex } from "../format";
import type { SstvImage, SstvReport, SstvReportDetection } from "../api";

// ---------------------------------------------------------------------------
// Shared pieces (same vocabulary as the PKI/RSA labs: pki-section rows,
// rsa-error-banner diagnostics, pki-kind-chip facts)
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

/** Number/percentage helpers that return null when the report omits a field. */
function pctOf(v: number | undefined, digits = 0): string | null {
  if (v === undefined || !Number.isFinite(v)) return null;
  return `${(v * 100).toFixed(digits)}%`;
}

function numOf(v: number | undefined, digits: number, suffix = ""): string | null {
  if (v === undefined || !Number.isFinite(v)) return null;
  return `${v.toFixed(digits)}${suffix}`;
}

function signedNum(v: number | undefined, digits: number, suffix = ""): string | null {
  if (v === undefined || !Number.isFinite(v)) return null;
  return `${v >= 0 ? "+" : ""}${v.toFixed(digits)}${suffix}`;
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

// ------------------------------------------------------------- summary ----

function DetectionView({ detection }: { detection: SstvReportDetection }) {
  const vis =
    detection.vis_code !== undefined
      ? `VIS 0x${detection.vis_code.toString(16).padStart(2, "0")}`
      : null;
  return (
    <div className="pki-report">
      <div className="pki-report-head">
        <span className="pki-kind-chip">{detection.mode ?? "unknown mode"}</span>
        {vis && <span className="pki-kind-chip">{vis}</span>}
        {detection.detected_by && <span className="pki-kind-chip">via {detection.detected_by}</span>}
        {detection.complete === false && <span className="pki-kind-chip">incomplete</span>}
      </div>
      <Chips
        items={[
          detection.confidence !== undefined
            ? `confidence ${pctOf(detection.confidence) ?? "?"}`
            : null,
          detection.signal_agreement !== undefined
            ? `signal agreement ${pctOf(detection.signal_agreement) ?? "?"}`
            : null,
          detection.coverage !== undefined ? `coverage ${pctOf(detection.coverage) ?? "?"}` : null,
          detection.width !== undefined && detection.height !== undefined
            ? `${detection.width}×${detection.height}`
            : null,
          detection.matched_syncs !== undefined ? `${detection.matched_syncs} matched syncs` : null,
          signedNum(detection.frequency_offset_hz, 1, " Hz")
            ? `freq offset ${signedNum(detection.frequency_offset_hz, 1, " Hz")}`
            : null,
          numOf(detection.clock_rate, 4, "×")
            ? `clock ${numOf(detection.clock_rate, 4, "×")}${
                detection.clock_error_percent !== undefined
                  ? ` (${signedNum(detection.clock_error_percent, 2, "%")})`
                  : ""
              }`
            : null,
          numOf(detection.image_start_seconds, 2, " s")
            ? `image starts at ${numOf(detection.image_start_seconds, 2, " s")}`
            : null,
          detection.image_quality !== undefined
            ? `image plausibility ${pctOf(detection.image_quality) ?? "?"}`
            : null,
        ]}
      />
      {detection.evidence && detection.evidence.length > 0 && (
        <div className="pki-alternatives">evidence: {detection.evidence.join(" · ")}</div>
      )}
      {detection.ambiguous_with && detection.ambiguous_with.length > 0 && (
        <div className="pki-alternatives">
          ambiguous with {detection.ambiguous_with.join(", ")} — these decode identically without
          a VIS header
        </div>
      )}
    </div>
  );
}

function ReportSummary({ report }: { report: SstvReport }) {
  const audio = report.audio;
  return (
    <Section title="Detection summary">
      <Chips
        items={[
          report.tool_version ? `engine ${report.tool_version}` : null,
          report.hypotheses_evaluated !== undefined
            ? `${report.hypotheses_evaluated} hypotheses evaluated`
            : null,
          numOf(audio?.duration_seconds, 2, " s")
            ? `audio ${numOf(audio?.duration_seconds, 2, " s")}`
            : null,
          numOf(audio?.analysis_rate_hz, 0, " Hz")
            ? `analysis rate ${numOf(audio?.analysis_rate_hz, 0, " Hz")}`
            : null,
          audio?.source_channels !== undefined ? `${audio.source_channels} source ch` : null,
          audio?.selected_channel ?? null,
          numOf(audio?.normalized_peak, 2) ? `peak ${numOf(audio?.normalized_peak, 2)}` : null,
        ]}
      />
      {report.warnings && report.warnings.length > 0 && (
        <div className="sstv-warnings">
          {report.warnings.map((w, i) => (
            <div key={i} className="sstv-warning">
              ⚠ {w}
            </div>
          ))}
        </div>
      )}
      {(report.detections ?? []).length === 0 ? (
        <div className="dim">
          No SSTV transmission detected. The report's warnings above say what the analysis saw.
        </div>
      ) : (
        (report.detections ?? []).map((d, i) => <DetectionView key={i} detection={d} />)
      )}
    </Section>
  );
}

// --------------------------------------------------------------- images ----

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

function CandidateView({
  rank,
  candidate,
  applyBusy,
  onApply,
}: {
  rank: number;
  candidate: LsbCandidate;
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
        <span className="spacer" />
        <button
          className="tool-btn"
          onClick={onApply}
          disabled={applyBusy}
          title="Run Extract Bits with this candidate's settings"
        >
          {applyBusy ? "Extracting…" : "Apply"}
        </button>
      </div>
      <div className="dim sstv-cand-config">
        {candidate.settings.config} — {candidate.settings.description}
      </div>
      <div className="dim sstv-cand-reason">{candidate.reason}</div>
      <BytePreview bytes={previewBytes} />
      <div className="dim sstv-cand-total">
        full extraction: {formatSize(candidate.total_bytes)}
        {candidate.truncated ? " (preview was truncated)" : ""}
      </div>
    </div>
  );
}

function AppliedView({
  applied,
  onSendBytes,
  onSendAutoDecode,
}: {
  applied: ExtractResult;
  onSendBytes: (base64: string) => void;
  onSendAutoDecode: (base64: string) => void;
}) {
  const [copied, setCopied] = useState(false);
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
          onClick={() => onSendBytes(bytesToBase64(applied.data))}
          title="Put the extracted bytes into the Workbench input (base64)"
        >
          → Workbench
        </button>
        <button
          className="tool-btn"
          onClick={() => onSendAutoDecode(bytesToBase64(applied.data))}
          title="Run Auto Analyze on the extracted bytes"
        >
          → Auto Decode
        </button>
        <button
          className={`tool-btn${copied ? " copied" : ""}`}
          onClick={() => {
            void navigator.clipboard.writeText(toHex(applied.data)).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            });
          }}
          title="Copy the full payload as lowercase hex"
        >
          {copied ? "Copied ✓" : "Copy Hex"}
        </button>
      </div>
      {applied.data.length > 0 && <BytePreview bytes={applied.data} />}
    </div>
  );
}

function ImageCard({ image }: { image: SstvImage }) {
  const run: LsbRun | undefined = useSstvStore((s) => s.lsbRuns[image.detection_index]);
  const setLsbDeep = useSstvStore((s) => s.setLsbDeep);
  const runAutoLsb = useSstvStore((s) => s.runAutoLsb);
  const applyCandidate = useSstvStore((s) => s.applyCandidate);
  const sendToWorkbench = useSstvStore((s) => s.sendToWorkbench);
  const sendToAutoDecode = useSstvStore((s) => s.sendToAutoDecode);
  const openInStegoLab = useSstvStore((s) => s.openInStegoLab);
  const dataUrl = `data:image/png;base64,${image.png_base64}`;
  const lsb: LsbRun = run ?? {
    busy: false,
    error: null,
    deep: false,
    candidates: null,
    applyBusy: false,
    applyError: null,
    applied: null,
  };

  return (
    <div className="sstv-image-card">
      <img src={dataUrl} alt={`decoded SSTV image ${image.mode_name}`} />
      <div className="sstv-image-head">
        <span className="pki-kind-chip">{image.mode_name}</span>
        <span className="pki-kind-chip">
          {image.width}×{image.height}
        </span>
        <span className="dim">{formatSize(image.size)}</span>
      </div>
      <div className="sstv-image-actions">
        <button
          className="tool-btn"
          onClick={() =>
            downloadPng(
              image.png_base64,
              `sstv-${image.detection_index + 1}-${image.mode_slug}.png`,
            )
          }
          title="Download the PNG through the browser"
        >
          Save PNG
        </button>
        <button
          className="tool-btn"
          onClick={() => sendToWorkbench(image.png_base64)}
          title="Put the PNG into the Workbench input (base64)"
        >
          → Workbench
        </button>
        <button
          className="tool-btn"
          onClick={() => openInStegoLab(image)}
          title="Load this PNG as the Stego Lab's active image (in-memory, no temp files)"
        >
          → Stego Lab
        </button>
      </div>

      <div className="sstv-lsb-box">
        <div className="pki-run-row">
          <label
            className="pki-select-label"
            title="Adds rarer configurations (3/4-bit LSB, MSB bit 7, single-channel bit 2/7) to the Fast enumeration"
          >
            deep
            <input
              type="checkbox"
              checked={lsb.deep}
              onChange={(e) => setLsbDeep(image.detection_index, e.target.checked)}
              disabled={lsb.busy}
            />
          </label>
          <button
            className="bake-btn"
            onClick={() => void runAutoLsb(image, lsb.deep)}
            disabled={lsb.busy}
            title="Run the auto_lsb_scan registry op on this image"
          >
            {lsb.busy ? "Scanning…" : "Run Auto LSB"}
          </button>
        </div>
        <ErrorBanner error={lsb.error} />
        {lsb.candidates !== null && lsb.candidates.length === 0 && (
          <div className="dim">no candidates scored above the empty-extract baseline</div>
        )}
        {lsb.candidates !== null && lsb.candidates.length > 0 && (
          <div className="sstv-candidates">
            {lsb.candidates.map((candidate, i) => (
              <CandidateView
                key={candidate.fingerprint}
                rank={i + 1}
                candidate={candidate}
                applyBusy={lsb.applyBusy}
                onApply={() => void applyCandidate(image, candidate)}
              />
            ))}
          </div>
        )}
        <ErrorBanner error={lsb.applyError} />
        {lsb.applied && (
          <AppliedView
            applied={lsb.applied}
            onSendBytes={sendToWorkbench}
            onSendAutoDecode={sendToAutoDecode}
          />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- input ----

function AudioInputSection() {
  const fileName = useSstvStore((s) => s.fileName);
  const fileSize = useSstvStore((s) => s.fileSize);
  const fileBytes = useSstvStore((s) => s.fileBytes);
  const loadFile = useSstvStore((s) => s.loadFile);
  const clearFile = useSstvStore((s) => s.clearFile);
  const modes = useSstvStore((s) => s.modes);
  const modesError = useSstvStore((s) => s.modesError);
  const channelKind = useSstvStore((s) => s.channelKind);
  const channelIndex = useSstvStore((s) => s.channelIndex);
  const forcedMode = useSstvStore((s) => s.forcedMode);
  const blind = useSstvStore((s) => s.blind);
  const maxSeconds = useSstvStore((s) => s.maxSeconds);
  const setChannelKind = useSstvStore((s) => s.setChannelKind);
  const setChannelIndex = useSstvStore((s) => s.setChannelIndex);
  const setForcedMode = useSstvStore((s) => s.setForcedMode);
  const setBlind = useSstvStore((s) => s.setBlind);
  const setMaxSeconds = useSstvStore((s) => s.setMaxSeconds);
  const decoding = useSstvStore((s) => s.decoding);
  const decodeError = useSstvStore((s) => s.decodeError);
  const decode = useSstvStore((s) => s.decode);
  const [dragOver, setDragOver] = useState(false);

  const onDrop = (e: DragEvent<HTMLElement>) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) void loadFile(file);
  };

  return (
    <Section title="Audio input">
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
          accept="audio/*,.wav,.flac,.mp3,.ogg,.oga,.opus,.m4a,.aac"
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
              {fileBytes ? "" : " — reading…"}
            </div>
            <div className="dim">click to choose a different file, or drop one here</div>
          </>
        ) : (
          <>
            <div>drop an audio file here, or click to choose</div>
            <div className="dim">WAV, FLAC, MP3, Ogg — anything the engine ingests</div>
          </>
        )}
      </label>
      {fileName && (
        <div className="pki-run-row">
          <button
            className="tool-btn"
            onClick={clearFile}
            disabled={decoding}
            title="Clear the chosen file and results"
          >
            Clear
          </button>
        </div>
      )}

      <div className="pki-run-row">
        <label
          className="pki-select-label"
          title="auto scores every channel and picks the strongest; mono averages all channels; index is zero-based"
        >
          channel
          <select
            value={channelKind}
            onChange={(e) => setChannelKind(e.target.value as SstvChannelKind)}
          >
            <option value="auto">auto</option>
            <option value="mono">mono (average)</option>
            <option value="left">left</option>
            <option value="right">right</option>
            <option value="index">channel index…</option>
          </select>
        </label>
        {channelKind === "index" && (
          <label className="pki-select-label">
            index
            <input
              type="number"
              min={0}
              step={1}
              value={channelIndex}
              onChange={(e) => {
                const parsed = Number.parseInt(e.target.value, 10);
                setChannelIndex(Number.isNaN(parsed) || parsed < 0 ? 0 : parsed);
              }}
            />
          </label>
        )}
      </div>

      <div className="pki-run-row">
        <label
          className="pki-select-label"
          title="Restrict the decode to one mode instead of detecting; blank = automatic"
        >
          mode
          <select value={forcedMode} onChange={(e) => setForcedMode(e.target.value)}>
            <option value="">automatic (detect)</option>
            {modes.map((m) => (
              <option key={m.slug} value={m.slug}>
                {m.name} ({m.slug} · VIS 0x{m.vis_code.toString(16).padStart(2, "0")})
              </option>
            ))}
          </select>
        </label>
      </div>
      {modesError && <ErrorBanner error={`mode list unavailable: ${modesError}`} />}

      <div className="pki-run-row">
        <label
          className="pki-select-label"
          title="Reject audio longer than this before any decode work; the engine caps it at 300 s"
        >
          max seconds
          <input
            type="number"
            min={1}
            max={SSTV_MAX_SECONDS_CAP}
            step={1}
            value={maxSeconds}
            onChange={(e) => setMaxSeconds(Number(e.target.value))}
          />
        </label>
        <label
          className="pki-select-label"
          title="Fall back to sync-period inference when the VIS header is absent or damaged"
        >
          blind recovery
          <input type="checkbox" checked={blind} onChange={(e) => setBlind(e.target.checked)} />
        </label>
      </div>

      <div className="pki-run-row">
        <button
          className="bake-btn"
          onClick={() => void decode()}
          disabled={decoding || fileBytes === null || fileBytes.length === 0}
          title={fileBytes ? "Decode with sstv_decode_audio" : "Choose an audio file first"}
        >
          {decoding ? "Decoding…" : "Decode"}
        </button>
        {decoding && (
          <span className="dim sstv-busy-note">
            decoding runs to completion on the engine side — not cancellable
          </span>
        )}
      </div>
      <ErrorBanner error={decodeError} />
    </Section>
  );
}

// ------------------------------------------------------------- evidence ----

function EvidenceSection() {
  const report = useSstvStore((s) => s.result?.report ?? null);
  const reportOpen = useSstvStore((s) => s.reportOpen);
  const setReportOpen = useSstvStore((s) => s.setReportOpen);
  const json = useMemo(() => (report ? JSON.stringify(report, null, 2) : ""), [report]);
  if (!report) return null;
  return (
    <Section title="Evidence">
      <button className="pki-advanced-toggle" onClick={() => setReportOpen(!reportOpen)}>
        <span className="pki-twist">{reportOpen ? "▾" : "▸"}</span> Raw report JSON (
        {formatSize(json.length)}) — everything the engine measured, nothing added
      </button>
      {reportOpen && <pre className="sstv-evidence">{json}</pre>}
    </Section>
  );
}

// ----------------------------------------------------------------- page ----

export function SstvLabPage() {
  const result = useSstvStore((s) => s.result);
  const loadModes = useSstvStore((s) => s.loadModes);

  useEffect(() => {
    void loadModes();
  }, [loadModes]);

  return (
    <div className="page sstv-page">
      <h2>SSTV Lab</h2>
      <p className="dim sstv-expl">
        Automatic SSTV decode: VIS / sync-period mode detection, frequency-offset and clock
        recovery, and a full-resolution decode of the best candidates. Decoded images can be
        saved, sent to the Workbench or the Stego Lab, or passed through the Auto LSB scanner —
        all analysis runs in the Rust engine.
      </p>
      <div className="sstv-layout">
        <div className="sstv-input-col">
          <AudioInputSection />
        </div>
        <div className="sstv-results-col">
          {result && (
            <>
              <ReportSummary report={result.report} />
              {result.images.length > 0 && (
                <Section title={`Decoded images (${result.images.length})`}>
                  <div className="sstv-images">
                    {result.images.map((image) => (
                      <ImageCard key={image.detection_index} image={image} />
                    ))}
                  </div>
                </Section>
              )}
              <EvidenceSection />
            </>
          )}
          {!result && (
            <div className="rsa-empty dim">
              No decode yet. Load an SSTV recording and press <b>Decode</b> — the report shows how
              each mode was detected (VIS header, sync period, or forced) with confidence, timing
              and frequency evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
