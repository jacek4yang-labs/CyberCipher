import { useEffect } from "react";
import { useStore } from "../store";
import type { AssistHit, AutoCandidate } from "../api";
import { formatSize } from "../format";

/** The backend already bounds previews; the card shows a further-trimmed copy. */
const ASSIST_PREVIEW_LIMIT = 600;

export function AutoPage() {
  const candidates = useStore((s) => s.autoCandidates);
  const autoRunning = useStore((s) => s.autoRunning);
  const runAuto = useStore((s) => s.runAuto);
  const applyAutoCandidate = useStore((s) => s.applyAutoCandidate);
  const inputText = useStore((s) => s.inputText);
  const ready = inputText.trim().length > 0;

  const assistCiphertext = useStore((s) => s.assistCiphertext);
  const assistEncoding = useStore((s) => s.assistEncoding);
  const assistKeyCandidate = useStore((s) => s.assistKeyCandidate);
  const assistIvHex = useStore((s) => s.assistIvHex);
  const assistHint = useStore((s) => s.assistHint);
  const assistResult = useStore((s) => s.assistResult);
  const assistRunning = useStore((s) => s.assistRunning);
  const assistError = useStore((s) => s.assistError);
  const setAssistCiphertext = useStore((s) => s.setAssistCiphertext);
  const setAssistEncoding = useStore((s) => s.setAssistEncoding);
  const setAssistKeyCandidate = useStore((s) => s.setAssistKeyCandidate);
  const setAssistIvHex = useStore((s) => s.setAssistIvHex);
  const setAssistHint = useStore((s) => s.setAssistHint);
  const runCryptoAssist = useStore((s) => s.runCryptoAssist);
  const applyAssistHit = useStore((s) => s.applyAssistHit);

  const assistReady =
    assistCiphertext.trim().length > 0 && assistKeyCandidate.trim().length > 0;

  // Ctrl+Enter runs the assist while the Auto Analyze page is open.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        void runCryptoAssist();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [runCryptoAssist]);

  return (
    <div className="page auto-page">
      <h2>Auto Analyze</h2>
      <p className="dim auto-expl">
        Bounded, explainable automatic decoding: cheap detectors propose
        transformations, the engine executes and scores them (beam width 16,
        max depth 6), and every claim shows its evidence. Nothing is certain
        unless the evidence says so.
      </p>
      <button className="bake-btn" onClick={() => void runAuto()} disabled={!ready || autoRunning}>
        {autoRunning ? "Analyzing…" : "Analyze input"}
      </button>
      {!ready && <p className="dim">Set an input in the Workbench first — the analyzer uses the same input buffer and encoding.</p>}

      <div className="auto-results">
        {candidates.length === 0 && !autoRunning && ready && (
          <div className="dim">No plausible decoding found — high-entropy or unknown-binary input is reported honestly rather than guessed.</div>
        )}
        {candidates.map((c, i) => (
          <CandidateCard key={i} candidate={c} index={i} onApply={() => applyAutoCandidate(i)} />
        ))}
      </div>

      <h2>Crypto Assist</h2>
      <p className="dim auto-expl">
        AES parameter recovery around what you already have: give the ciphertext
        and the key material in any encoding, and the assist enumerates only the
        structurally possible candidates — key as UTF-8/hex/Base64, every mode
        and padding, IV from your input, carved from the first/last block, or
        zero — executes them through the real operation registry, and ranks the
        results with per-candidate evidence. It never truncates keys and never
        claims a match it cannot show.
      </p>

      <div className="assist-card">
        <div className="assist-form">
          <div className="assist-field">
            <label htmlFor="assist-ciphertext">ciphertext</label>
            <textarea
              id="assist-ciphertext"
              spellCheck={false}
              placeholder="paste the ciphertext — the outer encoding is decoded first…"
              value={assistCiphertext}
              onChange={(e) => setAssistCiphertext(e.target.value)}
            />
          </div>
          <div className="assist-row">
            <div className="assist-field assist-enc">
              <label htmlFor="assist-encoding">encoding</label>
              <select
                id="assist-encoding"
                value={assistEncoding}
                onChange={(e) => setAssistEncoding(e.target.value as typeof assistEncoding)}
                title="How the ciphertext text is decoded into bytes before the search"
              >
                <option value="utf8">UTF-8</option>
                <option value="hex">Hex</option>
                <option value="base64">Base64</option>
                <option value="decimal">Decimal</option>
              </select>
            </div>
            <div className="assist-field">
              <label htmlFor="assist-key">key candidate</label>
              <input
                id="assist-key"
                type="text"
                spellCheck={false}
                autoComplete="off"
                placeholder="as text, hex or Base64 — decoded to 16/24/32 bytes"
                value={assistKeyCandidate}
                onChange={(e) => setAssistKeyCandidate(e.target.value)}
              />
            </div>
            <div className="assist-field">
              <label htmlFor="assist-iv">iv (hex, optional)</label>
              <input
                id="assist-iv"
                type="text"
                spellCheck={false}
                autoComplete="off"
                placeholder="e.g. 0f0e0d0c… — else carved or zero"
                value={assistIvHex}
                onChange={(e) => setAssistIvHex(e.target.value)}
              />
            </div>
            <div className="assist-field">
              <label htmlFor="assist-hint">known plaintext (optional)</label>
              <input
                id="assist-hint"
                type="text"
                spellCheck={false}
                autoComplete="off"
                placeholder='e.g. flag{ — boosts matching hits'
                value={assistHint}
                onChange={(e) => setAssistHint(e.target.value)}
              />
            </div>
          </div>
          <div className="assist-run-row">
            <button
              className="bake-btn"
              onClick={() => void runCryptoAssist()}
              disabled={!assistReady || assistRunning}
              title="Run the assist search (Ctrl+Enter)"
            >
              {assistRunning ? "Assisting…" : "Assist"}
            </button>
            <span className="dim assist-kbd">Ctrl+Enter · 10 s budget</span>
          </div>
          {assistError && <div className="assist-error">{assistError}</div>}
        </div>
      </div>

      {assistRunning && (
        <div className="auto-results assist-results">
          <div className="dim">Searching structurally possible candidates…</div>
        </div>
      )}
      {assistResult && !assistRunning && (
        <div className="auto-results assist-results">
          <div className="assist-meta">
            {assistResult.hits.length} hit{assistResult.hits.length === 1 ? "" : "s"} ·{" "}
            {assistResult.candidates_tried} candidates tried ·{" "}
            {assistResult.candidates_pruned} pruned ·{" "}
            {Math.round(assistResult.deadline_ms / 1000)} s budget
            {assistResult.timed_out && (
              <span className="assist-warn"> · budget exhausted — results are partial</span>
            )}
          </div>
          {assistResult.hits.length === 0 && (
            <div className="dim">
              Every structurally possible candidate executed and scored, and none
              produced a plausible plaintext — reported honestly rather than
              guessed. The key material may not be AES-128/192/256, or the
              ciphertext may be encoded twice.
            </div>
          )}
          {assistResult.hits.map((hit) => (
            <HitCard key={hit.rank} hit={hit} onApply={() => applyAssistHit(hit)} />
          ))}
        </div>
      )}
    </div>
  );
}

function CandidateCard({
  candidate,
  index,
  onApply,
}: {
  candidate: AutoCandidate;
  index: number;
  onApply: () => void;
}) {
  const scorePct = Math.round(candidate.score * 100);
  return (
    <div className={`auto-card${candidate.confident ? " confident" : ""}`}>
      <div className="auto-card-head">
        <span className="auto-rank">#{index + 1}</span>
        <span className="auto-score">{scorePct}%</span>
        {candidate.confident ? (
          <span className="auto-confident">confident</span>
        ) : (
          <span className="auto-unconfident">unconfirmed</span>
        )}
        <span className="auto-size">
          {formatSize(candidate.size)} · {candidate.kind}
        </span>
        <button className="bake-btn" onClick={onApply} title="Build this decoding as a recipe in the Workbench">
          Apply as recipe
        </button>
      </div>
      <div className="auto-path">
        {candidate.path.map((op, i) => (
          <span key={i}>
            <code>{op}</code>
            {i < candidate.path.length - 1 && <span className="arrow"> → </span>}
          </span>
        ))}
      </div>
      <ul className="auto-evidence">
        {candidate.evidence.map((e, i) => (
          <li key={i}>✓ {e}</li>
        ))}
      </ul>
      <pre className="auto-preview">{candidate.preview.slice(0, 400)}</pre>
      {candidate.flag_like && <div className="flag-hint">🎯 {candidate.flag_like}</div>}
    </div>
  );
}

function HitCard({ hit, onApply }: { hit: AssistHit; onApply: () => void }) {
  const scorePct = Math.round(hit.score * 100);
  const carved = hit.iv_source === "first_block" || hit.iv_source === "last_block";
  return (
    <div className={`auto-card${hit.confident ? " confident" : ""}`}>
      <div className="auto-card-head">
        <span className="auto-rank">#{hit.rank}</span>
        <span className="auto-score">{scorePct}%</span>
        {hit.confident ? (
          <span className="auto-confident">confident</span>
        ) : (
          <span className="auto-unconfident">unconfirmed</span>
        )}
        <span className="auto-size">
          {hit.cipher} · {hit.mode} · {hit.key_length * 8}-bit key
        </span>
        <button
          className="bake-btn"
          onClick={onApply}
          title={
            carved
              ? "Build this as a recipe in the Workbench — the carved IV block must then be trimmed from the input by hand"
              : "Build this decryption as a recipe in the Workbench"
          }
        >
          Apply as Recipe
        </button>
      </div>
      <div className="assist-params">
        <span>
          key <code>{hit.key_hex}</code> ({hit.key_interpretation})
        </span>
        {hit.mode !== "ecb" && (
          <span>
            iv <code>{hit.iv_hex}</code> ({hit.iv_source.replace("_", " ")})
          </span>
        )}
        {hit.padding && (
          <span>
            padding <code>{hit.padding}</code>
          </span>
        )}
      </div>
      <ul className="auto-evidence">
        {hit.evidence.map((e, i) => (
          <li key={i}>✓ {e}</li>
        ))}
      </ul>
      <pre className="auto-preview">{hit.preview.slice(0, ASSIST_PREVIEW_LIMIT)}</pre>
    </div>
  );
}
