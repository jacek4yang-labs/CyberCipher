import { useStore } from "../store";
import type { AutoCandidate } from "../api";
import { formatSize } from "../format";

export function AutoPage() {
  const candidates = useStore((s) => s.autoCandidates);
  const autoRunning = useStore((s) => s.autoRunning);
  const runAuto = useStore((s) => s.runAuto);
  const applyAutoCandidate = useStore((s) => s.applyAutoCandidate);
  const inputText = useStore((s) => s.inputText);
  const ready = inputText.trim().length > 0;

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
