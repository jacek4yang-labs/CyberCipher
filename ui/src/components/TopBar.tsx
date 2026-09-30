import { useStore } from "../store";
import type { Page } from "../store";
import { useOutputFlag } from "./DataPanel";
import { formatDuration } from "../format";
import { useState } from "react";

export function TopBar() {
  const page = useStore((s) => s.page);
  const setPage = useStore((s) => s.setPage);
  const autoBake = useStore((s) => s.autoBake);
  const setAutoBake = useStore((s) => s.setAutoBake);
  const bake = useStore((s) => s.bake);
  const baking = useStore((s) => s.baking);
  const setSaveDialogOpen = useStore((s) => s.setSaveDialogOpen);
  const theme = useStore((s) => s.theme);
  const setTheme = useStore((s) => s.setTheme);

  return (
    <header className="top-bar">
      <div className="brand" onClick={() => setPage("workbench")}>
        Cyber<span>Cipher</span>
      </div>
      <nav className="nav">
        {(
          [
            ["workbench", "Workbench"],
            ["rsa-lab", "RSA Lab"],
            ["pki-lab", "PKI Lab"],
            ["sstv-lab", "SSTV Lab"],
            ["auto", "Auto Analyze"],
            ["recipes", "Recipes"],
            ["settings", "Settings"],
          ] as [Page, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            className={`nav-btn${page === id ? " active" : ""}`}
            onClick={() => setPage(id)}
          >
            {label}
          </button>
        ))}
      </nav>
      <div className="top-actions">
        <label className="auto-bake" title="Automatically bake when input or recipe changes (instant and interactive operations only)">
          <input
            type="checkbox"
            checked={autoBake}
            onChange={(e) => setAutoBake(e.target.checked)}
          />
          Auto Bake
        </label>
        <button className="bake-btn" onClick={() => void bake(true)} disabled={baking}>
          {baking ? "Baking…" : "▶ Bake"}
        </button>
        <button className="tool-btn" onClick={() => setSaveDialogOpen(true)} title="Save recipe (Ctrl+S)">
          Save
        </button>
        <button
          className="tool-btn"
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          title="Toggle theme"
        >
          {theme === "dark" ? "☀" : "☾"}
        </button>
      </div>
    </header>
  );
}

export function StatusBar() {
  const report = useStore((s) => s.report);
  const baking = useStore((s) => s.baking);
  const lastError = useStore((s) => s.lastError);
  const recipe = useStore((s) => s.recipe);
  const flag = useOutputFlag();

  const status = lastError
    ? `error: ${lastError}`
    : report?.blocked_at
      ? "stopped at manual-bake operation"
      : baking
        ? "baking…"
        : recipe.length === 0
          ? "empty recipe"
          : "ready";

  return (
    <footer className="status-bar">
      <span className={lastError ? "status-err" : "status-ok"}>{status}</span>
      <span className="spacer" />
      {report && !lastError && (
        <span>
          {report.stages.length} stage{report.stages.length === 1 ? "" : "s"}
          {report.cached_stages > 0 ? ` (${report.cached_stages} cached)` : ""} ·{" "}
          {formatDuration(report.duration_us)}
        </span>
      )}
      {flag && <span className="flag-hint" title={flag}>🎯 {flag.slice(0, 60)}</span>}
    </footer>
  );
}

export function SaveDialog() {
  const open = useStore((s) => s.saveDialogOpen);
  const setOpen = useStore((s) => s.setSaveDialogOpen);
  const saveRecipe = useStore((s) => s.saveRecipe);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  const submit = async () => {
    try {
      await saveRecipe(name);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="modal-backdrop" onClick={() => setOpen(false)}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Save recipe</h3>
        <input
          autoFocus
          type="text"
          placeholder="Recipe name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void submit();
            if (e.key === "Escape") setOpen(false);
          }}
        />
        {error && <div className="modal-error">{error}</div>}
        <div className="modal-actions">
          <button className="tool-btn" onClick={() => setOpen(false)}>
            Cancel
          </button>
          <button className="bake-btn" onClick={() => void submit()} disabled={!name.trim()}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
