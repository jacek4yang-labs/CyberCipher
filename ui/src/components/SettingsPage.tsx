import { useStore } from "../store";

export function SettingsPage() {
  const theme = useStore((s) => s.theme);
  const setTheme = useStore((s) => s.setTheme);
  const autoBake = useStore((s) => s.autoBake);
  const setAutoBake = useStore((s) => s.setAutoBake);

  return (
    <div className="page">
      <h2>Settings</h2>
      <div className="settings-group">
        <div className="settings-row">
          <label htmlFor="theme">Theme</label>
          <select id="theme" value={theme} onChange={(e) => setTheme(e.target.value as "dark" | "light")}>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
          <span className="dim">High-contrast technical theme.</span>
        </div>
        <div className="settings-row">
          <label htmlFor="autobake">Auto Bake</label>
          <input
            id="autobake"
            type="checkbox"
            checked={autoBake}
            onChange={(e) => setAutoBake(e.target.checked)}
          />
          <span className="dim">
            Re-run the recipe automatically while you type. Heavy and solver operations always
            require an explicit Bake.
          </span>
        </div>
      </div>

      <h2>About</h2>
      <div className="settings-group dim">
        <p>
          CyberCipher — Crypto, decode, analyze, solve. A local-first cryptography and CTF
          workbench. All processing happens on this machine; nothing is sent to remote services.
        </p>
        <p>
          Saved recipes live in your user configuration directory under{" "}
          <code>cybercipher/recipes/</code>.
        </p>
      </div>
    </div>
  );
}
