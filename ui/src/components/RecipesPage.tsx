import { useEffect, useState } from "react";
import { api, type RecipeMeta } from "../api";
import { useStore } from "../store";

export function RecipesPage() {
  const [recipes, setRecipes] = useState<RecipeMeta[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [importJson, setImportJson] = useState("");
  const [importName, setImportName] = useState("");
  const loadRecipeByName = useStore((s) => s.loadRecipeByName);
  const importRecipeJson = useStore((s) => s.importRecipeJson);
  const setPage = useStore((s) => s.setPage);

  const refresh = () => {
    api
      .listSavedRecipes()
      .then(setRecipes)
      .catch((e) => setError(String(e)));
  };

  useEffect(refresh, []);

  const remove = async (name: string) => {
    await api.deleteRecipe(name);
    refresh();
  };

  const doImport = () => {
    if (importRecipeJson(importJson)) {
      setImportJson("");
      setImportName("");
      setPage("workbench");
    } else {
      setError("Import failed: not a valid CyberCipher v1 recipe.");
    }
  };

  return (
    <div className="page">
      <h2>Saved recipes</h2>
      {error && <div className="op-error">{error}</div>}
      <div className="recipe-table">
        {recipes.length === 0 && <div className="dim">No saved recipes yet. Save one from the Workbench.</div>}
        {recipes.map((r) => (
          <div className="recipe-row" key={r.name}>
            <span className="recipe-row-name">{r.name}</span>
            <span className="dim">{r.op_count} ops</span>
            <span className="dim">{r.modified}</span>
            <div className="recipe-row-actions">
              <button
                className="bake-btn"
                onClick={() => {
                  void loadRecipeByName(r.name);
                }}
              >
                Load
              </button>
              <button className="tool-btn danger" onClick={() => void remove(r.name)}>
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>

      <h2>Import recipe (JSON)</h2>
      <div className="import-area">
        <input
          type="text"
          placeholder="Name (optional)"
          value={importName}
          onChange={(e) => setImportName(e.target.value)}
        />
        <textarea
          rows={6}
          spellCheck={false}
          placeholder='{"version":1,"nodes":[{"id":"n1","op":"from-hex","enabled":true,"params":{}}]}'
          value={importJson}
          onChange={(e) => setImportJson(e.target.value)}
        />
        <button className="bake-btn" onClick={doImport} disabled={!importJson.trim()}>
          Import & open
        </button>
      </div>
    </div>
  );
}
