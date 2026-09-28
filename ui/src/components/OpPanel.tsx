import { useEffect, useRef, useState } from "react";
import { useStore } from "../store";
import type { OperationInfo } from "../api";

const COST_LABEL: Record<OperationInfo["cost"], string> = {
  instant: "inst",
  interactive: "int",
  heavy: "heavy",
  solver: "solver",
  external: "ext",
};

export function OpPanel() {
  const ops = useStore((s) => s.ops);
  const addOp = useStore((s) => s.addOp);
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const q = query.trim().toLowerCase();
  const filtered = q
    ? ops.filter((op) => matches(op, q))
    : ops;

  const groups = new Map<string, OperationInfo[]>();
  for (const op of filtered) {
    const list = groups.get(op.category) ?? [];
    list.push(op);
    groups.set(op.category, list);
  }

  return (
    <div className="op-panel">
      <div className="op-search">
        <input
          ref={searchRef}
          type="text"
          placeholder="Search operations  ( / )"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          spellCheck={false}
        />
      </div>
      <div className="op-list">
        {filtered.length === 0 && <div className="op-empty">No operations match “{query}”.</div>}
        {[...groups.entries()].map(([category, list]) => (
          <div key={category}>
            <div className="op-category">{categoryLabel(category)}</div>
            {list.map((op) => (
              <button
                key={op.id}
                className="op-item"
                title={`${op.description}\n\nCost: ${op.cost}${op.provenance.standard ? `\nSource: ${op.provenance.standard}` : ""}`}
                onClick={() => addOp(op.id)}
                data-kind="op-item"
                data-op-id={op.id}
              >
                <span className="op-name">{op.name}</span>
                <span className={`op-cost cost-${op.cost}`}>{COST_LABEL[op.cost]}</span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

function matches(op: OperationInfo, q: string): boolean {
  if (op.name.toLowerCase().includes(q)) return true;
  if (op.id.includes(q)) return true;
  if (op.aliases.some((a) => a.toLowerCase().includes(q))) return true;
  if (op.tags.some((t) => t.includes(q))) return true;
  if (op.description.toLowerCase().includes(q)) return true;
  return false;
}

function categoryLabel(category: string): string {
  return category
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" / ");
}
