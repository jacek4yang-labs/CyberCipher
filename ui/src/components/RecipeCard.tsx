import { useState } from "react";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { useStore } from "../store";
import type { RecipeNode } from "../api";
import { ParamEditor, StageBadge, ErrorDetails } from "./ParamEditor";
import { formatDuration } from "../format";

export function RecipeCard({ node, index }: { node: RecipeNode; index: number }) {
  const op = useStore((s) => s.opsById[node.op]);
  const report = useStore((s) => s.report);
  const removeOp = useStore((s) => s.removeOp);
  const duplicateOp = useStore((s) => s.duplicateOp);
  const toggleEnabled = useStore((s) => s.toggleEnabled);
  const [expanded, setExpanded] = useState(op ? op.params.length > 0 : false);

  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: node.id,
  });

  if (!op) {
    return (
      <div className="recipe-card unknown" ref={setNodeRef} style={css(transform, transition)}>
        <div className="recipe-card-head">
          <span className="recipe-index">{index + 1}</span>
          <span className="recipe-name">Unknown operation: {node.op}</span>
          <button className="icon-btn" onClick={() => removeOp(node.id)} title="Remove">
            ✕
          </button>
        </div>
      </div>
    );
  }

  const stage = report?.stages.find((s) => s.node_id === node.id);
  const blocked = report?.blocked_at === node.id;

  return (
    <div
      ref={setNodeRef}
      style={css(transform, transition)}
      className={`recipe-card${node.enabled ? "" : " disabled"}${isDragging ? " dragging" : ""}${blocked ? " blocked" : ""}`}
    >
      <div className="recipe-card-head">
        <button className="drag-handle" {...attributes} {...listeners} title="Drag to reorder">
          ⠿
        </button>
        <span className="recipe-index">{index + 1}</span>
        <span className="recipe-name" title={op.description}>
          {op.name}
        </span>
        {op.security !== "neutral" && (
          <span className={`sec-chip sec-${op.security}`}>{op.security}</span>
        )}
        <input
          type="checkbox"
          checked={node.enabled}
          onChange={() => toggleEnabled(node.id)}
          title="Enable / disable this operation"
        />
        <button className="icon-btn" onClick={() => duplicateOp(node.id)} title="Duplicate">
          ⧉
        </button>
        <button className="icon-btn" onClick={() => removeOp(node.id)} title="Remove">
          ✕
        </button>
      </div>
      <div className="recipe-card-sub">
        <StageBadge stage={stage} />
        {op.params.length > 0 && (
          <button className="link-btn" onClick={() => setExpanded(!expanded)}>
            {expanded ? "hide params" : "params"}
          </button>
        )}
        <button
          className="link-btn"
          title={`Standard: ${op.provenance.standard}\nImplementation: ${op.provenance.implementation}\nVectors: ${op.provenance.test_vectors}`}
          onClick={() => setExpanded((e) => !e)}
        >
          info
        </button>
        {blocked && <span className="blocked-note">manual bake required (cost: {op.cost})</span>}
      </div>
      {stage?.error && <ErrorDetails error={stage.error} />}
      {blocked && (
        <div className="blocked-banner">
          Auto Bake stopped here: this operation is cost class{" "}
          <strong>{op.cost}</strong> and only runs on an explicit Bake.
        </div>
      )}
      {expanded && (
        <div className="recipe-card-body">
          <div className="op-desc">{op.description}</div>
          <ParamEditor nodeId={node.id} specs={op.params} params={node.params} />
          <div className="op-provenance">
            <div>
              <span>standard:</span> {op.provenance.standard}
            </div>
            <div>
              <span>implementation:</span> {op.provenance.implementation}
            </div>
            <div>
              <span>vectors:</span> {op.provenance.test_vectors}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function css(transform: unknown, transition: string | undefined) {
  return {
    transform: CSS.Transform.toString(transform as never),
    transition,
  } as React.CSSProperties;
}

export function RecipeTotal() {
  const report = useStore((s) => s.report);
  const baking = useStore((s) => s.baking);
  if (!report) return null;
  const cached = report.cached_stages;
  const label = baking
    ? "baking…"
    : `${cached > 0 ? `${cached} cached · ` : ""}${formatDuration(report.duration_us)}`;
  return <div className="recipe-total">{label}</div>;
}
