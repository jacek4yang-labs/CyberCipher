import type { OperationError, ParamSpec, ParamValue, StageReport } from "../api";
import { useStore } from "../store";
import { formatDuration, formatSize } from "../format";

export function ParamEditor({
  nodeId,
  specs,
  params,
}: {
  nodeId: string;
  specs: ParamSpec[];
  params: Record<string, ParamValue>;
}) {
  const setParam = useStore((s) => s.setParam);
  if (specs.length === 0) return null;
  return (
    <div className="param-grid">
      {specs.map((spec) => {
        const value = params[spec.key];
        const id = `${nodeId}-${spec.key}`;
        return (
          <div className="param-row" key={spec.key}>
            <label htmlFor={id} title={spec.hint}>
              {spec.label}
            </label>
            {spec.kind === "boolean" ? (
              <input
                id={id}
                type="checkbox"
                checked={value === true}
                onChange={(e) => setParam(nodeId, spec.key, e.target.checked)}
              />
            ) : spec.kind === "integer" || spec.kind === "float" ? (
              <input
                id={id}
                type="number"
                step={spec.kind === "float" ? "any" : 1}
                value={typeof value === "number" ? value : ""}
                onChange={(e) =>
                  setParam(
                    nodeId,
                    spec.key,
                    e.target.value === "" ? 0 : Number(e.target.value),
                  )
                }
              />
            ) : spec.kind === "options" || spec.kind === "encoding" ? (
              <select
                id={id}
                value={String(value ?? spec.options[0]?.value ?? "")}
                onChange={(e) => setParam(nodeId, spec.key, e.target.value)}
              >
                {spec.options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            ) : spec.kind === "text_area" ? (
              <textarea
                id={id}
                rows={3}
                spellCheck={false}
                value={String(value ?? "")}
                onChange={(e) => setParam(nodeId, spec.key, e.target.value)}
              />
            ) : (
              <input
                id={id}
                type="text"
                spellCheck={false}
                value={String(value ?? "")}
                onChange={(e) => setParam(nodeId, spec.key, e.target.value)}
              />
            )}
            {spec.hint && <div className="param-hint">{spec.hint}</div>}
          </div>
        );
      })}
    </div>
  );
}

export function StageBadge({ stage }: { stage: StageReport | undefined }) {
  if (!stage) return <span className="stage-badge stage-pending">queued</span>;
  if (stage.status === "error") {
    return <span className="stage-badge stage-error">error</span>;
  }
  if (stage.status === "skipped") {
    return <span className="stage-badge stage-skip">skipped</span>;
  }
  if (stage.status === "cached") {
    return (
      <span className="stage-badge stage-cached" title={`cached · ${formatSize(stage.size)}`}>
        cached · {formatSize(stage.size)}
      </span>
    );
  }
  return (
    <span className="stage-badge stage-ok" title={`${stage.kind} · ${formatSize(stage.size)}`}>
      {stage.kind} · {formatSize(stage.size)} · {formatDuration(stage.duration_us)}
    </span>
  );
}

export function ErrorDetails({ error }: { error: OperationError }) {
  return (
    <div className="op-error">
      <div className="op-error-head">
        <span className={`err-kind err-${error.kind}`}>{error.kind.replace(/_/g, " ")}</span>
        {error.parameter && <span className="err-param">parameter: {error.parameter}</span>}
      </div>
      <div className="op-error-msg">{error.message}</div>
      {(error.expected || error.actual) && (
        <div className="op-error-row">
          {error.expected && <span>expected: {error.expected}</span>}
          {error.actual && <span>got: {error.actual}</span>}
        </div>
      )}
      {error.details && <div className="op-error-details">{error.details}</div>}
    </div>
  );
}
