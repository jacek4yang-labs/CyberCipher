import { useDroppable } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { useStore } from "../store";
import { RecipeCard, RecipeTotal } from "./RecipeCard";

export function RecipePanel() {
  const recipe = useStore((s) => s.recipe);
  const assistRecipeNote = useStore((s) => s.assistRecipeNote);
  const dismissAssistRecipeNote = useStore((s) => s.dismissAssistRecipeNote);
  const bakeAlternates = useStore((s) => s.bakeAlternates);
  const applyBakeAlternate = useStore((s) => s.applyBakeAlternate);
  const dismissBakeNote = useStore((s) => s.dismissBakeNote);
  const { setNodeRef, isOver } = useDroppable({ id: "recipe-panel" });

  return (
    <div className="recipe-panel">
      <div className="panel-head">
        <span>Recipe</span>
        <RecipeTotal />
      </div>
      {assistRecipeNote && (
        <div className="assist-note-banner" role="note">
          <span>{assistRecipeNote}</span>
          <button
            className="icon-btn"
            onClick={dismissAssistRecipeNote || dismissBakeNote}
            title="Dismiss this note"
            aria-label="Dismiss recipe note"
          >
            ✕
          </button>
        </div>
      )}
      {bakeAlternates.length > 1 && (
        <div className="bake-alternates" role="list" aria-label="Alternative decodes">
          <span className="hint">other decodes:</span>
          {bakeAlternates.map((alt) => (
            <button
              key={`${alt.index}-${alt.label}`}
              className="alt-chip"
              role="listitem"
              onClick={() => applyBakeAlternate(alt.index)}
              title="Apply this decode as the recipe"
            >
              {alt.label}
            </button>
          ))}
        </div>
      )}
      <div
        ref={setNodeRef}
        className={`recipe-list${isOver ? " drag-over" : ""}`}
      >
        <SortableContext items={recipe.map((n) => n.id)} strategy={verticalListSortingStrategy}>
          {recipe.map((node, i) => (
            <RecipeCard key={node.id} node={node} index={i} />
          ))}
        </SortableContext>
        {recipe.length === 0 && (
          <div className="recipe-empty">
            Drop operations here, or click them in the operations panel.
            <br />
            <span className="hint">
              Try: From Hex → From Base64 → XOR → Decode Text (UTF-8)
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
