import { useDroppable } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { useStore } from "../store";
import { RecipeCard, RecipeTotal } from "./RecipeCard";

export function RecipePanel() {
  const recipe = useStore((s) => s.recipe);
  const { setNodeRef, isOver } = useDroppable({ id: "recipe-panel" });

  return (
    <div className="recipe-panel">
      <div className="panel-head">
        <span>Recipe</span>
        <RecipeTotal />
      </div>
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
