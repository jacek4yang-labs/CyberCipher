import { useEffect, useRef } from "react";
import {
  DndContext,
  DragOverlay,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import { TopBar, StatusBar, SaveDialog } from "./components/TopBar";
import { OpPanel } from "./components/OpPanel";
import { RecipePanel } from "./components/RecipePanel";
import { DataPanel } from "./components/DataPanel";
import { RecipesPage } from "./components/RecipesPage";
import { SettingsPage } from "./components/SettingsPage";
import { useStore, debounce } from "./store";
import { useState } from "react";

export default function App() {
  const ready = useStore((s) => s.ready);
  const page = useStore((s) => s.page);
  const init = useStore((s) => s.init);

  useEffect(() => {
    void init();
  }, [init]);

  if (!ready) {
    return <div className="loading">CyberCipher</div>;
  }

  return (
    <div className="app">
      <TopBar />
      {page === "workbench" ? <Workbench /> : page === "recipes" ? <RecipesPage /> : <SettingsPage />}
      <StatusBar />
      <SaveDialog />
    </div>
  );
}

function Workbench() {
  const addOp = useStore((s) => s.addOp);
  const moveOp = useStore((s) => s.moveOp);
  const recipe = useStore((s) => s.recipe);
  const inputText = useStore((s) => s.inputText);
  const inputEncoding = useStore((s) => s.inputEncoding);
  const bake = useStore((s) => s.bake);
  const autoBake = useStore((s) => s.autoBake);
  const saveDialogOpen = useStore((s) => s.setSaveDialogOpen);
  const [dragOpName, setDragOpName] = useState<string | null>(null);

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 4 } }));

  // Debounced auto bake on any change to input or recipe.
  const debouncedBake = useRef(
    debounce(() => {
      void useStore.getState().bake(false);
    }, 300),
  ).current;

  useEffect(() => {
    if (!autoBake) return;
    debouncedBake();
  }, [inputText, inputEncoding, recipe, autoBake, debouncedBake]);

  // Global keyboard shortcuts.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        void bake(true);
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        saveDialogOpen(true);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [bake, saveDialogOpen]);

  const onDragStart = (event: DragStartEvent) => {
    const data = event.active.data.current as { kind?: string; opId?: string } | undefined;
    if (data?.kind === "new-op") {
      const op = useStore.getState().opsById[data.opId ?? ""];
      setDragOpName(op?.name ?? data.opId ?? null);
    } else if (typeof event.active.id === "string" && event.active.id.startsWith("n")) {
      const node = recipe.find((n) => n.id === event.active.id);
      const op = node && useStore.getState().opsById[node.op];
      setDragOpName(op?.name ?? node?.op ?? null);
    }
  };

  const onDragEnd = (event: DragEndEvent) => {
    setDragOpName(null);
    const { active, over } = event;
    if (!over) return;
    const data = active.data.current as { kind?: string; opId?: string } | undefined;

    if (data?.kind === "new-op") {
      // Insert a new operation. Drop position: before the hovered card, else append.
      const overIndex = recipe.findIndex((n) => n.id === over.id);
      addOp(data.opId ?? "", overIndex >= 0 ? overIndex : undefined);
      return;
    }
    if (over.id !== active.id && over.id !== "recipe-panel") {
      const from = recipe.findIndex((n) => n.id === active.id);
      const overIndex = recipe.findIndex((n) => n.id === over.id);
      if (from >= 0 && overIndex >= 0) moveOp(active.id as string, overIndex);
    } else if (over.id === "recipe-panel") {
      moveOp(active.id as string, recipe.length);
    }
  };

  return (
    <main className="workbench">
      <DndContext sensors={sensors} onDragStart={onDragStart} onDragEnd={onDragEnd}>
        <OpPanel />
        <RecipePanel />
        <DataPanel />
        <DragOverlay>
          {dragOpName && <div className="drag-ghost">{dragOpName}</div>}
        </DragOverlay>
      </DndContext>
    </main>
  );
}
