import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, extractVariables, type Item, type ItemInput, type ItemKind, type ItemSummary } from "./api";
import { Palette } from "./screens/Palette";
import { Editor } from "./screens/Editor";
import { Unlock } from "./screens/Unlock";
import { Settings } from "./screens/Settings";
import { VariablesForm } from "./screens/VariablesForm";
import "./App.css";

type Screen =
  | { name: "loading" }
  | { name: "setup" }
  | { name: "locked"; quick: boolean }
  | { name: "palette" }
  | { name: "settings" }
  | { name: "editor"; item?: Item; prefill?: Partial<ItemInput> }
  | { name: "variables"; item: ItemSummary; body: string; mode: "paste" | "type" | "copy" };

export default function App() {
  const [screen, setScreen] = useState<Screen>({ name: "loading" });
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const resetKey = useRef(0);
  const [, force] = useState(0);
  const pendingSettings = useRef(false);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await api.status();
      if (!s.exists) setScreen({ name: "setup" });
      else if (!s.unlocked) setScreen({ name: "locked", quick: s.quick_unlock_available });
      else if (pendingSettings.current) {
        pendingSettings.current = false;
        setScreen({ name: "settings" });
      } else setScreen((cur) => (cur.name === "settings" ? cur : { name: "palette" }));
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refreshStatus();
    const unShown = listen("palette-shown", () => {
      resetKey.current += 1;
      setError(null);
      refreshStatus();
      force((n) => n + 1);
    });
    const unLocked = listen("vault-locked", () => refreshStatus());
    const unSettings = listen("open-settings", () => {
      pendingSettings.current = true;
      refreshStatus();
    });
    return () => {
      unShown.then((f) => f());
      unLocked.then((f) => f());
      unSettings.then((f) => f());
    };
  }, [refreshStatus]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 1800);
    return () => clearTimeout(t);
  }, [toast]);

  // Global keys: Escape closes sub-screens, Ctrl+L locks, Ctrl+, opens settings.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const sub = screen.name === "editor" || screen.name === "variables" || screen.name === "settings";
      if (e.key === "Escape" && sub) {
        e.preventDefault();
        setScreen({ name: "palette" });
      }
      const unlocked = screen.name !== "locked" && screen.name !== "setup" && screen.name !== "loading";
      if (e.ctrlKey && e.key.toLowerCase() === "l" && unlocked) {
        e.preventDefault();
        api.lock();
      }
      if (e.ctrlKey && e.key === "," && unlocked) {
        e.preventDefault();
        setScreen({ name: "settings" });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [screen.name]);

  const useItem = async (item: ItemSummary, mode: "paste" | "type" | "copy") => {
    try {
      if (item.has_variables) {
        const full = await api.get(item.id, true);
        setScreen({ name: "variables", item, body: full.body, mode });
        return;
      }
      await api.use(item.id, mode);
      if (mode === "copy") setToast(item.sensitive ? "Copied. Clears in 30 s." : "Copied");
    } catch (e) {
      setError(String(e));
    }
  };

  const openEditor = async (item?: ItemSummary, kind?: ItemKind) => {
    try {
      if (item) {
        const full = await api.get(item.id, true);
        setScreen({ name: "editor", item: full });
      } else {
        const clip = kind !== "secret" ? await api.clipboardRead().catch(() => null) : null;
        setScreen({
          name: "editor",
          prefill: { kind: kind ?? "text", body: clip && clip.length < 20000 ? clip : "" },
        });
      }
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="shell" data-tauri-drag-region>
      {error && (
        <div className="error-bar" onClick={() => setError(null)}>
          {error}
        </div>
      )}
      {toast && <div className="toast">{toast}</div>}

      {screen.name === "loading" && <div className="center muted">Loading…</div>}

      {(screen.name === "setup" || screen.name === "locked") && (
        <Unlock
          mode={screen.name === "setup" ? "create" : "unlock"}
          quickAvailable={screen.name === "locked" && screen.quick}
          onDone={() => {
            setError(null);
            refreshStatus();
          }}
          onError={setError}
        />
      )}

      {screen.name === "palette" && (
        <Palette
          key={resetKey.current}
          onUse={useItem}
          onNew={(kind) => openEditor(undefined, kind)}
          onEdit={(it) => openEditor(it)}
          onSettings={() => setScreen({ name: "settings" })}
          onError={setError}
        />
      )}

      {screen.name === "settings" && (
        <Settings
          onClose={() => setScreen({ name: "palette" })}
          onError={setError}
          onSaved={() => {
            setToast("Settings saved");
            setScreen({ name: "palette" });
          }}
        />
      )}

      {screen.name === "editor" && (
        <Editor
          item={screen.item}
          prefill={screen.prefill}
          onCancel={() => setScreen({ name: "palette" })}
          onSaved={() => {
            setToast("Saved");
            setScreen({ name: "palette" });
          }}
          onError={setError}
        />
      )}

      {screen.name === "variables" && (
        <VariablesForm
          title={screen.item.title}
          variables={extractVariables(screen.body)}
          onCancel={() => setScreen({ name: "palette" })}
          onSubmit={async (vars) => {
            try {
              await api.use(screen.item.id, screen.mode, vars);
              setScreen({ name: "palette" });
            } catch (e) {
              setError(String(e));
            }
          }}
        />
      )}
    </div>
  );
}
