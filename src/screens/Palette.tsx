import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, type ItemKind, type ItemSummary } from "../api";

interface Props {
  onUse: (item: ItemSummary, mode: "paste" | "type" | "copy") => void;
  onNew: (kind?: ItemKind) => void;
  onEdit: (item: ItemSummary) => void;
  onSettings: () => void;
  onError: (msg: string) => void;
}

const KIND_LABEL: Record<ItemKind, string> = {
  text: "Text",
  prompt: "Prompt",
  secret: "Secret",
  clip: "Clip",
};

const FILTERS: Array<{ label: string; kind?: ItemKind }> = [
  { label: "All" },
  { label: "Text", kind: "text" },
  { label: "Prompts", kind: "prompt" },
  { label: "Secrets", kind: "secret" },
  { label: "Clips", kind: "clip" },
];

export function Palette({ onUse, onNew, onEdit, onSettings, onError }: Props) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState(0);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [sel, setSel] = useState(0);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.search(query, FILTERS[filter].kind);
      setItems(res);
      setSel((s) => Math.min(s, Math.max(res.length - 1, 0)));
    } catch (e) {
      onError(String(e));
    }
  }, [query, filter, onError]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const t = setTimeout(load, 40);
    return () => clearTimeout(t);
  }, [load]);

  useEffect(() => {
    const un = listen("clips-changed", () => load());
    return () => {
      un.then((f) => f());
    };
  }, [load]);

  useEffect(() => {
    const el = listRef.current?.children[sel] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const current = items[sel];

  const togglePin = async (it: ItemSummary) => {
    try {
      await api.setPinned(it.id, !it.pinned);
      load();
    } catch (e) {
      onError(String(e));
    }
  };

  const doDelete = async (it: ItemSummary) => {
    try {
      await api.remove(it.id);
      setConfirmDelete(null);
      load();
    } catch (e) {
      onError(String(e));
    }
  };

  const onKey = (e: React.KeyboardEvent) => {
    const k = e.key;
    if (k === "ArrowDown") {
      e.preventDefault();
      setSel((s) => Math.min(s + 1, items.length - 1));
    } else if (k === "ArrowUp") {
      e.preventDefault();
      setSel((s) => Math.max(s - 1, 0));
    } else if (k === "Tab") {
      e.preventDefault();
      setFilter((f) => (f + (e.shiftKey ? FILTERS.length - 1 : 1)) % FILTERS.length);
      setSel(0);
    } else if (k === "Enter" && current) {
      e.preventDefault();
      if (confirmDelete === current.id) return doDelete(current);
      onUse(current, e.ctrlKey ? "copy" : e.altKey ? "type" : "paste");
    } else if (k === "Escape") {
      e.preventDefault();
      if (confirmDelete) setConfirmDelete(null);
      else if (query) setQuery("");
      else api.hide();
    } else if (e.ctrlKey && k.toLowerCase() === "n") {
      e.preventDefault();
      const k0 = FILTERS[filter].kind;
      onNew(k0 === "clip" ? "text" : k0);
    } else if (e.ctrlKey && k.toLowerCase() === "e" && current) {
      e.preventDefault();
      onEdit(current);
    } else if (e.ctrlKey && k.toLowerCase() === "p" && current) {
      e.preventDefault();
      togglePin(current);
    } else if (k === "Delete" && current) {
      e.preventDefault();
      setConfirmDelete(confirmDelete === current.id ? null : current.id);
    }
  };

  return (
    <div className="palette">
      <div className="searchbar">
        <span className="search-icon">⌕</span>
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setSel(0);
            setConfirmDelete(null);
          }}
          onKeyDown={onKey}
          placeholder="Search snippets, prompts, secrets…"
          spellCheck={false}
          autoComplete="off"
        />
        <div className="filters">
          {FILTERS.map((f, i) => (
            <button
              key={f.label}
              className={i === filter ? "chip active" : "chip"}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => {
                setFilter(i);
                setSel(0);
              }}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      <ul className="results" ref={listRef}>
        {items.length === 0 && (
          <li className="empty">
            {query ? "No matches." : FILTERS[filter].kind === "clip" ? "Nothing copied yet. Text you copy anywhere shows up here while the vault is unlocked." : "Nothing here yet."}{" "}
            {FILTERS[filter].kind !== "clip" && (
              <button className="link" onMouseDown={(e) => e.preventDefault()} onClick={() => onNew(FILTERS[filter].kind)}>
                Create one (Ctrl+N)
              </button>
            )}
          </li>
        )}
        {items.map((it, i) => (
          <li
            key={it.id}
            className={
              "row" + (i === sel ? " selected" : "") + (confirmDelete === it.id ? " danger" : "")
            }
            onMouseEnter={() => setSel(i)}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => onUse(it, "paste")}
          >
            <span className={"kind kind-" + it.kind}>{KIND_LABEL[it.kind]}</span>
            <div className="row-main">
              <div className="row-title">
                {it.pinned && <span className="pin">📌</span>}
                {it.title}
                {it.trigger && <span className="badge trigger">{it.trigger}</span>}
                {it.has_variables && <span className="badge">vars</span>}
                {it.paste_mode === "copy_only" && <span className="badge">copy</span>}
              </div>
              <div className="row-preview">
                {confirmDelete === it.id ? (
                  <span className="danger-text">Press Enter again to delete, Esc to cancel</span>
                ) : (
                  it.preview
                )}
              </div>
            </div>
            <div className="row-meta">
              {it.folder && <span className="folder">{it.folder}</span>}
              {it.tags.slice(0, 3).map((t) => (
                <span key={t} className="tag">
                  #{t}
                </span>
              ))}
            </div>
          </li>
        ))}
      </ul>

      <div className="footer">
        <span><kbd>↵</kbd> paste</span>
        <span><kbd>Ctrl</kbd>+<kbd>↵</kbd> copy</span>
        <span><kbd>Alt</kbd>+<kbd>↵</kbd> type</span>
        <span><kbd>Ctrl</kbd>+<kbd>N</kbd> new</span>
        <span><kbd>Ctrl</kbd>+<kbd>E</kbd> edit</span>
        <span><kbd>Ctrl</kbd>+<kbd>P</kbd> pin</span>
        <span><kbd>Tab</kbd> filter</span>
        <span><kbd>Ctrl</kbd>+<kbd>L</kbd> lock</span>
        <button className="link footer-link" onMouseDown={(e) => e.preventDefault()} onClick={onSettings}>
          ⚙ Settings
        </button>
      </div>
    </div>
  );
}
