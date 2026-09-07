import { useEffect, useRef, useState } from "react";
import { api, type Item, type ItemInput, type ItemKind, type PasteMode } from "../api";

interface Props {
  item?: Item;
  prefill?: Partial<ItemInput>;
  onCancel: () => void;
  onSaved: () => void;
  onError: (msg: string) => void;
}

export function Editor({ item, prefill, onCancel, onSaved, onError }: Props) {
  const [kind, setKind] = useState<ItemKind>(item?.kind ?? prefill?.kind ?? "text");
  const [title, setTitle] = useState(item?.title ?? prefill?.title ?? "");
  const [body, setBody] = useState(item?.body ?? prefill?.body ?? "");
  const [tags, setTags] = useState((item?.tags ?? prefill?.tags ?? []).join(", "));
  const [folder, setFolder] = useState(item?.folder ?? prefill?.folder ?? "");
  const [pinned, setPinned] = useState(item?.pinned ?? false);
  const [sensitive, setSensitive] = useState(item?.sensitive ?? prefill?.sensitive ?? false);
  const [pasteMode, setPasteMode] = useState<PasteMode>(item?.paste_mode ?? "paste");
  const [trigger, setTrigger] = useState(item?.trigger ?? "");
  const [showBody, setShowBody] = useState(!(item?.sensitive ?? false));
  const [busy, setBusy] = useState(false);
  const titleRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    titleRef.current?.focus();
  }, []);

  const isSecret = kind === "secret" || sensitive;

  const save = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.save({
        id: item?.id,
        kind,
        title,
        body,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        folder,
        pinned,
        sensitive: isSecret,
        paste_mode: pasteMode,
        trigger: trigger.trim(),
      });
      onSaved();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.ctrlKey && (e.key === "Enter" || e.key.toLowerCase() === "s")) {
      e.preventDefault();
      save();
    }
  };

  return (
    <div className="editor" onKeyDown={onKey}>
      <div className="editor-head">
        <strong>{item ? "Edit item" : "New item"}</strong>
        <div className="kinds">
          {((kind === "clip" ? ["clip", "text", "prompt", "secret"] : ["text", "prompt", "secret"]) as ItemKind[]).map((k) => (
            <button
              key={k}
              className={k === kind ? "chip active" : "chip"}
              onClick={() => {
                setKind(k);
                if (k === "secret") setSensitive(true);
              }}
            >
              {k}
            </button>
          ))}
        </div>
      </div>

      {kind === "clip" && (
        <p className="hint" style={{ margin: 0 }}>
          This is a clipboard clip; old clips get trimmed automatically. Change the type to Text, Prompt or
          Secret to keep it for good.
        </p>
      )}
      <input ref={titleRef} placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} />

      <div className="body-wrap">
        <textarea
          placeholder={
            kind === "prompt"
              ? "Prompt text. Use {{variable}} for blanks you fill in when pasting."
              : kind === "secret"
                ? "Password, API key or token"
                : "Text to paste"
          }
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={kind === "secret" ? 2 : 8}
          spellCheck={false}
          style={isSecret && !showBody ? ({ WebkitTextSecurity: "disc" } as React.CSSProperties) : undefined}
        />
        {isSecret && (
          <button className="link reveal" onClick={() => setShowBody((s) => !s)}>
            {showBody ? "Hide" : "Reveal"}
          </button>
        )}
      </div>

      <div className="grid2">
        <input placeholder="Tags, comma separated" value={tags} onChange={(e) => setTags(e.target.value)} />
        <input placeholder="Folder" value={folder} onChange={(e) => setFolder(e.target.value)} />
      </div>
      {kind !== "clip" && (
        <label className="trigger-row">
          <span>Type-anywhere trigger</span>
          <input
            placeholder=";sig"
            value={trigger}
            onChange={(e) => setTrigger(e.target.value.replace(/\s+/g, ""))}
            spellCheck={false}
          />
          <span className="hint">Typing this in any app replaces it with the text above. Start it with ; or : so it never fires by accident.</span>
        </label>
      )}

      <div className="options">
        <label>
          <input type="checkbox" checked={pinned} onChange={(e) => setPinned(e.target.checked)} /> Pinned
        </label>
        <label>
          <input
            type="checkbox"
            checked={isSecret}
            disabled={kind === "secret"}
            onChange={(e) => setSensitive(e.target.checked)}
          />{" "}
          Sensitive (masked, clipboard wiped, hidden from Win+V)
        </label>
        <label>
          Deliver by{" "}
          <select value={pasteMode} onChange={(e) => setPasteMode(e.target.value as PasteMode)}>
            <option value="paste">Paste (Ctrl+V)</option>
            <option value="type" disabled={isSecret}>Type keystrokes</option>
            <option value="copy_only">Copy only</option>
          </select>
        </label>
      </div>

      <div className="editor-actions">
        <button className="ghost" onClick={onCancel}>Cancel (Esc)</button>
        <button onClick={save} disabled={busy || !title.trim()}>
          {busy ? "Saving…" : "Save (Ctrl+S)"}
        </button>
      </div>
    </div>
  );
}
