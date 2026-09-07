import { useEffect, useState } from "react";
import { api, type Settings as SettingsT } from "../api";

interface Props {
  onClose: () => void;
  onError: (msg: string) => void;
  onSaved: () => void;
}

const LOCK_CHOICES: Array<{ label: string; value: number }> = [
  { label: "1 minute", value: 1 },
  { label: "5 minutes", value: 5 },
  { label: "15 minutes", value: 15 },
  { label: "30 minutes", value: 30 },
  { label: "1 hour", value: 60 },
  { label: "4 hours", value: 240 },
  { label: "Never", value: 0 },
];

export function Settings({ onClose, onError, onSaved }: Props) {
  const [s, setS] = useState<SettingsT | null>(null);
  const [autostart, setAutostart] = useState(true);
  const [busy, setBusy] = useState(false);
  const [backupPw, setBackupPw] = useState("");
  const [askBackupPw, setAskBackupPw] = useState(false);
  const [importPick, setImportPick] = useState<{ path: string; encrypted: boolean } | null>(null);
  const [importPw, setImportPw] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [confirmPlain, setConfirmPlain] = useState(false);

  useEffect(() => {
    api.settingsGet().then(setS).catch((e) => onError(String(e)));
    api.autostartGet().then(setAutostart).catch(() => {});
  }, [onError]);

  if (!s) return <div className="center muted">Loading…</div>;

  const run = async (label: string, fn: () => Promise<string | null>) => {
    setBusy(true);
    setNote(null);
    try {
      const out = await fn();
      setNote(out ?? label + " cancelled.");
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const exportEncrypted = () =>
    run("Backup", async () => {
      if (backupPw.length < 8) throw new Error("Backup password needs at least 8 characters.");
      const p = await api.backupExportEncrypted(backupPw);
      if (p) {
        setAskBackupPw(false);
        setBackupPw("");
        return "Backup saved to " + p;
      }
      return null;
    });

  const exportPlain = () =>
    run("Export", async () => {
      setConfirmPlain(false);
      const p = await api.backupExportPlain();
      return p ? "Exported to " + p : null;
    });

  const pickImport = () =>
    run("Import", async () => {
      const pick = await api.backupPickImport();
      if (!pick) return null;
      if (pick.encrypted) {
        setImportPick(pick);
        return "Enter the password for this backup below.";
      }
      const r = await api.backupImport(pick.path);
      return `Imported: ${r.added} added, ${r.updated} updated, ${r.skipped} unchanged.`;
    });

  const finishImport = () =>
    run("Import", async () => {
      if (!importPick) return null;
      const r = await api.backupImport(importPick.path, importPw);
      setImportPick(null);
      setImportPw("");
      return `Imported: ${r.added} added, ${r.updated} updated, ${r.skipped} unchanged.`;
    });

  const save = async () => {
    setBusy(true);
    try {
      await api.settingsSet(s);
      await api.autostartSet(autostart);
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
    <div className="editor settings" onKeyDown={onKey}>
      <div className="editor-head">
        <strong>Settings</strong>
      </div>

      <section>
        <h3>Auto-lock</h3>
        <label className="row-setting">
          <span>Lock after no activity for</span>
          <select
            value={s.auto_lock_minutes}
            onChange={(e) => setS({ ...s, auto_lock_minutes: Number(e.target.value) })}
          >
            {LOCK_CHOICES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={s.lock_on_windows_lock}
            onChange={(e) => setS({ ...s, lock_on_windows_lock: e.target.checked })}
          />{" "}
          Lock when Windows locks (Win+L, screen timeout)
        </label>
        <label>
          <input
            type="checkbox"
            checked={s.lock_on_sleep}
            onChange={(e) => setS({ ...s, lock_on_sleep: e.target.checked })}
          />{" "}
          Lock when the computer sleeps
        </label>
      </section>

      <section>
        <h3>Unlocking</h3>
        <label>
          <input
            type="checkbox"
            checked={s.quick_unlock}
            onChange={(e) => setS({ ...s, quick_unlock: e.target.checked })}
          />{" "}
          Allow unlocking with my Windows password
        </label>
        <p className="hint">
          Windows keeps a copy of the vault key that only your Windows account can open. You still
          type your Windows password each time. Your master password always works too.
        </p>
      </section>

      <section>
        <h3>Clipboard history</h3>
        <label>
          <input
            type="checkbox"
            checked={s.clip_history_enabled}
            onChange={(e) => setS({ ...s, clip_history_enabled: e.target.checked })}
          />{" "}
          Remember text I copy (encrypted, only while the vault is unlocked)
        </label>
        <label className="row-setting">
          <span>Keep the last</span>
          <select
            value={s.clip_max_items}
            onChange={(e) => setS({ ...s, clip_max_items: Number(e.target.value) })}
          >
            {[50, 100, 200, 500, 1000].map((n) => (
              <option key={n} value={n}>
                {n} clips
              </option>
            ))}
          </select>
        </label>
        <label className="row-setting">
          <span>If a copy looks like a password or key</span>
          <select
            value={s.clip_secret_policy}
            onChange={(e) => setS({ ...s, clip_secret_policy: e.target.value as "mask" | "skip" })}
          >
            <option value="mask">save it masked</option>
            <option value="skip">do not save it</option>
          </select>
        </label>
        <label className="col-setting">
          <span>Never record copies from these apps (comma separated)</span>
          <input
            value={s.clip_ignore_apps.join(", ")}
            onChange={(e) =>
              setS({ ...s, clip_ignore_apps: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })
            }
            placeholder="keepassxc.exe, bitwarden.exe"
          />
        </label>
        <div className="btn-row">
          <button
            className="ghost"
            disabled={busy}
            onClick={() =>
              run("Clear", async () => {
                const n = await api.clipsClear();
                return `Removed ${n} clips (pinned ones kept).`;
              })
            }
          >
            Clear clipboard history
          </button>
        </div>
      </section>

      <section>
        <h3>Text expansion</h3>
        <label>
          <input
            type="checkbox"
            checked={s.expansion_enabled}
            onChange={(e) => setS({ ...s, expansion_enabled: e.target.checked })}
          />{" "}
          Replace triggers as I type (for example ;sig becomes your signature)
        </label>
        <p className="hint">
          Set a trigger on any item in its editor. Expansion works only while the vault is unlocked and
          never inside Snippet Vault itself. Secrets are always pasted, never typed out.
        </p>
      </section>

      <section>
        <h3>Startup</h3>
        <label>
          <input type="checkbox" checked={autostart} onChange={(e) => setAutostart(e.target.checked)} />{" "}
          Start Snippet Vault when Windows starts
        </label>
      </section>

      <section>
        <h3>Backup</h3>
        <div className="btn-row">
          <button className="ghost" disabled={busy} onClick={() => setAskBackupPw((v) => !v)}>
            Encrypted backup…
          </button>
          <button className="ghost" disabled={busy} onClick={() => setConfirmPlain((v) => !v)}>
            Plain export…
          </button>
          <button className="ghost" disabled={busy} onClick={pickImport}>
            Import…
          </button>
          <button className="link" disabled={busy} onClick={() => api.openDataFolder().catch((e) => onError(String(e)))}>
            Open vault folder
          </button>
        </div>
        {confirmPlain && (
          <div className="inline-form warn">
            <span>This file is readable by anyone who opens it, including your passwords and keys.</span>
            <button disabled={busy} onClick={exportPlain}>Export anyway</button>
          </div>
        )}
        {askBackupPw && (
          <div className="inline-form">
            <input
              type="password"
              placeholder="Password for the backup file (your master password is fine)"
              value={backupPw}
              onChange={(e) => setBackupPw(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && exportEncrypted()}
              autoFocus
            />
            <button disabled={busy} onClick={exportEncrypted}>Save backup</button>
          </div>
        )}
        {importPick && (
          <div className="inline-form">
            <input
              type="password"
              placeholder="Password of the backup file"
              value={importPw}
              onChange={(e) => setImportPw(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && finishImport()}
              autoFocus
            />
            <button disabled={busy} onClick={finishImport}>Import</button>
          </div>
        )}
        {note && <p className="hint">{note}</p>}
        <p className="hint">
          The encrypted backup is a single file you can keep on a USB stick or in OneDrive. Import merges;
          it never deletes anything already in the vault.
        </p>
      </section>

      <div className="editor-actions">
        <button className="ghost" onClick={onClose}>
          Cancel (Esc)
        </button>
        <button onClick={save} disabled={busy}>
          {busy ? "Saving…" : "Save (Ctrl+S)"}
        </button>
      </div>
    </div>
  );
}
