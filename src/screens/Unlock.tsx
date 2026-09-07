import { useEffect, useRef, useState } from "react";
import { api } from "../api";

interface Props {
  mode: "create" | "unlock";
  quickAvailable: boolean;
  onDone: () => void;
  onError: (msg: string) => void;
}

export function Unlock({ mode, quickAvailable, onDone, onError }: Props) {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLInputElement>(null);

  useEffect(() => {
    ref.current?.focus();
  }, [mode]);

  const quick = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.quickUnlock();
      onDone();
      await api.show();
    } catch (err) {
      const msg = String(err);
      // The Windows dialog stole focus and hid us; come back.
      await api.show().catch(() => {});
      if (msg !== "cancelled") onError(msg);
      ref.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    if (mode === "unlock" && pw === "" && quickAvailable) return quick();
    if (mode === "create") {
      if (pw.length < 8) return onError("Use at least 8 characters.");
      if (pw !== pw2) return onError("Passwords do not match.");
    }
    setBusy(true);
    try {
      if (mode === "create") await api.create(pw);
      else await api.unlock(pw);
      setPw("");
      setPw2("");
      onDone();
    } catch (err) {
      onError(String(err));
      setPw("");
      ref.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="unlock" onSubmit={submit}>
      <div className="logo">🔐</div>
      <h1>{mode === "create" ? "Create your vault" : "Snippet Vault is locked"}</h1>
      <p className="muted">
        {mode === "create"
          ? "Pick a master password. It never leaves this computer and cannot be recovered if forgotten."
          : quickAvailable
            ? "Press Enter to unlock with your Windows password, or type your master password."
            : "Enter your master password to continue."}
      </p>

      {mode === "unlock" && quickAvailable && (
        <button type="button" onClick={quick} disabled={busy}>
          {busy ? "Waiting for Windows…" : "Unlock with Windows password"}
        </button>
      )}

      <input
        ref={ref}
        type="password"
        placeholder="Master password"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
        autoComplete="off"
        disabled={busy}
      />
      {mode === "create" && (
        <input
          type="password"
          placeholder="Repeat password"
          value={pw2}
          onChange={(e) => setPw2(e.target.value)}
          autoComplete="off"
          disabled={busy}
        />
      )}
      {(mode === "create" || !quickAvailable || pw !== "") && (
        <button type="submit" disabled={busy}>
          {busy ? "Working…" : mode === "create" ? "Create vault" : "Unlock"}
        </button>
      )}
      <div className="hint">Ctrl+Shift+Space opens this window from anywhere.</div>
    </form>
  );
}
