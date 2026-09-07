# Snippet Vault

Encrypted snippets, AI prompts, passwords and API keys behind one hotkey.
Windows tray app built with Tauri 2 (Rust core + React UI). MIT licensed.

## Install

Download the latest `Snippet Vault_x.y.z_x64-setup.exe` (or the `.msi`) from
[Releases](https://github.com/JK-0001/snippet-vault/releases) and run it.

The installer is not code-signed yet, so Windows SmartScreen shows a warning the
first time. Click "More info", then "Run anyway". Requires Windows 10 (2004+) or 11
with the WebView2 runtime, which Windows 11 and most Windows 10 machines already have.

## Use it

| Action | Keys |
|---|---|
| Open / close the palette from anywhere | `Ctrl+Shift+Space` |
| Paste selected item into the app you were in | `Enter` |
| Copy only (no paste) | `Ctrl+Enter` |
| Type it as keystrokes (for apps that block paste) | `Alt+Enter` |
| New item (pre-filled from clipboard) | `Ctrl+N` |
| Edit selected | `Ctrl+E` |
| Pin / unpin | `Ctrl+P` |
| Delete (press twice) | `Delete` |
| Switch filter All / Text / Prompts / Secrets / Clips | `Tab` |
| Lock the vault | `Ctrl+L` |
| Clear search, then hide | `Esc` |

The app starts with Windows by default and lives in the tray. Right-click the tray
icon to turn "Start with Windows" off, lock the vault, or quit.

### Locking

The vault locks itself after 15 minutes without keyboard or mouse activity, when
Windows locks (Win+L or screen timeout) and when the laptop sleeps. Change these under
Settings (Ctrl+, inside the palette, or the tray menu).

To unlock, either type the master password or press Enter on the empty field to use
"Unlock with Windows password". That option keeps a copy of the vault key wrapped by
Windows Data Protection (DPAPI) for your account and asks Windows to verify your
account password each time. It is a convenience against people at your keyboard, not
against malware running as you. Turn it off in Settings if you prefer master-password only.

### Screenshot and screen-share protection

The palette window is excluded from screen capture by default: screenshots, screen
recordings, Zoom/Teams sharing and the Snipping Tool show a black box where the window
is. Remote Desktop shows it black as well, so there is a switch under Settings > Privacy.

### Text expansion

Give any snippet, prompt or secret a trigger in its editor, for example `;sig` or
`:addr`. From then on, typing that trigger in any app deletes it and inserts the item.
Notes:

- Start triggers with `;` or `:` so they never fire inside normal words.
- Secrets are always inserted through the clipboard (and wiped afterwards), never typed
  out key by key. Items set to "Type keystrokes" are typed; the rest are pasted.
- Prompts with `{{blanks}}` open the fill-in form instead, then paste on Enter.
- Expansion pauses while the vault is locked and never runs inside Snippet Vault itself.
- Turn it off under Settings > Text expansion.

### Clipboard history

While the vault is unlocked, every text you copy in any app is saved as an encrypted
"clip" and shows up under the Clips tab, newest first. Details:

- Clips never appear in the All tab, so they do not clutter your snippets.
- Copying the same text again just moves it to the top.
- Text that looks like a password, API key or token is saved masked (or not saved at
  all, your choice in Settings).
- Copies from password managers are ignored (KeePassXC, KeePass, Bitwarden, 1Password
  by default; editable). Apps that flag their clipboard data as private are respected.
- Only the last 200 clips are kept (configurable). Pinned clips are never trimmed.
- To keep a clip forever, press Ctrl+E on it and change its type to Text, Prompt or Secret.
- Clipboard history pauses while the vault is locked, since nothing can be encrypted then.

### Backup and restore

Settings has a Backup section:

- **Encrypted backup** writes one `.svault` file protected by a password you choose
  (your master password is fine). Same encryption as the vault itself. Keep it on a
  USB stick or in OneDrive.
- **Plain export** writes readable JSON, including secrets. Only behind a warning.
- **Import** reads either file and merges: new items are added, items with the same id
  keep whichever copy was edited last, nothing is deleted.
- **Open vault folder** shows where the live vault file is.

Prompts can contain `{{blanks}}`. When you paste one, a small form asks you to fill them in.

Secrets (and anything marked sensitive) are masked in the list, never typed as
keystrokes, kept out of the Windows clipboard history (Win+V) and cloud clipboard,
and wiped from the clipboard 30 seconds after a copy.

## Where data lives

`%APPDATA%\com.khatriautomations.snippetvault\vault.db`

Only ciphertext is on disk. Master password -> Argon2id (64 MiB, 3 passes) ->
wraps a random vault key -> XChaCha20-Poly1305 per record. Back up that one file.
There is no password recovery.

## Develop

```bash
pnpm install
pnpm tauri dev
```

Tests for the crypto and vault layers:

```bash
cd src-tauri && cargo test
```

Release installer (NSIS + MSI in `src-tauri/target/release/bundle/`):

```bash
pnpm tauri build
```

## Layout

- `src-tauri/src/crypto.rs`  key derivation, AEAD, key wrapping
- `src-tauri/src/vault.rs`   SQLite ciphertext store, in-memory index, fuzzy search
- `src-tauri/src/paste.rs`   Win32 clipboard + focus + SendInput paste engine
- `src-tauri/src/commands.rs` the only API the UI can call
- `src-tauri/src/expansion.rs` low-level keyboard hook, trigger matching, in-place replace
- `src-tauri/src/detect.rs`  heuristics for "this copied text is a secret"
- `src-tauri/src/backup.rs`  encrypted .svault and plain JSON export/import
- `src-tauri/src/winsec.rs`  DPAPI, Windows credential check, lock/sleep/idle watchers
- `src-tauri/src/settings.rs` settings.json next to the vault
- `src-tauri/src/lib.rs`     tray, global hotkey, window placement, auto-lock threads
- `src/`                     React palette, editor, unlock screens

See `PLAN.md` for the roadmap and threat model.

## Status and security notes

Early release, built for personal use. The vault format and crypto design are
described in `PLAN.md`; the design borrows from KeePassXC and Bitwarden, and the
paste routine follows PowerToys Advanced Paste and espanso (ideas only, no GPL code).
Not audited. If you find a security issue, please open an issue or contact the
author privately first.

## Credits

Ideas and UX patterns from EcoPaste, Ortu, Sklad, CopyQ, Maccy, espanso and
Microsoft PowerToys. Thanks to the Tauri team for the plugins this app leans on.

## License

MIT. See `LICENSE`.
