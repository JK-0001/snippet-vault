# Snippet Vault — project plan

Secure Windows tray app: one hotkey opens a search palette of your reusable texts,
AI prompts, passwords and API keys. Enter pastes the item into whatever window you
were typing in. Everything is encrypted at rest. Research date: 2026-09-07.

## 1. Decision: build fresh on Tauri 2, borrow from proven repos

No existing repo does "clipboard/snippet manager + real secrets vault" well enough
to fork whole. The best ones are either copyleft (CopyQ, Ditto, espanso are GPL),
non-commercial (PasteBar is CC BY-NC), or young with unaudited crypto (Sklad).

| Layer | Choice | Why |
|---|---|---|
| Shell | Tauri 2.x (Rust core + WebView2 UI) | 5-10 MB install, Rust owns all crypto, official plugins for hotkey/tray/autostart/single-instance. WebView2 is already on this machine. |
| UI | React + TypeScript + Tailwind | Largest pool of reusable code (EcoPaste, PasteBar, Sklad all use React). |
| Storage | SQLite (rusqlite) with FTS5 for search, values encrypted app-side | Fast search over thousands of items, single file, easy backup. |
| Crypto | Argon2id (64 MiB, t=3, p=4) -> master key; XChaCha20-Poly1305 per record; vault key wrapped by master key | Same class of design as KeePassXC / Bitwarden; password change does not re-encrypt data. |
| Quick unlock | Windows Hello via KeyCredentialManager (KeePassXC pattern) with DPAPI-wrapped cached key | Convenience only; master password remains the root secret. |
| Paste engine | Own Rust/Win32 module (~300 lines) | Foreground-window capture, modifier release, tagged SendInput Ctrl+V, clipboard backup/restore, history exclusion. |

Not using: Tauri Stronghold plugin (maintainers say it will be removed in v3),
Electron (80-200 MB, safeStorage is DPAPI only), keytar (archived 2022).

### What to borrow, and from where

| Source | License | Take |
|---|---|---|
| EcoPaste (github.com/EcoPasteHub/EcoPaste) | Apache-2.0 | Tauri 2 project layout, tray + hotkey wiring, clipboard listener, SQLite FTS5 schema, backup/restore flow |
| Ortu (github.com/abhijith-p-subash/ortu) | MIT | Secret auto-detection regexes, masking in list view, fuzzy re-rank on top of FTS |
| Sklad (github.com/Rench321/sklad) | MIT | Master-password onboarding, auto-lock UX, quick-create-from-anywhere window. Audit its crypto before lifting any of it. |
| PowerToys Advanced Paste (github.com/microsoft/PowerToys) | MIT | `SendPasteKeyCombination`: release all 8 modifiers, then SendInput Ctrl+V tagged with dwExtraInfo |
| espanso (github.com/espanso/espanso) | GPL-3.0 | Policy only, no code: inject short text via KEYEVENTF_UNICODE, clipboard for >100 chars, 300 ms pre-paste and restore delays, preserve_clipboard |
| CopyQ, Maccy | GPL / MIT | UX only: keyboard-first list, pin shortcut, per-app ignore rules, ignore sensitive clipboard types |
| keepass-rs | MIT | Later: export vault to KDBX4 so KeePassXC can open it |

## 2. What goes in the app (data model)

One table `items`, one encrypted blob per row.

| Field | Notes |
|---|---|
| kind | `text` (canned replies, addresses, signatures), `prompt` (Claude/LLM prompts, supports `{{variables}}`), `secret` (password, API key, token), `clip` (captured clipboard history, optional) |
| title, body | body encrypted; title encrypted too, search runs on a decrypted in-memory FTS index while unlocked |
| tags, folder | nested folders + free tags (EcoPaste/PasteBar model) |
| pinned, use_count, last_used | pinned first, then frecency ordering |
| sensitive | true forces: masked in UI, copy-only (never keystroke inject), clipboard auto-clear 30 s, excluded from Win+V history, require re-auth if vault idle > N min |
| paste_mode | `paste` (Ctrl+V), `type` (SendInput unicode, for apps that block paste), `copy_only` |
| trigger | optional `;sig`-style abbreviation for phase 4 text expansion |

Vault file: `%APPDATA%\SnippetVault\vault.db` + versioned header (Argon2 params, salt,
wrapped vault key). Encrypted export `.svault`, plain JSON export behind a warning,
KDBX export later.

## 3. Feature scope by phase

### Phase 0: setup (half a day)
- Install rustup + Visual Studio Build Tools (C++ workload). Rust is not on this machine yet.
- `pnpm create tauri-app` (React + TS). Add plugins: global-shortcut, single-instance, autostart, positioner, clipboard-manager, opener.
- Strict CSP, capabilities scoped to the one palette window, no remote content.

### Phase 1: vault core (week 1)
- Rust `vault` crate: create/open/lock, Argon2id, XChaCha20-Poly1305, key wrapping, `secrecy`/`zeroize` on every key and plaintext, `CryptProtectMemory` on the resident vault key.
- Item CRUD over Tauri commands; the webview only receives plaintext for the item being viewed or pasted.
- Master password onboarding + unlock screen. Unit tests with known-answer vectors.

### Phase 2: palette + paste (week 2)
- Tray icon, autostart, single instance. Hotkey default `Ctrl+Shift+Space` (configurable).
- On hotkey: record `GetForegroundWindow()`, show borderless palette near caret/cursor, focus search box.
- Search-as-you-type (FTS5 + fuzzy), arrow keys, `Enter` = paste, `Ctrl+Enter` = copy only, `Ctrl+P` = pin, `Ctrl+N` = new item from current clipboard/selection, `Esc` = hide.
- Paste engine: hide window, re-activate saved HWND (AttachThreadInput fallback), release modifiers, clipboard swap with retry, Ctrl+V, restore previous clipboard after delay. Detect elevated target and show "run as admin to paste here" hint.
- Prompt variables: `{{name}}` opens a small form before paste.

### Phase 3: secrets hardening (week 3)
- Auto-lock on idle (GetLastInputInfo), on Windows lock screen (WTS_SESSION_LOCK), on sleep, and after N minutes.
- Windows Hello quick unlock. Optional, off by default.
- Clipboard: set `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0` on every write; timed clear only if clipboard still holds our value.
- `set_content_protected(true)` on the palette (blocks screenshots/screen share). Toggleable, because it renders black over Remote Desktop.
- Secret detection on clipboard capture (Ortu regexes) -> auto-mark sensitive or skip storing.
- Encrypted backup/export, import from CSV/JSON/KeePass.

### Phase 4: polish (week 4+)
- Optional clipboard history with per-app ignore list (password managers, terminals).
- Text-expansion triggers via Raw Input (espanso approach) for `;sig`-style abbreviations.
- Per-app default paste mode, Mica/Acrylic look, light/dark.
- Signed MSI/NSIS installer, Tauri updater, crash-free logging that never logs item bodies.
- Optional sync: the encrypted vault file in OneDrive/Syncthing, last-writer-wins, no server.

## 4. Threat model

Protects against: theft of the vault file (Argon2id + AEAD), Win+V / cloud clipboard
leakage, screenshots and screen sharing, shoulder surfing (masking), exposure while
idle or when the screen locks, accidental plaintext export.

Partially protects against: same-user malware. DPAPI and Windows Hello quick-unlock
can be driven by any process running as you, so they are convenience layers only.

Does not protect against: admin/kernel malware, memory dumps while unlocked, keyloggers
while you paste, a compromised WebView2 renderer reading the one item it was shown.

## 5. Open decisions

1. Hotkey default: `Ctrl+Shift+Space` vs `Alt+Space` (conflicts with PowerToys Run/Command Palette if installed).
2. Should `prompt` and `text` items be readable without unlocking, with only `secret` items behind the master password? Simpler and safer default is one locked vault, Hello quick-unlock makes it painless. Plan assumes single vault.
3. Product name. Working name: Snippet Vault.
4. License if ever published: MIT (keeps Apache/MIT borrowing clean; excludes GPL code).

## 6. Status log

- 2026-09-07: Phases 0, 1 and 2 built. Rust vault (Argon2id + XChaCha20-Poly1305, 6 passing tests), tray + Ctrl+Shift+Space palette, fuzzy search, editor, prompt variables, Win32 paste engine with clipboard restore and Win+V exclusion for sensitive items. Phase 3 items still open: idle/lock-screen auto-lock, Windows Hello, screenshot protection toggle, secret detection on clipboard, encrypted export, elevated-target warning.
- 2026-09-07 (later): user installed and confirmed hotkey + paste work. Added start-with-Windows (on by default, tray toggle); window now only auto-shows on first run.
- 2026-09-08: Phase 3 part 1. Auto-lock on idle (default 15 min), Windows lock screen and sleep; Settings screen (Ctrl+, / tray); quick unlock via Windows account password (CredUI + LogonUser SID check + DPAPI-wrapped vault key). Windows Hello skipped: user device does not support it. Still open: contentProtected toggle, secret detection on clipboard, encrypted export, elevated-target warning, code signing.
- 2026-09-08 (later): Backup/restore shipped: encrypted .svault (Argon2id + XChaCha20, own password), plain JSON behind warning, merge import, open-vault-folder. Native dialogs no longer auto-hide the palette. Still open: contentProtected toggle, secret detection on clipboard capture, elevated-target warning, KDBX export, code signing.
- 2026-09-08 (v0.2.0): Clipboard history: WM_CLIPBOARDUPDATE listener on the hidden watcher window, own-write marker format so pastes/restores are not recorded, respects ExcludeClipboardContentFromMonitorProcessing, per-app ignore list, secret detection (regex set + entropy) with mask/skip policy, dedupe, trim to N, Clips tab, promote clip to snippet via editor. Still open: contentProtected toggle, elevated-target warning, text-expansion triggers, KDBX export, code signing, auto-update.
- 2026-09-08 (v0.3.0): Text expansion via WH_KEYBOARD_LL hook on its own thread: rolling 64-char buffer, ToUnicodeEx with foreground layout and no-state-change flag, ignores injected input and our own window, clears on navigation keys and shortcuts, longest-trigger-first match, worker thread sends backspaces then pastes/types in place (secrets always paste), prompts with variables hand off to the palette. Trigger field on items with uniqueness validation. Still open: contentProtected toggle, elevated-target warning, KDBX export, code signing, auto-update.
- 2026-09-08 (v0.3.1): Screen-capture protection via set_content_protected (WDA_EXCLUDEFROMCAPTURE), on by default, toggle under Settings > Privacy. Still open: elevated-target warning, KDBX export, code signing, auto-update.
- 2026-09-08 (v0.4.0): Auto-update via tauri-plugin-updater against GitHub Releases latest.json, minisign key in ~/.tauri (backed up by the user), passive NSIS install, background check at +45 s and every 6 h, banner with install/later, manual check in Settings and tray. scripts/release.py automates version bump, signed build, latest.json and gh release. Still open: elevated-target warning, KDBX export, code signing.
- 2026-09-09 (v0.4.1): Fix: app did not start at login. The autostart plugin wrote an unquoted path with a trailing space to the Run key and Explorer failed to launch it (Shell-Core log: PID 0). Replaced with our own Run-key writer (quoted path + --autostart), self-repair on launch, opt-out marker file. Added file logging (%APPDATA%\\com.khatriautomations.snippetvault\\snippet-vault.log) and a panic hook.
