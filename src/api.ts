import { invoke } from "@tauri-apps/api/core";

export type ItemKind = "text" | "prompt" | "secret" | "clip";
export type PasteMode = "paste" | "type" | "copy_only";

export interface ItemSummary {
  id: string;
  kind: ItemKind;
  title: string;
  preview: string;
  tags: string[];
  folder: string;
  pinned: boolean;
  sensitive: boolean;
  paste_mode: PasteMode;
  trigger: string;
  use_count: number;
  last_used: number;
  has_variables: boolean;
}

export interface Item {
  id: string;
  kind: ItemKind;
  title: string;
  body: string;
  tags: string[];
  folder: string;
  pinned: boolean;
  sensitive: boolean;
  paste_mode: PasteMode;
  trigger: string;
  use_count: number;
  last_used: number;
  created_at: number;
  updated_at: number;
}

export interface ItemInput {
  id?: string;
  kind: ItemKind;
  title: string;
  body: string;
  tags: string[];
  folder: string;
  pinned: boolean;
  sensitive: boolean;
  paste_mode: PasteMode;
  trigger?: string;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  item_count: number;
  path: string;
  quick_unlock_available: boolean;
}

export interface Settings {
  auto_lock_minutes: number;
  lock_on_windows_lock: boolean;
  lock_on_sleep: boolean;
  quick_unlock: boolean;
  clip_history_enabled: boolean;
  clip_max_items: number;
  clip_ignore_apps: string[];
  clip_secret_policy: "mask" | "skip";
  expansion_enabled: boolean;
}

export interface ImportPick {
  path: string;
  encrypted: boolean;
}

export interface ImportResult {
  added: number;
  updated: number;
  skipped: number;
}

export const api = {
  backupExportEncrypted: (password: string) =>
    invoke<string | null>("backup_export_encrypted", { password }),
  backupExportPlain: () => invoke<string | null>("backup_export_plain"),
  backupPickImport: () => invoke<ImportPick | null>("backup_pick_import"),
  backupImport: (path: string, password?: string) =>
    invoke<ImportResult>("backup_import", { path, password: password ?? null }),
  openDataFolder: () => invoke<void>("open_data_folder"),
  clipsClear: () => invoke<number>("clips_clear"),
  status: () => invoke<VaultStatus>("vault_status"),
  create: (password: string) => invoke<void>("vault_create", { password }),
  unlock: (password: string) => invoke<number>("vault_unlock", { password }),
  quickUnlock: () => invoke<number>("vault_quick_unlock"),
  lock: () => invoke<void>("vault_lock"),
  settingsGet: () => invoke<Settings>("settings_get"),
  settingsSet: (settings: Settings) => invoke<Settings>("settings_set", { settings }),
  autostartGet: () => invoke<boolean>("autostart_get"),
  autostartSet: (enabled: boolean) => invoke<boolean>("autostart_set", { enabled }),
  search: (query: string, kind?: ItemKind) =>
    invoke<ItemSummary[]>("items_search", { query, kind: kind ?? null, limit: 60 }),
  get: (id: string, reveal = false) => invoke<Item>("item_get", { id, reveal }),
  save: (input: ItemInput) => invoke<Item>("item_save", { input }),
  remove: (id: string) => invoke<void>("item_delete", { id }),
  setPinned: (id: string, pinned: boolean) => invoke<void>("item_set_pinned", { id, pinned }),
  use: (id: string, mode?: "paste" | "type" | "copy", vars?: Record<string, string>) =>
    invoke<void>("item_use", { id, mode: mode ?? null, vars: vars ?? null }),
  clipboardRead: () => invoke<string | null>("clipboard_read"),
  hide: () => invoke<void>("palette_hide"),
  show: () => invoke<void>("palette_show"),
  quit: () => invoke<void>("app_quit"),
};

/** Extract unique {{variable}} names in order of appearance. */
export function extractVariables(body: string): string[] {
  const out: string[] = [];
  const re = /\{\{\s*([A-Za-z0-9_ .-]+?)\s*\}\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) {
    const name = m[1].trim();
    if (!out.includes(name)) out.push(name);
  }
  return out;
}
