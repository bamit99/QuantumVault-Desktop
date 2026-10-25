import { invoke } from "@tauri-apps/api/core";

/** A single encrypted file in the vault (decrypted metadata). */
export interface FileEntry {
  id: string;
  name: string;
  size: number;
  mime: string;
  created: number;
  modified: number;
}

/** A decrypted file returned by `extract_file`. */
export interface ExtractedFile {
  id: string;
  name: string;
  mime: string;
  data: number[];
}

/** A registered vault with computed status. */
export interface VaultStatus {
  name: string;
  path: string;
  exists: boolean;
  unlocked: boolean;
}

/** Typed wrapper over the Rust Tauri commands. */
export const api = {
  // lifecycle
  createVault: (path: string, passphrase: string) =>
    invoke<string>("create_vault", { path, passphrase }),
  openVault: (path: string, passphrase: string) =>
    invoke<string>("open_vault", { path, passphrase }),
  lockVault: (path: string) => invoke<void>("lock_vault", { path }),
  removeVault: (path: string) => invoke<void>("remove_vault", { path }),
  listVaults: () => invoke<VaultStatus[]>("list_vaults"),
  discoverVaults: (folder: string) => invoke<string[]>("discover_vaults", { folder }),
  isUnlocked: (path: string) => invoke<boolean>("is_unlocked", { path }),

  passphraseStrength: (passphrase: string) =>
    invoke<string | null>("passphrase_strength", { passphrase }),

  // files (keyed by vault path)
  listFiles: (vault: string) => invoke<FileEntry[]>("list_files", { vault }),
  addFileFromPath: (vault: string, path: string) =>
    invoke<FileEntry>("add_file_from_path", { vault, path }),
  addFolderFromPath: (vault: string, path: string) =>
    invoke<number>("add_folder_from_path", { vault, path }),
  extractFile: (vault: string, id: string) =>
    invoke<ExtractedFile>("extract_file", { vault, id }),
  extractFileTo: (vault: string, id: string, destDir: string) =>
    invoke<string>("extract_file_to", { vault, id, destDir }),
  deleteFile: (vault: string, id: string) => invoke<void>("delete_file", { vault, id }),
  renameFile: (vault: string, id: string, newName: string) =>
    invoke<void>("rename_file", { vault, id, newName }),
};

/** Format a byte size for display. */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}
