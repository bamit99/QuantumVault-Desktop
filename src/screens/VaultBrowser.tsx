import { useCallback, useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  DownloadSimple,
  Eye,
  File,
  FileImage,
  FilePdf,
  FileText,
  FolderPlus,
  LockSimple,
  PencilSimple,
  Plus,
  Trash,
} from "@phosphor-icons/react";
import { open } from "@tauri-apps/plugin-dialog";
import { Button } from "../components/Button";
import { Brand } from "../components/Brand";
import { Footer } from "../components/Footer";
import { PreviewModal } from "../components/Preview";
import { api, formatSize, type ExtractedFile, type FileEntry } from "../lib/api";

function iconFor(mime: string) {
  if (mime.startsWith("image/")) return <FileImage size={26} weight="duotone" className="text-accent" />;
  if (mime === "application/pdf") return <FilePdf size={26} weight="duotone" className="text-danger" />;
  if (mime.startsWith("text/")) return <FileText size={26} weight="duotone" className="text-ink-dim" />;
  return <File size={26} weight="duotone" className="text-ink-dim" />;
}

export function VaultBrowser({
  path,
  onLock,
}: {
  path: string;
  onLock: () => void;
}) {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [busyMsg, setBusyMsg] = useState("");
  const [error, setError] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [preview, setPreview] = useState<ExtractedFile | null>(null);

  const refresh = useCallback(async () => {
    try {
      setFiles(await api.listFiles(path));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const vaultName = path.split(/[\\/]/).filter(Boolean).pop() ?? "Vault";

  async function addFiles() {
    const selected = await open({ multiple: true, title: "Choose files to encrypt" });
    if (!selected) return;
    const paths = Array.isArray(selected) ? selected : [selected];
    setBusy(true);
    setBusyMsg(`Encrypting ${paths.length} file${paths.length === 1 ? "" : "s"}…`);
    setError("");
    try {
      for (const p of paths) await api.addFileFromPath(path, p);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
      setBusyMsg("");
    }
  }

  async function addFolder() {
    const selected = await open({ directory: true, title: "Choose a folder to encrypt" });
    if (typeof selected !== "string") return;
    setBusy(true);
    setBusyMsg("Encrypting folder…");
    setError("");
    try {
      await api.addFolderFromPath(path, selected);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
      setBusyMsg("");
    }
  }

  async function openPreview(entry: FileEntry) {
    try {
      setPreview(await api.extractFile(path, entry.id));
    } catch (e) {
      setError(String(e));
    }
  }

  async function extract(entry: FileEntry) {
    const dir = await open({ directory: true, title: "Extract to…" });
    if (typeof dir !== "string") return;
    try {
      await api.extractFileTo(path, entry.id, dir);
    } catch (e) {
      setError(String(e));
    }
  }

  async function commitRename(entry: FileEntry) {
    const name = editingName.trim();
    if (name && name !== entry.name) {
      try {
        await api.renameFile(path, entry.id, name);
        await refresh();
      } catch (e) {
        setError(String(e));
      }
    }
    setEditingId(null);
  }

  async function remove(entry: FileEntry) {
    try {
      await api.deleteFile(path, entry.id);
      setConfirmDelete(null);
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  async function lock() {
    try {
      await api.lockVault(path);
    } finally {
      onLock();
    }
  }

  return (
    <div className="flex min-h-full flex-col">
      <header className="glass sticky top-0 z-10 border-x-0 border-t-0">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <Brand size={32} wordSize="text-lg" />
          <div className="flex items-center gap-3">
            <span className="mono-value hidden max-w-[260px] truncate sm:block">{path}</span>
            <Button variant="ghost" size="sm" icon={<LockSimple size={16} />} onClick={lock}>
              Lock
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{vaultName}</h1>
            <p className="mt-1 text-sm text-ink-dim">
              {files.length} file{files.length === 1 ? "" : "s"} · encrypted at rest
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" icon={<FolderPlus size={18} weight="bold" />} onClick={addFolder} disabled={busy}>
              Add folder
            </Button>
            <Button icon={<Plus size={18} weight="bold" />} onClick={addFiles} disabled={busy}>
              {busy ? busyMsg || "Working…" : "Add files"}
            </Button>
          </div>
        </div>

        {error && (
          <p className="mt-4 rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-sm text-danger">
            {error}
          </p>
        )}

        <div className="mt-6">
          {loading ? (
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="glass h-28 animate-pulse rounded-xl" />
              ))}
            </div>
          ) : files.length === 0 ? (
            <EmptyState onAdd={addFiles} onAddFolder={addFolder} />
          ) : (
            <motion.ul layout className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-4">
              <AnimatePresence>
                {files.map((f) => {
                  const slash = f.name.lastIndexOf("/");
                  const baseName = slash >= 0 ? f.name.slice(slash + 1) : f.name;
                  const folder = slash >= 0 ? f.name.slice(0, slash) : "";
                  return (
                    <motion.li
                      key={f.id}
                      layout
                      initial={{ opacity: 0, scale: 0.96 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.9 }}
                      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                      onDoubleClick={() => openPreview(f)}
                      className="group glass relative flex cursor-pointer flex-col rounded-xl p-4 transition-colors hover:border-line-strong"
                      title={`${f.name} — double-click to preview`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-surface-2">
                          {iconFor(f.mime)}
                        </div>
                        <div className="flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                          <IconBtn title="Preview" onClick={() => openPreview(f)}>
                            <Eye size={16} />
                          </IconBtn>
                          <IconBtn title="Extract" onClick={() => extract(f)}>
                            <DownloadSimple size={16} />
                          </IconBtn>
                          <IconBtn
                            title="Rename"
                            onClick={() => {
                              setEditingId(f.id);
                              setEditingName(baseName);
                            }}
                          >
                            <PencilSimple size={16} />
                          </IconBtn>
                          {confirmDelete === f.id ? (
                            <IconBtn title="Confirm delete" danger onClick={() => remove(f)}>
                              <Trash size={16} weight="fill" />
                            </IconBtn>
                          ) : (
                            <IconBtn title="Delete" onClick={() => setConfirmDelete(f.id)}>
                              <Trash size={16} />
                            </IconBtn>
                          )}
                        </div>
                      </div>

                      {editingId === f.id ? (
                        <input
                          autoFocus
                          value={editingName}
                          onChange={(e) => setEditingName(e.currentTarget.value)}
                          onBlur={() => commitRename(f)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") commitRename(f);
                            if (e.key === "Escape") setEditingId(null);
                          }}
                          className="mt-3 w-full rounded-md border border-accent/50 bg-surface-2 px-2 py-1 text-sm text-ink focus:outline-none"
                        />
                      ) : (
                        <>
                          {folder && (
                            <p className="mono-value mt-3 truncate text-[11px]">{folder}/</p>
                          )}
                          <p className="mt-0.5 truncate text-sm font-medium text-ink">{baseName}</p>
                        </>
                      )}

                      <div className="mt-1 flex items-center justify-between">
                        <span className="text-xs text-ink-faint">{formatSize(f.size)}</span>
                        <span className="text-xs text-ink-faint">
                          {new Date(f.modified * 1000).toLocaleDateString()}
                        </span>
                      </div>
                    </motion.li>
                  );
                })}
              </AnimatePresence>
            </motion.ul>
          )}
        </div>
      </main>

      <Footer className="border-t border-line" />

      <AnimatePresence>
        {preview && <PreviewModal file={preview} onClose={() => setPreview(null)} />}
      </AnimatePresence>
    </div>
  );
}

function IconBtn({
  children,
  title,
  danger,
  onClick,
}: {
  children: React.ReactNode;
  title: string;
  danger?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      title={title}
      onClick={onClick}
      className={`flex h-7 w-7 items-center justify-center rounded-lg transition-colors cursor-pointer ${
        danger
          ? "bg-danger/15 text-danger hover:bg-danger/25"
          : "bg-surface-2 text-ink-dim hover:text-ink hover:bg-elevated"
      }`}
    >
      {children}
    </button>
  );
}

function EmptyState({ onAdd, onAddFolder }: { onAdd: () => void; onAddFolder: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="glass flex flex-col items-center justify-center rounded-2xl px-6 py-16 text-center"
    >
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/10 text-accent">
        <Plus size={30} weight="bold" />
      </div>
      <h3 className="mt-5 text-lg font-semibold text-ink">Your vault is empty</h3>
      <p className="mt-2 max-w-sm text-sm leading-relaxed text-ink-dim">
        Add files or an entire folder to encrypt them. They're stored as opaque
        ciphertext in your cloud folder — nothing readable leaks to the cloud.
      </p>
      <div className="mt-6 flex gap-2">
        <Button variant="secondary" icon={<FolderPlus size={18} weight="bold" />} onClick={onAddFolder}>
          Add folder
        </Button>
        <Button icon={<Plus size={18} weight="bold" />} onClick={onAdd}>
          Add files
        </Button>
      </div>
    </motion.div>
  );
}
