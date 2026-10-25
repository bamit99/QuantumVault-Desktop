import { useCallback, useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { FolderPlus, LockKey, LockSimple, Plus, ShieldCheck, Trash } from "@phosphor-icons/react";
import { Button } from "../components/Button";
import { Brand, Mark } from "../components/Brand";
import { Footer } from "../components/Footer";
import { UnlockModal } from "../components/UnlockModal";
import { api, type VaultStatus } from "../lib/api";

export function Home({
  onCreate,
  onAdd,
  onOpen,
}: {
  onCreate: () => void;
  onAdd: () => void;
  onOpen: (path: string) => void;
}) {
  const [vaults, setVaults] = useState<VaultStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [unlockTarget, setUnlockTarget] = useState<VaultStatus | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setVaults(await api.listVaults());
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function handleClick(v: VaultStatus) {
    if (!v.exists) return; // folder is missing — nothing to unlock
    if (v.unlocked) onOpen(v.path);
    else setUnlockTarget(v);
  }

  async function remove(path: string) {
    try {
      await api.removeVault(path);
      setConfirmRemove(null);
      await refresh();
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="flex min-h-full flex-col">
      <header className="glass sticky top-0 z-10 border-x-0 border-t-0">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <Brand size={32} wordSize="text-lg" />
          <div className="flex gap-2">
            <Button variant="secondary" icon={<FolderPlus size={18} weight="bold" />} onClick={onAdd}>
              Add vault
            </Button>
            <Button icon={<Plus size={18} weight="bold" />} onClick={onCreate}>
              Create vault
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">
        {/* hero branding */}
        <div className="flex flex-col items-center text-center">
          <Mark size={76} />
          <h1 className="mt-6 text-4xl font-semibold tracking-tighter leading-none md:text-5xl">
            Quantum <span className="text-accent">Vault</span>
          </h1>
          <p className="mt-3 max-w-md text-[15px] leading-relaxed text-ink-dim">
            Post-quantum encrypted vaults for your cloud folders.
          </p>
        </div>

        <div className="mt-10">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold tracking-tight text-ink">Your vaults</h2>
            <span className="text-sm text-ink-dim">
              {vaults.length} registered
            </span>
          </div>

          <div className="mt-4">
            {loading ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="glass h-20 animate-pulse rounded-xl" />
              ))}
            </div>
          ) : vaults.length === 0 ? (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass flex flex-col items-center justify-center rounded-2xl px-6 py-16 text-center"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/10 text-accent">
                <ShieldCheck size={30} weight="duotone" />
              </div>
              <h3 className="mt-5 text-lg font-semibold text-ink">No vaults yet</h3>
              <p className="mt-2 max-w-sm text-sm leading-relaxed text-ink-dim">
                Create a new vault or add an existing one from your cloud folders.
              </p>
              <div className="mt-6 flex gap-2">
                <Button variant="secondary" icon={<FolderPlus size={18} weight="bold" />} onClick={onAdd}>
                  Add vault
                </Button>
                <Button icon={<Plus size={18} weight="bold" />} onClick={onCreate}>
                  Create vault
                </Button>
              </div>
            </motion.div>
          ) : (
            <motion.ul layout className="space-y-3">
              <AnimatePresence>
                {vaults.map((v) => (
                  <motion.li
                    key={v.path}
                    layout
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.97 }}
                    transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                    onClick={() => handleClick(v)}
                    className={`group glass flex items-center gap-4 rounded-xl p-4 transition-colors ${
                      v.exists
                        ? "cursor-pointer hover:border-line-strong"
                        : "opacity-60"
                    }`}
                  >
                    <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-ink-dim">
                      {v.unlocked ? (
                        <LockKey size={24} weight="duotone" className="text-accent" />
                      ) : (
                        <LockSimple size={24} weight="duotone" />
                      )}
                    </div>

                    <div className="min-w-0 flex-1">
                      <p className="truncate font-medium text-ink">{v.name}</p>
                      <p className="mono-value truncate text-[11px]">{v.path}</p>
                    </div>

                    <StatusDot exists={v.exists} />

                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded-md px-2 py-0.5 text-[11px] font-medium ${
                          !v.exists
                            ? "bg-danger/15 text-danger"
                            : v.unlocked
                              ? "bg-accent/15 text-accent"
                              : "bg-surface-2 text-ink-dim"
                        }`}
                      >
                        {!v.exists ? "Missing" : v.unlocked ? "Unlocked" : "Locked"}
                      </span>
                      {confirmRemove === v.path ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            remove(v.path);
                          }}
                          className="flex h-8 w-8 items-center justify-center rounded-lg bg-danger/15 text-danger hover:bg-danger/25 transition-colors cursor-pointer"
                          title="Confirm remove"
                        >
                          <Trash size={16} weight="fill" />
                        </button>
                      ) : (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setConfirmRemove(v.path);
                          }}
                          className="flex h-8 w-8 items-center justify-center rounded-lg text-ink-faint opacity-0 transition-opacity hover:text-danger hover:bg-danger/10 group-hover:opacity-100 cursor-pointer"
                          title="Remove from list"
                        >
                          <Trash size={16} />
                        </button>
                      )}
                    </div>
                  </motion.li>
                ))}
              </AnimatePresence>
            </motion.ul>
          )}
          </div>
        </div>
      </main>

      <Footer className="border-t border-line" />

      <AnimatePresence>
        {unlockTarget && (
          <UnlockModal
            name={unlockTarget.name}
            path={unlockTarget.path}
            onClose={() => setUnlockTarget(null)}
            onUnlocked={(p) => {
              setUnlockTarget(null);
              onOpen(p);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function StatusDot({ exists }: { exists: boolean }) {
  return (
    <span
      className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${
        exists ? "bg-accent" : "bg-danger"
      }`}
      title={
        exists
          ? "Available — vault folder found"
          : "Missing — vault folder not found at this path"
      }
    />
  );
}
