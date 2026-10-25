import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { ArrowLeft, FolderSimple, LockKey, MagnifyingGlass } from "@phosphor-icons/react";
import { open } from "@tauri-apps/plugin-dialog";
import { Button } from "../components/Button";
import { UnlockModal } from "../components/UnlockModal";
import { api } from "../lib/api";

function base(path: string) {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

export function AddVault({
  onDone,
  onBack,
}: {
  onDone: (path: string) => void;
  onBack: () => void;
}) {
  const [root, setRoot] = useState("");
  const [found, setFound] = useState<string[]>([]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [unlockTarget, setUnlockTarget] = useState<{ name: string; path: string } | null>(null);

  async function pickAndScan() {
    const selected = await open({ directory: true, title: "Choose a folder to scan for vaults" });
    if (typeof selected !== "string") return;
    setRoot(selected);
    setError("");
    setScanning(true);
    try {
      const vaults = await api.discoverVaults(selected);
      setFound(vaults);
      if (vaults.length === 0) {
        setError("No vaults found in that folder (or its subfolders).");
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center px-6 py-12">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="glass-strong w-full max-w-md rounded-2xl p-8"
      >
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-sm text-ink-dim hover:text-ink transition-colors cursor-pointer"
        >
          <ArrowLeft size={16} /> Back
        </button>

        <h2 className="mt-4 text-2xl font-semibold tracking-tight">Add an existing vault</h2>
        <p className="mt-1 text-sm text-ink-dim">
          Scan a cloud folder for existing vaults, then unlock them.
        </p>

        <div className="mt-6">
          <Button
            variant="secondary"
            size="lg"
            className="w-full"
            icon={<FolderSimple size={18} weight="bold" />}
            onClick={pickAndScan}
            disabled={scanning}
          >
            {root ? base(root) : "Choose a folder to scan"}
          </Button>
        </div>

        {error && (
          <p className="mt-4 rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-sm text-danger">
            {error}
          </p>
        )}

        {scanning && (
          <div className="mt-4 flex items-center justify-center gap-2 py-6 text-sm text-ink-dim">
            <MagnifyingGlass size={18} className="animate-pulse" /> Scanning for vaults…
          </div>
        )}

        {found.length > 0 && (
          <div className="mt-4 space-y-2">
            <p className="text-xs text-ink-faint">Found {found.length} vault{found.length === 1 ? "" : "s"}:</p>
            {found.map((p) => (
              <button
                key={p}
                onClick={() => setUnlockTarget({ name: base(p), path: p })}
                className="glass flex w-full items-center gap-3 rounded-xl p-3 text-left transition-colors hover:border-line-strong cursor-pointer"
              >
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent">
                  <LockKey size={18} weight="duotone" />
                </div>
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-ink">{base(p)}</p>
                  <p className="mono-value truncate text-[11px]">{p}</p>
                </div>
              </button>
            ))}
          </div>
        )}
      </motion.div>

      <AnimatePresence>
        {unlockTarget && (
          <UnlockModal
            name={unlockTarget.name}
            path={unlockTarget.path}
            onClose={() => setUnlockTarget(null)}
            onUnlocked={(p) => {
              setUnlockTarget(null);
              onDone(p);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
