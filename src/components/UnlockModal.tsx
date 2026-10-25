import { useEffect, useState } from "react";
import { motion } from "motion/react";
import { Eye, EyeSlash, LockSimple, X } from "@phosphor-icons/react";
import { Button } from "./Button";
import { Field, Input } from "./Field";
import { api } from "../lib/api";

/** Password prompt to unlock a specific vault. */
export function UnlockModal({
  name,
  path,
  onClose,
  onUnlocked,
}: {
  name: string;
  path: string;
  onClose: () => void;
  onUnlocked: (path: string) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function unlock() {
    setError("");
    setBusy(true);
    try {
      await api.openVault(path, passphrase);
      onUnlocked(path);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.96 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        onClick={(e) => e.stopPropagation()}
        className="glass-strong w-full max-w-sm rounded-2xl p-6"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent/15 text-accent">
              <LockSimple size={20} weight="bold" />
            </div>
            <div className="min-w-0">
              <p className="truncate font-semibold text-ink">{name}</p>
              <p className="mono-value truncate text-[11px]">{path}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-ink-dim hover:text-ink hover:bg-surface-2 transition-colors cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        <div className="mt-5 flex flex-col gap-3">
          <Field label="Passphrase" id="unlock-pass">
            <Input
              id="unlock-pass"
              type={show ? "text" : "password"}
              value={passphrase}
              onChange={(e) => setPassphrase(e.currentTarget.value)}
              placeholder="Enter the vault passphrase"
              autoFocus
              onKeyDown={(e) => e.key === "Enter" && unlock()}
            />
            <button
              onClick={() => setShow((s) => !s)}
              className="absolute right-2 top-1/2 -translate-y-1/2 flex h-8 w-8 items-center justify-center rounded-lg text-ink-faint hover:text-ink transition-colors cursor-pointer"
            >
              {show ? <EyeSlash size={18} /> : <Eye size={18} />}
            </button>
          </Field>

          {error && (
            <p className="rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-sm text-danger">
              {error}
            </p>
          )}

          <Button size="lg" disabled={!passphrase || busy} onClick={unlock}>
            {busy ? "Unlocking…" : "Unlock"}
          </Button>
        </div>
      </motion.div>
    </motion.div>
  );
}
