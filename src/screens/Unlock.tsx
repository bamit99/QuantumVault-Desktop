import { useState } from "react";
import { motion } from "motion/react";
import { ArrowLeft, Eye, EyeSlash, FolderSimple, LockSimple } from "@phosphor-icons/react";
import { open } from "@tauri-apps/plugin-dialog";
import { Button } from "../components/Button";
import { Field, Input } from "../components/Field";
import { api } from "../lib/api";

export function Unlock({
  onDone,
  onBack,
}: {
  onDone: (path: string) => void;
  onBack: () => void;
}) {
  const [path, setPath] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function pickFolder() {
    const selected = await open({ directory: true, title: "Choose the vault folder" });
    if (typeof selected === "string") setPath(selected);
  }

  async function unlock() {
    setError("");
    setBusy(true);
    try {
      await api.openVault(path, passphrase);
      onDone(path);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
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

        <div className="mt-4 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent/15 text-accent">
            <LockSimple size={22} weight="bold" />
          </div>
          <h2 className="text-2xl font-semibold tracking-tight">Unlock vault</h2>
        </div>

        <div className="mt-6 flex flex-col gap-4">
          <Field label="Vault folder" id="unlock-folder" hint={path || "The folder containing vault.meta"}>
            <Input
              id="unlock-folder"
              value={path}
              onChange={(e) => setPath(e.currentTarget.value)}
              placeholder="e.g. G:\My Drive\My documents"
            />
            <button
              onClick={pickFolder}
              className="absolute right-2 top-1/2 -translate-y-1/2 flex h-8 w-8 items-center justify-center rounded-lg text-ink-dim hover:text-ink hover:bg-surface-2 transition-colors cursor-pointer"
              title="Browse"
            >
              <FolderSimple size={18} />
            </button>
          </Field>

          <Field label="Passphrase" id="unlock-pass">
            <Input
              id="unlock-pass"
              type={show ? "text" : "password"}
              value={passphrase}
              onChange={(e) => setPassphrase(e.currentTarget.value)}
              placeholder="Your passphrase"
              onKeyDown={(e) => e.key === "Enter" && unlock()}
            />
            <button
              onClick={() => setShow((s) => !s)}
              className="absolute right-2 top-1/2 -translate-y-1/2 flex h-8 w-8 items-center justify-center rounded-lg text-ink-faint hover:text-ink transition-colors cursor-pointer"
              title={show ? "Hide" : "Show"}
            >
              {show ? <EyeSlash size={18} /> : <Eye size={18} />}
            </button>
          </Field>

          {error && (
            <p className="rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-sm text-danger">
              {error}
            </p>
          )}

          <Button
            size="lg"
            disabled={!path || !passphrase || busy}
            onClick={unlock}
            icon={<LockSimple size={18} weight="bold" />}
          >
            {busy ? "Unlocking…" : "Unlock"}
          </Button>
        </div>
      </motion.div>
    </div>
  );
}
