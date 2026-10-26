import { useState } from "react";
import { motion } from "motion/react";
import { ArrowLeft, Eye, EyeSlash, FolderSimple } from "@phosphor-icons/react";
import { open } from "@tauri-apps/plugin-dialog";
import { Button } from "../components/Button";
import { Field, Input } from "../components/Field";
import { StrengthMeter } from "../components/StrengthMeter";
import { api } from "../lib/api";
import { usePassphraseStrength } from "../lib/strength";

export function CreateVault({
  onDone,
  onBack,
}: {
  onDone: (path: string) => void;
  onBack: () => void;
}) {
  const [name, setName] = useState("");
  const [parent, setParent] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // The backend policy is authoritative: 12+ characters *or* a 4-word
  // passphrase, and no common word / low-variety string.
  const strength = usePassphraseStrength(passphrase);

  async function pickFolder() {
    const selected = await open({ directory: true, title: "Choose a cloud folder" });
    if (typeof selected === "string") setParent(selected);
  }

  const mismatch = confirm.length > 0 && confirm !== passphrase;
  const canCreate =
    name.trim().length > 0 &&
    parent.length > 0 &&
    strength.ok &&
    !mismatch &&
    !busy;

  async function create() {
    setError("");
    setBusy(true);
    try {
      const path = `${parent.replace(/[\\/]+$/, "")}\\${name.trim()}`;
      await api.createVault(path, passphrase);
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

        <h2 className="mt-4 text-2xl font-semibold tracking-tight">Create a vault</h2>
        <p className="mt-1 text-sm text-ink-dim">
          Pick a cloud-synced folder and set a passphrase. It can't be recovered if
          you forget it.
        </p>

        <div className="mt-6 flex flex-col gap-4">
          <Field label="Vault name" id="vault-name">
            <Input
              id="vault-name"
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
              placeholder="My documents"
              autoFocus
            />
          </Field>

          <Field
            label="Cloud folder"
            id="vault-folder"
            hint={parent || "Choose where the encrypted vault lives"}
          >
            <Input
              id="vault-folder"
              value={parent}
              onChange={(e) => setParent(e.currentTarget.value)}
              placeholder="e.g. G:\My Drive"
            />
            <button
              onClick={pickFolder}
              className="absolute right-2 top-1/2 -translate-y-1/2 flex h-8 w-8 items-center justify-center rounded-lg text-ink-dim hover:text-ink hover:bg-surface-2 transition-colors cursor-pointer"
              title="Browse"
            >
              <FolderSimple size={18} />
            </button>
          </Field>

          <Field
            label="Passphrase"
            id="pass"
            hint="At least 12 characters, or a 4-word passphrase"
          >
            <Input
              id="pass"
              type={show ? "text" : "password"}
              value={passphrase}
              onChange={(e) => setPassphrase(e.currentTarget.value)}
              placeholder="A long, unique passphrase"
            />
            <button
              onClick={() => setShow((s) => !s)}
              className="absolute right-2 top-1/2 -translate-y-1/2 flex h-8 w-8 items-center justify-center rounded-lg text-ink-faint hover:text-ink transition-colors cursor-pointer"
              title={show ? "Hide" : "Show"}
            >
              {show ? <EyeSlash size={18} /> : <Eye size={18} />}
            </button>
          </Field>

          <StrengthMeter
            passphrase={passphrase}
            problem={strength.problem}
            ok={strength.ok}
          />

          <Field label="Confirm passphrase" id="confirm" error={mismatch ? "Passphrases don't match" : undefined}>
            <Input
              id="confirm"
              type={show ? "text" : "password"}
              value={confirm}
              onChange={(e) => setConfirm(e.currentTarget.value)}
              placeholder="Re-enter your passphrase"
            />
          </Field>

          {error && (
            <p className="rounded-lg border border-danger/25 bg-danger/10 px-3 py-2 text-sm text-danger">
              {error}
            </p>
          )}

          <Button size="lg" disabled={!canCreate} onClick={create}>
            {busy ? "Creating…" : "Create vault"}
          </Button>
        </div>
      </motion.div>
    </div>
  );
}
