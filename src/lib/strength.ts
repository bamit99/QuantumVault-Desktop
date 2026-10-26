import { useEffect, useState } from "react";
import { api } from "./api";

/**
 * Passphrase strength, judged by the Rust KDF (the single source of truth).
 *
 * The backend policy (`crypto::kdf::strength_problem`) accepts a passphrase
 * with at least 12 characters **or** a 4-word passphrase, rejects low-variety
 * strings and rejects common words/sequences. The UI must not be more
 * permissive than that, so the check is delegated to the backend rather than
 * reimplemented here.
 */
export interface PassphraseStrength {
  /** The backend's rejection reason, or `null` when the passphrase is accepted. */
  problem: string | null;
  /** True once the backend has answered (or the field is empty). */
  ready: boolean;
  /** True when the backend accepts this passphrase. */
  ok: boolean;
}

/**
 * Debounced backend-backed passphrase check.
 *
 * `ok` is `false` until the backend has answered, so a form that gates on it
 * can never submit a passphrase the backend will reject.
 */
export function usePassphraseStrength(passphrase: string): PassphraseStrength {
  const [problem, setProblem] = useState<string | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (passphrase.length === 0) {
      setProblem(null);
      setReady(true);
      return;
    }
    setReady(false);
    const t = setTimeout(() => {
      api
        .passphraseStrength(passphrase)
        .then((p) => {
          setProblem(p);
          setReady(true);
        })
        .catch(() => {
          // If the check cannot run, stay conservative: block submission.
          setProblem("Could not verify the passphrase — try again");
          setReady(true);
        });
    }, 150);
    return () => clearTimeout(t);
  }, [passphrase]);

  return {
    problem,
    ready,
    ok: passphrase.length > 0 && ready && problem === null,
  };
}
