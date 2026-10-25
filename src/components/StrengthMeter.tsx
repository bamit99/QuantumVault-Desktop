import { useEffect, useState } from "react";
import { api } from "../lib/api";

/**
 * A 4-segment passphrase strength meter backed by the Rust KDF's strength check.
 */
export function StrengthMeter({ passphrase }: { passphrase: string }) {
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    if (passphrase.length === 0) {
      setProblem(null);
      return;
    }
    const t = setTimeout(() => {
      api.passphraseStrength(passphrase).then(setProblem).catch(() => setProblem(null));
    }, 150);
    return () => clearTimeout(t);
  }, [passphrase]);

  // Heuristic segment fill by length.
  const segments = passphrase.length === 0 ? 0 : passphrase.length < 8 ? 1 : passphrase.length < 12 ? 2 : passphrase.length < 16 ? 3 : 4;
  const strong = passphrase.length >= 12 && problem === null;

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex gap-1.5">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded-full transition-colors duration-300 ${
              i < segments
                ? strong
                  ? "bg-accent"
                  : passphrase.length >= 8
                    ? "bg-warning"
                    : "bg-danger"
                : "bg-line"
            }`}
          />
        ))}
      </div>
      {passphrase.length > 0 && (
        <p className={`text-xs ${strong ? "text-accent" : "text-ink-faint"}`}>
          {strong ? "Strong passphrase" : problem ?? "Keep going…"}
        </p>
      )}
    </div>
  );
}
