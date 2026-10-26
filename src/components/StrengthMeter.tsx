/**
 * A 4-segment passphrase strength meter.
 *
 * Presentational: the authoritative verdict comes from the backend
 * (`crypto::kdf::strength_problem`) via the `usePassphraseStrength` hook, so
 * the meter and the backend can never disagree about what is acceptable.
 */
export function StrengthMeter({
  passphrase,
  problem,
  ok,
}: {
  passphrase: string;
  /** The backend's rejection reason, or `null` when the passphrase is accepted. */
  problem: string | null;
  /** True when the backend accepts this passphrase. */
  ok: boolean;
}) {
  // Heuristic segment fill by length; a passphrase the backend accepts is
  // always shown as full strength.
  const words = passphrase.split(" ").filter((w) => w.length > 0).length;
  const segments =
    passphrase.length === 0
      ? 0
      : ok
        ? 4
        : passphrase.length < 8 && words < 4
          ? 1
          : passphrase.length < 12 && words < 4
            ? 2
            : 3;

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex gap-1.5">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded-full transition-colors duration-300 ${
              i < segments
                ? ok
                  ? "bg-accent"
                  : segments >= 3
                    ? "bg-warning"
                    : "bg-danger"
                : "bg-line"
            }`}
          />
        ))}
      </div>
      {passphrase.length > 0 && (
        <p className={`text-xs ${ok ? "text-accent" : "text-ink-faint"}`}>
          {ok ? "Strong passphrase" : problem ?? "Keep going…"}
        </p>
      )}
    </div>
  );
}
