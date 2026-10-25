/** Brand mark + wordmark. */

/**
 * The Quantum Vault mark: a hexagonal lattice cell (a nod to ML-KEM's
 * lattice-based math) with a keyhole cut through it. Emerald = "secure".
 */
export function Mark({ size = 40, className = "" }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="qv-hex" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#34D399" />
          <stop offset="0.55" stopColor="#10B981" />
          <stop offset="1" stopColor="#059669" />
        </linearGradient>
      </defs>
      {/* hexagon */}
      <path
        d="M24 2.8 42.4 13.4v21.2L24 45.2 5.6 34.6V13.4L24 2.8Z"
        fill="url(#qv-hex)"
        stroke="rgba(255,255,255,0.16)"
        strokeWidth="0.8"
      />
      {/* inner top highlight */}
      <path
        d="M24 5.4 39.4 14.3v15.6l-15.4 8.9-15.4-8.9V14.3L24 5.4Z"
        fill="none"
        stroke="rgba(255,255,255,0.18)"
        strokeWidth="0.5"
      />
      {/* keyhole */}
      <circle cx="24" cy="19.6" r="4.3" fill="#04150D" />
      <path d="M21 23.6h6l-1.3 9.2h-3.4L21 23.6Z" fill="#04150D" />
    </svg>
  );
}

export function Wordmark({ size = "text-xl" }: { size?: string }) {
  return (
    <span className={`font-semibold tracking-tight text-ink ${size}`}>
      Quantum <span className="text-accent">Vault</span>
    </span>
  );
}

export function Brand({
  size = 40,
  wordSize = "text-xl",
}: {
  size?: number;
  wordSize?: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <Mark size={size} />
      <Wordmark size={wordSize} />
    </div>
  );
}
