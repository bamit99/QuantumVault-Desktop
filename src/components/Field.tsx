import { forwardRef, type InputHTMLAttributes, type ReactNode } from "react";

interface FieldProps {
  label: string;
  id: string;
  hint?: string;
  error?: string;
  trailing?: ReactNode;
  children: ReactNode;
}

/** Label-above-input block with optional hint, error, and trailing content. */
export function Field({ label, id, hint, error, trailing, children }: FieldProps) {
  return (
    <div className="flex flex-col gap-2">
      <label
        htmlFor={id}
        className="text-[13px] font-medium text-ink-dim"
      >
        {label}
      </label>
      <div className="relative">
        {children}
        {trailing && (
          <div className="absolute right-3 top-1/2 -translate-y-1/2">{trailing}</div>
        )}
      </div>
      {error ? (
        <p className="text-xs text-danger">{error}</p>
      ) : hint ? (
        <p className="text-xs text-ink-faint">{hint}</p>
      ) : null}
    </div>
  );
}

const inputBase =
  "w-full h-11 rounded-xl bg-surface-2 border border-line px-3.5 text-sm text-ink " +
  "placeholder:text-ink-faint transition-colors duration-200 " +
  "focus:outline-none focus:border-accent/50 focus:ring-2 focus:ring-accent/20";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className = "", ...rest }, ref) {
    return <input ref={ref} className={`${inputBase} ${className}`} {...rest} />;
  },
);
