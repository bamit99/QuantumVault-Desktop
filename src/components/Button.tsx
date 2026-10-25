import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";

const base =
  "inline-flex items-center justify-center gap-2 rounded-xl font-medium text-sm " +
  "transition-all duration-200 select-none focus-visible:outline-none " +
  "focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 " +
  "focus-visible:ring-offset-bg active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none " +
  "cursor-pointer whitespace-nowrap";

const variants: Record<Variant, string> = {
  primary:
    "bg-accent text-on-accent hover:bg-accent-deep shadow-[0_1px_0_rgba(255,255,255,0.1)_inset,0_10px_24px_-10px_rgba(16,185,129,0.6)]",
  secondary:
    "bg-surface-2 text-ink border border-line-strong hover:bg-elevated hover:border-line-strong",
  ghost: "text-ink-dim hover:text-ink hover:bg-surface-2",
  danger:
    "bg-danger/10 text-danger border border-danger/25 hover:bg-danger/20",
};

const sizes = {
  sm: "h-9 px-3.5",
  md: "h-11 px-5",
  lg: "h-12 px-6 text-[15px]",
};

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: keyof typeof sizes;
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, Props>(function Button(
  { variant = "primary", size = "md", icon, className = "", children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
      {...rest}
    >
      {icon}
      {children}
    </button>
  );
});
