/** MamorAI brand mark (shield + M + the AI "watching eye") and wordmark. */
export function LogoMark({ size = 30, variant = "solid" }: { size?: number; variant?: "solid" | "outline" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      {variant === "solid"
        ? <path d="M32 4 L56 13 V31 C56 46 45 56 32 60 C19 56 8 46 8 31 V13 Z" fill="#3A56F0" />
        : <path d="M32 4 L56 13 V31 C56 46 45 56 32 60 C19 56 8 46 8 31 V13 Z" fill="#141E36" stroke="#3A56F0" strokeWidth="3" strokeLinejoin="round" />}
      <polyline points="20,43 20,25 32,35 44,25 44,43" fill="none" stroke="#FFFFFF" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="32" cy="18" r="4" fill={variant === "solid" ? "#FFFFFF" : "#8EA2FF"} />
    </svg>
  );
}

export function Wordmark({ className = "text-xl" }: { className?: string }) {
  return <span className={`font-display font-semibold tracking-tight ${className}`}>Mamor<span className="text-teal-300">AI</span></span>;
}
