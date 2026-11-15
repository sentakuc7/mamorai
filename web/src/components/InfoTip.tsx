/* ⓘ mark: hover / focus / tap shows a short explanation, with an optional link to a help page (EDR-140) */
import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";

export default function InfoTip({ title, children, href, linkLabel = "手順を見る", align = "left" }: { title: string; children: React.ReactNode; href?: string; linkLabel?: string; align?: "left" | "right" }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wrap = useRef<HTMLSpanElement | null>(null);
  const show = () => { if (timer.current) clearTimeout(timer.current); setOpen(true); };
  const hideSoon = () => { if (timer.current) clearTimeout(timer.current); timer.current = setTimeout(() => setOpen(false), 180); };
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    const onDown = (e: MouseEvent) => { if (wrap.current && !wrap.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("keydown", onKey); document.addEventListener("mousedown", onDown);
    return () => { document.removeEventListener("keydown", onKey); document.removeEventListener("mousedown", onDown); };
  }, [open]);
  return (
    <span ref={wrap} className="relative inline-flex align-middle" onMouseEnter={show} onMouseLeave={hideSoon}>
      <button type="button" aria-label={`${title}（説明）`} aria-expanded={open} aria-describedby={open ? id : undefined}
        className="ml-1 inline-flex h-[18px] w-[18px] items-center justify-center rounded-full border border-current text-[11px] font-bold leading-none opacity-80 hover:opacity-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-teal-400"
        onFocus={show} onBlur={hideSoon} onClick={() => setOpen((o) => !o)}>i</button>
      {open && (
        <span id={id} role="tooltip" onMouseEnter={show} onMouseLeave={hideSoon}
          className={`absolute top-6 z-50 flex w-[320px] max-w-[80vw] flex-col gap-1.5 rounded-xl border border-slate-600 bg-[#0D1428] px-3.5 py-3 text-left text-[12.5px] font-normal leading-relaxed text-slate-200 shadow-xl ${align === "right" ? "right-0" : "left-0"}`}>
          <span className="text-[13px] font-semibold text-slate-100">{title}</span>
          <span className="text-slate-300">{children}</span>
          {href && <Link to={href} className="mt-0.5 self-start text-teal-300 hover:underline" onClick={() => setOpen(false)}>{linkLabel} →</Link>}
        </span>
      )}
    </span>
  );
}
