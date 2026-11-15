import type { ReactNode } from "react";
import { Ico, I } from "./Icon";

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return <div><label className="label">{label}</label>{children}{hint && <div className="mt-1 text-[11px] leading-relaxed text-slate-400">{hint}</div>}</div>;
}

/** Editable list of one-line strings (textarea per item keeps commands intact). */
export function ListEditor({ items, onChange, placeholder, mono }: { items: string[]; onChange: (v: string[]) => void; placeholder?: string; mono?: boolean }) {
  const set = (i: number, v: string) => onChange(items.map((x, k) => (k === i ? v : x)));
  return (
    <div className="space-y-1">
      {items.map((x, i) => (
        <div key={i} className="flex items-start gap-1">
          <span className="mt-1.5 w-4 shrink-0 text-right font-mono text-[11px] text-slate-500">{i + 1}</span>
          <textarea className={`input min-h-[2rem] py-1 ${mono ? "font-mono text-xs" : ""}`} rows={Math.min(6, Math.max(1, x.split("\n").length, Math.ceil(x.length / 70)))} value={x} onChange={(e) => set(i, e.target.value)} placeholder={placeholder} />
          <button className="mt-1 text-slate-500 hover:text-rose-300" title="削除" onClick={() => onChange(items.filter((_, k) => k !== i))}>✕</button>
          <button className="mt-1 text-slate-500 hover:text-slate-200 disabled:opacity-30" title="上へ" disabled={i === 0} onClick={() => { const a = [...items]; [a[i - 1], a[i]] = [a[i], a[i - 1]]; onChange(a); }}>↑</button>
        </div>
      ))}
      <button className="text-xs text-teal-300 hover:text-teal-200" onClick={() => onChange([...items, ""])}>＋ 追加</button>
    </div>
  );
}

export function Chip({ children, tone = "slate" }: { children: ReactNode; tone?: "slate" | "teal" | "amber" | "rose" | "emerald" | "sky" }) {
  const cls = { slate: "bg-slate-700 text-slate-300", teal: "bg-[#1A2547] text-[#B9C6FF]", amber: "bg-[#3A2A10] text-[#FFC27A]", rose: "bg-[#3A1418] text-[#FF9A9D]", emerald: "bg-[#12301F] text-[#7FE0B0]", sky: "bg-sky-500/15 text-sky-200" }[tone];
  return <span className={`inline-flex items-center gap-1 rounded-full px-2 py-px text-[11px] font-bold ${cls}`}>{children}</span>;
}

export const ENV_JA: Record<string, string> = { lab: "検証", staging: "ステージング", production: "本番", mixed: "混在" };
export const ENV_TONE: Record<string, "slate" | "teal" | "amber" | "rose" | "emerald" | "sky"> = { lab: "teal", staging: "amber", production: "rose", mixed: "sky" };
/** EDR-154: client PCs use the same field with plain words — 業務用 (= production: stricter approvals) / 検証用 (= lab) */
export const ENV_JA_CLIENT: Record<string, string> = { lab: "検証用", staging: "検証用", production: "業務用", mixed: "混在" };
export const envJa = (env: string, role?: string | null) => (role === "client" ? ENV_JA_CLIENT : ENV_JA)[env] ?? env;
export const ENV_OPTIONS = {
  server: [["lab", "検証（止めても困らない）"], ["staging", "ステージング（本番の前に確かめる環境）"], ["production", "本番（止めると業務が止まる）"]],
  client: [["production", "業務用（社員が仕事で使っている。止めると困る）"], ["lab", "検証用（テスト用の PC）"]],
} as const;
export const ROLE_JA: Record<string, string> = { server: "サーバー", client: "クライアント端末" };

const SECTION_ICON: Record<string, string> = { "🔌": I.plug, "🛡️": I.approve, "📡": I.signal, "📖": I.book, "🛠": I.wrench, "🕵️": I.search, "🖧": I.hosts, "🎯": I.target, "🚫": I.ban, "📌": I.pin, "🔍": I.search, "🕘": I.history, "📎": I.clip };

export function Section({ title, icon, count, children, tone }: { title: string; icon?: string; count?: number; children: ReactNode; tone?: string }) {
  return (
    <section className={`flex flex-col gap-2.5 rounded-[14px] border p-4 ${tone ?? "border-slate-700 bg-slate-800"}`}>
      <h3 className="flex items-center gap-2 text-[15px] font-semibold text-slate-100">{icon && (SECTION_ICON[icon] ? <Ico d={SECTION_ICON[icon]} size={16} /> : <span>{icon}</span>)}<span>{title}</span>{count !== undefined && <span className="font-normal text-slate-400">({count})</span>}</h3>
      {children}
    </section>
  );
}
