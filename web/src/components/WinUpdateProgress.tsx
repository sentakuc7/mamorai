/** EDR-168: per-update status of a Windows Update / winget run, shown on the approval card. */
import { useEffect, useState } from "react";

interface Item { key: string; kind: "wu" | "app"; title: string | null; size_mb: number | null; state: string; note?: string }
export interface WinUpdateState { phase: string; items: Item[]; started_at: string; last_seen_at: string | null; finished_at: string | null; reboot_required: boolean | null; ok: boolean | null }

const ST: Record<string, { ja: string; cls: string; spin?: boolean }> = {
  pending: { ja: "待機", cls: "bg-slate-700 text-slate-300" },
  downloading: { ja: "ダウンロード中", cls: "bg-[#10304A] text-[#8FCBFF]", spin: true },
  downloaded: { ja: "ダウンロード済み", cls: "bg-[#10304A] text-[#8FCBFF]" },
  installing: { ja: "インストール中", cls: "bg-[#2A2410] text-[#F5D98A]", spin: true },
  installed: { ja: "完了", cls: "bg-[#12301F] text-[#7FE0B0]" },
  failed: { ja: "失敗", cls: "bg-[#3A1418] text-[#FF9A9D]" },
  unknown: { ja: "不明", cls: "bg-slate-700 text-slate-400" },
};
const dur = (ms: number) => { const s = Math.max(0, Math.floor(ms / 1000)); const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60; return h ? `${h} 時間 ${m} 分` : m ? `${m} 分 ${x} 秒` : `${x} 秒`; };

export default function WinUpdateProgress({ st, running }: { st: WinUpdateState; running: boolean }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { if (!running) return; const t = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(t); }, [running]);
  const end = st.finished_at ? new Date(st.finished_at).getTime() : now;
  const elapsed = end - new Date(st.started_at).getTime();
  const quiet = st.last_seen_at ? now - new Date(st.last_seen_at).getTime() : null;
  const done = st.items.filter((i) => i.state === "installed").length, failed = st.items.filter((i) => i.state === "failed").length;
  const totalMb = st.items.reduce((a, i) => a + (i.size_mb ?? 0), 0);
  return (
    <div className="space-y-2 rounded-[10px] border border-[#24314D] bg-[#0B1222] p-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <span className={`font-semibold ${st.ok === false ? "text-[#FF9A9D]" : st.ok ? "text-[#7FE0B0]" : "text-[#8FCBFF]"}`}>{running && <span className="mr-1.5 inline-block h-2 w-2 animate-pulse rounded-full bg-[#5AB0FF]" />}{st.phase}</span>
        <span className="text-slate-400">経過 {dur(elapsed)}</span>
        <span className="text-slate-400">完了 {done}{failed ? ` · 失敗 ${failed}` : ""} / {st.items.length} 件{totalMb ? `（合計 約 ${totalMb.toLocaleString()} MB）` : ""}</span>
        {running && quiet != null && <span className={quiet > 15 * 60_000 ? "text-[#FFC27A]" : "text-slate-500"}>端末からの最後の報告 {dur(quiet)}前</span>}
        {st.reboot_required && <span className="rounded-full bg-[#2A2410] px-2 py-0.5 text-[#F5D98A]">再起動が必要</span>}
      </div>
      {st.items.length > 0 ? (
        <ul className="flex flex-col gap-1">{st.items.map((i) => { const s = ST[i.state] ?? ST.unknown; return (
          <li key={`${i.kind}:${i.key}`} className="flex flex-wrap items-center gap-2 text-[12px]">
            <span className={`inline-flex min-w-[92px] items-center justify-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold ${s.cls}`}>{s.spin && running && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" />}{s.ja}</span>
            <span className="font-mono text-slate-300">{i.kind === "app" ? i.key : i.key}</span>
            <span className="min-w-0 flex-1 truncate text-slate-400" title={i.title ?? ""}>{i.title ?? ""}</span>
            {i.size_mb != null && <span className="text-[11px] text-slate-500">{i.size_mb.toLocaleString()} MB</span>}
            {i.note && <span className="w-full pl-[100px] font-mono text-[11px] text-[#FF9A9D]">{i.note}</span>}
          </li>); })}</ul>
      ) : <div className="text-xs text-slate-500">端末からの一覧を待っています…</div>}
      {running && <div className="text-[11px] text-slate-500">大きい累積更新は、ダウンロードとインストールにそれぞれ数十分かかることがあります。インストール中は端末からの報告が止まりますが、異常ではありません。</div>}
    </div>
  );
}
