import { Link } from "react-router-dom";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useMode, SEV_LABEL, VERDICT_LABEL, RISK_LABEL } from "../lib/mode";
import { StepFlow } from "./ApprovalCard";
import { Ico, I } from "./Icon";

export interface NextAction { id: number; title: string; host_id: number | null; host_name?: string; commands: string[]; rollback: string[]; risk: string; why?: string; plain?: string; impact?: string; status: string; approval_id?: number | null; kind?: string; due?: string | null; session_id?: number; after_id?: number | null; relation?: string | null }
/** LLM が配列ではなく文字列で返すことがあるので必ず配列に正規化する */
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))) : v == null || v === "" ? [] : [typeof v === "string" ? v : JSON.stringify(v)]);
interface Proposal { summary: string; summary_simple?: string; severity: string; verdict: string; findings?: string[]; actions?: any[]; questions?: string[] }

const STATUS_JA: Record<string, string> = { proposed: "未対応", blocked: "依存待ち", approved: "承認待ち", executing: "実行中", done: "完了", rejected: "見送り", rolled_back: "巻き戻し" };
const REL_JA: Record<string, string> = { revert: "元に戻す", verify: "結果確認", next: "続き" };
const STATUS_CLS: Record<string, string> = { proposed: "bg-[#3A2A10] text-[#FFC27A]", blocked: "bg-violet-500/20 text-violet-200", approved: "bg-[#10304A] text-[#8FCBFF]", executing: "bg-[#10304A] text-[#8FCBFF]", done: "bg-[#12301F] text-[#7FE0B0]", rejected: "bg-slate-700 text-slate-400", rolled_back: "bg-[#3A1418] text-[#FF9A9D]" };
const SEV_HEX: Record<string, string> = { critical: "#F2555A", high: "#FF8A3D", medium: "#F5C542", low: "#3CCB8C", info: "#9AA6BF" };
const VERDICT_HEX: Record<string, string> = { malicious: "#F2555A", suspicious: "#F5C542", benign: "#3CCB8C", false_positive: "#3CCB8C", misconfiguration: "#FF8A3D" };
const RISK_TXT: Record<string, string> = { high: "text-[#FF9A9D]", medium: "text-[#FFC27A]", low: "text-[#7FE0B0]" };

/** Severity ring: 0–4 segments */
function SeverityRing({ severity }: { severity: string }) {
  const lv = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity] ?? 0;
  const color = SEV_HEX[severity] ?? "#9AA6BF";
  const r = 30, c = 2 * Math.PI * r, frac = Math.max(lv, 0.15) / 4;
  return (
    <div className="relative h-[72px] w-[72px] shrink-0">
      <svg viewBox="0 0 72 72" className="h-[72px] w-[72px] -rotate-90">
        <circle cx="36" cy="36" r={r} fill="none" stroke="#1E2942" strokeWidth="7" />
        <circle cx="36" cy="36" r={r} fill="none" stroke={color} strokeWidth="7" strokeDasharray={`${c * frac} ${c}`} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-none"><span className="font-display text-[15px] font-bold" style={{ color }}>{SEV_LABEL[severity] ?? severity}</span><span className="mt-0.5 text-[10px] text-slate-500">重大度</span></div>
    </div>
  );
}

/**
 * EDR-158: cards in one horizontal row (scroll left/right) so many proposals never push the chat out of view.
 * ◀ ▶ buttons appear only when the row overflows; the row also scrolls with Shift+wheel / touchpad / drag bar.
 */
function HStrip({ children, label }: { children: ReactNode; label: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [edge, setEdge] = useState({ l: false, r: false });
  const upd = () => { const el = ref.current; if (!el) return; setEdge({ l: el.scrollLeft > 4, r: el.scrollLeft + el.clientWidth < el.scrollWidth - 4 }); };
  useEffect(() => { upd(); const el = ref.current; if (!el) return; const ro = new ResizeObserver(upd); ro.observe(el); for (const c of Array.from(el.children)) ro.observe(c); return () => ro.disconnect(); });
  const go = (dir: number) => { const el = ref.current; if (el) el.scrollBy({ left: dir * Math.max(300, el.clientWidth * 0.8), behavior: "smooth" }); };
  const btn = "absolute top-1/2 z-10 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full border border-slate-600 bg-slate-900/90 text-slate-200 shadow-lg hover:border-teal-400 hover:text-white";
  return (
    <div className="relative">
      <div ref={ref} onScroll={upd} role="list" aria-label={label} className="flex snap-x gap-2.5 overflow-x-auto pb-2 [scrollbar-width:thin] [&>*]:w-[300px] [&>*]:shrink-0 [&>*]:snap-start">{children}</div>
      {edge.l && <button type="button" aria-label="左へ" className={`${btn} -left-2`} onClick={() => go(-1)}>◀</button>}
      {edge.r && <button type="button" aria-label="右へ" className={`${btn} -right-2`} onClick={() => go(1)}>▶</button>}
    </div>
  );
}

const EVERY_JA = (m: number) => ({ 60: "1 時間ごと", 120: "2 時間ごと", 180: "3 時間ごと", 360: "6 時間ごと", 720: "12 時間ごと", 1440: "毎日", 2880: "2 日ごと", 4320: "3 日ごと", 10080: "毎週", 20160: "2 週間ごと", 43200: "30 日ごと" } as Record<number, string>)[m] ?? `${m} 分ごと`;

export default function ProposalPanel({ proposal, actions, schedules = [], canAct, busy, onRun, onSkip, onReopen }: {
  proposal: Proposal; actions: NextAction[]; schedules?: any[]; canAct: boolean; busy: boolean;
  onRun: (a: NextAction) => void; onSkip: (a: NextAction) => void; onReopen: (a: NextAction) => void;
}) {
  const { mode } = useMode();
  const [open, setOpen] = useState(true);
  const [showDone, setShowDone] = useState(false);
  const live = actions.filter((a) => !["done", "rejected", "rolled_back"].includes(a.status));
  const finished = actions.filter((a) => ["done", "rejected", "rolled_back"].includes(a.status));
  const summary = mode === "simple" ? (proposal.summary_simple || proposal.summary) : proposal.summary;
  return (
    <div className="min-w-0 max-w-full max-h-[55vh] shrink-0 overflow-y-auto overflow-x-hidden rounded-2xl border border-slate-700 bg-slate-800 p-[18px]">
      <div className="flex items-start gap-4">
        <SeverityRing severity={proposal.severity} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400">調査結果</span>
            <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-100"><span className="h-2 w-2 rounded-full" style={{ background: VERDICT_HEX[proposal.verdict] ?? "#7F8BA6" }} />{VERDICT_LABEL[proposal.verdict] ?? proposal.verdict}</span>
            <span className="text-slate-500">· 提案 {actions.length} 件（未対応 {live.length}）{schedules.filter((x) => x.state === "active").length ? ` · 定期実行 ${schedules.filter((x) => x.state === "active").length}` : ""}</span>
            <button className="ml-auto rounded-md px-2 py-1 text-slate-400 hover:bg-slate-700 hover:text-slate-200" onClick={() => setOpen(!open)}>{open ? "たたむ ▴" : "ひらく ▾"}</button>
          </div>
          {open && <div className="mt-2 whitespace-pre-wrap text-[15px] leading-[1.8] text-slate-100">{summary}</div>}
          {open && mode === "detail" && arr(proposal.findings).length ? <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs text-slate-400">{arr(proposal.findings).map((f, i) => <li key={i}>{f}</li>)}</ul> : null}
          {open && arr(proposal.questions).length ? <div className="mt-2 text-xs text-[#FFC27A]">確認したいこと: {arr(proposal.questions).join(" / ")}</div> : null}
        </div>
      </div>
      {open && schedules.filter((x) => x.state === "active").length > 0 && (
        <div className="mt-4"><HStrip label="定期実行">
          {schedules.filter((x) => x.state === "active").map((x) => (
            <div key={`sc${x.id}`} className="rounded-xl border border-violet-500/40 bg-violet-500/10 p-3.5 text-sm">
              <div className="flex items-center gap-2">
                <span className="rounded bg-violet-500/25 px-1.5 py-0.5 text-[10px] text-violet-100">{x.enabled ? (x.last_status === "running" ? "実行中" : "定期実行中") : "一時停止"}</span>
                <span className="inline-flex items-center gap-1.5 font-semibold text-slate-100"><Ico d={I.clock} size={14} />{x.title}</span>
                <span className="ml-auto shrink-0 rounded border border-violet-500/40 px-1.5 text-[10px] text-violet-200">{EVERY_JA(x.interval_min)}{x.at_time && x.interval_min >= 1440 ? ` ${x.at_time}` : ""}</span>
              </div>
              {x.goal && <div className="mt-1 text-xs text-slate-300">達成条件: {x.goal}</div>}
              <div className="mt-1 text-[11px] text-slate-400">実行 {x.run_count}{x.max_runs ? `/${x.max_runs}` : ""} 回{x.next_run_at && x.enabled ? ` · 次回 ${new Date(x.next_run_at).toLocaleString("ja-JP")}` : ""}</div>
              {x.last_result && <div className="mt-1 line-clamp-2 text-[11px] text-violet-200/80">前回: {String(x.last_result).replace(/\*\*/g, "")}</div>}
              <Link to="/schedules" className="mt-1 inline-block text-[11px] text-teal-300 hover:underline">スケジュールで管理 →</Link>
            </div>
          ))}
        </HStrip></div>
      )}
      {open && (
        <div className="mt-4">
          {live.length > 1 && <div className="mb-1.5 text-[11px] text-slate-400">提案 {live.length} 件 — 左右にスクロールできます</div>}
          {live.length > 0 && <HStrip label="提案">
          {live.map((a) => (
            <div key={a.id} className="flex flex-col gap-1.5 rounded-xl border border-[#24314D] bg-slate-900 p-3.5 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${STATUS_CLS[a.status] ?? ""}`}>{STATUS_JA[a.status] ?? a.status}</span>
                <span className={`ml-auto shrink-0 text-[11px] font-semibold ${RISK_TXT[a.risk] ?? "text-slate-400"}`}>{RISK_LABEL[a.risk] ?? a.risk}</span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold text-slate-100">{a.kind === "followup" && <span className="mr-1 text-violet-300" title="残タスク（今すぐ実行するものは無い）"><Ico d={I.pin} size={13} className="inline text-violet-300" /></span>}{a.title}</span>
                {a.kind === "followup" && a.due && <span className="rounded border border-violet-500/40 px-1 text-[10px] text-violet-200">期限 {a.due}</span>}
                {a.after_id && <span className="rounded border border-violet-500/40 px-1 text-[10px] text-violet-200" title={`タスク #${a.after_id} が完了すると自動で実行可能になります`}>#{a.after_id} 完了後{a.relation ? ` · ${REL_JA[a.relation] ?? a.relation}` : ""}</span>}
              </div>
              <div className="text-[13px] leading-relaxed text-slate-300">{mode === "simple" ? (a.plain || a.why) : a.why}</div>
              {a.impact && <div className="text-xs text-[#FFC27A]">影響: {a.impact}</div>}
              {a.host_name && <div className="font-mono text-[11px] text-slate-500">対象: {a.host_name}</div>}
              {mode === "detail" && a.commands?.length ? <StepFlow steps={a.commands.map((c, i) => ({ purpose: `step ${i + 1}`, command: c }))} /> : null}
              {mode === "detail" && a.commands?.length ? <pre className="max-h-32 overflow-auto whitespace-pre-wrap rounded-lg border border-[#24314D] bg-[#070B15] p-2 font-mono text-[10px] text-slate-400 break-all max-w-full">{a.commands.join("\n")}</pre> : null}
              {canAct && a.status === "proposed" && a.kind === "followup" && (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] text-violet-200">残タスクとして Action ボードで追跡します</span>
                  <Link to={`/next-actions?s=${a.session_id ?? ""}`} className="text-[11px] text-teal-300 hover:underline">Action ボードへ →</Link>
                  <button className="rounded-lg border border-slate-600 px-2.5 py-1 text-[11px] text-slate-200 hover:border-teal-400 disabled:opacity-40" disabled={busy} title="実際に設定変更が必要なタスクなら、AI に実行計画を作らせて承認待ちにします" onClick={() => onRun(a)}>▶ 実行を依頼</button>
                </div>
              )}
              {a.status === "blocked" && <div className="mt-2 text-[11px] text-violet-200">タスク #{a.after_id} が完了すると自動で実行可能になり、AI が計画を作ります</div>}
              {canAct && a.status === "proposed" && a.kind !== "followup" && (
                <div className="mt-1 flex gap-2">
                  <button className="inline-flex min-h-[38px] flex-1 items-center justify-center gap-1.5 rounded-[10px] bg-teal-500 px-3 text-[13px] font-semibold text-white hover:bg-teal-400 disabled:opacity-40" disabled={busy} onClick={() => onRun(a)}><Ico d={I.play} size={13} className="" />この提案を進める</button>
                  <button className="min-h-[38px] rounded-[10px] border border-slate-600 px-3 text-[13px] text-slate-300 hover:border-slate-500 hover:text-white disabled:opacity-40" disabled={busy} onClick={() => onSkip(a)}>見送る</button>
                </div>
              )}
              {a.status === "approved" && <div className="mt-1 text-xs text-[#8FCBFF]">{a.approval_id ? `承認カード #${a.approval_id} を確認してください（下のチャット）` : a.kind === "followup" ? <span className="text-violet-200">追跡中（Action ボード）<button className="ml-2 text-[11px] text-teal-300 hover:underline" disabled={busy} onClick={() => onRun(a)}>▶ 実行を依頼</button></span> : "AI が変更計画を作成中…"}</div>}
            </div>
          ))}
          </HStrip>}
          {live.length === 0 && <div className="text-xs text-slate-500">未対応の提案はありません</div>}
        </div>
      )}
      {open && finished.length > 0 && (
        <div className="mt-3 border-t border-slate-700 pt-2.5">
          <button className="text-xs text-slate-400 hover:text-slate-200" onClick={() => setShowDone(!showDone)}>{showDone ? "▾" : "▸"} 対応済み・見送り {finished.length} 件</button>
          {showDone && <div className="mt-2 space-y-1.5">{finished.map((a) => (
            <div key={a.id} className="flex flex-wrap items-center gap-2 text-xs text-slate-400"><span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${STATUS_CLS[a.status] ?? ""}`}>{STATUS_JA[a.status] ?? a.status}</span><span className={a.status === "done" ? "text-slate-300" : "line-through decoration-slate-600"}>{a.title}</span>{a.approval_id && <span className="text-slate-600">承認 #{a.approval_id}</span>}{a.status === "done" && a.impact && <span className="text-slate-500">— {a.impact}</span>}{canAct && a.status === "rejected" && <button className="text-teal-300 hover:underline" onClick={() => onReopen(a)}>やっぱり進める</button>}</div>
          ))}</div>}
        </div>
      )}
    </div>
  );
}
