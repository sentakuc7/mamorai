import { useState } from "react";
import WinUpdateProgress from "./WinUpdateProgress";
import { api, fmtTs } from "../lib/api";
import { useMode, RISK_LABEL } from "../lib/mode";
import { Ico, I } from "./Icon";

export interface Approval { host_action?: string | null; cloud_action?: string | null;
  id: number; session_id: number; tool_call_id?: number; host_id: number | null; host_name?: string; host_environment?: string; session_title?: string;
  title?: string | null; command: string; intent?: string | null; rollback?: string | null; risk: string; decision: string;
  steps?: { purpose: string; command: string }[] | null; next_action_id?: number | null;
  auto_checks?: { classification?: string; reason?: string; checks?: { name: string; level: string; detail: string }[] } | null;
  exec_result?: any; run_after?: string | null; decided_at?: string | null; decision_note?: string | null; executed_command?: string | null; created_at?: string;
}

const PILL = { ok: "bg-[#12301F] text-[#7FE0B0]", warn: "bg-[#3A2A10] text-[#FFC27A]", block: "bg-[#3A1418] text-[#FF9A9D]", info: "bg-[#10304A] text-[#8FCBFF]" };
const LEVEL: Record<string, string> = { block: PILL.block, warn: PILL.warn, info: PILL.info, ok: PILL.ok };
const LEVEL_MARK: Record<string, string> = { block: "✕", warn: "!", info: "i", ok: "✓" };
const RISK: Record<string, string> = { low: PILL.ok, medium: PILL.warn, high: PILL.block };
const PRE = "max-h-64 max-w-full overflow-auto whitespace-pre-wrap break-all rounded-[10px] border border-[#24314D] bg-[#070B15] p-3 font-mono text-xs leading-relaxed";

/** Numbered step flow: 1 → 2 → 3 */
export function StepFlow({ steps, done, failedAt }: { steps: { purpose: string; command?: string }[]; done?: number; failedAt?: number | null }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {steps.map((st, i) => {
        const n = i + 1;
        const state = failedAt === n ? "fail" : done !== undefined && n <= done ? "ok" : "todo";
        const cls = state === "ok" ? "border-[#1E4A34] bg-[#0F241A] text-[#BDF0D6]" : state === "fail" ? "border-[#5A1E24] bg-[#2A0F14] text-[#FF9A9D]" : "border-slate-600 bg-slate-900 text-slate-200";
        const dot = state === "ok" ? "bg-[#1E4A34] text-[#7FE0B0]" : state === "fail" ? "bg-[#3A1418] text-[#FF9A9D]" : "bg-[#1A2547] text-teal-200";
        return (
          <div key={i} className="flex items-center gap-1.5">
            <div className={`flex items-center gap-2 rounded-[10px] border px-3 py-2 text-[13px] ${cls}`} title={st.command}>
              <span className={`flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-full font-mono text-[11px] font-bold ${dot}`}>{state === "ok" ? "✓" : state === "fail" ? "✕" : n}</span>
              <span>{st.purpose}</span>
            </div>
            {i < steps.length - 1 && <span className="text-slate-500">→</span>}
          </div>
        );
      })}
    </div>
  );
}

export default function ApprovalCard({ a, canAct, onDone }: { a: Approval; canAct: boolean; onDone?: () => void }) {
  const { mode } = useMode();
  const [cmd, setCmd] = useState(a.command); const [note, setNote] = useState(""); const [busy, setBusy] = useState(false); const [err, setErr] = useState(""); const [showCmd, setShowCmd] = useState(mode === "detail");
  const blocked = a.auto_checks?.checks?.some((c) => c.level === "block");
  // EDR-94: self-drive allowance (fix-and-retry without asking), default by environment
  const [selfDrive, setSelfDrive] = useState<number>(a.host_environment === "production" ? 3 : 5);
  const pending = a.decision === "pending";
  const steps = a.steps && a.steps.length ? a.steps : null;
  const intentLines = (a.intent ?? "").split("\n").filter(Boolean);
  const [intent, plain] = [intentLines[0], intentLines.slice(1).join(" ")];
  const execSteps = a.exec_result?.steps as any[] | undefined;
  const failedAt = execSteps?.find((x) => x.exit_code !== 0)?.step ?? null;
  const act = async (kind: "approve" | "reject") => {
    setBusy(true); setErr("");
    try {
      if (kind === "approve") await api.post(`/approvals/${a.id}/approve`, { command: cmd !== a.command ? cmd : undefined, note: note || undefined, self_drive: selfDrive });
      else { if (!note.trim()) { setErr("却下理由を入力してください（AI に返されます）"); setBusy(false); return; } await api.post(`/approvals/${a.id}/reject`, { note }); }
      onDone?.();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const statusCls = pending ? PILL.warn : a.decision === "rejected" ? PILL.block : a.exec_result?.status === "failed" ? PILL.block : a.exec_result?.status === "interrupted" ? PILL.warn : (!a.exec_result || a.exec_result.status === "running") ? `${PILL.info} animate-pulse` : PILL.ok;
  const statusText = pending ? "承認待ち" : a.decision === "rejected" ? "却下" : a.exec_result?.status === "failed" ? "実行失敗" : a.exec_result?.status === "interrupted" ? "中断" : (!a.exec_result || a.exec_result.status === "running") ? `実行中 ${a.exec_result?.current_step ?? 1}/${a.exec_result?.steps_total ?? "?"}` : "実行済み";
  return (
    <div className={`flex w-full min-w-0 max-w-full flex-col gap-3 overflow-hidden rounded-[14px] border bg-slate-800 p-[18px] ${pending ? "border-teal-500 shadow-[0_0_0_1px_rgba(58,86,240,.25)]" : "border-slate-700"}`}>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-semibold ${statusCls}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{statusText}</span>
        <span className="text-base font-bold text-slate-100">{a.title || (steps ? "変更計画" : "コマンド実行")}</span>
        <span className="font-mono text-[13px] text-teal-200">{a.host_name ?? `host#${a.host_id}`}</span>
        {a.host_environment && a.host_environment !== "lab" && <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${a.host_environment === "production" ? PILL.block : "bg-slate-700 text-slate-300"}`}>{a.host_environment}</span>}
        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${RISK[a.risk] ?? "bg-slate-700 text-slate-300"}`}>{RISK_LABEL[a.risk] ?? a.risk}</span>
        <span className="ml-auto font-mono text-[11px] text-slate-500">#{a.id} · {fmtTs(a.created_at)}</span>
      </div>
      {plain && <div className="text-[15px] leading-[1.7] text-slate-100">{plain}</div>}
      {intent && (mode === "simple" && plain ? null : <div className="text-[13px] text-slate-400"><span className="text-slate-500">理由: </span>{intent}</div>)}
      {steps ? (
        <div className="space-y-2">
          <div className="text-xs font-semibold text-slate-400">やること（{steps.length} ステップ・まとめて承認）</div>
          <StepFlow steps={steps} done={execSteps?.length} failedAt={failedAt} />
        </div>
      ) : null}
      {a.auto_checks?.checks?.length ? (
        <div className="flex flex-wrap gap-1.5">{a.auto_checks.checks.filter((c) => mode === "detail" || c.level !== "ok").map((c, i) => <span key={i} className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs ${LEVEL[c.level] ?? "bg-slate-700 text-slate-300"}`} title={c.detail}><span className="flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold ring-1 ring-current">{LEVEL_MARK[c.level] ?? "·"}</span>{c.name}{c.level !== "ok" ? ` — ${c.detail}` : ""}</span>)}</div>
      ) : null}
      {(mode === "detail" || showCmd) ? (
        <>
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-400">実行コマンド{pending && canAct && !steps ? "（編集可）" : ""}{mode === "detail" && a.auto_checks?.reason ? <span className="font-normal text-slate-500">{a.auto_checks.classification} — {a.auto_checks.reason}</span> : null}{mode !== "detail" && <button className="ml-auto font-normal text-teal-300 hover:underline" onClick={() => setShowCmd(false)}>コマンドを隠す</button>}</div>
            {pending && canAct && !steps ? <textarea className={`h-20 w-full resize-y rounded-[10px] border bg-[#070B15] p-3 font-mono text-xs text-slate-100 outline-none focus:border-teal-500 ${blocked ? "border-[#5A1E24]" : "border-[#24314D]"}`} value={cmd} onChange={(e) => setCmd(e.target.value)} /> : <pre className={`${PRE} text-slate-200 ${blocked ? "!border-[#5A1E24]" : ""}`}>{a.executed_command ?? a.command}</pre>}
            {blocked && pending && <div className="text-xs text-[#FF9A9D]">自動チェックでブロック。コマンドを編集すれば実行可</div>}
          </div>
          {a.rollback && <div className="space-y-1.5"><div className="text-xs font-semibold text-slate-400">元に戻すには（ロールバック）</div><pre className={`${PRE} text-slate-400`}>{a.rollback}</pre></div>}
        </>
      ) : (
        <button className="self-start text-[13px] text-teal-300 hover:underline" onClick={() => setShowCmd(true)}>コマンドを見る</button>
      )}
      {a.run_after && (() => { // EDR-168: approve now, run later
        const at = new Date(a.run_after); const when = at.toLocaleString("ja-JP", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
        const st = a.exec_result?.status;
        if (pending) return <div className="flex items-center gap-2 rounded-[10px] border border-violet-500/50 bg-violet-500/10 px-3 py-2 text-[13px] text-violet-100"><Ico d={I.clock} size={14} className="" />承認すると、すぐではなく <b>{when}</b> に実行します（それまでは取り消せます）</div>;
        if (st === "scheduled") return <div className="flex flex-wrap items-center gap-2 rounded-[10px] border border-violet-500/50 bg-violet-500/10 px-3 py-2 text-[13px] text-violet-100"><Ico d={I.clock} size={14} className="" />承認済み — <b>{when}</b> に実行予定{canAct && <button className="ml-auto rounded-md border border-violet-300/60 px-2.5 py-1 text-xs hover:bg-violet-500/20" onClick={async () => { if (!confirm("この予約を取り消しますか？（実行しません）")) return; try { await api.post(`/approvals/${a.id}/cancel-scheduled`, {}); onDone?.(); } catch (e: any) { alert(e.message); } }}>予約を取り消す</button>}</div>;
        if (st === "cancelled") return <div className="rounded-[10px] border border-slate-600 px-3 py-2 text-[13px] text-slate-400">予約（{when}）は取り消されました。実行していません</div>;
        if (st === "held") return <div className="rounded-[10px] border border-[#6B5A19] bg-[#2A2410] px-3 py-2 text-[13px] text-[#F5D98A]">{when} に実行する予定でしたが、緊急停止中だったため実行しませんでした</div>;
        return null;
      })()}
      {a.exec_result && !["scheduled", "cancelled", "held"].includes(a.exec_result.status) && (
        <div className="space-y-1.5">
          {a.exec_result.win_update && <WinUpdateProgress st={a.exec_result.win_update} running={a.exec_result.status === "running"} />}
          {a.exec_result.status === "running" && <div className="flex items-center gap-1.5 text-xs text-[#8FCBFF]"><span className="h-2 w-2 animate-pulse rounded-full bg-[#5AB0FF]" />ステップ {a.exec_result.current_step}/{a.exec_result.steps_total} を実行中: {a.exec_result.current_purpose}</div>}
          {a.exec_result.status === "interrupted" && <div className="flex items-center gap-1.5 text-xs text-[#FFC27A]"><Ico d={I.alerts} size={13} className="" />{a.exec_result.error}</div>}
          <div className={`text-xs font-semibold ${a.exec_result.status === "failed" ? "text-[#FF9A9D]" : a.exec_result.status === "done" || a.exec_result.exit_code === 0 ? "text-[#7FE0B0]" : "text-slate-400"}`}>実行結果 {a.exec_result.steps_total ? `(${a.exec_result.steps_done}/${a.exec_result.steps_total} ステップ、` : "("}exit {a.exec_result.exit_code ?? "-"}, {a.exec_result.duration_ms ?? "-"}ms)</div>
          {a.exec_result.note && <div className="text-xs text-[#FFC27A]">{a.exec_result.note}</div>}
          {(mode === "detail" || showCmd || a.exec_result.status === "failed") && a.exec_result.status !== "running" && <pre className={`${PRE} max-h-48 text-slate-300`}>{a.exec_result.error ?? (((a.exec_result.stdout ?? "") + (a.exec_result.stderr ? "\n[stderr]\n" + a.exec_result.stderr : "")) || "(no output)")}</pre>}
        </div>
      )}
      {!pending && a.decision_note && <div className="text-xs text-slate-400"><span className="text-slate-500">メモ: </span>{a.decision_note}</div>}
      {pending && canAct && (
        <div className="flex flex-col gap-2.5">
          <input className="input min-h-[40px]" placeholder="メモ / 却下理由（却下時は必須。AI に返されます）" value={note} onChange={(e) => setNote(e.target.value)} />
          {a.host_action && <div className="text-[12px] text-[#FFC27A]">ホストへの遮断操作です。自動の再実行はしません。解除はホスト画面の「遮断の操作」から承認を通して行えます。</div>}
          {!a.decision_note?.startsWith("retry-of") && !a.host_action && !a.cloud_action && (
            <div className="flex flex-wrap items-center gap-2 text-[13px] text-slate-300">
              <label htmlFor={`selfdrive-${a.id}`}>失敗したら AI が自分で直して再実行してよい回数</label>
              <select id={`selfdrive-${a.id}`} className="rounded-lg border border-slate-600 bg-slate-900 px-2 py-1 text-[13px] text-slate-100" value={selfDrive} onChange={(e) => setSelfDrive(Number(e.target.value))}>
                {[0, 1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n === 0 ? "0（毎回確認）" : `${n} 回`}</option>)}
              </select>
              <span className="text-[11px] text-slate-500" title="外部リポジトリの追加・OS 全体のアップグレード・パッケージの削除・処理の強制終了・ソースからのビルドや本体の差し替え・ファイアウォールの方針変更・再起動">※ 手段を大きく変える操作は回数に関係なく毎回確認します</span>
            </div>
          )}
          {err && <div className="text-xs text-[#FF9A9D]">{err}</div>}
          <div className="flex flex-wrap gap-2">
            <button className="inline-flex min-h-[44px] items-center gap-2 rounded-[10px] bg-teal-500 px-5 text-sm font-semibold text-white hover:bg-teal-400 disabled:cursor-not-allowed disabled:opacity-40" disabled={busy || (blocked && cmd === a.command)} onClick={() => act("approve")} title={blocked ? "自動チェックでブロック。コマンドを編集すれば実行可" : ""}><Ico d={I.approve} size={16} className="" />{cmd !== a.command ? "編集して実行" : steps ? `${steps.length} ステップをまとめて承認して実行` : "承認して実行"}</button>
            <button className="min-h-[44px] rounded-[10px] border border-[#4A1E24] px-5 text-sm font-semibold text-[#FF9A9D] hover:bg-[#3A1418] disabled:opacity-40" disabled={busy} onClick={() => act("reject")}>却下</button>
          </div>
        </div>
      )}
    </div>
  );
}
