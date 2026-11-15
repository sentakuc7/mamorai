import { useContext, useEffect, useState } from "react";
import { onServerEvent } from "../lib/events";
import { Link } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import { Ico, I } from "../components/Icon";

/**
 * スケジュール（EDR-77）: AI チャットや人間が登録した定期タスクの一覧。
 * 各実行は登録元セッションに「スケジュール実行」として投入され、結果はそのチャットと、ここの実行履歴に出る。
 */

interface Sched { id: number; session_id: number; session_title?: string; session_status?: string; session_kind?: string; title: string; prompt: string; interval_min: number; at_time: string | null; max_runs: number | null; run_count: number; enabled: number | boolean; state: string; next_run_at: string | null; last_run_at: string | null; last_result: string | null; last_status: string | null; created_by: string; goal: string | null; created_at: string }
interface Run { id: number; started_at: string; finished_at: string | null; status: string; result: string | null }

const EVERY: [number, string][] = [[60, "1 時間ごと"], [120, "2 時間ごと"], [180, "3 時間ごと"], [360, "6 時間ごと"], [720, "12 時間ごと"], [1440, "毎日"], [2880, "2 日ごと"], [4320, "3 日ごと"], [10080, "毎週"], [20160, "2 週間ごと"], [43200, "30 日ごと"]];
const everyLabel = (m: number) => EVERY.find(([v]) => v === m)?.[1] ?? `${m} 分ごと`;
const STATE_JA: Record<string, string> = { active: "有効", done: "達成", cancelled: "取消" };
/** 状態チップ [背景, 文字, 枠] — MamorAI デザイン v0.2 */
const STATE_TONE: Record<string, [string, string, string]> = { active: ["#10304A", "#8FCBFF", "#2D5F8F"], paused: ["#1E2942", "#B4BED3", "#2A3756"], done: ["#12301F", "#7FE0B0", "#1E4A34"], cancelled: ["#1A2030", "#9AA6BF", "#2A3756"] };
const RUN_FG: Record<string, string> = { waiting_approval: "#FFC27A", ok: "#7FE0B0", error: "#FF9A9D", timeout: "#FF9A9D", skipped: "#FFC27A", running: "#8FCBFF" };
const RUN_JA: Record<string, string> = { waiting_approval: "承認待ち", ok: "完了", error: "失敗", timeout: "タイムアウト", skipped: "保留", running: "実行中" };
const KIND_JA: Record<string, string> = { investigate: "調査", cloud_setup: "クラウド管理", host_setup: "ホスト", overview_setup: "攻撃可視化", playbook_setup: "プレイブック" };

const BTN = "inline-flex min-h-[36px] items-center gap-1.5 rounded-lg border px-3 text-[13px] transition";
const FIELD = "min-h-[40px] rounded-[10px] border border-slate-600 bg-slate-900 px-3 text-sm text-slate-100 placeholder-slate-500 focus:border-teal-400 focus:outline-none";

export default function Schedules() {
  const { user } = useContext(UserCtx); const canAct = user?.role === "admin" || user?.role === "operator"; const admin = user?.role === "admin";
  const [items, setItems] = useState<Sched[]>([]); const [filter, setFilter] = useState<"active" | "all">("active");
  const [open, setOpen] = useState<number | null>(null); const [runs, setRuns] = useState<Record<number, Run[]>>({});
  const [msg, setMsg] = useState(""); const [form, setForm] = useState<any | null>(null);
  const load = () => api.get<{ items: Sched[] }>("/schedules").then((r) => setItems(r.items));
  useEffect(() => { load(); return onServerEvent(["schedule", "status"], load); }, []);
  const loadRuns = (id: number) => api.get<{ items: Run[] }>(`/schedules/${id}/runs`).then((r) => setRuns((x) => ({ ...x, [id]: r.items })));
  const toggle = (id: number) => { if (open === id) setOpen(null); else { setOpen(id); loadRuns(id); } };
  const upd = async (s: Sched, body: any) => { await api.put(`/schedules/${s.id}`, body); load(); };
  const runNow = async (s: Sched) => { const r = await api.post<{ started: boolean; reason?: string }>(`/schedules/${s.id}/run`, {}); setMsg(r.started ? `#${s.id} を実行しました。結果はセッション #${s.session_id} のチャットに出ます。` : `実行できません: ${r.reason}`); load(); if (open === s.id) setTimeout(() => loadRuns(s.id), 1500); };
  const del = async (s: Sched) => { if (!window.confirm(`スケジュール「${s.title}」と実行履歴を削除します。よろしいですか？`)) return; await api.del(`/schedules/${s.id}`); load(); };
  const submit = async () => { try { await api.post("/schedules", { ...form, interval_min: Number(form.interval_min), max_runs: form.max_runs ? Number(form.max_runs) : null, at_time: form.at_time || null, goal: form.goal || null }); setForm(null); load(); } catch (e: any) { setMsg(e.message); } };
  const shown = items.filter((s) => filter === "all" || s.state === "active");
  const active = items.filter((s) => s.state === "active" && s.enabled);
  const next = active.map((s) => s.next_run_at).filter(Boolean).sort()[0];

  return (
    <div className="flex max-w-[1240px] flex-col gap-4">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="flex items-center gap-2.5 text-2xl font-bold"><Ico d={I.clock} size={22} />スケジュール</h1>
        <span className="flex-[1_1_320px] text-[13px] text-slate-400">有効 {active.length} 件{next && ` · 次回 ${fmtTs(next)}`} · 30 秒ごとに判定。実行結果は登録元のチャットに出ます</span>
        <div role="group" aria-label="表示" className="flex gap-1 rounded-[10px] border border-slate-700 bg-slate-800 p-[3px]">
          {([["active", "有効"], ["all", "すべて"]] as const).map(([k, l]) => <button key={k} className={`min-h-[34px] rounded-lg px-3.5 text-[13px] transition ${filter === k ? "bg-teal-500 text-white" : "text-slate-300 hover:text-white"}`} onClick={() => setFilter(k)}>{l}</button>)}
        </div>
        {canAct && <button className="min-h-[40px] rounded-[10px] bg-teal-500 px-4 text-sm font-semibold text-white hover:bg-teal-400" onClick={() => setForm({ title: "", prompt: "", interval_min: 1440, at_time: "06:00", kind: "investigate" })}>＋ 手動で登録</button>}
      </header>
      {msg && <div className="flex items-center gap-2 rounded-[14px] border border-teal-500/40 bg-slate-800 px-4 py-3 text-sm text-teal-200"><span className="flex-1">{msg}</span><button className="text-xs text-slate-400 hover:text-white" aria-label="閉じる" onClick={() => setMsg("")}>×</button></div>}
      {shown.length === 0 && <div className="rounded-[14px] border border-slate-700 bg-slate-800 p-6 text-center text-sm text-slate-400">スケジュールはありません。Sidekick やクラウド管理の AI に「修正版が出るまで毎日確認して」のように頼むと登録されます。</div>}

      {shown.map((s) => {
        const isOpen = open === s.id; const paused = s.state === "active" && !s.enabled;
        const [stBg, stFg, stBd] = STATE_TONE[paused ? "paused" : s.state] ?? STATE_TONE.cancelled;
        return (
          <article key={s.id} className={`overflow-hidden rounded-[14px] border bg-slate-800 ${isOpen ? "border-teal-500" : "border-slate-700"}`}>
            <div className="flex flex-wrap items-center gap-2.5 px-4 py-3">
              <button aria-label={isOpen ? "たたむ" : "展開"} className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-600 text-xs text-slate-300 hover:text-white" onClick={() => toggle(s.id)}>{isOpen ? "▼" : "▶"}</button>
              <span className="flex-[1_1_260px] text-[15px] font-bold text-slate-100">{s.title}</span>
              <span className="rounded-full border px-2.5 py-0.5 text-xs font-semibold" style={{ background: stBg, color: stFg, borderColor: stBd }}>{STATE_JA[s.state]}{paused ? "（停止中）" : ""}</span>
              <span className="font-mono text-[13px] text-slate-300">{everyLabel(s.interval_min)}{s.at_time && s.interval_min >= 1440 ? ` ${s.at_time}` : ""}</span>
              <Link to={`/sidekick/${s.session_id}`} className="text-[13px] text-teal-300 hover:text-teal-200" title="登録元のチャットを開く">{KIND_JA[s.session_kind ?? ""] ?? s.session_kind} #{s.session_id} · {s.session_title}</Link>
              <span className="text-xs text-slate-400">実行 {s.run_count}{s.max_runs ? `/${s.max_runs}` : ""} 回</span>
              <span className="ml-auto flex flex-wrap gap-2.5 text-xs text-slate-400">
                {s.last_run_at && <span>前回 {fmtTs(s.last_run_at)} <span className="font-semibold" style={{ color: RUN_FG[s.last_status ?? ""] }}>{RUN_JA[s.last_status ?? ""] ?? s.last_status}</span></span>}
                {s.state === "active" && s.enabled && s.next_run_at && <span>次回 {fmtTs(s.next_run_at)}</span>}
              </span>
            </div>
            {s.last_result && <div className="truncate pb-3 pl-[58px] pr-4 text-[13px] text-slate-300" title={s.last_result}>直近の結果: {s.last_result}</div>}
            {isOpen && (
              <div className="grid gap-[18px] border-t border-slate-700 bg-slate-900 p-4 [grid-template-columns:repeat(auto-fit,minmax(320px,1fr))]">
                <div className="flex flex-col gap-2.5">
                  <div className="text-xs text-slate-400">毎回の指示</div>
                  <div className="whitespace-pre-wrap rounded-[10px] border border-slate-700 bg-[#070B15] px-3.5 py-3 text-sm leading-relaxed text-slate-100">{s.prompt}</div>
                  {s.goal && <div className="text-[13px] text-slate-100"><span className="text-slate-400">達成条件: </span>{s.goal}</div>}
                  <div className="text-xs text-slate-400">登録: {s.created_by === "agent" ? "AI" : "人間"} · {fmtTs(s.created_at)}</div>
                  {canAct && <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <button className={`${BTN} border-teal-500 bg-teal-500 font-semibold text-white hover:bg-teal-400`} onClick={() => runNow(s)}>▶ 今すぐ実行</button>
                    {s.state === "active" && <button className={`${BTN} border-slate-600 text-slate-100 hover:bg-slate-700`} onClick={() => upd(s, { enabled: !s.enabled })}><Ico d={s.enabled ? I.pause : I.play} size={13} className="" />{s.enabled ? "一時停止" : "再開"}</button>}
                    {s.state !== "active" && <button className={`${BTN} border-slate-600 text-slate-100 hover:bg-slate-700`} onClick={() => upd(s, { enabled: true })}>↩ 有効に戻す</button>}
                    <label className="inline-flex items-center gap-1.5 text-xs text-slate-400">間隔
                      <select className="min-h-[36px] rounded-lg border border-slate-600 bg-slate-800 px-2 text-[13px] text-slate-100" value={s.interval_min} onChange={(e) => upd(s, { interval_min: Number(e.target.value) })}>{EVERY.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
                    </label>
                    {s.interval_min >= 1440 && <label className="inline-flex items-center gap-1.5 text-xs text-slate-400">時刻
                      <input key={`${s.id}-${s.at_time ?? ""}`} className="min-h-[34px] w-16 rounded-lg border border-slate-600 bg-slate-800 px-2 text-[13px] text-slate-100" defaultValue={s.at_time ?? ""} placeholder="HH:MM" onBlur={(e) => e.target.value !== (s.at_time ?? "") && upd(s, { at_time: e.target.value || null })} />
                    </label>}
                    {s.state === "active" && <button className={`${BTN} border-[#1E4A34] text-[#7FE0B0] hover:bg-[#1E4A34]/40`} onClick={() => upd(s, { state: "done" })}><Ico d={I.check} size={13} className="" />達成にする</button>}
                    {s.state === "active" && <button className={`${BTN} border-slate-600 text-slate-300 hover:bg-slate-700`} onClick={() => upd(s, { state: "cancelled" })}>取消</button>}
                    {admin && <button className={`${BTN} border-[#4A1E24] text-[#FF9A9D] hover:bg-[#4A1E24]/40`} onClick={() => del(s)}><Ico d={I.trash} size={14} className="" />削除</button>}
                  </div>}
                </div>
                <div className="flex flex-col gap-2">
                  <div className="text-xs text-slate-400">実行履歴</div>
                  <div className="flex max-h-80 flex-col gap-1.5 overflow-y-auto">
                    {(runs[s.id] ?? []).map((r) => (
                      <div key={r.id} className="flex flex-col gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-2">
                        <div className="flex gap-2.5 text-xs"><span className="font-mono text-slate-400">{fmtTs(r.started_at)}</span><span className="font-semibold" style={{ color: RUN_FG[r.status] }}>{RUN_JA[r.status] ?? r.status}</span></div>
                        {r.result && <div className="whitespace-pre-wrap text-[13px] leading-relaxed text-slate-300">{r.result}</div>}
                      </div>
                    ))}
                    {!(runs[s.id] ?? []).length && <div className="text-[13px] text-slate-400">まだ実行されていません</div>}
                  </div>
                </div>
              </div>
            )}
          </article>
        );
      })}

      {form && <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-[rgba(5,8,16,0.72)] px-4 py-20 backdrop-blur-sm" onClick={() => setForm(null)}>
        <div role="dialog" aria-labelledby="sf-h" className="flex w-full max-w-[640px] flex-col gap-3.5 rounded-2xl border border-slate-600 bg-slate-800 p-[22px]" onClick={(e) => e.stopPropagation()}>
          <div id="sf-h" className="flex items-center gap-2 text-[17px] font-bold"><Ico d={I.clock} size={18} />スケジュールを手動で登録</div>
          <div className="text-[13px] leading-relaxed text-slate-400">新しい調査セッションが作られ、毎回そのチャットに指示が投入されます。既存のチャットに紐づけたいときは、そのチャットで AI に頼んでください。</div>
          <label className="flex flex-col gap-1.5 text-xs text-slate-400">タイトル<input className={`${FIELD} py-2.5`} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="例: CVE-2026-80668 の修正版カーネル確認" /></label>
          <label className="flex flex-col gap-1.5 text-xs text-slate-400">毎回の指示（ホスト名・コマンド・何をもって達成とするか）<textarea rows={4} className={`${FIELD} resize-y py-2.5`} value={form.prompt} onChange={(e) => setForm({ ...form, prompt: e.target.value })} placeholder="例: web03 で sudo apt update && apt list --upgradable | grep linux-image-cloud-amd64 を実行し、修正版（6.1.0-55 以降）が出ているか確認する" /></label>
          <div className="grid gap-2.5 [grid-template-columns:repeat(auto-fit,minmax(130px,1fr))]">
            <label className="flex flex-col gap-1.5 text-xs text-slate-400">間隔<select className={FIELD} value={form.interval_min} onChange={(e) => setForm({ ...form, interval_min: Number(e.target.value) })}>{EVERY.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
            {Number(form.interval_min) >= 1440 && <label className="flex flex-col gap-1.5 text-xs text-slate-400">時刻（JST）<input className={FIELD} value={form.at_time} onChange={(e) => setForm({ ...form, at_time: e.target.value })} /></label>}
            <label className="flex flex-col gap-1.5 text-xs text-slate-400">最大回数（空=無制限）<input className={FIELD} value={form.max_runs ?? ""} onChange={(e) => setForm({ ...form, max_runs: e.target.value })} /></label>
            <label className="flex flex-col gap-1.5 text-xs text-slate-400">種別<select className={FIELD} value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option value="investigate">調査（Sidekick）</option><option value="cloud_setup">クラウド管理</option></select></label>
          </div>
          <label className="flex flex-col gap-1.5 text-xs text-slate-400">達成条件（任意）<input className={`${FIELD} py-2.5`} value={form.goal ?? ""} onChange={(e) => setForm({ ...form, goal: e.target.value })} placeholder="例: 修正版カーネルが apt で入手可能になる" /></label>
          <div className="flex justify-end gap-2">
            <button className="min-h-[42px] rounded-[10px] border border-slate-600 px-4 text-sm text-slate-100 hover:bg-slate-700" onClick={() => setForm(null)}>キャンセル</button>
            <button className="min-h-[42px] rounded-[10px] bg-teal-500 px-[18px] text-sm font-semibold text-white hover:bg-teal-400 disabled:opacity-50" disabled={!form.title || !form.prompt} onClick={submit}>登録</button>
          </div>
        </div>
      </div>}
    </div>
  );
}
