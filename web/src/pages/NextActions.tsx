import { useEffect, useMemo, useState, type ReactNode } from "react";
import { onServerEvent } from "../lib/events";
import { Link, useSearchParams } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { Ico, I } from "../components/Icon";
import { SEV_LABEL, VERDICT_LABEL } from "../lib/mode";

/**
 * Action ボード: 親タスク（Sidekick / Sentinel のセッション）ごとに 1 ブロック。
 * ブロックの中は状態ごとの横並び列（未対応 → 依存待ち → 承認済・待ち → 実行中 → 完了 → 却下 → 巻き戻し）で、
 * どの派生タスクが待ちで、どれが終わったかが一目で分かる。カードをクリックで詳細を展開。
 * kind=followup（残タスク: ベンダー修正待ち・経過観察など、今すぐ実行するものが無いタスク）はピンのマークで区別する。
 */

/** [status, 見出し, 文字色, 下線色] — MamorAI デザイン v0.2 */
const COLS: [string, string, string, string][] = [
  ["proposed", "未対応", "#FFC27A", "#8A6A2A"], ["blocked", "依存待ち", "#C8B6FF", "#5B4A8F"], ["approved", "承認済・待ち", "#8FCBFF", "#2D5F8F"], ["executing", "実行中", "#7FD9E6", "#2A6A75"],
  ["done", "完了", "#7FE0B0", "#2A6A4A"], ["rejected", "却下", "#9AA6BF", "#2A3756"], ["rolled_back", "巻き戻し", "#FF9A9D", "#7A2A30"],
];
const RISK_FG: Record<string, string> = { low: "#7FE0B0", medium: "#FFC27A", high: "#FF9A9D" };
const VERDICT_TONE: Record<string, [string, string]> = { malicious: ["#3A1418", "#FF9A9D"], suspicious: ["#3A2A10", "#FFC27A"], misconfiguration: ["#3A2A10", "#FFC27A"], benign: ["#12301F", "#7FE0B0"], false_positive: ["#12301F", "#7FE0B0"], unknown: ["#1E2942", "#B4BED3"] };
const OPEN = new Set(["proposed", "blocked", "approved", "executing"]);
const REL_JA: Record<string, string> = { revert: "元に戻す", verify: "結果確認", next: "続き" };
const COMPASS = "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM15.5 8.5l-2 5-5 2 2-5z";
const EVERY_JA: Record<number, string> = { 60: "1 時間ごと", 120: "2 時間ごと", 180: "3 時間ごと", 360: "6 時間ごと", 720: "12 時間ごと", 1440: "毎日", 2880: "2 日ごと", 4320: "3 日ごと", 10080: "毎週", 20160: "2 週間ごと", 43200: "30 日ごと" };

interface Parent { session_id: number; title: string; origin: string; status: string; created_at: string | null; summary: any; hosts: string[]; actions: any[]; open: number; total: number; followups: number; schedules: any[] }

function group(items: any[], schedules: any[] = []): Parent[] {
  const m = new Map<number, Parent>();
  for (const a of items) {
    let p = m.get(a.session_id);
    if (!p) { p = { session_id: a.session_id, title: a.session_title ?? `セッション #${a.session_id}`, origin: a.session_origin, status: a.session_status, created_at: a.session_created_at ?? a.created_at, summary: a.session_summary, hosts: [], actions: [], open: 0, total: 0, followups: 0, schedules: [] }; m.set(a.session_id, p); }
    p.actions.push(a); p.total++; if (OPEN.has(a.status)) p.open++; if (a.kind === "followup" && OPEN.has(a.status)) p.followups++;
    if (a.host_name && !p.hosts.includes(a.host_name)) p.hosts.push(a.host_name);
  }
  // 有効なスケジュール（定期実行）は「実行中」列のカードとして親タスクに載せる
  for (const sc of schedules.filter((x) => x.state === "active")) {
    let p = m.get(sc.session_id);
    if (!p) { p = { session_id: sc.session_id, title: sc.session_title ?? `セッション #${sc.session_id}`, origin: "user", status: sc.session_status, created_at: sc.created_at, summary: null, hosts: [], actions: [], open: 0, total: 0, followups: 0, schedules: [] }; m.set(sc.session_id, p); }
    p.schedules.push(sc); p.open++; p.total++;
  }
  for (const p of m.values()) p.actions.sort((x, y) => x.id - y.id);
  return [...m.values()].sort((a, b) => (b.open > 0 ? 1 : 0) - (a.open > 0 ? 1 : 0) || b.session_id - a.session_id);
}

export default function NextActions() {
  const [items, setItems] = useState<any[]>([]); const [sentinel, setSentinel] = useState<any>(null);
  const [filter, setFilter] = useState<"open" | "all">("open");
  const [params, setParams] = useSearchParams();
  const focus = Number(params.get("s") ?? 0);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const [scheds, setScheds] = useState<any[]>([]);
  const load = () => { api.get<{ items: any[] }>("/next-actions?limit=200").then((r) => setItems(r.items)); api.get<{ items: any[] }>("/schedules").then((r) => setScheds(r.items)).catch(() => {}); api.get("/sentinel/status").then(setSentinel); };
  useEffect(() => { load(); return onServerEvent(["next_actions", "status", "schedule"], load); }, []);
  const setStatus = async (id: number, status: string) => { await api.post(`/next-actions/${id}/status`, { status }); load(); };
  /** 実行を依頼: 承認済にして元セッションの AI に計画を作らせる（提案パネルの「この提案を進める」と同じ） */
  const runAction = async (a: any) => {
    await api.post(`/next-actions/${a.id}/status`, { status: "approved" });
    await api.post(`/sessions/${a.session_id}/message`, { message: `提案「${a.title}」を実行して。必要な手順（設定変更・検証・再起動など）は 1 つの計画にまとめて、承認は 1 回で済むようにして（SSH のホストは apply_change、Windows のエージェントだけの端末は host_action。アプリの更新は win_updates で確認してから update_install の apps）。next_action_id: ${a.id}` });
    load();
  };
  const parents = useMemo(() => group(items, scheds), [items, scheds]);
  const shown = parents.filter((p) => (filter === "all" || p.open > 0) && (!focus || p.session_id === focus));
  const totals = { open: parents.reduce((a, p) => a + p.open, 0), parents: parents.filter((p) => p.open > 0).length, followups: parents.reduce((a, p) => a + p.followups, 0) };
  const toggleCollapse = (id: number) => setCollapsed((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  return (
    <div className="flex flex-col gap-[18px]">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="flex items-center gap-2.5 text-2xl font-bold"><Ico d={I.board} size={22} />Action ボード</h1>
        <span className="text-[13px] text-slate-300">進行中の親タスク {totals.parents} 件 · 未処理 {totals.open} 件{totals.followups ? <>（うち 残タスク {totals.followups}）</> : null}</span>
        {sentinel && <span className="text-[13px] text-slate-400">· Sentinel: {sentinel.enabled ? "有効" : "無効"} · 最終実行 {sentinel.lastRun ? `${fmtTs(sentinel.lastRun.at)}${sentinel.lastRun.error ? " (error: " + sentinel.lastRun.error + ")" : ""}` : "-"}</span>}
        <div className="ml-auto flex items-center gap-2">
          {focus ? <button className="min-h-[34px] rounded-lg border border-slate-600 px-3 text-[13px] text-slate-300 hover:text-white" onClick={() => setParams({})}>× 絞り込み解除（#{focus}）</button> : null}
          <div role="group" aria-label="表示" className="flex gap-1 rounded-[10px] border border-slate-700 bg-slate-800 p-[3px]">
            {([["open", "進行中"], ["all", "すべて"]] as const).map(([k, l]) => <button key={k} className={`min-h-[34px] rounded-lg px-3.5 text-[13px] transition ${filter === k ? "bg-teal-500 text-white" : "text-slate-300 hover:text-white"}`} onClick={() => setFilter(k)}>{l}</button>)}
          </div>
        </div>
      </header>

      {shown.length === 0 && <div className="rounded-2xl border border-slate-700 bg-slate-800 p-6 text-center text-sm text-slate-400">{filter === "open" ? "進行中の親タスクはありません。「すべて」で完了済みも表示できます。" : "アクションはまだありません。"}</div>}

      {shown.map((p) => {
        const verdict = p.summary?.proposal?.verdict; const sev = p.summary?.proposal?.severity; const isCol = collapsed.has(p.session_id);
        const done = p.actions.filter((a) => a.status === "done").length;
        const [vBg, vFg] = VERDICT_TONE[verdict] ?? VERDICT_TONE.unknown;
        const sentinelOrigin = p.origin === "alert";
        return (
          <section key={p.session_id} className="overflow-hidden rounded-2xl border border-slate-700 bg-slate-800">
            {/* 親タスクのヘッダー */}
            <div className="flex flex-wrap items-center gap-2.5 border-b border-slate-700 bg-[#0F1729] px-4 py-3">
              <button aria-label={isCol ? "展開" : "たたむ"} title={isCol ? "展開" : "たたむ"} className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-600 text-xs text-slate-300 hover:text-white" onClick={() => toggleCollapse(p.session_id)}>{isCol ? "▶" : "▼"}</button>
              <Link to={`/sidekick/${p.session_id}`} className="text-[15px] font-bold text-slate-100 hover:text-teal-200" title="セッションを開く">{p.title}</Link>
              <span className="inline-flex items-center gap-1.5 rounded-md bg-[#15204A] px-2 py-0.5 text-xs text-teal-200"><Ico d={sentinelOrigin ? I.approve : COMPASS} size={12} className="" />{sentinelOrigin ? "Sentinel" : "Sidekick"} #{p.session_id}</span>
              {verdict && <span className="rounded-md px-2 py-0.5 text-xs" style={{ background: vBg, color: vFg }}>調査結果: {VERDICT_LABEL[verdict] ?? verdict}{sev ? ` / 重大度 ${SEV_LABEL[String(sev).toLowerCase()] ?? sev}` : ""}</span>}
              <span className="font-mono text-xs text-slate-400">{p.hosts.length ? p.hosts.join(", ") : "ホスト指定なし"} · {p.created_at ? fmtTs(p.created_at) : ""}</span>
              <span className="ml-auto flex flex-wrap gap-1.5 text-xs">
                {p.followups > 0 && <span className="rounded-md bg-[#24183F] px-2 py-0.5 text-[#C8B6FF]">残タスク {p.followups}</span>}
                {p.open === 0 ? <span className="rounded-md bg-[#12301F] px-2 py-0.5 text-[#7FE0B0]">すべて処理済み</span> : <span className="rounded-md bg-[#3A2A10] px-2 py-0.5 text-[#FFC27A]">未処理 {p.open}</span>}
                <span className="rounded-md bg-slate-900 px-2 py-0.5 text-slate-400">完了 {done}/{p.total}</span>
              </span>
            </div>
            {/* 状態ごとの横並び列（カンバン） */}
            {!isCol && (
              <div className="overflow-x-auto">
                <div className="grid min-w-[1400px] gap-2.5 p-3 [grid-template-columns:repeat(7,minmax(190px,1fr))]">
                  {COLS.map(([k, label, fg, line]) => {
                    const rows = p.actions.filter((x) => x.status === k);
                    const sc = k === "executing" ? p.schedules : [];
                    return (
                      <div key={k} className="flex min-w-0 flex-col gap-2">
                        <div className="flex items-center gap-1.5 border-b-2 px-0.5 pb-1.5 pt-1 text-xs font-bold" style={{ color: fg, borderColor: line }}>{label} <span className="ml-auto font-normal text-slate-400">{rows.length + sc.length}</span></div>
                        {sc.map((x) => (
                          <div key={`sc${x.id}`} className="flex flex-col gap-1.5 rounded-[10px] border border-[#1F4A55] bg-[#0E1A2A] p-2.5 text-xs">
                            <div className="flex items-center gap-1.5 text-[13px] font-semibold text-slate-100"><Ico d={I.clock} size={14} className="text-[#5EC8D8]" />{x.title}</div>
                            <div className="text-slate-400">{x.enabled ? "定期実行中" : "一時停止"} · {EVERY_JA[x.interval_min] ?? `${x.interval_min} 分ごと`}{x.at_time && x.interval_min >= 1440 ? ` ${x.at_time}` : ""} · {x.run_count}{x.max_runs ? `/${x.max_runs}` : ""} 回</div>
                            {x.goal && <div className="line-clamp-2 text-slate-300">達成条件: {x.goal}</div>}
                            {x.last_result && <div className="line-clamp-2 text-slate-400">前回: {String(x.last_result).replace(/\*\*/g, "")}</div>}
                            <div className="flex justify-between gap-1.5 text-slate-400">{x.next_run_at && x.enabled ? <span>次回 {fmtTs(x.next_run_at)}</span> : <span />}<Link to="/schedules" className="text-teal-300 hover:text-teal-200">スケジュール →</Link></div>
                          </div>
                        ))}
                        {rows.map((a) => <ActionCard key={a.id} a={a} idx={p.actions.indexOf(a) + 1} afterLabel={a.after_id ? (p.actions.findIndex((x) => x.id === a.after_id) >= 0 ? `${p.actions.findIndex((x) => x.id === a.after_id) + 1}.「${p.actions.find((x) => x.id === a.after_id)?.title}」` : `#${a.after_id}`) : null} onStatus={setStatus} onRun={runAction} />)}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </section>
        );
      })}
      <div className="border-t border-slate-700 pt-3.5 text-[13px] leading-relaxed text-slate-400">提案されたアクションの実行は Sidekick セッション内で「〜を実行して」と依頼し、承認カードで実行してください。残タスク（ピンのマーク）は実行するコマンドが無いもの（修正版待ち・経過観察・手作業）で、片付いたら「完了」にしてください。</div>
    </div>
  );
}

/** カードのボタン（デザインの色分け: 実行=藍塗り / 却下・巻き戻し=赤 / 解放=紫 / 完了=緑 / 追跡=sky / その他=灰） */
const BTN: Record<string, string> = {
  run: "border-teal-500 bg-teal-500 text-white hover:bg-teal-400",
  reject: "border-[#4A1E24] text-[#FF9A9D] hover:bg-[#4A1E24]/40",
  release: "border-[#3F2F6A] text-[#C8B6FF] hover:bg-[#3F2F6A]/40",
  done: "border-[#1E4A34] text-[#7FE0B0] hover:bg-[#1E4A34]/40",
  track: "border-[#2D5F8F] text-[#8FCBFF] hover:bg-[#2D5F8F]/40",
  plain: "border-slate-600 text-slate-300 hover:bg-slate-700",
};
const Btn = ({ k, onClick, title, children }: { k: keyof typeof BTN; onClick: () => void; title?: string; children: ReactNode }) => (
  <button title={title} className={`min-h-[28px] rounded-[7px] border px-2.5 text-[11px] transition ${BTN[k]}`} onClick={onClick}>{children}</button>
);

function ActionCard({ a, idx, afterLabel, onStatus, onRun }: { a: any; idx: number; afterLabel: string | null; onStatus: (id: number, s: string) => void; onRun: (a: any) => void }) {
  const [open, setOpen] = useState(false);
  const fu = a.kind === "followup";
  return (
    <div className="flex flex-col rounded-[10px] border border-slate-600 bg-slate-900">
      <button className="flex flex-col gap-1.5 p-2.5 text-left" onClick={() => setOpen(!open)}>
        <span className="flex items-start gap-1.5 text-[13px] font-semibold leading-snug text-slate-100">
          <span className="font-mono text-slate-500">{idx}.</span>
          {fu && <span title="残タスク" className="mt-0.5"><Ico d={I.pin} size={14} className="text-[#C8B6FF]" /></span>}
          <span>{a.title}</span>
        </span>
        <span className="font-mono text-[11px] text-slate-400">{a.host_name ?? "-"} · <span style={{ color: RISK_FG[a.risk] }}>risk {a.risk}</span>{fu && a.due ? ` · 期限 ${a.due}` : ""}</span>
        {a.after_id && <span className="text-[11px] leading-relaxed text-[#C8B6FF]" title="依存先のタスクが完了すると自動で未対応に戻り、AI が計画を作ります">依存: {afterLabel} の完了後{a.relation ? `（${REL_JA[a.relation] ?? a.relation}）` : ""}</span>}
        {!open && <span className="line-clamp-2 text-xs leading-relaxed text-slate-300">{a.plain ?? a.why}</span>}
      </button>
      {open && (
        <div className="flex flex-col gap-1.5 px-2.5 pb-2 text-xs leading-relaxed">
          {a.plain && <div className="text-slate-100">{a.plain}</div>}
          {a.why && <div className="text-slate-300"><span className="text-slate-500">理由: </span>{a.why}</div>}
          {a.impact && <div className="text-[#FFC27A]"><span className="text-slate-500">影響: </span>{a.impact}</div>}
          {a.commands?.length ? <pre className="whitespace-pre-wrap break-all rounded-lg border border-slate-700 bg-[#070B15] p-2 font-mono text-[11px] text-slate-200">{a.commands.join("\n")}</pre> : null}
          {a.rollback?.length ? <div><div className="text-[11px] text-slate-500">巻き戻し</div><pre className="whitespace-pre-wrap break-all rounded-lg border border-slate-700 bg-[#070B15] p-2 font-mono text-[11px] text-slate-400">{a.rollback.join("\n")}</pre></div> : null}
          {a.approval_id && <Link to="/approvals" className="text-xs text-teal-300 hover:text-teal-200">承認 #{a.approval_id}</Link>}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-1 px-2.5 pb-2.5">
        {a.status === "proposed" && (fu
          ? <><Btn k="track" onClick={() => onStatus(a.id, "approved")}>追跡する</Btn><Btn k="done" onClick={() => onStatus(a.id, "done")}>完了</Btn><Btn k="reject" onClick={() => onStatus(a.id, "rejected")}>却下</Btn><Btn k="run" title="設定変更が必要なら AI に実行計画を作らせて承認待ちにする" onClick={() => onRun(a)}>▶ 実行を依頼</Btn></>
          : <><Btn k="run" title="AI が実行計画を作り、承認キューに積みます" onClick={() => onRun(a)}>▶ 実行を依頼</Btn><Btn k="reject" onClick={() => onStatus(a.id, "rejected")}>却下</Btn></>)}
        {a.status === "blocked" && <><Btn k="release" title="依存を待たずに今すぐ未対応にする" onClick={() => onStatus(a.id, "proposed")}>今すぐ解放</Btn><Btn k="reject" onClick={() => onStatus(a.id, "rejected")}>却下</Btn></>}
        {a.status === "approved" && <><Btn k="done" onClick={() => onStatus(a.id, "done")}>完了</Btn><Btn k="plain" onClick={() => onStatus(a.id, "proposed")}>未対応に戻す</Btn></>}
        {a.status === "done" && !fu && <Btn k="reject" onClick={() => onStatus(a.id, "rolled_back")}>巻き戻した</Btn>}
        {(a.status === "rejected" || a.status === "rolled_back" || (a.status === "done" && fu)) && <Btn k="plain" onClick={() => onStatus(a.id, "proposed")}>↩ 再開</Btn>}
        <Link to={`/sidekick/${a.session_id}`} className="ml-auto font-mono text-[11px] text-teal-300 hover:text-teal-200">{a.session_origin === "alert" ? "Sentinel" : "Sidekick"} #{a.session_id}</Link>
      </div>
    </div>
  );
}
