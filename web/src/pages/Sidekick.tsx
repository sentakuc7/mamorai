import { useContext, useEffect, useMemo, useState } from "react";
import AgentIntro, { AgentMark, AGENT_NAME } from "../components/AgentIntro";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import { useMode, KIND_LABEL } from "../lib/mode";
import { DISPLAY_COLOR, DISPLAY_JA, DISPLAY_TIP, PULSE, displayKey } from "../lib/sessionDisplay";
import SessionChat, { type SessionDetail, type PendingFile, SESSION_STATUS_JA } from "../components/SessionChat";
import SessionCard, { type Row, STATUS_COLOR } from "../components/SessionCard";
import { Ico, I } from "../components/Icon";

export default function Sidekick() {
  const { user } = useContext(UserCtx); const canAct = user?.role === "admin" || user?.role === "operator";
  const { mode } = useMode();
  const { id } = useParams(); const nav = useNavigate(); const loc = useLocation();
  const sid = id ? Number(id) : null;
  const [sessions, setSessions] = useState<Row[]>([]); const [archivedCount, setArchivedCount] = useState(0);
  const [showArchive, setShowArchive] = useState(false); const [q, setQ] = useState(""); const [filter, setFilter] = useState<"all" | "open" | "done">("all");
  const [detail, setDetail] = useState<SessionDetail | null>(null); const [llm, setLlm] = useState<any>(null); const [err, setErr] = useState("");
  const loadList = () => api.get<{ items: Row[]; archived_count: number }>(`/sessions?limit=200&kind=investigate${showArchive ? "&archived=1" : ""}`).then((r) => { setSessions(r.items); setArchivedCount(r.archived_count); }).catch((e) => setErr(e.message));
  useEffect(() => { loadList(); }, [showArchive]);
  useEffect(() => { api.get("/llm/status").then(setLlm); }, []);
  useEffect(() => { if (!sid) setDetail(null); }, [sid]);

  const create = async (text: string, attachments: PendingFile[]) => {
    const st = loc.state as any;
    const r = await api.post<{ id: number }>("/sessions", { message: text.trim() || undefined, alert: st?.alert, attachments: attachments.length ? attachments : undefined });
    nav(`/sidekick/${r.id}`, { replace: true }); loadList();
    return r.id;
  };
  const archive = async (x: Row) => { await api.post(`/sessions/${x.id}/${x.archived_at ? "unarchive" : "archive"}`); if (x.id === sid && !x.archived_at) nav("/sidekick"); loadList(); };
  const del = async (x: Row) => {
    if (!confirm(`「${x.label || x.title}」を完全に削除しますか？\n会話・ツール実行結果・生成ファイル・承認履歴がすべて消えます（監査ログは残ります）。`)) return;
    try { await api.del(`/sessions/${x.id}`); if (x.id === sid) nav("/sidekick"); loadList(); } catch (e: any) { alert(e.message); }
  };
  const open = (x: Row) => nav(`/sidekick/${x.id}`);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return sessions.filter((x) => {
      const closed = ["done", "cancelled", "failed", "rejected"].includes(displayKey(x as any)); // EDR-172: 遮断中・定期確認中などは進行中
      if (filter === "open" && closed) return false;
      if (filter === "done" && !closed) return false;
      if (!needle) return true;
      return [x.title, x.label ?? "", (x.tags ?? []).join(" "), KIND_LABEL[x.kind ?? ""] ?? "", SESSION_STATUS_JA[x.status] ?? "", DISPLAY_JA[displayKey(x as any)] ?? "", `#${x.id}`].some((v) => v.toLowerCase().includes(needle));
    });
  }, [sessions, q, filter]);
  const s = detail?.session as Row | undefined;
  const prefill = (loc.state as any)?.prefill as string | undefined;

  const stColor = s ? STATUS_COLOR[s.status] ?? "#7F8BA6" : "#7F8BA6";
  return (
    <div className="-m-6 flex h-screen min-h-0">
      <aside aria-label="調査の履歴" className="flex w-[300px] shrink-0 flex-col gap-2.5 border-r border-slate-700 bg-[#0C1322] px-3.5 py-4">
        <div className="flex gap-2">
          <button className="flex min-h-[40px] flex-1 items-center justify-center gap-1.5 rounded-[10px] bg-teal-500 text-sm font-semibold text-white transition hover:bg-teal-400" onClick={() => { setShowArchive(false); nav("/sidekick"); }}><Ico d={I.plus} size={16} className="" />新しく相談</button>
          <button className={`relative flex w-11 items-center justify-center rounded-[10px] border text-slate-300 transition hover:bg-slate-700 ${showArchive ? "border-teal-400 bg-teal-500/15" : "border-[#24314D]"}`} title="アーカイブ" aria-label={`アーカイブ（${archivedCount} 件）`} onClick={() => setShowArchive(!showArchive)}><Ico d={I.archive} size={18} className="" />{archivedCount > 0 && <span className="absolute -right-1.5 -top-1.5 rounded-full bg-teal-500 px-1.5 text-[11px] font-bold text-white">{archivedCount}</span>}</button>
        </div>
        <label htmlFor="sk-q" className="sr-only">履歴を検索</label>
        <input id="sk-q" className="rounded-[10px] border border-[#24314D] bg-slate-800 px-3 py-2 text-[13px] text-slate-100 placeholder-slate-500 focus:border-teal-400 focus:outline-none" placeholder={showArchive ? "アーカイブを検索（ラベル・タグ・本文）" : "検索（ラベル・タグ・本文・#番号）"} value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="flex items-center gap-1">
          {(["all", "open", "done"] as const).map((f) => <button key={f} onClick={() => setFilter(f)} className={`min-h-[30px] rounded-lg px-2.5 text-xs transition ${filter === f ? "bg-[#1A2547] text-white" : "text-slate-400 hover:text-slate-200"}`}>{f === "all" ? "すべて" : f === "open" ? "進行中" : "完了"}</button>)}
          <span className="ml-auto text-xs text-slate-400">{showArchive ? "アーカイブ · " : ""}{filtered.length} 件</span>
        </div>
        <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto pr-1">
          {err && <div className="text-xs text-rose-400">{err}</div>}
          {filtered.map((x) => <SessionCard key={x.id} x={x} active={x.id === sid} canAct={canAct} onOpen={() => open(x)} onArchive={() => archive(x)} onDelete={() => del(x)} />)}
          {!filtered.length && <div className="p-3 text-center text-xs text-slate-500">{showArchive ? "アーカイブは空です" : q ? "一致する履歴がありません" : "履歴がありません"}</div>}
        </div>
        <div className="border-t border-slate-700 pt-2.5 font-mono text-[11px] text-slate-500">{llm ? (llm.ok ? `LLM: ${llm.provider} / ${llm.model}` : `LLM 未設定: ${llm.error}`) : ""}</div>
      </aside>
      <section aria-label="調査チャット" className="flex min-h-0 min-w-0 flex-1 flex-col gap-4 px-7 pb-6 pt-[18px]">
        <header className="flex flex-wrap items-center gap-2.5">
          <h1 className="inline-flex items-center gap-2 font-display text-[22px] font-semibold"><AgentMark size={24} />Sidekick</h1>{!s && <span className="text-[13px] text-slate-400">{AGENT_NAME} — 質問・調査・パッチ当て・システム改善、なんでも</span>}
          {s && <>
            {(() => { const dk = displayKey(s as any); const c = DISPLAY_COLOR[dk] ?? stColor; const dd = (s as any).display; return <span title={DISPLAY_TIP[dk]} className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold" style={{ background: `${c}22`, color: c }}><span className={`h-[7px] w-[7px] rounded-full ${PULSE.has(dk) ? "animate-pulse" : ""}`} style={{ background: c }} />{DISPLAY_JA[dk] ?? SESSION_STATUS_JA[s.status] ?? s.status}{dd?.note ? <span className="font-normal opacity-80">{dd.note}</span> : null}{(dd?.extra ?? []).map((k: string) => <span key={k} className="font-normal opacity-80">・{DISPLAY_JA[k] ?? k}</span>)}</span>; })()}
            <span className="min-w-0 flex-[1_1_220px] truncate text-[15px] font-semibold text-slate-100">{s.label || s.title}</span>
            {!!s.tags?.length && <span className="hidden gap-1 lg:flex">{s.tags.map((t) => <span key={t} className="rounded bg-[#15204A] px-[7px] py-px text-xs text-teal-300">#{t}</span>)}</span>}
            {mode === "detail" && <span className="font-mono text-[11px] text-slate-500">{s.llm_model} · in {s.token_in} / out {s.token_out} tok</span>}
            {canAct && <button className="inline-flex min-h-[34px] items-center gap-1.5 rounded-lg border border-[#24314D] px-3 text-[13px] text-slate-300 hover:bg-slate-700" title="ラベルを付け直す" onClick={async () => { await api.post(`/sessions/${s.id}/label`); loadList(); }}><Ico d={I.tag} size={14} className="" />ラベル更新</button>}
            {canAct && ["waiting_user", "waiting_external"].includes(s.status) && <button className="inline-flex min-h-[34px] items-center gap-1.5 rounded-lg border border-[#24314D] px-3 text-[13px] text-slate-300 hover:bg-slate-700" onClick={async () => { await api.post(`/sessions/${s.id}/done`); loadList(); }}><Ico d={I.check} size={14} className="" />完了にする</button>}
            {canAct && ["done", "cancelled", "failed"].includes(s.status) && <button className="inline-flex min-h-[34px] items-center gap-1.5 rounded-lg border border-[#24314D] px-3 text-[13px] text-slate-300 hover:bg-slate-700" title="完了したチケットを再開します（返信を書いても自動で再開します）" onClick={async () => { await api.post(`/sessions/${s.id}/reopen`); loadList(); }}><Ico d={I.undo} size={14} className="" />再開する</button>}
            {canAct && !["done", "cancelled", "failed"].includes(s.status) && <button className="inline-flex min-h-[34px] items-center rounded-lg border border-[#4A1E24] px-3 text-[13px] text-[#FF9A9D] hover:bg-rose-900/30" onClick={async () => { await api.post(`/sessions/${s.id}/cancel`); loadList(); }}>中止</button>}
          </>}
        </header>
        <SessionChat key={sid ?? "new"} sid={sid} create={create} className="min-h-0 flex-1" onSessionLoaded={setDetail} onEvent={() => loadList()} initialInput={sid ? "" : prefill} placeholder={sid ? "返信（割り込み可。画像は Ctrl+V で貼り付け）" : "なんでも相談してください（質問・調査・パッチ当て・改善…）"}
          emptyHint={<div className="rounded-2xl border border-slate-700 bg-slate-800 p-5"><AgentIntro examples={["pc-c の直近の High アラートを見て", "脆弱性が多い端末のパッチ計画を立てて", "wazuh01 のディスク残量を確認して", "fail2ban が最近 BAN した IP をまとめて", "MamorAI の運用で改善できるところは？", "Sysmon って何？入れると何が分かるの？"]} onPick={(t) => { create(t, []).catch((e) => setErr(e.message)); }}
            note={<>クリップ（添付）ボタンで、設定ファイル・IP リスト・ログ（テキスト）や画像を読ませられます。「CSV で出して」「ポンチ絵付きでレポートにして」「PPT にして」と頼むと、ファイルをカードで出します。履歴には AI が自動でラベルとタグを付けます。ホスト登録・プレイブック・クラウドなどの相談は、各画面の「AIエージェントに相談」の履歴から見られます（Sidekick の一覧には出ません）。</>} /></div>} />
      </section>
    </div>
  );
}
