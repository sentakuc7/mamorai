import { Fragment, useEffect, useMemo, useState } from "react";
import { api, fmtTs } from "../lib/api";
import { t } from "../lib/i18n";
import { Ico, I } from "../components/Icon";

/** 監査ログ: 追記専用の記録を新しい順に表示。行をクリックで payload を整形表示。絞り込み・書き出しは読み込んだ範囲（直近 200 件）に対して行う。 */
const ACTOR_CLS: Record<string, string> = { user: "bg-[#1A2547] text-[#B9C6FF]", agent: "bg-[#12301F] text-[#7FE0B0]", system: "bg-slate-600 text-slate-300" };
const ACTOR_JA: Record<string, string> = { user: "人", agent: "AI", system: "システム" };

function download(name: string, body: string, type: string) {
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([body], { type })); a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

export default function Audit() {
  const [items, setItems] = useState<any[]>([]); const [loading, setLoading] = useState(false);
  const [actor, setActor] = useState("all"); const [q, setQ] = useState(""); const [open, setOpen] = useState<number | null>(null);
  const load = () => { setLoading(true); api.get<{ items: any[] }>("/audit?limit=200").then((r) => setItems(r.items)).finally(() => setLoading(false)); };
  useEffect(() => { load(); }, []);
  const shown = useMemo(() => items.filter((x) => (actor === "all" || x.actor === actor) && (!q || [x.event, JSON.stringify(x.payload ?? ""), String(x.actor_id ?? ""), String(x.id)].some((v) => v.toLowerCase().includes(q.toLowerCase())))), [items, actor, q]);
  const stamp = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "");
  const toCsv = () => ["id,ts,actor,actor_id,event,payload", ...shown.map((x) => [x.id, x.ts, x.actor, x.actor_id ?? "", x.event, JSON.stringify(x.payload ?? null)].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))].join("\r\n");
  return (
    <div className="mx-auto max-w-[1600px] space-y-4">
      <header className="flex flex-wrap items-center gap-3">
        <div className="flex flex-[1_1_320px] flex-col gap-1">
          <h1 className="flex items-center gap-2 text-[26px] font-bold"><Ico d={I.history} size={22} />{t("nav.audit")}</h1>
          <div className="text-[13px] text-slate-400">追記専用。全プロンプト・ツール呼び出し・承認・実行結果を記録（直近 200 件）</div>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <button className="btn-secondary px-3 py-1.5 text-xs" onClick={() => download(`mamorai-audit-${stamp}.json`, JSON.stringify(shown, null, 2), "application/json")}>JSON で書き出し</button>
          <button className="btn-secondary px-3 py-1.5 text-xs" onClick={() => download(`mamorai-audit-${stamp}.csv`, "﻿" + toCsv(), "text/csv")}>CSV で書き出し</button>
          <button className="btn-secondary px-3 py-1.5 text-xs" onClick={load} disabled={loading}>{loading ? "読み込み中…" : "↻ 更新"}</button>
        </div>
      </header>
      <div className="flex flex-wrap items-center gap-2">
        <div role="group" aria-label="実行者で絞り込み" className="flex overflow-hidden rounded-lg border border-slate-600 text-xs">
          {["all", "user", "agent", "system"].map((a) => <button key={a} onClick={() => setActor(a)} className={`px-3 py-1.5 ${actor === a ? "bg-teal-500/20 text-teal-200" : "text-slate-400 hover:bg-slate-700"}`}>{a === "all" ? "すべて" : ACTOR_JA[a]}</button>)}
        </div>
        <input className="input w-72 min-h-[36px] rounded-lg" placeholder="検索（イベント名・内容・#番号）" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="text-xs text-slate-400">{shown.length} 件</span>
      </div>
      <div className="flex flex-wrap gap-3.5 text-xs text-slate-400">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-teal-300" />人 = 人の操作</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#3CCB8C]" />AI = AI の操作</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-slate-400" />システム = 自動処理</span>
      </div>
      <div className="overflow-x-auto rounded-[14px] border border-slate-700 bg-slate-800">
        <table className="w-full min-w-[860px]">
          <thead><tr className="border-b border-slate-700"><th className="th w-16">#</th><th className="th w-44">日時</th><th className="th w-32">実行者</th><th className="th w-64">イベント</th><th className="th">内容</th><th className="th w-9"></th></tr></thead>
          <tbody>{shown.map((x) => (
            <Fragment key={x.id}>
              <tr className={`cursor-pointer border-t border-slate-700 transition hover:bg-slate-700/60 ${open === x.id ? "bg-slate-700/60" : ""}`} onClick={() => setOpen(open === x.id ? null : x.id)}>
                <td className="td font-mono text-xs text-slate-400">{x.id}</td>
                <td className="td whitespace-nowrap font-mono text-xs text-slate-300">{fmtTs(x.ts)}</td>
                <td className="td text-xs"><span className={`rounded-full px-2.5 py-0.5 font-medium ${ACTOR_CLS[x.actor] ?? "bg-slate-600 text-slate-300"}`}>{ACTOR_JA[x.actor] ?? x.actor}</span>{x.actor_id ? <span className="ml-1.5 font-mono text-slate-400">#{x.actor_id}</span> : null}</td>
                <td className="td font-mono text-xs text-slate-100">{x.event}</td>
                <td className="td max-w-xl truncate font-mono text-xs text-slate-400">{JSON.stringify(x.payload)}</td>
                <td className="td"><Ico d={open === x.id ? "M6 15l6-6 6 6" : "M6 9l6 6 6-6"} size={14} className="text-slate-400" /></td>
              </tr>
              {open === x.id && <tr className="bg-slate-900/60"><td colSpan={6} className="px-4 pb-4 pt-1"><pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-slate-700 bg-[#070B15] p-3 font-mono text-xs text-slate-200">{JSON.stringify(x.payload, null, 2)}</pre></td></tr>}
            </Fragment>
          ))}</tbody>
        </table>
        {!shown.length && !loading && <div className="p-6 text-center text-sm text-slate-400">該当する記録はありません</div>}
      </div>
    </div>
  );
}
