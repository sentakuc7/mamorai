import { useContext, useEffect, useState } from "react";
import { onServerEvent } from "../lib/events";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { UserCtx } from "../main";
import ApprovalCard, { type Approval } from "../components/ApprovalCard";
import { Ico, I } from "../components/Icon";

export default function Approvals() {
  const { user } = useContext(UserCtx); const canAct = user?.role === "admin" || user?.role === "operator";
  const [tab, setTab] = useState<"pending" | "approved" | "rejected" | "edited">("pending");
  const [items, setItems] = useState<Approval[]>([]);
  const load = () => api.get<{ items: Approval[] }>(`/approvals?decision=${tab}`).then((r) => setItems(r.items));
  useEffect(() => { load(); }, [tab]);
  useEffect(() => { return onServerEvent(["approval", "status"], load); }, [tab]);
  const TABS = [["pending", "承認待ち"], ["approved", "承認済み"], ["edited", "編集して承認"], ["rejected", "却下"]] as const;
  return (
    <div className="mx-auto flex w-full max-w-[1180px] flex-col gap-[18px]">
      <div className="flex flex-wrap items-center gap-4">
        <h1 className="flex items-center gap-2.5 font-display text-2xl font-bold"><Ico d={I.approve} size={22} className="text-teal-300" />承認キュー</h1>
        <div role="tablist" aria-label="承認の状態" className="flex flex-wrap gap-1 rounded-xl border border-slate-700 bg-slate-800 p-1">
          {TABS.map(([k, ja]) => (
            <button key={k} role="tab" aria-selected={tab === k} className={`inline-flex min-h-[38px] items-center gap-2 rounded-[9px] px-3.5 text-[13px] font-semibold transition ${tab === k ? "bg-teal-500 text-white" : "text-slate-400 hover:bg-slate-700 hover:text-slate-200"}`} onClick={() => setTab(k)}>
              {ja}<span className="font-mono text-[11px] font-normal opacity-75">{k}</span>
              {k === "pending" && tab === "pending" && items.length > 0 && <span className="rounded-full bg-[#D93A40] px-1.5 text-[11px] leading-[18px] text-white">{items.length}</span>}
            </button>
          ))}
        </div>
      </div>
      <p className="text-[13px] text-slate-400">変更系のコマンドはすべてここを通ります。承認者・コマンド・結果は監査ログに残ります。</p>
      {items.length === 0 && <div className="rounded-xl border border-dashed border-slate-600 p-8 text-center text-sm text-slate-500">なし</div>}
      {items.map((a) => (
        <div key={a.id} className="flex flex-col gap-2">
          <div className="text-xs text-slate-500">セッション <Link className="text-teal-300 hover:underline" to={`/sidekick/${a.session_id}`}><span className="font-mono">#{a.session_id}</span> {a.session_title}</Link></div>
          <ApprovalCard a={a} canAct={canAct} onDone={load} />
        </div>
      ))}
    </div>
  );
}
