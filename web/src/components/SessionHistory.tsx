import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { SESSION_STATUS_JA } from "./SessionChat";
import SessionCard, { type Row } from "./SessionCard";
import { Ico, I } from "./Icon";

/** History drawer for one kind of AI session (playbook_setup / host_setup): search, archive view, open / archive / delete. */
export default function SessionHistory({ kind, title, currentId, canAct, onOpen, onClose }: { kind: string; title: string; currentId: number | null; canAct: boolean; onOpen: (id: number) => void; onClose: () => void }) {
  const [items, setItems] = useState<Row[]>([]); const [archivedCount, setArchivedCount] = useState(0);
  const [showArchive, setShowArchive] = useState(false); const [q, setQ] = useState(""); const [err, setErr] = useState("");
  const load = () => api.get<{ items: Row[]; archived_count: number }>(`/sessions?limit=200&kind=${kind}${showArchive ? "&archived=1" : ""}`).then((r) => { setItems(r.items); setArchivedCount(r.archived_count); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [kind, showArchive]);
  const filtered = useMemo(() => { const n = q.trim().toLowerCase(); return items.filter((x) => !n || [x.title, x.label ?? "", (x.tags ?? []).join(" "), SESSION_STATUS_JA[x.status] ?? "", `#${x.id}`].some((v) => v.toLowerCase().includes(n))); }, [items, q]);
  const archive = async (x: Row) => { await api.post(`/sessions/${x.id}/${x.archived_at ? "unarchive" : "archive"}`); load(); };
  const del = async (x: Row) => { if (!confirm(`「${x.label || x.title}」を完全に削除しますか？`)) return; try { await api.del(`/sessions/${x.id}`); load(); } catch (e: any) { alert(e.message); } };
  return (
    <div className="fixed inset-0 z-40 flex" onClick={onClose}>
      <div className="flex-1 bg-[#05080F]/70 backdrop-blur-[2px]" />
      <aside className="flex h-full w-[26rem] max-w-full flex-col gap-2.5 border-l border-slate-700 bg-[#0C1322] px-3.5 py-4 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2">
          <h2 className="flex items-center gap-2 font-display text-base font-bold"><Ico d={I.history} size={18} />{title}</h2>
          <button className={`relative ml-auto flex h-10 w-11 items-center justify-center rounded-[10px] border ${showArchive ? "border-teal-500 bg-[#1A2547]" : "border-slate-600 hover:border-slate-500"}`} title="アーカイブ" aria-label="アーカイブ" onClick={() => setShowArchive(!showArchive)}><Ico d={I.archive} size={16} className="text-slate-300" />{archivedCount > 0 && <span className="absolute -right-1.5 -top-1.5 rounded-full bg-teal-500 px-1.5 text-[10px] font-semibold text-white">{archivedCount}</span>}</button>
          <button className="h-10 rounded-[10px] border border-slate-600 px-3 text-xs text-slate-300 hover:border-slate-500 hover:text-white" onClick={onClose}>閉じる ✕</button>
        </div>
        <input className="input min-h-[40px]" placeholder={showArchive ? "アーカイブを検索" : "検索（ラベル・タグ・#番号）"} value={q} onChange={(e) => setQ(e.target.value)} autoFocus />
        <div className="text-[11px] text-slate-500">{showArchive ? "アーカイブ · " : ""}{filtered.length} 件 · この画面の「AIエージェントに相談」の履歴です（Sidekick には出ません）</div>
        <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto pr-1">
          {err && <div className="text-xs text-[#FF9A9D]">{err}</div>}
          {filtered.map((x) => <SessionCard key={x.id} x={x} active={x.id === currentId} canAct={canAct} onOpen={() => { onOpen(x.id); onClose(); }} onArchive={() => archive(x)} onDelete={() => del(x)} />)}
          {!filtered.length && <div className="rounded-[10px] border border-dashed border-slate-600 p-4 text-center text-xs text-slate-500">{showArchive ? "アーカイブは空です" : "履歴がありません"}</div>}
        </div>
      </aside>
    </div>
  );
}
