import { fmtTs } from "../lib/api";
import { KIND_LABEL } from "../lib/mode";
import { type SessionRow, SESSION_STATUS_JA } from "./SessionChat";
import { Ico, I } from "./Icon";
import { DISPLAY_COLOR, DISPLAY_JA, DISPLAY_TIP, PULSE, displayKey, type SessionDisplay } from "../lib/sessionDisplay";

export type Row = SessionRow & { label?: string | null; tags?: string[]; archived_at?: string | null; display?: SessionDisplay | null };
/** 互換のため残す（絵文字は画面には出さない）。 */
export const STATUS_ICON: Record<string, string> = { running: "⏳", waiting_approval: "✋", waiting_user: "💬", waiting_external: "🕒", done: "✅", failed: "⚠️", cancelled: "⛔" };
/** MamorAI: セッション状態の色（ドット・文字） */
export const STATUS_COLOR: Record<string, string> = { running: "#5AB0FF", waiting_approval: "#F5C542", waiting_user: "#3CCB8C", waiting_external: "#A78BFA", done: "#7F8BA6", failed: "#F2555A", cancelled: "#7F8BA6" };

export default function SessionCard({ x, active, canAct, onOpen, onArchive, onDelete }: { x: Row; active: boolean; canAct: boolean; onOpen: () => void; onArchive: () => void; onDelete: () => void }) {
  const kind = x.origin === "alert" ? "Sentinel" : x.kind && x.kind !== "investigate" ? KIND_LABEL[x.kind] : "Sidekick";
  const archived = !!x.archived_at;
  const dk = displayKey(x); const color = DISPLAY_COLOR[dk] ?? STATUS_COLOR[x.status] ?? "#7F8BA6"; // EDR-172
  return (
    <div className={`group relative rounded-[10px] border transition ${active ? "border-teal-500 bg-[#141F3F]" : "border-slate-700 bg-slate-900 hover:border-slate-600"}`}>
      <button className="flex w-full min-w-0 flex-col gap-1 px-3 py-2.5 text-left" onClick={onOpen}>
        <span className="flex w-full items-center gap-1.5 text-[11px] text-slate-400">
          <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap font-semibold" style={{ color }} title={DISPLAY_TIP[dk]}><span className={`h-[7px] w-[7px] rounded-full ${PULSE.has(dk) ? "animate-pulse" : ""}`} style={{ background: color }} />{DISPLAY_JA[dk] ?? SESSION_STATUS_JA[x.status] ?? x.status}{x.display?.note && <span className="font-normal text-slate-400">{x.display.note}</span>}</span>
          <span className="min-w-0 truncate font-mono">{kind} #{x.id}</span>
          <span className="ml-auto shrink-0">{fmtTs(x.created_at).replace(/^\d{4}\//, "")}</span>
        </span>
        <span className="line-clamp-2 text-sm font-semibold leading-snug text-slate-100">{x.label || x.title}</span>
        {x.label && x.label !== x.title && <span className="truncate text-xs text-slate-400">{x.title}</span>}
        {!!x.display?.extra?.length && <span className="flex flex-wrap gap-1">{x.display.extra.map((k) => <span key={k} title={DISPLAY_TIP[k]} className="rounded-full border px-1.5 text-[10px]" style={{ borderColor: `${DISPLAY_COLOR[k]}66`, color: DISPLAY_COLOR[k] }}>{DISPLAY_JA[k] ?? k}</span>)}</span>}
        {!!x.tags?.length && <span className="flex flex-wrap gap-1">{x.tags.map((t) => <span key={t} className="rounded bg-[#15204A] px-1.5 text-[11px] text-teal-300">#{t}</span>)}</span>}
      </button>
      {canAct && (
        <div className="absolute bottom-1.5 right-1.5 hidden gap-0.5 rounded-md bg-slate-900/90 group-hover:flex">
          <button className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:bg-slate-700 hover:text-slate-200" title={archived ? "アーカイブから戻す" : "アーカイブ"} aria-label={archived ? "アーカイブから戻す" : "アーカイブ"} onClick={(e) => { e.stopPropagation(); onArchive(); }}><Ico d={archived ? I.undo : I.archive} size={14} className="" /></button>
          <button className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:bg-rose-900/40 hover:text-rose-300" title="削除" aria-label="削除" onClick={(e) => { e.stopPropagation(); onDelete(); }}><Ico d={I.trash} size={14} className="" /></button>
        </div>
      )}
    </div>
  );
}
