import { Link } from "react-router-dom";
import { onServerEvent } from "../lib/events";
import Diagram, { parseDiagram } from "./Diagram";
import { useContext, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { UserCtx } from "../main";
import { useMode, TOOL_LABEL } from "../lib/mode";
import { LogoMark } from "./Logo";
import ApprovalCard, { type Approval } from "./ApprovalCard";
import ProposalPanel, { type NextAction } from "./ProposalPanel";
import DeckPreview, { type DeckSpec } from "./DeckPreview";
import { Ico, I } from "./Icon";

export interface SessionRow { id: number; title: string; status: string; origin: string; kind?: string; created_at: string; updated_at?: string; llm_model?: string; token_in: number; token_out: number; summary?: any }
export interface SessionFile { id: number; name: string; size: number; mime?: string; direction?: "in" | "out"; description?: string | null; created_at?: string }
export interface SessionDetail { session: SessionRow; messages: any[]; tool_calls: any[]; approvals: Approval[]; next_actions: NextAction[]; attachments?: SessionFile[]; schedules?: any[] }
export type PendingFile = { name: string; content: string; mime?: string; encoding?: "utf8" | "base64" };

export const SESSION_STATUS_CLS: Record<string, string> = { running: "bg-sky-500/20 text-sky-300", waiting_approval: "bg-amber-500/20 text-amber-300", waiting_user: "bg-emerald-500/15 text-emerald-300", waiting_external: "bg-violet-500/20 text-violet-200", done: "bg-slate-700 text-slate-300", failed: "bg-rose-500/20 text-rose-300", cancelled: "bg-slate-600/60 text-slate-500" };
export const SESSION_STATUS_JA: Record<string, string> = { running: "作業中", waiting_approval: "承認待ち", waiting_user: "返答待ち", waiting_external: "対応待ち", done: "完了", failed: "失敗", cancelled: "中止" };

function ToolCallCard({ tc }: { tc: any }) {
  const [open, setOpen] = useState(false);
  const a = tc.args ?? {};
  const head = tc.tool === "ssh_exec" ? `${a.host}$ ${a.command}` : tc.tool === "indexer_query" ? `${a.index} ${JSON.stringify(a.query).slice(0, 120)}` : tc.tool === "wazuh_api" ? `GET ${a.path}` : tc.tool === "process_tree" ? `agent ${a.agent_id} ${a.process_guid}` : tc.tool === "version_check" ? `${a.product} ${a.version}${a.agent ? " @" + a.agent : ""}` : tc.tool === "pkg_candidates" ? `${a.host} ${a.package}${a.fixed_version ? " → " + a.fixed_version : ""}` : tc.tool === "record_decision" ? a.text : tc.tool === "apply_change" ? a.title : tc.tool === "read_attachment" ? a.name : tc.tool === "save_playbook" ? a.name : tc.tool === "register_host" ? `${a.name} ${a.ssh_user}@${a.address}` : tc.tool === "update_host" || tc.tool === "test_host" ? a.host : tc.tool === "generate_ssh_key" ? a.name : tc.tool;
  const cls = tc.classification ? <span className={`rounded-full px-1.5 text-[10px] font-semibold ${tc.classification === "read" ? "bg-[#12301F] text-[#7FE0B0]" : "bg-[#3A2A10] text-[#FFC27A]"}`}>{tc.classification}</span> : null;
  return (
    <div className="w-full min-w-0 overflow-hidden rounded-lg bg-[#070B15] font-mono text-xs">
      <button className="flex w-full min-w-0 items-center gap-2 px-3 py-2 text-left hover:bg-[#0E1526]" onClick={() => setOpen(!open)}>
        <span className="text-slate-500">{open ? "▾" : "▸"}</span>
        <span className="shrink-0 text-teal-300">{tc.tool}</span>{cls}
        <span className="truncate text-slate-300">{head}</span>
        <span className={`ml-auto shrink-0 text-[10px] ${tc.status === "failed" ? "text-[#FF9A9D]" : tc.status === "pending_approval" ? "text-[#FFC27A]" : "text-slate-500"}`}>{tc.status}</span>
      </button>
      {open && <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all border-t border-[#24314D] p-3 font-mono text-[11px] text-slate-300">{a.intent ? `intent: ${a.intent}\n\n` : ""}{typeof tc.result === "string" ? tc.result : JSON.stringify(tc.result, null, 2)}</pre>}
    </div>
  );
}

/** Simple mode: a group of consecutive tool calls → one strip */
function StepStrip({ calls }: { calls: any[] }) {
  const [open, setOpen] = useState(false);
  const counts: Record<string, number> = {};
  for (const c of calls) counts[c.tool] = (counts[c.tool] ?? 0) + 1;
  const failed = calls.filter((c) => c.status === "failed").length;
  return (
    <div className="ml-[42px] w-full min-w-0 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2.5 text-xs text-slate-400">
      <button className="flex w-full flex-wrap items-center gap-2 text-left" onClick={() => setOpen(!open)}>
        <span className="text-slate-500">{open ? "▾" : "▸"}</span>
        <span className="inline-flex items-center gap-1.5 font-semibold text-slate-300"><Ico d={I.search} size={13} />やったこと:</span>
        {Object.entries(counts).map(([tool, n]) => <span key={tool} className="rounded-full border border-slate-700 bg-slate-800 px-2.5 py-0.5 text-slate-300">{TOOL_LABEL[tool] ?? tool} <span className="font-mono text-slate-500">×{n}</span></span>)}
        {failed > 0 && <span className="text-[#FF9A9D]">（失敗 {failed}）</span>}
      </button>
      {open && <div className="mt-2.5 space-y-1">{calls.map((tc) => <ToolCallCard key={tc.id} tc={tc} />)}</div>}
    </div>
  );
}

/** Animated "AI is thinking / running a tool" bubble, shown under the last message while the session is running. */
function Thinking({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3"><LogoMark size={30} /><div className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-[13px] text-slate-300">
      <span className="flex items-end gap-0.5" aria-hidden>
        {[0, 1, 2].map((i) => <span key={i} className="inline-block h-1.5 w-1.5 animate-bounce rounded-full bg-teal-300" style={{ animationDelay: `${i * 0.15}s` }} />)}
      </span>
      <span className="animate-pulse">{label}</span>
    </div></div>
  );
}

/** Download through fetch+blob: a plain <a download> fails in Chrome on self-signed HTTPS ("ネットワークエラー"). */
export async function downloadFile(url: string, name: string) {
  const r = await fetch(url, { credentials: "same-origin" });
  if (!r.ok) throw new Error(`download failed: ${r.status}`);
  const blob = await r.blob();
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
}

/** Output file produced by the agent (write_file / write_pptx): preview + download. */
export function FileCard({ sid, f, deck }: { sid: number; f: SessionFile; deck?: DeckSpec }) {
  const [open, setOpen] = useState(/\.(svg|pptx)$/i.test(f.name));
  const [text, setText] = useState<string | null>(null);
  const url = `/api/sessions/${sid}/files/${f.id}`;
  const ext = f.name.toLowerCase().split(".").pop() ?? "";
  const icon = ext === "csv" || ext === "tsv" || ext === "xlsx" ? I.list : ext === "svg" ? I.target : ext === "html" ? I.globe : ext === "md" ? I.edit : ext === "pptx" ? I.board : I.book;
  const [dlErr, setDlErr] = useState("");
  const canPreview = !["pptx", "xlsx", "docx"].includes(ext) || (ext === "pptx" && !!deck);
  useEffect(() => { if (open && text === null && ["csv", "tsv", "md", "txt", "json"].includes(ext)) fetch(url, { credentials: "same-origin" }).then((r) => r.text()).then((t) => setText(t.replace(/^\uFEFF/, ""))).catch(() => setText("")); }, [open]);
  const rows = text && (ext === "csv" || ext === "tsv") ? text.split(/\r?\n/).filter(Boolean).slice(0, 21).map((l) => l.split(ext === "tsv" ? "\t" : /,(?=(?:[^"]*"[^"]*")*[^"]*$)/).map((c) => c.replace(/^"|"$/g, "").replace(/""/g, "\""))) : null;
  return (
    <div className="w-full min-w-0 max-w-3xl overflow-hidden rounded-xl border border-[#24314D] bg-slate-900">
      <div className="flex flex-wrap items-center gap-2.5 px-3.5 py-3 text-xs">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[#15204A]"><Ico d={icon} size={17} className="text-teal-300" /></span>
        <span className="font-mono text-[13px] font-semibold text-slate-100">{f.name}</span>
        <span className="font-mono text-slate-500">{(f.size / 1024).toFixed(1)} KB</span>
        {f.description && <span className="text-slate-400">— {f.description}</span>}
        <span className="ml-auto flex items-center gap-2">
          {canPreview && <button className="rounded-lg border border-slate-600 px-2.5 py-1.5 text-slate-200 hover:border-teal-400" onClick={() => setOpen(!open)}>{open ? "プレビューを閉じる" : "プレビュー"}</button>}
          <button className="rounded-lg bg-teal-500 px-3 py-1.5 font-semibold text-white hover:bg-teal-400" onClick={() => downloadFile(`${url}?download`, f.name).catch((e) => setDlErr(e.message))}>ダウンロード</button>
        </span>
      </div>
      {dlErr && <div className="px-3.5 pb-2 text-xs text-[#FF9A9D]">{dlErr}</div>}
      {ext === "pptx" && <div className="px-3 pb-2 text-[11px] text-slate-500">PowerPoint ファイル（グラフ・表は PowerPoint 上で編集できます）</div>}
      {open && canPreview && (
        <div className="border-t border-[#24314D] p-2.5">
          {ext === "pptx" && deck && <DeckPreview deck={deck} />}
          {ext === "svg" && <div className="rounded bg-slate-800 p-2"><img src={url} alt={f.name} className="mx-auto max-h-[28rem] w-full object-contain" /></div>}
          {ext === "html" && <iframe title={f.name} src={url} sandbox="" className="h-96 w-full rounded bg-white" />}
          {rows && <div className="max-h-80 overflow-auto"><table className="w-full text-[11px]"><tbody>{rows.map((r, i) => <tr key={i} className={i === 0 ? "bg-slate-700/70 font-semibold text-slate-100" : "border-t border-slate-700 text-slate-300"}>{r.map((c, k) => <td key={k} className="px-2 py-1 align-top">{c}</td>)}</tr>)}</tbody></table>{text && text.split(/\r?\n/).filter(Boolean).length > 21 && <div className="px-2 py-1 text-[10px] text-slate-500">…先頭 20 行のみ表示</div>}</div>}
          {text !== null && ext === "md" && <div className="max-h-80 overflow-auto text-sm text-slate-200"><Rich text={text} /></div>}
          {text !== null && (ext === "txt" || ext === "json") && <pre className="max-h-80 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-slate-300">{text}</pre>}
          {text === null && !["svg", "html", "pptx"].includes(ext) && <div className="text-xs text-slate-500">読み込み中…</div>}
        </div>
      )}
    </div>
  );
}

/** Minimal markdown-ish rendering for assistant messages: headings, bullets, code fences, bold. */
function Rich({ text }: { text: string }) {
  const parts = text.split(/(```[\s\S]*?```)/g);
  return (
    <div className="space-y-1">
      {parts.map((p, i) => {
        if (/^```diagram\b/.test(p)) { const spec = parseDiagram(p.replace(/^```diagram[^\n]*\n?/, "").replace(/```$/, "")); if (spec) return <Diagram key={i} spec={spec} />; }
        if (p.startsWith("```")) return <pre key={i} className="max-w-full overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-slate-700 bg-[#070B15] p-3 font-mono text-[11px] text-slate-200">{p.replace(/^```[^\n]*\n?/, "").replace(/```$/, "")}</pre>;
        const lines = p.split("\n"); const out: JSX.Element[] = [];
        for (let k = 0; k < lines.length; k++) {
          const line = lines[k];
          if (/^\s*\|.*\|\s*$/.test(line) && k + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[k + 1])) {
            const tbl: string[][] = [line.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim())];
            k += 2;
            while (k < lines.length && /^\s*\|.*\|\s*$/.test(lines[k])) { tbl.push(lines[k].trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim())); k++; }
            k--;
            out.push(<div key={`${i}-t${k}`} className="my-1 overflow-x-auto"><table className="text-xs"><tbody>{tbl.map((r, ri) => <tr key={ri} className={ri === 0 ? "bg-slate-900/50 font-semibold text-slate-50" : "border-t border-slate-700"}>{r.map((c, ci) => <td key={ci} className="px-2 py-1 align-top">{c}</td>)}</tr>)}</tbody></table></div>);
            continue;
          }
          out.push(renderLine(line, `${i}-${k}`));
        }
        return out;
      })}
    </div>
  );
  function renderLine(line: string, key: string): JSX.Element {
          const h = line.match(/^(#{1,4})\s+(.*)/);
          const bold = (s: string) => s.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((x, m) => x.startsWith("**") ? <b key={m} className="text-slate-50">{x.slice(2, -2)}</b> : x.startsWith("`") ? <code key={m} className="break-all rounded bg-slate-950 px-1 font-mono text-[11px] text-teal-200">{x.slice(1, -1)}</code> : x);
          if (h) return <div key={key} className={`font-semibold text-slate-50 ${h[1].length <= 2 ? "mt-2 text-sm" : "mt-1 text-xs"}`}>{bold(h[2])}</div>;
          const li = line.match(/^(\s*)([-*•]|\d+[.)])\s+(.*)/);
          if (li) return <div key={key} className="flex gap-1.5" style={{ paddingLeft: Math.min(li[1].length, 8) * 6 }}><span className="shrink-0 text-slate-500">{/^\d/.test(li[2]) ? li[2] : "•"}</span><span>{bold(li[3])}</span></div>;
          if (/^\s*[-=]{3,}\s*$/.test(line)) return <hr key={key} className="border-slate-600" />;
          if (!line.trim()) return <div key={key} className="h-1" />;
          return <div key={key}>{bold(line)}</div>;
  }
}

export default function SessionChat({ sid, create, placeholder, initialInput, onSessionLoaded, onEvent, showProposal = true, emptyHint, className = "" }: {
  sid: number | null;
  initialInput?: string;
  /** Called when there is no session yet; must create one and return its id. */
  create?: (text: string, attachments: PendingFile[]) => Promise<number>;
  placeholder?: string;
  onSessionLoaded?: (d: SessionDetail) => void;
  /** Fired on every SSE event (parent can refresh its own lists, e.g. after save_playbook). */
  onEvent?: (type: string, data: any) => void;
  showProposal?: boolean;
  emptyHint?: React.ReactNode;
  className?: string;
}) {
  const { user } = useContext(UserCtx); const canAct = user?.role === "admin" || user?.role === "operator";
  const { mode } = useMode();
  const [detail, setDetail] = useState<SessionDetail | null>(null);
  const [input, setInput] = useState(initialInput ?? ""); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const [pending, setPending] = useState<PendingFile[]>([]);
  const bottom = useRef<HTMLDivElement>(null); const fileRef = useRef<HTMLInputElement>(null);
  const loadDetail = (s: number) => api.get<SessionDetail>(`/sessions/${s}`).then((d) => { setDetail(d); onSessionLoaded?.(d); }).catch((e) => setErr(e.message));
  useEffect(() => { setDetail(null); setErr(""); if (sid) loadDetail(sid); }, [sid]);
  useEffect(() => {
    if (!sid) return;
    return onServerEvent(["message", "tool_call", "tool_result", "approval", "next_actions", "status", "error", "schedule"], (data, ev) => { loadDetail(sid); onEvent?.(ev, data); }, sid);
  }, [sid]);
  useEffect(() => { bottom.current?.scrollIntoView({ behavior: "smooth" }); }, [detail?.messages.length, detail?.approvals.length, detail?.tool_calls.length, detail?.session.status]);

  const IMG = /^image\/(png|jpeg|gif|webp)$/;
  const readFiles = async (list: FileList | File[] | null) => {
    if (!list) return;
    const out: PendingFile[] = [];
    for (const f of Array.from(list)) {
      if (IMG.test(f.type)) {
        // 画像（スクリーンショット等）: base64 で添付し、AI にはそのまま画像として渡る
        if (f.size > 4_000_000) { setErr(`${f.name}: 画像は 4MB までです`); continue; }
        const b64 = await new Promise<string>((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(",")[1] ?? ""); r.onerror = () => rej(r.error); r.readAsDataURL(f); });
        const name = f.name && f.name !== "image.png" ? f.name : `clipboard-${new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14)}.${f.type.split("/")[1] === "jpeg" ? "jpg" : f.type.split("/")[1]}`;
        out.push({ name, content: b64, mime: f.type, encoding: "base64" });
        continue;
      }
      if (f.size > 2_000_000) { setErr(`${f.name}: 2MB を超えています`); continue; }
      const text = await f.text();
      if (text.includes("\u0000")) { setErr(`${f.name}: テキストファイルか画像（png/jpg/gif/webp）のみ添付できます`); continue; }
      out.push({ name: f.name, content: text, mime: f.type || undefined });
    }
    setPending((p) => [...p.filter((x) => !out.some((o) => o.name === x.name)), ...out]);
    if (fileRef.current) fileRef.current.value = "";
  };
  // クリップボードから画像 / ファイルを貼り付け（Ctrl+V）、ドラッグ＆ドロップも受ける
  const onPaste = (e: React.ClipboardEvent) => {
    const files = Array.from(e.clipboardData?.files ?? []);
    if (!files.length || !canAct) return;
    e.preventDefault(); readFiles(files);
  };
  const onDrop = (e: React.DragEvent) => { const files = Array.from(e.dataTransfer?.files ?? []); if (!files.length || !canAct) return; e.preventDefault(); readFiles(files); };
  const send = async () => {
    const text = input;
    if (!text.trim() && !pending.length) return; setBusy(true); setErr("");
    try {
      if (sid) { if (pending.length) await api.post(`/sessions/${sid}/attachments`, { attachments: pending, message: text }); else await api.post(`/sessions/${sid}/message`, { message: text }); }
      else if (create) await create(text, pending);
      setInput(""); setPending([]);
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const runAction = async (a: NextAction) => {
    if (!sid) return;
    await api.post(`/next-actions/${a.id}/status`, { status: "approved" });
    await api.post(`/sessions/${sid}/message`, { message: `提案「${a.title}」を実行して。必要な手順（設定変更・検証・再起動など）は 1 つの計画にまとめて、承認は 1 回で済むようにして（SSH のホストは apply_change、Windows のエージェントだけの端末は host_action。アプリの更新は win_updates で確認してから update_install の apps）。next_action_id: ${a.id}` });
  };
  const setStatus = async (a: NextAction, status: string) => { await api.post(`/next-actions/${a.id}/status`, { status }); if (sid) loadDetail(sid); };

  const s = detail?.session;
  const timeline: { key: string; node: JSX.Element }[] = [];
  if (detail) {
    let strip: any[] = [];
    const flush = () => { if (strip.length) { timeline.push({ key: `strip${strip[0].id}`, node: <StepStrip calls={strip} /> }); strip = []; } };
    // EDR-88: attempts of one approved change that failed and were fixed automatically (retry-of #N) are folded into
    // the final card; the AI's narration and investigation in between go into the same fold.
    const baseOf = new Map<number, number>();
    for (const ap of detail.approvals as any[]) { const mm = String(ap.decision_note ?? "").match(/^retry-of #(\d+) /); if (mm) baseOf.set(ap.id, Number(mm[1])); }
    const bases = new Set(baseOf.values());
    const chainBase = (id: number): number | null => baseOf.get(id) ?? (bases.has(id) ? id : null);
    const lastOf = new Map<number, number>();
    for (const ap of detail.approvals as any[]) { const b = chainBase(ap.id); if (b != null) lastOf.set(b, Math.max(lastOf.get(b) ?? 0, ap.id)); }
    let hideFor: number | null = null; let hidden: JSX.Element[] = []; let attempts = 0;
    const fold = (finalCard: JSX.Element | null, key: string) => {
      const n = attempts;
      const body = <details className="rounded-lg border border-[#24314D] bg-[#0B1224] px-3 py-1.5 text-[12px] text-slate-400"><summary className="cursor-pointer select-none">↻ 途中で {n} 回失敗 → AI が自動で元に戻して修正・再実行しました（承認済みの範囲内）　経過を見る</summary><div className="mt-2 space-y-2">{hidden}</div></details>;
      timeline.push({ key, node: <div className="ml-[42px] w-full min-w-0 space-y-1.5">{body}{finalCard}</div> });
      hideFor = null; hidden = []; attempts = 0;
    };
    const card = (ap: any) => <div id={`approval-${ap.id}`} className="w-full min-w-0"><ApprovalCard a={ap} canAct={canAct} onDone={() => loadDetail(sid!)} /></div>;
    for (const m of detail.messages) {
      if (m.role === "user") {
        flush();
        if (hideFor != null) fold(null, `fold-u${m.id}`);
        const raw = String(m.content ?? "").replace(/\[system\][^\n]*/g, "").trim();
        if (!raw) continue;
        // alert JSON appended by the "調査" button → show as a compact, collapsible chip instead of a wall of text
        const ctxIdx = raw.indexOf("\n\nAlert context (JSON):");
        const txt = (ctxIdx >= 0 ? raw.slice(0, ctxIdx) : raw).replace(/\s*next_action_id:\s*\d+/, "");
        const ctx = ctxIdx >= 0 ? raw.slice(ctxIdx + "\n\nAlert context (JSON):".length).trim() : null;
        if (/^⏰ スケジュール実行/.test(txt)) {
          // スケジューラが投入した自動実行: 人間の発言と区別し、指示部分は畳む
          const [head, ...rest] = txt.split("\n"); const body = rest.join("\n").replace(/\n\n\[指示\][\s\S]*$/, "").trim();
          timeline.push({ key: `m${m.id}`, node: <div className="w-full rounded-xl border border-violet-500/40 bg-violet-500/10 px-3.5 py-2.5 text-sm text-violet-100"><div className="flex items-center gap-1.5 font-semibold"><Ico d={I.clock} size={14} className="text-violet-300" />{head.replace(/^⏰\s*/, "")}</div>{body && <div className="mt-1 whitespace-pre-wrap text-xs text-violet-200/80">{body}</div>}<Link to="/schedules" className="mt-1 inline-block text-[11px] text-violet-300 hover:underline">スケジュール一覧 →</Link></div> });
          continue;
        }
        const imgs: { mime: string; attachment_id?: number }[] = Array.isArray((m as any).images) ? (m as any).images : [];
        timeline.push({ key: `m${m.id}`, node: <div className="ml-auto min-w-0 max-w-[78%] whitespace-pre-wrap break-words rounded-[16px_16px_4px_16px] bg-[#1A2547] px-4 py-3 text-[15px] leading-[1.7] text-slate-100 [overflow-wrap:anywhere]">{txt}{imgs.length > 0 && <div className="mt-1 flex flex-wrap gap-1">{imgs.map((im, i) => im.attachment_id ? <a key={i} href={`/api/sessions/${sid}/files/${im.attachment_id}`} target="_blank" rel="noreferrer"><img src={`/api/sessions/${sid}/files/${im.attachment_id}`} alt="" className="max-h-40 rounded-lg border border-[#24314D]" /></a> : null)}</div>}{ctx && <details className="mt-1.5 text-[11px] text-teal-200"><summary className="cursor-pointer">アラートの元データ（添付）</summary><pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-[#070B15] p-2 font-mono text-[10px] text-slate-300">{ctx}</pre></details>}</div> });
      } else if (m.role === "assistant") {
        if (m.content && hideFor != null) { hidden.push(<div key={`hm${m.id}`} className="text-[12px] leading-relaxed text-slate-400"><Rich text={m.content} /></div>); }
        else if (m.content) { flush(); timeline.push({ key: `m${m.id}`, node: <div className="flex min-w-0 max-w-[92%] gap-3"><span className="shrink-0 pt-0.5"><LogoMark size={30} /></span><div className="min-w-0 break-words text-[15px] leading-[1.8] text-slate-100 [overflow-wrap:anywhere]"><Rich text={m.content} /></div></div> }); }
        // a message can carry text AND tool calls (e.g. "修正します" + apply_change): render both, so approval cards never go missing
        for (const tc of m.tool_calls ?? []) {
          const row = detail.tool_calls.find((x: any) => x.args?._call_id === tc.id); if (!row) continue;
          const ap = detail.approvals.find((x: any) => x.tool_call_id === row.id);
          if (ap) {
            flush();
            const b = chainBase(ap.id);
            if (b != null && ap.id !== lastOf.get(b)) { if (hideFor == null) { hideFor = b; } hidden.push(<div key={`ha${ap.id}`}>{card(ap)}</div>); attempts++; continue; }
            if (b != null && hideFor === b) { fold(card(ap), `a${ap.id}`); continue; }
            timeline.push({ key: `a${ap.id}`, node: <div className="ml-[42px] w-full min-w-0">{card(ap)}</div> }); continue;
          }
          if (hideFor != null) { hidden.push(<div key={`ht${row.id}`}><ToolCallCard tc={row} /></div>); continue; }
          if (row.tool === "write_file" || row.tool === "write_pptx") { flush(); const f = detail.attachments?.find((x) => x.direction === "out" && x.name === row.args?.name); if (f) timeline.push({ key: `f${row.id}`, node: <div className="ml-[42px] w-full min-w-0"><FileCard sid={sid!} f={f} deck={row.tool === "write_pptx" ? row.args?.deck : undefined} /></div> }); continue; }
          if (row.tool === "propose_next_actions") { flush(); timeline.push({ key: `p${row.id}`, node: <div className="w-full text-center text-[11px] text-teal-300/80">調査結果と提案を更新しました（上のパネル）</div> }); continue; }
          if (mode === "simple") strip.push(row); else timeline.push({ key: `t${row.id}`, node: <div className="ml-[42px] w-full min-w-0"><ToolCallCard tc={row} /></div> });
        }
      }
    }
    flush();
    if (hideFor != null) fold(null, "fold-end");
  }

  return (
    <div className={`flex min-h-0 min-w-0 flex-col ${className}`}>
      {detail?.attachments?.length ? <div className="mb-2 flex flex-wrap gap-1.5 text-[11px] text-slate-400">{detail.attachments.map((a) => <button key={a.id} onClick={() => downloadFile(`/api/sessions/${sid}/files/${a.id}?download`, a.name).catch(() => {})} title="ダウンロード" className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 hover:border-teal-400 ${a.direction === "out" ? "border-[#2A3C7A] bg-[#15204A] text-teal-200" : "border-slate-700 bg-slate-800"}`}><Ico d={a.direction === "out" ? I.book : I.clip} size={12} className="" />{a.name} <span className="font-mono text-slate-500">{(a.size / 1024).toFixed(1)}KB</span></button>)}</div> : null}
      {showProposal && s?.summary?.proposal && <ProposalPanel proposal={s.summary.proposal} actions={detail!.next_actions} schedules={detail!.schedules ?? []} canAct={canAct} busy={busy} onRun={runAction} onSkip={(a) => setStatus(a, "rejected")} onReopen={(a) => setStatus(a, "proposed")} />}
      <div className="min-h-0 min-w-0 flex-1 space-y-3.5 overflow-y-auto overflow-x-hidden pr-1 pt-1">
        {!sid && emptyHint}
        {err && <div className="text-sm text-[#FF9A9D]">{err}</div>}
        {timeline.map((x) => <div key={x.key} className="flex min-w-0">{x.node}</div>)}
        {(() => {
          const cur = detail?.tool_calls.filter((t: any) => t.result == null && t.status === "executed").slice(-1)[0];
          const executing = detail?.approvals.find((a: any) => ["approved", "edited"].includes(a.decision) && (!a.exec_result || a.exec_result.status === "running"));
          if (executing) { const x = executing.exec_result; return <div className="flex"><Thinking label={`承認された変更を実行中…${x?.steps_total ? `ステップ ${x.current_step}/${x.steps_total}（${x.current_purpose ?? ""}）` : `（${executing.title || "サーバーで作業中"}）`}`} /></div>; }
          if (s?.status === "running" || busy) return <div className="flex"><Thinking label={cur ? `${TOOL_LABEL[cur.tool] ?? cur.tool}中…` : "考え中…"} /></div>;
          const pend = detail?.approvals.find((a: any) => a.decision === "pending");
          if (s?.status === "waiting_approval" && pend) return <div className="flex"><div className="flex w-full flex-wrap items-center gap-2.5 rounded-xl border border-[#5A4316] bg-[#2A1F0C] px-4 py-2.5 text-[13px] text-[#FFD48A]"><span className="h-2 w-2 animate-pulse rounded-full bg-[#F5C542]" /> AI はあなたの承認を待っています（承認カード #{pend.id}）<button className="ml-auto rounded-lg border border-[#5A4316] px-3 py-1 text-xs font-semibold text-[#FFD48A] hover:bg-[#3A2A10]" onClick={() => document.getElementById(`approval-${pend.id}`)?.scrollIntoView({ behavior: "smooth", block: "center" })}>カードへ移動</button></div></div>;
          return null;
        })()}
        {s?.status === "waiting_external" && <WaitBanner sid={sid!} />}
        {s?.status === "failed" && <div className="rounded-xl border border-[#4A1E24] bg-[#3A1418] px-4 py-2.5 text-[13px] text-[#FF9A9D]">失敗: {s.summary?.error ?? "(理由不明)"} — 返信すると同じセッションで再開できます</div>}
        <div ref={bottom} />
      </div>
      {pending.length > 0 && <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">{pending.map((f) => <span key={f.name} className="flex items-center gap-1.5 rounded-lg border border-[#2A3C7A] bg-[#15204A] px-2 py-1 text-teal-200">{f.encoding === "base64" ? <img src={`data:${f.mime};base64,${f.content}`} alt={f.name} className="h-10 max-w-[80px] rounded object-cover" /> : <Ico d={I.clip} size={12} className="" />} {f.name} <button className="text-slate-400 hover:text-[#FF9A9D]" aria-label="添付を外す" onClick={() => setPending((p) => p.filter((x) => x.name !== f.name))}>✕</button></span>)}</div>}
      <div className="mt-3 flex items-end gap-2 rounded-[14px] border border-[#24314D] bg-slate-800 p-2.5 focus-within:border-teal-500">
        <input ref={fileRef} type="file" multiple className="hidden" accept=".txt,.md,.conf,.cfg,.ini,.yaml,.yml,.json,.xml,.log,.csv,.sh,.rules,text/*,image/png,image/jpeg,image/gif,image/webp" onChange={(e) => readFiles(e.target.files)} />
        <button className="flex h-11 w-11 shrink-0 items-center justify-center rounded-[10px] text-slate-300 hover:bg-slate-700 disabled:opacity-40" title="テキストファイル / 画像を添付（Ctrl+V で貼り付け、ドロップも可）" disabled={!canAct || busy} onClick={() => fileRef.current?.click()} aria-label="ファイルを添付"><Ico d={I.clip} size={18} className="text-slate-300" /></button>
        <textarea className="h-16 min-w-0 flex-1 resize-none bg-transparent px-1 py-2 text-[15px] leading-relaxed text-slate-100 placeholder:text-slate-500 focus:outline-none" placeholder={placeholder ?? (sid ? "返信（割り込み可。画像は Ctrl+V で貼り付け）" : "依頼を書いて送信")} value={input} onChange={(e) => setInput(e.target.value)} onPaste={onPaste} onDrop={onDrop} onDragOver={(e) => e.preventDefault()} onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) send(); }} disabled={!canAct} />
        <button className="h-11 shrink-0 whitespace-nowrap rounded-[10px] bg-teal-500 px-5 text-sm font-semibold text-white hover:bg-teal-400 disabled:opacity-40" disabled={busy || !canAct} onClick={send}>送信</button>
      </div>
    </div>
  );
}

/** 対応待ちの理由（このチケットのスケジュール / 依存待ちタスク）を表示 */
function WaitBanner({ sid }: { sid: number }) {
  const [sc, setSc] = useState<any[]>([]); const [blk, setBlk] = useState<any[]>([]);
  useEffect(() => {
    api.get<{ items: any[] }>(`/schedules?session_id=${sid}`).then((r) => setSc(r.items.filter((x) => x.state === "active" && x.enabled))).catch(() => {});
    api.get<{ items: any[] }>("/next-actions?limit=200").then((r) => setBlk(r.items.filter((x) => x.session_id === sid && x.status === "blocked"))).catch(() => {});
  }, [sid]);
  return (
    <div className="rounded-xl border border-violet-500/40 bg-violet-500/10 px-4 py-3 text-xs text-violet-100">
      <div className="flex items-center gap-1.5 font-semibold"><Ico d={I.clock} size={14} className="" />対応待ち — あなたの返事ではなく、外部の状況が変わるのを待っています</div>
      {sc.map((x) => <div key={x.id} className="mt-0.5"><Link to="/schedules" className="underline">スケジュール #{x.id}</Link>「{x.title}」 次回 {x.next_run_at ? new Date(x.next_run_at).toLocaleString("ja-JP") : "-"}{x.last_result ? <span className="text-violet-300/80"> · 前回: {String(x.last_result).slice(0, 80)}</span> : null}</div>)}
      {blk.map((x) => <div key={x.id} className="mt-0.5">タスク「{x.title}」は #{x.after_id} の完了待ち</div>)}
      {!sc.length && !blk.length && <div className="mt-0.5 text-violet-300/80">AI が「外部要因待ち」としてマークしています。状況が変わったら返信してください。</div>}
      <div className="mt-1 text-violet-300/70">何か指示したいときはそのまま返信できます（返信すると AI が再開します）。</div>
    </div>
  );
}
