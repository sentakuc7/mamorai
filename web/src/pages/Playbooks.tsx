import { useContext, useEffect, useMemo, useState } from "react";
import AgentIntro, { AgentTitle } from "../components/AgentIntro";
import { useSearchParams } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import { useMode } from "../lib/mode";
import SessionChat, { type SessionRow, type PendingFile, SESSION_STATUS_CLS, SESSION_STATUS_JA } from "../components/SessionChat";
import SessionHistory from "../components/SessionHistory";
import { Field, ListEditor, Chip, Section, ENV_JA, ENV_TONE } from "../components/fields";
import { Ico, I } from "../components/Icon";

interface Fix { title: string; when: string; commands: string[]; rollback: string[]; approval: "always" | "auto_low_risk" | "never"; note: string }
interface Meta { purpose: string; targets: string[]; environment: string | null; record_to: string; tags: string[]; facts: string[]; prohibitions: string[]; procedures: { title: string; steps: string[] }[]; fixes: Fix[]; precedents: { date: string; summary: string; ref: string }[]; extra: { title: string; items: string[] }[] }
interface Playbook { id: number; name: string; scope: string; enabled: boolean; builtin: boolean; version: number; markdown: string; meta: Meta; structured: boolean; updated_at: string }

const APPROVAL_JA: Record<string, string> = { always: "常に承認", auto_low_risk: "低リスク自動可", never: "提案のみ" };
const APPROVAL_TONE: Record<string, "amber" | "emerald" | "slate"> = { always: "amber", auto_low_risk: "emerald", never: "slate" };
const emptyMeta = (): Meta => ({ purpose: "", targets: [], environment: null, record_to: "", tags: [], facts: [], prohibitions: [], procedures: [], fixes: [], precedents: [], extra: [] });

// ---------------- card ----------------
function PlaybookCard({ p, active, onClick, hosts }: { p: Playbook; active: boolean; onClick: () => void; hosts: string[] }) {
  const m = p.meta;
  const unknownTargets = m.targets.filter((t) => !hosts.includes(t));
  return (
    <button onClick={onClick} className={`w-full rounded-xl border p-3.5 text-left transition ${active ? "border-teal-500 bg-[#1A2547]" : "border-slate-700 bg-slate-800 hover:border-slate-500/60"} ${p.enabled ? "" : "opacity-70"}`}>
      <div className="flex items-start gap-2">
        <div className="flex min-w-0 flex-1 flex-col gap-[7px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="truncate text-[15px] font-semibold text-slate-100">{p.name}</span>
            {!p.enabled && <Chip tone="rose">無効</Chip>}
            {p.builtin && <Chip>同梱</Chip>}
            {!p.structured && <Chip tone="amber">未整理</Chip>}
            {m.environment && <Chip tone={ENV_TONE[m.environment]}>{ENV_JA[m.environment]}</Chip>}
          </div>
          <div className="line-clamp-2 text-[13px] leading-relaxed text-slate-300">{m.purpose || "（目的が未記入）"}</div>
          <div className="flex flex-wrap gap-1.5 font-mono">
            {m.targets.slice(0, 4).map((t) => <Chip key={t} tone={unknownTargets.includes(t) ? "slate" : "teal"}>{t}</Chip>)}
            {m.targets.length > 4 && <Chip>+{m.targets.length - 4}</Chip>}
          </div>
          <div className="flex gap-2.5 text-xs text-slate-400">
            <span>禁止 {m.prohibitions.length}</span><span>手順 {m.procedures.length}</span><span>対処 {m.fixes.length}</span><span>前例 {m.precedents.length}</span><span className="ml-auto font-mono">v{p.version}</span>
          </div>
        </div>
      </div>
    </button>
  );
}

// ---------------- detail (structured view) ----------------
function PlaybookDetail({ p, onEdit, onReload, hosts }: { p: Playbook; onEdit: () => void; onReload: () => void; hosts: string[] }) {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const { mode } = useMode();
  const [showMd, setShowMd] = useState(false); const [err, setErr] = useState("");
  const m = p.meta;
  const act = async (fn: () => Promise<unknown>) => { setErr(""); try { await fn(); onReload(); } catch (e: any) { setErr(e.message); } };
  return (
    <div className="flex flex-col gap-3.5">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex min-w-0 flex-[1_1_320px] flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2"><h2 className="text-[22px] font-bold">{p.name}</h2>{p.builtin && <Chip>同梱</Chip>}{m.environment && <Chip tone={ENV_TONE[m.environment]}>{ENV_JA[m.environment]}</Chip>}<span className="font-mono text-xs text-slate-400">v{p.version} · 更新 {fmtTs(p.updated_at)}</span></div>
          <div className="flex flex-wrap gap-1.5">{m.targets.map((t) => <Chip key={t} tone={hosts.includes(t) ? "teal" : "slate"}>{t}{!hosts.includes(t) && " (未登録)"}</Chip>)}{m.tags.map((t) => <Chip key={"tag" + t}>#{t}</Chip>)}</div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {admin && <button className={`btn-secondary min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-3.5 ${p.enabled ? "" : "text-[#7FE0B0]"}`} onClick={() => act(() => api.put(`/playbooks/${p.id}`, { enabled: !p.enabled }))}>{p.enabled ? "無効にする" : "有効にする"}</button>}
          {admin && <button className="btn-secondary min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-3.5" onClick={onEdit}><Ico d={I.edit} size={16} className="" />編集</button>}
          {admin && !p.structured && <button className="btn-secondary min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-3.5" title="見出しごとに項目へ自動分割します（AI での整理は下の相談から）" onClick={() => act(() => api.post(`/playbooks/${p.id}/structure`))}>項目に分割</button>}
          <button className={`btn min-h-[40px] rounded-[10px] border border-teal-500 px-3.5 ${showMd ? "bg-teal-500 text-white" : "text-teal-200 hover:bg-teal-500/15"}`} onClick={() => setShowMd(!showMd)}>{showMd ? "項目表示" : "Markdown"}</button>
          {admin && !p.builtin && <button className="btn min-h-[40px] rounded-[10px] border border-[#4A1E24] px-3.5 text-[#FF9A9D] hover:bg-[#3A1418]" onClick={() => { if (confirm(`削除: ${p.name}?`)) act(() => api.del(`/playbooks/${p.id}`)); }}>削除</button>}
        </div>
      </div>
      {err && <div className="text-sm text-rose-400">{err}</div>}
      {!p.enabled && <div className="rounded-xl border border-[#4A1E24] bg-[#1A1014] px-3.5 py-2.5 text-[13px] text-[#FF9A9D]">このプレイブックは無効です。AI の調査には使われません。</div>}
      {showMd ? (
        <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap rounded-[14px] border border-slate-700 bg-[#070B15] p-[18px] font-mono text-[13px] leading-[1.8] text-slate-200">{p.markdown}</pre>
      ) : (
        <div className="grid gap-3.5 [overflow-wrap:anywhere] [grid-template-columns:repeat(auto-fit,minmax(320px,1fr))] [&>*]:min-w-0">
          <Section title="目的・対象" icon="🎯"><div className="whitespace-pre-wrap text-sm leading-[1.8] text-slate-100">{m.purpose || <span className="text-slate-500">未記入</span>}</div>{m.record_to && <div className="text-[13px] text-slate-400">記録先: <span className="font-mono text-slate-300">{m.record_to}</span></div>}</Section>
          <Section title="禁止事項" icon="🚫" count={m.prohibitions.length} tone="border-[#4A1E24] bg-[#1A1014]">
            {m.prohibitions.length ? <ul className="flex flex-col gap-1.5 text-sm leading-relaxed">{m.prohibitions.map((x, i) => <li key={i} className="flex gap-2.5 text-slate-100"><span className="font-bold text-[#F2555A]">✕</span><span>{x}</span></li>)}</ul> : <div className="text-xs text-slate-500">なし</div>}
          </Section>
          <Section title="環境の事実" icon="📌" count={m.facts.length}>
            {m.facts.length ? <ul className="flex flex-col gap-1.5 text-[13px] leading-relaxed">{m.facts.map((x, i) => <li key={i} className="flex gap-2.5"><span className="text-teal-300">•</span><span className="min-w-0 break-all font-mono text-slate-200">{x}</span></li>)}</ul> : <div className="text-xs text-slate-500">なし</div>}
          </Section>
          <Section title="調査手順" icon="🔍" count={m.procedures.length}>
            {m.procedures.length ? <div className="flex flex-col gap-3">{m.procedures.map((pr, i) => (
              <div key={i} className="flex flex-col gap-2"><div className="text-sm font-semibold text-slate-100">{pr.title}</div>
                <ol className="flex flex-col gap-1.5">{pr.steps.map((s, k) => <li key={k} className="flex gap-2.5 text-[13px] leading-relaxed text-slate-200"><span className="flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-full bg-[#1A2547] text-xs text-[#B9C6FF]">{k + 1}</span><span className="break-words">{s}</span></li>)}</ol></div>
            ))}</div> : <div className="text-xs text-slate-500">なし</div>}
          </Section>
          <div className="[grid-column:1/-1]"><Section title="定型の対処" icon="🛠" count={m.fixes.length}>
            {m.fixes.length ? <div className="flex flex-col gap-2.5">{m.fixes.map((f, i) => (
              <div key={i} className="flex flex-col gap-2 rounded-xl border border-slate-600 bg-slate-900 p-3.5">
                <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-slate-100">{f.title}</span><Chip tone={APPROVAL_TONE[f.approval]}>{APPROVAL_JA[f.approval]}</Chip></div>
                {f.when && <div className="text-[13px] text-slate-400">条件: {f.when}</div>}
                {(mode === "detail" || !f.note) && f.commands.length > 0 && <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-slate-700 bg-[#070B15] px-3 py-2.5 font-mono text-xs leading-[1.7] text-slate-200">{f.commands.join("\n")}</pre>}
                {mode === "detail" && f.rollback.length > 0 && <div className="text-xs text-slate-400">戻し方: <code className="font-mono text-slate-300">{f.rollback.join(" ; ")}</code></div>}
                {f.note && <div className="text-[13px] text-slate-300">{f.note}</div>}
              </div>
            ))}</div> : <div className="text-xs text-slate-500">なし</div>}
          </Section></div>
          <div className="[grid-column:1/-1]"><Section title="過去の前例" icon="🕘" count={m.precedents.length}>
            {m.precedents.length ? <ol className="flex flex-col gap-2">{m.precedents.map((x, i) => <li key={i} className="flex flex-wrap items-baseline gap-2.5 text-[13px] leading-relaxed"><span className="h-2 w-2 shrink-0 rounded-full bg-teal-500" /><span className="font-mono text-slate-400">{x.date || "日付不明"}</span><span className="min-w-0 flex-[1_1_260px] text-slate-100">{x.summary}</span>{x.ref && <span className="font-mono text-teal-300">{x.ref}</span>}</li>)}</ol> : <div className="text-xs text-slate-500">なし</div>}
          </Section></div>
          {m.extra.map((e, i) => <Section key={i} title={e.title || "補足"} icon="📎" count={e.items.length}><ul className="flex flex-col gap-1.5 text-[13px] text-slate-200">{e.items.map((x, k) => <li key={k} className="flex gap-2.5"><span className="text-teal-300">•</span><span className="break-words">{x}</span></li>)}</ul></Section>)}
        </div>
      )}
    </div>
  );
}

// ---------------- editor (structured form) ----------------
function PlaybookForm({ initial, hosts, onSaved, onCancel }: { initial: Playbook | null; hosts: string[]; onSaved: (p: Playbook) => void; onCancel: () => void }) {
  const [name, setName] = useState(initial?.name ?? ""); const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [m, setM] = useState<Meta>(initial?.meta ?? emptyMeta()); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const up = (patch: Partial<Meta>) => setM({ ...m, ...patch });
  const save = async () => {
    setBusy(true); setErr("");
    try {
      const body = { name, enabled, meta: { ...m, targets: m.targets.map((x) => x.trim()).filter(Boolean), tags: m.tags.map((x) => x.trim()).filter(Boolean), facts: m.facts.filter((x) => x.trim()), prohibitions: m.prohibitions.filter((x) => x.trim()) } };
      const r = initial ? await api.put<Playbook>(`/playbooks/${initial.id}`, body) : await api.post<Playbook>("/playbooks", body);
      onSaved(r);
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <div className="flex flex-col gap-3.5">
      <div className="flex flex-wrap items-center gap-2"><h2 className="text-[22px] font-bold">{initial ? `編集: ${initial.name}` : "プレイブックを追加"}</h2><span className="text-xs text-slate-400">項目ごとに入力します。AI 用の Markdown は自動生成されます。</span></div>
      <div className="grid gap-3 md:grid-cols-3">
        <Field label="名前"><input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="メールサーバー運用" /></Field>
        <Field label="環境区分"><select className="input" value={m.environment ?? ""} onChange={(e) => up({ environment: e.target.value || null })}><option value="">-</option><option value="lab">検証</option><option value="staging">ステージング</option><option value="production">本番</option><option value="mixed">混在</option></select></Field>
        <Field label="状態"><select className="input" value={String(enabled)} onChange={(e) => setEnabled(e.target.value === "true")}><option value="true">有効（AI が参照）</option><option value="false">無効</option></select></Field>
      </div>
      <Field label="目的（誰のための、何についてのプレイブックか）"><textarea className="input h-16" value={m.purpose} onChange={(e) => up({ purpose: e.target.value })} /></Field>
      <div className="grid gap-3 md:grid-cols-3">
        <Field label="対象ホスト / サービス（カンマ区切り）" hint={hosts.length ? `登録済み: ${hosts.join(", ")}` : undefined}><input className="input" value={m.targets.join(", ")} onChange={(e) => up({ targets: e.target.value.split(",").map((x) => x.trim()) })} /></Field>
        <Field label="記録先"><input className="input" value={m.record_to} onChange={(e) => up({ record_to: e.target.value })} placeholder="Jira EDR-55" /></Field>
        <Field label="タグ（カンマ区切り）"><input className="input" value={m.tags.join(", ")} onChange={(e) => up({ tags: e.target.value.split(",").map((x) => x.trim()) })} /></Field>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <Section title="環境の事実" icon="📌"><ListEditor items={m.facts} onChange={(v) => up({ facts: v })} placeholder="Wazuh manager 4.14 が /var/ossec に稼働" /></Section>
        <Section title="禁止事項" icon="🚫" tone="border-rose-800/50 bg-rose-500/5"><ListEditor items={m.prohibitions} onChange={(v) => up({ prohibitions: v })} placeholder="カメラ回線 IP を BAN しない" /></Section>
        <Section title="調査手順" icon="🔍">
          <div className="space-y-2">{m.procedures.map((pr, i) => (
            <div key={i} className="rounded-md border border-slate-700 p-2">
              <div className="flex gap-2"><input className="input" value={pr.title} placeholder="手順名（例: SSH ブルートフォースの確認）" onChange={(e) => up({ procedures: m.procedures.map((x, k) => (k === i ? { ...x, title: e.target.value } : x)) })} /><button className="text-slate-500 hover:text-rose-300" onClick={() => up({ procedures: m.procedures.filter((_, k) => k !== i) })}>✕</button></div>
              <div className="mt-1"><ListEditor items={pr.steps} onChange={(v) => up({ procedures: m.procedures.map((x, k) => (k === i ? { ...x, steps: v } : x)) })} placeholder="ステップ" /></div>
            </div>
          ))}<button className="text-xs text-teal-400 hover:underline" onClick={() => up({ procedures: [...m.procedures, { title: "", steps: [""] }] })}>+ 手順を追加</button></div>
        </Section>
        <Section title="定型の対処" icon="🛠">
          <div className="space-y-2">{m.fixes.map((f, i) => {
            const setF = (patch: Partial<Fix>) => up({ fixes: m.fixes.map((x, k) => (k === i ? { ...x, ...patch } : x)) });
            return (
              <div key={i} className="space-y-1 rounded-md border border-slate-700 p-2">
                <div className="flex gap-2"><input className="input" value={f.title} placeholder="対処名（例: 攻撃元 IP を fail2ban で BAN）" onChange={(e) => setF({ title: e.target.value })} /><select className="input w-44" value={f.approval} onChange={(e) => setF({ approval: e.target.value as Fix["approval"] })}><option value="always">常に承認</option><option value="auto_low_risk">低リスク自動可</option><option value="never">提案のみ</option></select><button className="text-slate-500 hover:text-rose-300" onClick={() => up({ fixes: m.fixes.filter((_, k) => k !== i) })}>✕</button></div>
                <input className="input" value={f.when} placeholder="条件（いつ適用するか）" onChange={(e) => setF({ when: e.target.value })} />
                <div className="grid gap-2 md:grid-cols-2"><div><div className="label">コマンド</div><ListEditor mono items={f.commands} onChange={(v) => setF({ commands: v })} /></div><div><div className="label">戻し方</div><ListEditor mono items={f.rollback} onChange={(v) => setF({ rollback: v })} /></div></div>
                <input className="input" value={f.note} placeholder="補足" onChange={(e) => setF({ note: e.target.value })} />
              </div>
            );
          })}<button className="text-xs text-teal-400 hover:underline" onClick={() => up({ fixes: [...m.fixes, { title: "", when: "", commands: [], rollback: [], approval: "always", note: "" }] })}>+ 対処を追加</button></div>
        </Section>
        <Section title="過去の前例" icon="🕘">
          <div className="space-y-1">{m.precedents.map((x, i) => (
            <div key={i} className="flex gap-1"><input className="input w-28" value={x.date} placeholder="2026-10-16" onChange={(e) => up({ precedents: m.precedents.map((y, k) => (k === i ? { ...y, date: e.target.value } : y)) })} /><input className="input" value={x.summary} placeholder="要約" onChange={(e) => up({ precedents: m.precedents.map((y, k) => (k === i ? { ...y, summary: e.target.value } : y)) })} /><input className="input w-24" value={x.ref} placeholder="EDR-xx" onChange={(e) => up({ precedents: m.precedents.map((y, k) => (k === i ? { ...y, ref: e.target.value } : y)) })} /><button className="text-slate-500 hover:text-rose-300" onClick={() => up({ precedents: m.precedents.filter((_, k) => k !== i) })}>✕</button></div>
          ))}<button className="text-xs text-teal-400 hover:underline" onClick={() => up({ precedents: [...m.precedents, { date: "", summary: "", ref: "" }] })}>+ 前例を追加</button></div>
        </Section>
        <Section title="補足（その他）" icon="📎">
          <div className="space-y-2">{m.extra.map((e, i) => (
            <div key={i} className="rounded-md border border-slate-700 p-2"><div className="flex gap-2"><input className="input" value={e.title} placeholder="見出し" onChange={(ev) => up({ extra: m.extra.map((x, k) => (k === i ? { ...x, title: ev.target.value } : x)) })} /><button className="text-slate-500 hover:text-rose-300" onClick={() => up({ extra: m.extra.filter((_, k) => k !== i) })}>✕</button></div><div className="mt-1"><ListEditor items={e.items} onChange={(v) => up({ extra: m.extra.map((x, k) => (k === i ? { ...x, items: v } : x)) })} /></div></div>
          ))}<button className="text-xs text-teal-400 hover:underline" onClick={() => up({ extra: [...m.extra, { title: "", items: [""] }] })}>+ 補足を追加</button></div>
        </Section>
      </div>
      {err && <div className="text-sm text-rose-400">{err}</div>}
      <div className="flex gap-2"><button className="btn-primary" disabled={busy || !name.trim()} onClick={save}>保存</button><button className="btn-secondary" onClick={onCancel}>キャンセル</button></div>
    </div>
  );
}

// ---------------- AI panel ----------------
function AiPanel({ selected, onChanged, sessionParam, editing }: { selected: Playbook | null; onChanged: () => void; sessionParam: number | null; editing: boolean }) {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin"; const chatOk = admin || user?.role === "operator";
  const [open, setOpen] = useState(true);
  const [sessions, setSessions] = useState<(SessionRow & { label?: string | null })[]>([]); const [sid, setSid] = useState<number | null>(sessionParam); const [err, setErr] = useState(""); const [hist, setHist] = useState(false);
  const loadList = () => api.get<{ items: SessionRow[] }>("/sessions?limit=20&kind=playbook_setup").then((r) => setSessions(r.items));
  useEffect(() => { loadList(); }, []);
  useEffect(() => { if (sessionParam) { setSid(sessionParam); setOpen(true); } }, [sessionParam]);
  useEffect(() => { if (editing) setOpen(false); }, [editing]);
  const start = async (opts: { message?: string; title?: string; context?: any }) => {
    setErr(""); try { const r = await api.post<{ id: number }>("/sessions", { kind: "playbook_setup", ...opts }); setSid(r.id); setOpen(true); loadList(); } catch (e: any) { setErr(e.message); }
  };
  const create = async (text: string, attachments: PendingFile[]) => { const r = await api.post<{ id: number }>("/sessions", { kind: "playbook_setup", message: text.trim() || undefined, attachments: attachments.length ? attachments : undefined }); setSid(r.id); loadList(); return r.id; };
  const cur = sessions.find((s) => s.id === sid);
  return (
    <section aria-label="AIエージェントに相談" className={`flex flex-col overflow-hidden rounded-2xl border border-slate-600 bg-slate-800 ${open ? "min-h-[22rem]" : ""}`} style={open ? { height: "38vh" } : undefined}>
      <div className="flex flex-wrap items-center gap-2.5 border-b border-slate-700 px-4 py-3">
        <AgentTitle context="プレイブック" />
        {cur && <><span className={`rounded px-1.5 text-[10px] ${SESSION_STATUS_CLS[cur.status] ?? ""}`}>{SESSION_STATUS_JA[cur.status] ?? cur.status}</span><span className="truncate text-xs text-slate-400">#{cur.id} {cur.label || cur.title}</span></>}
        {chatOk && open && <div className="ml-auto flex flex-wrap gap-2">
          <button className="btn-primary min-h-[36px] rounded-lg px-3 text-[13px]" onClick={() => start({})}>＋ 新しいプレイブックを作る</button>
          {selected && <button className="btn-secondary min-h-[36px] rounded-lg border border-slate-600 bg-transparent px-3 text-[13px]" onClick={() => start({ title: `プレイブック改善: ${selected.name}`, context: { playbook_id: selected.id }, message: `プレイブック「${selected.name}」を見直したい。まず内容を確認して、足りない項目や曖昧な点を質問して。` })}><Ico d={I.edit} size={13} className="" />「{selected.name}」を改善</button>}
          {selected && !selected.structured && <button className="btn-secondary min-h-[36px] rounded-lg border border-slate-600 bg-transparent px-3 text-[13px]" onClick={() => start({ title: `項目化: ${selected.name}`, context: { playbook_id: selected.id }, message: `プレイブック「${selected.name}」は文章のままなので、内容を変えずに項目（目的/対象/事実/禁止/手順/対処/前例/記録先）に整理して。下書きを見せてから playbook_id=${selected.id} で更新して。` })}><Ico d={I.list} size={13} className="" />「{selected.name}」を項目化</button>}
          <button className="btn-secondary min-h-[36px] rounded-lg border border-slate-600 bg-transparent px-3 text-[13px]" onClick={() => setHist(true)}><Ico d={I.history} size={13} className="" />履歴{sessions.length ? ` (${sessions.length})` : ""}</button>
        </div>}
        <button className={`min-h-[36px] px-2 text-[13px] text-slate-400 hover:text-slate-200 ${chatOk && open ? "" : "ml-auto"}`} onClick={() => setOpen(!open)}>{open ? "たたむ ▾" : "ひらく ▴"}</button>
      </div>
      {err && <div className="px-4 pt-2 text-xs text-rose-400">{err}</div>}
      {hist && <SessionHistory kind="playbook_setup" title="プレイブック作成の相談履歴" currentId={sid} canAct={!!chatOk} onOpen={(id) => { setSid(id); setOpen(true); loadList(); }} onClose={() => setHist(false)} />}
      {open && <SessionChat key={sid ?? "new"} sid={sid} create={create} showProposal={false} className="flex-1 px-3 pb-2 pt-3" onEvent={(type, data) => { loadList(); if (type === "status" && /playbook saved/.test(data?.detail ?? "")) onChanged(); if (type === "tool_result" && data?.tool_call?.tool === "save_playbook") onChanged(); }}
        placeholder={sid ? "返信（ファイル添付も可）" : "作りたいプレイブックのことを書くか、上のボタンから始めてください"}
        emptyHint={<AgentIntro compact lead={<>「こういうときはこう動いてほしい」を、AI がヒアリングしながらプレイブックにします。既存のメモ・設定ファイル・過去のインシデント記録（テキスト）を添付すると速いです。保存する前に、必ず全項目の下書きを見せます。</>} examples={["ランサムウェアが疑われたときの対応手順を作りたい", "SSH の総当たり攻撃への対応をまとめて", "夜間のアラートは朝まとめて報告するルールにしたい", "今あるプレイブックで足りないところは？"]} onPick={(t) => { create(t, []).catch((e) => setErr(e.message)); }} />} />}
    </section>
  );
}

// ---------------- page ----------------
export default function Playbooks() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [params, setParams] = useSearchParams();
  const [items, setItems] = useState<Playbook[]>([]); const [hosts, setHosts] = useState<string[]>([]);
  const [selId, setSelId] = useState<number | null>(params.get("id") ? Number(params.get("id")) : null);
  const [editing, setEditing] = useState<"new" | "edit" | null>(null); const [q, setQ] = useState(""); const [err, setErr] = useState("");
  const reload = () => api.get<{ items: Playbook[] }>("/playbooks").then((r) => { setItems(r.items); if (selId == null && r.items.length) setSelId(r.items[0].id); }).catch((e) => setErr(e.message));
  useEffect(() => { reload(); api.get<{ items: any[] }>("/hosts").then((r) => setHosts(r.items.map((h) => h.name))); }, []);
  useEffect(() => { if (selId) { params.set("id", String(selId)); setParams(params, { replace: true }); } }, [selId]);
  const sessionParam = params.get("session") ? Number(params.get("session")) : null;
  const filtered = useMemo(() => items.filter((p) => !q || p.name.toLowerCase().includes(q.toLowerCase()) || p.meta.purpose.toLowerCase().includes(q.toLowerCase()) || p.meta.targets.some((t) => t.toLowerCase().includes(q.toLowerCase()))), [items, q]);
  const selected = items.find((p) => p.id === selId) ?? null;
  const total = items.length, enabled = items.filter((p) => p.enabled).length;
  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="flex items-center gap-2 text-[26px] font-bold"><Ico d={I.book} size={22} className="text-teal-300" />プレイブック</h1>
        <span className="text-sm text-slate-400">{total} 件（有効 {enabled}）· 有効なものは AI の調査開始時に知識として渡されます</span>
        {admin && <button className="btn-primary ml-auto min-h-[40px] rounded-[10px] px-4 font-semibold" onClick={() => setEditing("new")}>＋ 手で追加</button>}
      </header>
      {err && <div className="text-sm text-rose-400">{err}</div>}
      <div className="flex min-h-0 flex-1 gap-5">
        <aside aria-label="プレイブック一覧" className="flex w-80 shrink-0 flex-col gap-2.5 overflow-y-auto pr-1">
          <input className="input min-h-[42px] rounded-[10px] bg-slate-800" aria-label="プレイブックを検索" placeholder="検索（名前・目的・対象）" value={q} onChange={(e) => setQ(e.target.value)} />
          {filtered.map((p) => <PlaybookCard key={p.id} p={p} hosts={hosts} active={p.id === selId && !editing} onClick={() => { setSelId(p.id); setEditing(null); }} />)}
          {!filtered.length && <div className="text-xs text-slate-500">プレイブックがありません</div>}
        </aside>
        <section aria-label="プレイブックの詳細" className="min-w-0 flex-1 overflow-y-auto pr-1">
          {editing === "new" && <PlaybookForm initial={null} hosts={hosts} onSaved={(p) => { setEditing(null); setSelId(p.id); reload(); }} onCancel={() => setEditing(null)} />}
          {editing === "edit" && selected && <PlaybookForm initial={selected} hosts={hosts} onSaved={() => { setEditing(null); reload(); }} onCancel={() => setEditing(null)} />}
          {!editing && selected && <PlaybookDetail p={selected} hosts={hosts} onEdit={() => setEditing("edit")} onReload={reload} />}
          {!editing && !selected && <div className="text-sm text-slate-500">左の一覧からプレイブックを選ぶか、「手で追加」または下の AI 相談から作成してください。</div>}
        </section>
      </div>
      <AiPanel selected={selected} onChanged={reload} sessionParam={sessionParam} editing={!!editing} />
    </div>
  );
}
