import { useContext, useEffect, useMemo, useState } from "react";
import { onServerEvent } from "../lib/events";
import AgentIntro, { AgentTitle } from "../components/AgentIntro";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import { KIND_LABEL } from "../lib/mode";
import SessionChat, { type SessionRow, type PendingFile, SESSION_STATUS_CLS, SESSION_STATUS_JA } from "../components/SessionChat";
import SessionHistory from "../components/SessionHistory";
import { Field, Chip, Section, ENV_TONE, envJa, ENV_OPTIONS, ROLE_JA } from "../components/fields";
import { Ico, I } from "../components/Icon";
import HostKarte from "../components/HostKarte";
import AgentMaint from "../components/AgentMaint";
import { AgentPackDialog, PackRevChip, usePackOverview } from "../components/AgentPack";
const verLt = (a: string, b: string) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0); } return false; };

interface LastTest { ok: boolean; at: string; code?: number; ms?: number; stdout?: string; stderr?: string; error?: string }
interface Host { id: number; name: string; wazuh_instance_id: number | null; agent_id: string | null; address: string; port: number; ssh_user: string; ssh_key_id: number | null; sudo_mode: string; environment: string; autonomy_level: number; autonomy_max: number; maintenance_window: string | null; tags: string[]; notes: string | null; host_key: string | null; last_test: LastTest | null; updated_at: string;
  kind: "managed" | "agent_only"; os_family: string | null; agent_status: string | null; agent_last_seen: string | null; agent_os: string | null; last_scan_at: string | null; scan_schedule_override: string | null; action_locked: boolean | number; isolation_state: string | null; ar_addon_version: string | null; pack_rev?: number | null; contain?: { status: "pending" | "isolated"; since: string | null } | null; ai_suggestions?: number; role?: "server" | "client"; role_auto?: "server" | "client"; role_source?: "auto" | "manual" }
interface Detail { host: Host; key: { id: number; name: string; fingerprint: string; public_key: string } | null; agent: any; playbooks: { id: number; name: string; purpose: string; enabled: boolean }[]; approvals: any[]; sessions: any[] }

const AUTONOMY_JA: Record<number, string> = { 0: "提案のみ（読み取りも承認）", 1: "読み取りは自動・変更は承認", 2: "低リスクの既承認コマンドは自動", 3: "チェック通過の変更は自動" };
const ago = (iso?: string) => { if (!iso) return ""; const s = (Date.now() - new Date(iso).getTime()) / 1000; return s < 60 ? "たった今" : s < 3600 ? `${Math.floor(s / 60)} 分前` : s < 86400 ? `${Math.floor(s / 3600)} 時間前` : `${Math.floor(s / 86400)} 日前`; };

const SCHED_JA: Record<string, string> = { "1d": "毎日", "7d": "週 1", "30d": "月 1", off: "しない" };
const agentOnly = (h: Host) => h.kind === "agent_only";
function AgentDot({ h }: { h: Host }) {
  const st = h.agent_status; const cls = st === "active" ? "bg-[#3CCB8C]" : st === "disconnected" ? "bg-[#F2555A]" : "bg-[#4A5578]";
  return <span title={`Wazuh エージェント: ${st ?? "不明"}${h.agent_last_seen ? `（最終通信 ${fmtTs(h.agent_last_seen)}）` : ""}`} className={`inline-block h-2.5 w-2.5 rounded-full ${cls}`} />;
}
function TestDot({ t }: { t: LastTest | null }) {
  const cls = !t ? "bg-[#4A5578]" : t.ok ? "bg-[#3CCB8C]" : "bg-[#F2555A]";
  const title = !t ? "未テスト" : `${t.ok ? "接続OK" : "接続失敗"} ${fmtTs(t.at)}${t.error ? " — " + t.error : ""}`;
  return <span title={title} className={`inline-block h-2.5 w-2.5 rounded-full ${cls}`} />;
}

// ---------------- card ----------------
function HostCard({ h, active, onClick, latest, same }: { h: Host; active: boolean; onClick: () => void; latest?: number | null; same?: number[] }) {
  return (
    <button onClick={onClick} className={`flex w-full flex-col gap-1.5 rounded-xl border p-3.5 text-left transition ${h.contain?.status === "isolated" ? `border-2 border-[#F0566E] ${active ? "bg-[#3A1418]" : "bg-[#2A1216] hover:bg-[#3A1418]"} shadow-[0_0_0_3px_rgba(240,86,110,0.18)]` : h.contain?.status === "pending" ? `border-2 border-dashed border-[#F2B33D] ${active ? "bg-[#1A2547]" : "bg-slate-800"}` : active ? "border-teal-500 bg-[#1A2547]" : "border-slate-700 bg-slate-800 hover:border-slate-500/60"}`}>
      {h.contain?.status === "isolated" && <span className="flex items-center gap-1.5 rounded-md bg-[#C62F38] px-2 py-1 text-[12px] font-bold text-white"><svg aria-hidden="true" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></svg>通信遮断中（Contain・隔離）<span className="ml-auto font-normal opacity-90">{h.contain.since ? `${fmtTs(h.contain.since).slice(5, 16)} から` : ""}</span></span>}
      {h.contain?.status === "pending" && <span className="flex items-center gap-1.5 rounded-md bg-[#2D2410] px-2 py-1 text-[12px] font-semibold text-[#F5D98A]">⏳ 通信遮断の承認待ち<span className="ml-auto font-normal opacity-80">承認キューで承認すると遮断します</span></span>}
      <span className="flex flex-wrap items-center gap-2">{agentOnly(h) ? <AgentDot h={h} /> : <TestDot t={h.last_test} />}<span className="truncate font-mono text-[15px] font-semibold text-slate-100">{h.name}</span><Chip tone={ENV_TONE[h.environment]}>{envJa(h.environment, h.role)}</Chip>{agentOnly(h) ? <Chip tone="sky">{h.os_family === "windows" ? "Windows" : "エージェント"}</Chip> : <Chip tone="teal">L{h.autonomy_level}</Chip>}{!!h.action_locked && <Chip tone="slate">🛡 遮断対象外</Chip>}<PackRevChip rev={h.pack_rev} latest={latest} same={same} />{(h.ai_suggestions ?? 0) > 0 && <span title={`AI の提案が ${h.ai_suggestions} 件あります`} className="text-[13px] text-[#9DB4FF]">✦</span>}</span>
      {agentOnly(h) ? <span className="truncate text-[12px] text-slate-300">{h.agent_os ?? "OS 不明"} · <span className="font-mono">{h.address}</span></span> : <span className="truncate font-mono text-[13px] text-slate-300">{h.ssh_user}@{h.address}:{h.port}</span>}
      <span className="text-xs text-slate-400">{agentOnly(h) ? <>agent {h.agent_id} · {h.agent_status === "disconnected" && h.agent_last_seen ? <span className="text-[#FF9A9D]">{ago(h.agent_last_seen).replace("前", "")}つながっていない</span> : h.agent_status ?? "-"}</> : <>{h.agent_id ? `agent ${h.agent_id}` : "agent なし"} · 鍵 {h.ssh_key_id ? `#${h.ssh_key_id}` : "なし"} · sudo {h.sudo_mode === "nopasswd" ? "✓" : "✗"} · hostkey {h.host_key ? "✓" : "未"}{h.last_test && <span className="ml-1.5 text-slate-500">{ago(h.last_test.at)}</span>}</>}{h.last_scan_at && <span className="ml-1.5 text-slate-500">· スキャン {ago(h.last_scan_at)}</span>}</span>
      {h.notes && <span className="line-clamp-2 text-xs leading-relaxed text-slate-400">{h.notes}</span>}
    </button>
  );
}

/* EDR-130: an agent-only Linux server where the agent pack prepared the "mamorai" SSH user → make it a managed host */
function PackSshButton({ h, onDone }: { h: Host; onDone: () => void }) {
  const [pack] = usePackOverview(); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const ssh = pack?.settings?.linux?.ssh;
  if (!pack || !ssh?.offer || !pack.ssh_key) return null;
  const go = async () => {
    if (!confirm(`${h.name} に、エージェントパックで作った SSH（ユーザー ${ssh.user}、鍵 #${pack.ssh_key!.id}）で接続するように設定しますか？\n初回の接続で、このサーバーの hostkey を記憶します。インストーラーが表示した hostkey と同じか確認してください。`)) return;
    let address = h.address;
    if (!address || address === "any" || !/^[A-Za-z0-9.:\-]+$/.test(address)) { address = (prompt("このサーバーに SSH でつなぐアドレス（IP または DNS 名）") ?? "").trim(); if (!address) return; }
    setBusy(true); setErr("");
    try { await api.put(`/hosts/${h.id}`, { address, ssh_user: ssh.user, ssh_key_id: pack.ssh_key!.id, port: 22, sudo_mode: ssh.sudo === "full" ? "nopasswd" : "none" }); await api.post(`/hosts/${h.id}/test`).catch(() => {}); onDone(); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return <div className="mt-2 flex flex-col gap-1.5"><button className="btn-secondary min-h-[36px] self-start rounded-[10px] border border-slate-600 bg-transparent px-3 text-sm" disabled={busy} onClick={go}>{busy ? "設定中…" : "パックで準備した SSH を使う"}</button><span className="text-[11px] text-slate-500">Linux 用パックで「MamorAI から操作できるようにする」を選んだサーバーだけ使えます。</span>{err && <span className="text-xs text-rose-300">{err}</span>}</div>;
}

// ---------------- detail ----------------
/** EDR-155: values the AI scan suggests for the host settings — never written without a click; decided fields stay quiet */
function AiSuggestions({ hostId, admin, role, refreshKey, onChanged }: { hostId: number; admin: boolean; role?: string; refreshKey?: number; onChanged: () => void }) {
  type Sg = { field: "notes" | "tags" | "environment"; value: any; current: any; reason: string; changed: boolean };
  const [items, setItems] = useState<Sg[]>([]); const [busy, setBusy] = useState(""); const [err, setErr] = useState("");
  const load = () => api.get<{ items: Sg[] }>(`/hosts/${hostId}/suggestions`).then((r) => setItems(r.items)).catch(() => setItems([]));
  useEffect(() => { load(); }, [hostId, refreshKey]);
  if (!items.length) return null;
  const act = async (f: Sg["field"], action: "apply" | "dismiss") => { setBusy(f); setErr(""); try { const r = await api.post<{ items: Sg[] }>(`/hosts/${hostId}/suggestions/${f}`, { action }); setItems(r.items); onChanged(); } catch (e: any) { setErr(e.message); } finally { setBusy(""); } };
  const label: Record<Sg["field"], string> = { notes: "役割メモ", tags: "タグ", environment: role === "client" ? "使い方" : "環境区分" };
  const show = (it: Sg, v: any) => it.field === "environment" ? envJa(v, role) : it.field === "tags" ? (v as string[]).join(", ") : String(v || "（空）");
  return (
    <section aria-label="AI の提案" className="rounded-[14px] border border-[#2B4A7A] bg-[#0F1A33] px-4 py-3">
      <div className="mb-1.5 flex items-center gap-2 text-[14px] font-semibold text-[#D6E0FF]">✦ AI の提案（{items.length}）<span className="text-[12px] font-normal text-slate-400">ホストの AI スキャンの結果から。押さない限り変わりません</span></div>
      {items.map((it) => (
        <div key={it.field} className="flex flex-wrap items-center gap-2 border-t border-[#24314D] py-2 text-[13px] first:border-t-0">
          <span className="w-20 shrink-0 text-slate-400">{label[it.field]}</span>
          <span className="min-w-0 flex-1 text-slate-100">{it.changed && <span className="mr-1.5 rounded bg-[#2D2410] px-1.5 py-0.5 text-[11px] text-[#F5D98A]">用途が変わったかもしれません</span>}<b>{show(it, it.value)}</b>{it.field !== "notes" && <span className="ml-1.5 text-slate-500">（今: {show(it, it.current)}）</span>}{it.reason && <div className="text-[12px] text-slate-400">根拠: {it.reason}</div>}{it.field === "environment" && it.value === "production" && <div className="text-[12px] text-[#F5D98A]">反映すると、このホストへの変更は承認のときに認証アプリの 6 桁も必要になります</div>}</span>
          {admin && <span className="flex shrink-0 gap-1.5"><button className="rounded-md bg-[#3A56F0] px-2.5 py-1 text-[12px] font-semibold text-white hover:bg-[#4A66FF] disabled:opacity-50" disabled={!!busy} onClick={() => act(it.field, "apply")}>反映する</button><button className="rounded-md border border-slate-600 px-2.5 py-1 text-[12px] text-slate-300 hover:bg-slate-700 disabled:opacity-50" disabled={!!busy} onClick={() => act(it.field, "dismiss")}>このままでいい</button></span>}
        </div>
      ))}
      {err && <div className="text-[12px] text-rose-400">{err}</div>}
    </section>
  );
}

function HostDetail({ id, onEdit, onReload, refreshKey }: { id: number; onEdit: () => void; onReload: () => void; refreshKey?: number }) {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin"; const canAct = admin || user?.role === "operator";
  const nav = useNavigate();
  const [d, setD] = useState<Detail | null>(null); const [err, setErr] = useState(""); const [testing, setTesting] = useState(false); const [showKey, setShowKey] = useState(false);
  const load = () => api.get<Detail>(`/hosts/${id}/detail`).then(setD).catch((e) => setErr(e.message));
  useEffect(() => { setD(null); load(); }, [id]);
  if (err) return <div className="text-sm text-rose-400">{err}</div>;
  if (!d) return <div className="text-sm text-slate-500">読み込み中…</div>;
  const h = d.host, t = h.last_test;
  const runTest = async () => { setTesting(true); try { await api.post(`/hosts/${id}/test`); } catch { /* result stored server-side */ } finally { setTesting(false); load(); onReload(); } };
  const agentStatus = d.agent?.status;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex min-w-0 flex-[1_1_320px] flex-col gap-1.5">
          <div className="flex flex-wrap items-center gap-2">{agentOnly(h) ? <AgentDot h={h} /> : <TestDot t={t} />}<h2 className="font-mono text-[22px] font-bold">{h.name}</h2>{h.role && <Chip tone="slate">{ROLE_JA[h.role]}</Chip>}<Chip tone={ENV_TONE[h.environment]}>{envJa(h.environment, h.role)}</Chip>{agentOnly(h) ? <Chip tone="sky">エージェントだけ（SSH なし）</Chip> : <Chip tone="teal">自律度 L{h.autonomy_level} / 上限 L{h.autonomy_max}</Chip>}{!!h.action_locked && <Chip tone="amber">遮断の対象外</Chip>}{h.scan_schedule_override && <Chip>定期スキャン: {SCHED_JA[h.scan_schedule_override]}</Chip>}{h.tags.map((x) => <Chip key={x}>#{x}</Chip>)}</div>
          <div className="text-sm text-slate-400">{h.notes || <span className="text-slate-500">役割メモなし</span>} · 更新 {fmtTs(h.updated_at)}</div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {canAct && !agentOnly(h) && <button className="btn-primary min-h-[40px] rounded-[10px] px-3.5" disabled={testing} onClick={runTest}><Ico d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3" size={16} className="" />{testing ? "テスト中…" : "接続テスト"}</button>}
          {admin && <button className="btn-secondary min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-3.5" onClick={onEdit}><Ico d={I.edit} size={16} className="" />編集</button>}
          {admin && h.host_key && <button className="btn-secondary min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-3.5" title="再インストールなどで hostkey が変わったときだけ" onClick={async () => { if (confirm("hostkey のピン留めを解除しますか？（次回接続時に再学習）")) { await api.post(`/hosts/${id}/reset-hostkey`); load(); } }}>hostkey リセット</button>}
          {admin && <button className="btn min-h-[40px] rounded-[10px] border border-[#4A1E24] px-3.5 text-[#FF9A9D] hover:bg-[#3A1418]" onClick={async () => { if (confirm(h.agent_id ? `「${h.name}」を MamorAI の一覧から削除しますか？\n\nWazuh エージェント（${h.agent_id}）は Wazuh に残ったままです。削除すると「取り込み対象外」になり、自動では一覧に戻りません（管理ホスト › 取り込み対象外 から元に戻せます）。\n端末自体を監視から外す場合は、Wazuh 側のエージェントも削除してください。` : `「${h.name}」を削除しますか？`)) { await api.del(`/hosts/${id}`); onReload(); } }}>削除</button>}
        </div>
      </div>
      <AiSuggestions hostId={id} admin={!!admin} role={h.role} refreshKey={refreshKey} onChanged={() => { load(); onReload(); }} />
      <div className="grid gap-3.5 [overflow-wrap:anywhere] [grid-template-columns:repeat(auto-fit,minmax(300px,1fr))] [&>*]:min-w-0">
        {agentOnly(h) ? <Section title="接続" icon="🔌"><div className="text-[13px] leading-relaxed text-slate-300">Wazuh エージェントだけのホストです（SSH は未登録）。情報は Wazuh から読み、遮断は Wazuh の自動対処（Windows はアドオン）で行います。{admin && <> SSH で入れるサーバーなら「編集」で SSH を設定すると管理ホストになります。</>}</div>{admin && h.os_family === "linux" && <PackSshButton h={h} onDone={() => { load(); onReload(); }} />}</Section> :
        <Section title="接続" icon="🔌">
          <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-2.5 gap-y-2 text-[13px]">
            <dt className="text-slate-400">SSH</dt><dd className="font-mono text-slate-200">{h.ssh_user}@{h.address}:{h.port}</dd>
            <dt className="text-slate-400">鍵</dt><dd className="text-slate-200">{d.key ? <>#{d.key.id} {d.key.name} <span className="text-slate-500">{d.key.fingerprint}</span> <button className="ml-1 rounded-md border border-slate-600 px-2 py-0.5 text-xs text-slate-200 hover:bg-slate-700" onClick={() => setShowKey(!showKey)}>{showKey ? "公開鍵を隠す" : "公開鍵を表示"}</button></> : <span className="text-rose-300">未設定</span>}</dd>
            {showKey && d.key && <><dt /><dd><pre className="select-all whitespace-pre-wrap break-all rounded-[10px] border border-slate-700 bg-[#070B15] px-3 py-2.5 font-mono text-xs text-slate-200">{d.key.public_key}</pre><div className="mt-1 text-xs text-slate-400">ホスト側: <code>~/.ssh/authorized_keys</code> に追加</div></dd></>}
            <dt className="text-slate-400">sudo</dt><dd className="text-slate-200">{h.sudo_mode === "nopasswd" ? "NOPASSWD（root 操作可）" : "なし（一般ユーザー権限のみ）"}</dd>
            <dt className="text-slate-400">hostkey</dt><dd className="text-slate-200">{h.host_key ? <span className="text-[#3CCB8C]">ピン留め済（{h.host_key.replace(" (pinned)", "")}）</span> : <span className="text-amber-300">未学習（初回接続で記憶）</span>}</dd>
            <dt className="text-slate-400">メンテ枠</dt><dd className="text-slate-200">{h.maintenance_window || "-"}</dd>
          </dl>
          <div className="flex flex-col gap-1.5 rounded-[10px] border border-slate-600 bg-slate-900 px-3 py-2.5 text-[13px]">
            <div className="flex items-center gap-2"><TestDot t={t} /><span className="font-semibold text-slate-100">{!t ? "接続テスト未実施" : t.ok ? "接続 OK" : "接続失敗"}</span>{t && <span className="text-slate-500">{fmtTs(t.at)}{t.ms ? ` · ${t.ms}ms` : ""}</span>}</div>
            {t?.error && <div className="mt-1 text-rose-300">{t.error}</div>}
            {t?.stdout && <pre className="whitespace-pre-wrap font-mono text-xs text-slate-400">{t.stdout}{t.stderr}</pre>}
          </div>
        </Section>}
        {!agentOnly(h) && <Section title="権限・自律度" icon="🛡️">
          <div className="flex flex-col gap-1.5">{[0, 1, 2, 3].map((l) => (
            <div key={l} className={`flex items-center gap-2.5 rounded-[10px] border px-2.5 py-2 text-[13px] ${l === h.autonomy_level ? "border-teal-500 bg-[#1A2547] text-slate-100" : "border-slate-700 bg-slate-900"} ${l > h.autonomy_max ? "text-slate-500" : "text-slate-100"}`}><span className="font-mono font-bold">L{l}</span><span className="flex-1">{AUTONOMY_JA[l]}</span>{l === h.autonomy_level && <span className="rounded-full bg-teal-500 px-2 py-px text-[11px] font-bold text-white">現在</span>}{l > h.autonomy_max && <span className="rounded-full bg-slate-700 px-2 py-px text-[11px] text-slate-400">上限超</span>}</div>
          ))}</div>
          <div className="text-xs leading-relaxed text-slate-400">変更系コマンドは承認カードを通ります。保護アドレスを含む変更はブロックされます。</div>
        </Section>}
        <Section title="エージェント（Wazuh・MamorAI）" icon="📡">
          {!h.agent_id ? <div className="text-xs text-slate-500">エージェント ID 未設定（編集で設定すると状態を表示します）</div> : d.agent?.error ? <div className="text-xs text-rose-300">取得失敗: {d.agent.error}</div> : !d.agent ? <div className="text-xs text-amber-300">agent {h.agent_id} が Wazuh に見つかりません</div> : (
            <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-2.5 gap-y-2 text-[13px]">
              <dt className="text-slate-400">ID / 名前</dt><dd className="font-mono text-slate-200">{d.agent.id} · {d.agent.name}</dd>
              <dt className="text-slate-400">状態</dt><dd><Chip tone={agentStatus === "active" ? "emerald" : agentStatus === "disconnected" ? "rose" : "amber"}>{agentStatus}</Chip></dd>
              <dt className="text-slate-400">OS</dt><dd className="text-slate-200">{d.agent.os?.name} {d.agent.os?.version}</dd>
              <dt className="text-slate-400">agent版</dt><dd className="font-mono text-slate-200">{d.agent.version}</dd>
              <dt className="text-slate-400">最終通信</dt><dd className="text-slate-200">{fmtTs(d.agent.lastKeepAlive)}</dd>
              <dt className="text-slate-400">グループ</dt><dd className="text-slate-200">{(d.agent.group ?? []).join(", ") || "-"}</dd>
            </dl>
          )}
          {h.agent_id && h.os_family === "windows" && <AgentMaint hostId={h.id} canAct={canAct} agentVersion={d.agent?.version ?? null} onChanged={() => { load(); onReload(); }} />}
        </Section>
        <Section title="関連プレイブック" icon="📖" count={d.playbooks.length}>
          {d.playbooks.length ? <ul className="flex flex-col gap-2.5">{d.playbooks.map((p) => <li key={p.id}><button className="mr-1.5 text-left text-sm font-semibold text-teal-300 hover:text-teal-200" onClick={() => nav(`/playbooks?id=${p.id}`)}>{p.name}</button>{!p.enabled && <Chip tone="rose">無効</Chip>}<div className="line-clamp-2 text-xs leading-relaxed text-slate-400">{p.purpose}</div></li>)}</ul> : <div className="text-xs text-slate-500">このホストを対象にしたプレイブックはありません。<button className="text-teal-400 hover:underline" onClick={() => nav(`/playbooks`)}>プレイブック画面</button>で作成できます。</div>}
        </Section>
        <Section title="最近の変更（承認履歴）" icon="🛠" count={d.approvals.length}>
          {d.approvals.length ? <ul className="flex flex-col gap-2.5">{d.approvals.map((a) => <li key={a.id} className="text-[13px]"><div className="flex flex-wrap items-center gap-2"><Chip tone={a.decision === "rejected" ? "slate" : a.exec === "executed" && (a.exit_code ?? 0) === 0 ? "emerald" : a.decision === "pending" ? "amber" : "rose"}>{a.decision === "pending" ? "承認待ち" : a.decision === "rejected" ? "却下" : a.exec === "executed" && (a.exit_code ?? 0) === 0 ? "実行済" : "失敗"}</Chip><button className="min-w-0 flex-1 truncate text-left text-teal-300 hover:text-teal-200" onClick={() => nav(`/sidekick/${a.session_id}`)}>{a.title || a.command.split("\n")[0]}</button><span className="ml-auto shrink-0 text-slate-500">{fmtTs(a.decided_at)}</span></div></li>)}</ul> : <div className="text-xs text-slate-500">なし</div>}
        </Section>
        <Section title="最近の調査・セッション" icon="🕵️" count={d.sessions.length}>
          {d.sessions.length ? <ul className="flex flex-col gap-2.5">{d.sessions.map((s) => <li key={s.id} className="flex flex-wrap items-center gap-2 text-[13px]"><span className={`rounded-full px-2 py-px text-[11px] ${SESSION_STATUS_CLS[s.status] ?? ""}`}>{SESSION_STATUS_JA[s.status] ?? s.status}</span><button className="min-w-0 flex-1 truncate text-left text-teal-300 hover:text-teal-200" onClick={() => nav(s.kind === "host_setup" ? `/hosts?session=${s.id}` : s.kind === "playbook_setup" ? `/playbooks?session=${s.id}` : `/sidekick/${s.id}`)}>{s.origin === "alert" ? "Sentinel" : KIND_LABEL[s.kind] ?? "Sidekick"} #{s.id} {s.title}</button><span className="ml-auto shrink-0 text-slate-500">{fmtTs(s.created_at)}</span></li>)}</ul> : <div className="text-xs text-slate-500">なし</div>}
        </Section>
      </div>
      <HostKarte hostId={h.id} canAct={canAct} admin={admin} refreshKey={refreshKey} onChanged={() => { load(); onReload(); }} />
    </div>
  );
}

// ---------------- form ----------------
function HostForm({ initial, onSaved, onCancel }: { initial: Host | null; onSaved: (h: Host) => void; onCancel: () => void }) {
  const [keys, setKeys] = useState<any[]>([]); const [wz, setWz] = useState<any[]>([]);
  const autoRole: "server" | "client" = initial?.role_auto ?? "server";
  const [f, setF] = useState<any>(initial ? { ...initial, tags: initial.tags.join(", "), role_choice: initial.role_source === "manual" ? initial.role : "auto" } : { role_choice: "auto", name: "", wazuh_instance_id: null, agent_id: "", address: "", port: 22, ssh_user: "", ssh_key_id: null, sudo_mode: "nopasswd", environment: "lab", autonomy_level: 1, autonomy_max: 1, maintenance_window: "", tags: "", notes: "" });
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { api.get<{ items: any[] }>("/ssh-keys").then((r) => { setKeys(r.items); if (!initial && r.items[0] && !f.ssh_key_id) setF((x: any) => ({ ...x, ssh_key_id: r.items[0].id })); }); api.get<{ items: any[] }>("/wazuh").then((r) => { setWz(r.items); if (!initial && r.items[0]) setF((x: any) => ({ ...x, wazuh_instance_id: x.wazuh_instance_id ?? r.items[0].id })); }); }, []);
  const save = async () => {
    setBusy(true); setErr("");
    try {
      const b: any = { scan_schedule_override: f.scan_schedule_override || null, action_locked: !!f.action_locked, name: f.name, address: f.address, port: Number(f.port), ssh_user: f.ssh_user, ssh_key_id: f.ssh_key_id ? Number(f.ssh_key_id) : null, sudo_mode: f.sudo_mode, environment: effRole === "client" && f.environment === "staging" ? "lab" : f.environment, role: f.role_choice, autonomy_level: Number(f.autonomy_level), autonomy_max: Number(f.autonomy_max), wazuh_instance_id: f.wazuh_instance_id ? Number(f.wazuh_instance_id) : null, agent_id: f.agent_id || null, maintenance_window: f.maintenance_window || null, notes: f.notes || null, tags: String(f.tags ?? "").split(",").map((s: string) => s.trim()).filter(Boolean) };
      if (initial?.kind === "agent_only" && !f.ssh_user) { delete b.ssh_user; delete b.ssh_key_id; delete b.port; delete b.sudo_mode; } // EDR-121: SSH stays unset
      const r = initial ? await api.put<Host>(`/hosts/${initial.id}`, b) : await api.post<Host>("/hosts", b);
      onSaved(r);
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const set = (k: string, v: any) => setF({ ...f, [k]: v });
  const effRole: "server" | "client" = f.role_choice === "auto" ? autoRole : f.role_choice;
  return (
    <div className="flex flex-col gap-3.5">
      <h2 className="text-[22px] font-bold">{initial ? `編集: ${initial.name}` : "ホストを追加"}</h2>
      <Section title="基本" icon="🖧"><div className="grid gap-3 md:grid-cols-3">
        <Field label="名前（AI がコマンド対象として使う識別名）"><input className="input" value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="web02" /></Field>
        <Field label="種別" hint={f.role_choice === "auto" ? `自動で判定しています（今: ${ROLE_JA[autoRole]}）。Wazuh のグループ（laptop / desktop など）と OS から決めます` : "手動で決めています。ダッシュボードの分け方と共通です"}><select className="input" value={f.role_choice} onChange={(e) => { const rc = e.target.value; const eff = rc === "auto" ? autoRole : rc; setF({ ...f, role_choice: rc, environment: eff === "client" && f.environment === "staging" ? "lab" : f.environment }); }}><option value="auto">自動（{ROLE_JA[autoRole]}）</option><option value="server">サーバー</option><option value="client">クライアント端末</option></select></Field>
        <Field label={effRole === "client" ? "使い方" : "環境区分"} hint={f.environment === "production" ? "このホストへの変更は、承認のときに認証アプリの 6 桁も必要になります" : undefined}><select className="input" value={effRole === "client" && f.environment === "staging" ? "lab" : f.environment} onChange={(e) => set("environment", e.target.value)}>{ENV_OPTIONS[effRole].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>
        <Field label="タグ（カンマ区切り）"><input className="input" value={f.tags} onChange={(e) => set("tags", e.target.value)} placeholder="linux, public-web" /></Field>
        <div className="md:col-span-3"><Field label="役割メモ（AI に 1 行で伝える: 何が動いているか）"><input className="input" value={f.notes ?? ""} onChange={(e) => set("notes", e.target.value)} placeholder={effRole === "client" ? "例: 経理担当の業務 PC。Office と会計ソフトを使用" : "例: Lightsail の WordPress 公開 Web。fail2ban なし、ufw あり"} /></Field></div>
      </div></Section>
      {initial?.kind === "agent_only" && <div className="rounded-[10px] border border-slate-600 bg-slate-900 px-3 py-2 text-[13px] text-slate-300">このホストは Wazuh から取り込んだエージェントだけのホストです。SSH の項目は空のままで保存できます。SSH で入れるサーバーなら、SSH ユーザーと鍵を設定すると管理ホスト（SSH で調査・変更できる）になります。</div>}
      <Section title="接続" icon="🔌"><div className="grid gap-3 md:grid-cols-4">
        <Field label="アドレス（コンソールから到達できる IP / DNS）"><input className="input" value={f.address} onChange={(e) => set("address", e.target.value)} placeholder="100.x.y.z / 10.20.30.x" /></Field>
        <Field label="ポート"><input className="input" type="number" value={f.port} onChange={(e) => set("port", e.target.value)} /></Field>
        <Field label="SSH ユーザー"><input className="input" value={f.ssh_user} onChange={(e) => set("ssh_user", e.target.value)} placeholder="ec2-user" /></Field>
        <Field label="SSH 鍵（設定 > SSH 鍵）"><select className="input" value={f.ssh_key_id ?? ""} onChange={(e) => set("ssh_key_id", e.target.value || null)}><option value="">-</option>{keys.map((k) => <option key={k.id} value={k.id}>#{k.id} {k.name}</option>)}</select></Field>
        <Field label="sudo"><select className="input" value={f.sudo_mode} onChange={(e) => set("sudo_mode", e.target.value)}><option value="nopasswd">NOPASSWD（sudo -n 可）</option><option value="none">なし</option></select></Field>
        <Field label="メンテ枠"><input className="input" value={f.maintenance_window ?? ""} onChange={(e) => set("maintenance_window", e.target.value)} placeholder="Sun 02:00-04:00 JST" /></Field>
      </div></Section>
      <Section title="Wazuh / 自律度" icon="🛡️"><div className="grid gap-3 md:grid-cols-4">
        <Field label="Wazuh インスタンス"><select className="input" value={f.wazuh_instance_id ?? ""} onChange={(e) => set("wazuh_instance_id", e.target.value || null)}><option value="">-</option>{wz.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select></Field>
        <Field label="エージェント ID（3 桁）"><input className="input" value={f.agent_id ?? ""} onChange={(e) => set("agent_id", e.target.value)} placeholder="013" /></Field>
        <Field label="自律度（現在）"><select className="input" value={f.autonomy_level} onChange={(e) => set("autonomy_level", e.target.value)}>{[0, 1, 2, 3].map((l) => <option key={l} value={l}>L{l} {AUTONOMY_JA[l]}</option>)}</select></Field>
        <Field label="自律度（上限）"><select className="input" value={f.autonomy_max} onChange={(e) => set("autonomy_max", e.target.value)}>{[0, 1, 2, 3].map((l) => <option key={l} value={l}>L{l}</option>)}</select></Field>
      </div></Section>
      <Section title="ホストスキャン・遮断" icon="🎯"><div className="grid gap-3 md:grid-cols-3">
        <Field label="定期スキャン（このホストだけ変える）" hint="空欄は全体の設定（設定 › ホストスキャン）に従います"><select className="input" value={f.scan_schedule_override ?? ""} onChange={(e) => set("scan_schedule_override", e.target.value || null)}><option value="">全体の設定に従う</option>{Object.entries(SCHED_JA).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
        <Field label="遮断の対象外" hint="Wazuh 本体・AD など、止めると全体が困るホストは対象外にします"><label className="mt-2 inline-flex items-center gap-2 text-sm"><input type="checkbox" checked={!!f.action_locked} disabled={String(f.agent_id) === "000"} onChange={(e) => set("action_locked", e.target.checked)} />このホストへの遮断・隔離・サービス停止を禁止する</label></Field>
      </div></Section>
      {err && <div className="text-sm text-rose-400">{err}</div>}
      <div className="flex gap-2"><button className="btn-primary min-h-[40px] rounded-[10px] px-5" disabled={busy || !f.name || !f.address || (!f.ssh_user && initial?.kind !== "agent_only")} onClick={save}>保存</button><button className="btn-secondary min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-5" onClick={onCancel}>キャンセル</button></div>
    </div>
  );
}

// ---------------- AI panel ----------------
function AiPanel({ selected, onChanged, sessionParam, editing }: { selected: Host | null; onChanged: () => void; sessionParam: number | null; editing: boolean }) {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin"; const chatOk = admin || user?.role === "operator";
  const [open, setOpen] = useState(true);
  const [sessions, setSessions] = useState<(SessionRow & { label?: string | null })[]>([]); const [sid, setSid] = useState<number | null>(sessionParam); const [err, setErr] = useState(""); const [hist, setHist] = useState(false);
  const loadList = () => api.get<{ items: SessionRow[] }>("/sessions?limit=20&kind=host_setup").then((r) => setSessions(r.items));
  useEffect(() => { loadList(); }, []);
  useEffect(() => { if (sessionParam) { setSid(sessionParam); setOpen(true); } }, [sessionParam]);
  useEffect(() => { if (editing) setOpen(false); }, [editing]);
  const start = async (opts: { message?: string; title?: string; context?: any }) => { setErr(""); try { const r = await api.post<{ id: number }>("/sessions", { kind: "host_setup", ...opts }); setSid(r.id); setOpen(true); loadList(); } catch (e: any) { setErr(e.message); } };
  const create = async (text: string, attachments: PendingFile[]) => { const r = await api.post<{ id: number }>("/sessions", { kind: "host_setup", message: text.trim() || undefined, attachments: attachments.length ? attachments : undefined }); setSid(r.id); loadList(); return r.id; };
  const cur = sessions.find((s) => s.id === sid);
  return (
    <section aria-label="AIエージェントに相談" className={`flex flex-col overflow-hidden rounded-2xl border border-slate-600 bg-slate-800 ${open ? "min-h-[22rem]" : ""}`} style={open ? { height: "38vh" } : undefined}>
      <div className="flex flex-wrap items-center gap-2.5 border-b border-slate-700 px-4 py-3">
        <AgentTitle context="ホスト登録・見直し" />
        {cur && <><span className={`rounded px-1.5 text-[10px] ${SESSION_STATUS_CLS[cur.status] ?? ""}`}>{SESSION_STATUS_JA[cur.status] ?? cur.status}</span><span className="truncate text-xs text-slate-400">#{cur.id} {cur.label || cur.title}</span></>}
        {chatOk && open && <div className="ml-auto flex flex-wrap gap-2">
          <button className="btn-primary min-h-[36px] rounded-lg px-3 text-[13px]" onClick={() => start({})}>＋ 新しいホストを登録</button>
          {selected && <button className="btn-secondary min-h-[36px] rounded-lg border border-slate-600 bg-transparent px-3 text-[13px]" onClick={() => start({ title: `ホスト見直し: ${selected.name}`, context: { host_id: selected.id }, message: `ホスト「${selected.name}」の登録内容を見直したい。まず test_host で現状を確認して、問題や改善点があれば教えて。` })}><Ico d={I.search} size={13} className="" />「{selected.name}」を見直す</button>}
          <button className="btn-secondary min-h-[36px] rounded-lg border border-slate-600 bg-transparent px-3 text-[13px]" onClick={() => setHist(true)}><Ico d={I.history} size={13} className="" />履歴{sessions.length ? ` (${sessions.length})` : ""}</button>
        </div>}
        <button className={`min-h-[36px] px-2 text-[13px] text-slate-400 hover:text-slate-200 ${chatOk && open ? "" : "ml-auto"}`} onClick={() => setOpen(!open)}>{open ? "たたむ ▾" : "ひらく ▴"}</button>
      </div>
      {err && <div className="px-4 pt-2 text-xs text-rose-400">{err}</div>}
      {hist && <SessionHistory kind="host_setup" title="ホスト登録・見直しの相談履歴" currentId={sid} canAct={!!chatOk} onOpen={(id) => { setSid(id); setOpen(true); loadList(); }} onClose={() => setHist(false)} />}
      {open && <SessionChat key={sid ?? "new"} sid={sid} create={create} showProposal={false} className="flex-1 px-3 pb-2 pt-3" onEvent={(type, data) => { loadList(); if (type === "status" && /host changed/.test(data?.detail ?? "")) onChanged(); if (type === "tool_result" && ["register_host", "update_host", "test_host", "generate_ssh_key"].includes(data?.tool_call?.tool)) onChanged(); }}
        placeholder={sid ? "返信" : "登録したいホストのことを書くか、上のボタンから始めてください"}
        emptyHint={<AgentIntro compact lead={<>ホストの登録や見直しはもちろん、管理しているホストのことなら何でも聞いてください。登録は、鍵の用意 → 公開鍵の設置 → 登録 → 接続テスト → うまくいかないときの切り分けまで案内します。秘密鍵やパスワードをチャットに貼る必要はありません。</>} examples={["Ubuntu サーバーを SSH で登録したい", "Windows の端末を追加するには？", selected ? `「${selected.name}」の接続を確認して` : "登録済みホストの接続を確認して", "エージェントだけの端末と SSH ありの違いは？"]} onPick={(t) => { create(t, []).catch((e) => setErr(e.message)); }} />} />}
    </section>
  );
}

/** EDR-153: agents not imported again because their host was deleted in MamorAI — list and undo */
function SyncIgnoreButton({ onChanged, admin }: { onChanged: () => void; admin: boolean }) {
  type Item = { key: string; agent_id: string; name: string | null; status: string | null; deleted_at: string | null };
  const [items, setItems] = useState<Item[]>([]); const [open, setOpen] = useState(false); const [msg, setMsg] = useState("");
  const load = () => api.get<{ items: Item[] }>("/hosts/sync-ignore").then((r) => setItems(r.items)).catch(() => {});
  useEffect(() => { load(); }, []);
  if (!items.length) return null;
  const undo = async (it: Item) => { setMsg(""); try { const r = await api.del<{ created: string[] }>(`/hosts/sync-ignore/${encodeURIComponent(it.key)}`); setMsg(r.created.length ? `取り込みました: ${r.created.join(", ")}` : "対象外から外しました（Wazuh にエージェントが無いため、取り込むものはありませんでした）"); load(); onChanged(); } catch (e: any) { setMsg(e.message); } };
  return (
    <span className="relative">
      <button className="min-h-[40px] rounded-[10px] border border-[#6B5A19] px-3 text-[13px] text-[#F5D98A] hover:bg-[#2A2410]" onClick={() => setOpen(!open)} title="MamorAI で削除したため、自動では取り込まないエージェント">取り込み対象外 {items.length}</button>
      {open && <div className="absolute right-0 top-11 z-40 w-[420px] max-w-[90vw] rounded-xl border border-slate-600 bg-[#0D1428] p-3 text-[13px] shadow-xl">
        <div className="mb-2 text-slate-300">MamorAI の一覧から削除したため、自動では取り込まないエージェントです。元に戻すと、すぐに一覧へ取り込みます。</div>
        {items.map((it) => <div key={it.key} className="flex items-center gap-2 border-t border-slate-700 py-2">
          <div className="min-w-0 flex-1"><div className="font-mono text-slate-100">{it.name ?? "（Wazuh に無い）"} <span className="text-slate-500">agent {it.agent_id}</span></div><div className="text-[11.5px] text-slate-400">{it.status ?? "-"}{it.deleted_at ? ` · ${fmtTs(it.deleted_at)} に削除` : ""}</div></div>
          {admin && <button className="rounded-md border border-slate-500 px-2 py-1 text-[12px] hover:bg-slate-700" onClick={() => undo(it)}>元に戻す</button>}
        </div>)}
        {msg && <div className="mt-2 text-[12.5px] text-[#3CCB8C]">{msg}</div>}
      </div>}
    </span>
  );
}

// ---------------- page ----------------
export default function Hosts() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [params, setParams] = useSearchParams();
  const [items, setItems] = useState<Host[]>([]); const [selId, setSelId] = useState<number | null>(params.get("id") ? Number(params.get("id")) : null);
  const [editing, setEditing] = useState<"new" | "edit" | null>(null); const [q, setQ] = useState(""); const [err, setErr] = useState("");
  const [kind, setKind] = useState<"all" | "managed" | "agent_only">(() => { try { return (localStorage.getItem("hosts.kind") as any) || "all"; } catch { return "all"; } });
  const [syncing, setSyncing] = useState(false); const [packOpen, setPackOpen] = useState(false);
  const [pack, reloadPack] = usePackOverview(); const canPack = admin || user?.role === "operator";
  const latestRev = (h: Host) => (h.os_family === "windows" ? pack?.packs.windows.rev : h.os_family === "linux" ? pack?.packs.linux.rev : null);
  const sameRevs = (h: Host): number[] => {
    const w = pack?.packs.windows as any;
    if (h.os_family === "windows") { // EDR-171: a pack that differs only in the add-on is current when the add-on itself is current
      const av = (h as any).ar_addon_version as string | null; const pv = w?.addon_version as string | null;
      const addonOk = !!av && !!pv && !verLt(av, pv);
      return [...(w?.same_as ?? []), ...(addonOk ? (w?.addon_only ?? []) : [])];
    }
    return ((h.os_family === "linux" ? (pack?.packs.linux as any)?.same_as : null) ?? []);
  };
  const reload = () => api.get<{ items: Host[] }>("/hosts").then((r) => { setItems(r.items); setSelId((cur) => (cur && r.items.some((h) => h.id === cur) ? cur : r.items[0]?.id ?? null)); }).catch((e) => setErr(e.message));
  const [tick, setTick] = useState(0);
  useEffect(() => { reload(); }, []);
  // EDR-144: Contain requested / approved / applied / released elsewhere (approval queue, AI) → refresh the cards and the karte
  useEffect(() => {
    let t: ReturnType<typeof setTimeout> | null = null;
    const bump = () => { if (t) clearTimeout(t); t = setTimeout(() => { reload(); setTick((x) => x + 1); }, 600); };
    const off = onServerEvent("approval", bump);
    const iv = setInterval(bump, 60_000);
    return () => { off(); clearInterval(iv); if (t) clearTimeout(t); };
  }, []);
  useEffect(() => { if (selId) { params.set("id", String(selId)); setParams(params, { replace: true }); } }, [selId]);
  const sessionParam = params.get("session") ? Number(params.get("session")) : null;
  const filtered = useMemo(() => items.filter((h) => (kind === "all" || h.kind === kind) && (!q || [h.name, h.address, h.ssh_user, h.notes ?? "", h.agent_os ?? "", h.tags.join(" ")].some((x) => x.toLowerCase().includes(q.toLowerCase())))), [items, q, kind]);
  const setKindP = (k: typeof kind) => { setKind(k); try { localStorage.setItem("hosts.kind", k); } catch { /* ignore */ } };
  const sync = async () => { setSyncing(true); setErr(""); try { const r = await api.post<{ created: string[] }>("/hosts/sync"); await reload(); if (r.created.length) alert(`取り込みました: ${r.created.join(", ")}`); } catch (e: any) { setErr(e.message); } finally { setSyncing(false); } };
  const selected = items.find((h) => h.id === selId) ?? null;
  const managed = items.filter((h) => !agentOnly(h)), clients = items.filter(agentOnly);
  const ok = managed.filter((h) => h.last_test?.ok).length, ng = managed.filter((h) => h.last_test && !h.last_test.ok).length;
  const disc = clients.filter((h) => h.agent_status === "disconnected").length;
  return (
    <div className="flex h-[calc(100vh-3rem)] flex-col gap-4">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="flex items-center gap-2 text-[26px] font-bold"><Ico d={I.hosts} size={22} className="text-teal-300" />管理ホスト</h1>
        <span className="text-sm text-slate-400">サーバー {managed.length} 台（<span className="text-[#3CCB8C]">接続OK {ok}</span> · <span className="text-[#F2555A]">失敗 {ng}</span>） · エージェントだけ {clients.length} 台{disc ? <span className="text-[#F2555A]">（切断 {disc}）</span> : ""}</span>
        {canPack && <button className="btn-secondary ml-auto min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-3.5" title="Windows / Linux の端末に Wazuh エージェントと MamorAI アドオンを入れる一式（設定を変えると自動で新しい版になります）" onClick={() => setPackOpen(true)}>エージェントパック{(() => { const d = pack?.secrets?.tailscale?.days_left; return d !== null && d !== undefined && d <= 14 ? <span className="ml-1.5 rounded-full bg-[#5A4A1A] px-1.5 py-px text-[11px] text-[#F5C542]" title="Tailscale の認証キーの期限が近づいています">{d < 0 ? "キー期限切れ" : `キー残り ${d} 日`}</span> : null; })()}</button>}
        <SyncIgnoreButton onChanged={reload} admin={!!admin} />
        {admin && <button className={`btn-secondary ${canPack ? "" : "ml-auto "}min-h-[40px] rounded-[10px] border border-slate-600 bg-transparent px-3.5`} disabled={syncing} title="Wazuh に登録されているエージェントを、まだ無いものだけホストとして取り込みます（10 分ごとにも自動で実行）" onClick={sync}>{syncing ? "取り込み中…" : "Wazuh から取り込む"}</button>}
        {admin && <button className="btn-primary min-h-[40px] rounded-[10px] px-4 font-semibold" onClick={() => setEditing("new")}>＋ 手で追加</button>}
      </header>
      {err && <div className="text-sm text-rose-400">{err}</div>}
      <div className="flex min-h-0 flex-1 gap-5">
        <aside aria-label="ホスト一覧" className="flex w-80 shrink-0 flex-col gap-2.5 overflow-y-auto pr-1">
          <div role="tablist" aria-label="ホストの種類" className="flex gap-1 rounded-[10px] bg-slate-800 p-1 text-[12px]">{([["all", `すべて ${items.length}`], ["managed", `サーバー ${managed.length}`], ["agent_only", `クライアント等 ${clients.length}`]] as const).map(([k, l]) => <button key={k} role="tab" aria-selected={kind === k} className={`flex-1 rounded-lg px-2 py-1.5 ${kind === k ? "bg-teal-500 font-semibold text-white" : "text-slate-300 hover:bg-slate-700"}`} onClick={() => setKindP(k)}>{l}</button>)}</div>
          <input className="input min-h-[42px] rounded-[10px] bg-slate-800" aria-label="ホストを検索" placeholder="検索（名前・アドレス・OS・メモ）" value={q} onChange={(e) => setQ(e.target.value)} />
          {filtered.map((h) => <HostCard key={h.id} h={h} latest={latestRev(h)} same={sameRevs(h)} active={h.id === selId && !editing} onClick={() => { setSelId(h.id); setEditing(null); }} />)}
          {!filtered.length && <div className="text-xs text-slate-500">ホストがありません</div>}
        </aside>
        <section aria-label="ホストの詳細" className="min-w-0 flex-1 overflow-y-auto pr-1">
          {editing === "new" && <HostForm initial={null} onSaved={(h) => { setEditing(null); setSelId(h.id); reload(); }} onCancel={() => setEditing(null)} />}
          {editing === "edit" && selected && <HostForm initial={selected} onSaved={() => { setEditing(null); reload(); }} onCancel={() => setEditing(null)} />}
          {!editing && selected && <HostDetail id={selected.id} onEdit={() => setEditing("edit")} onReload={reload} refreshKey={tick} />}
          {!editing && !selected && <div className="text-sm text-slate-500">左の一覧からホストを選ぶか、「手で追加」または下の AI 相談から登録してください。</div>}
        </section>
      </div>
      <AiPanel selected={selected} onChanged={reload} sessionParam={sessionParam} editing={!!editing} />
      {packOpen && <AgentPackDialog onClose={() => { setPackOpen(false); reloadPack(); }} />}
    </div>
  );
}
