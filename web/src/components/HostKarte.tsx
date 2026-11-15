/**
 * EDR-121: ホストカルテ — "ホストを AI でスキャン" の結果と、遮断操作（承認キュー経由）。
 * 数字はすべて収集した事実（facts）から表示し、AI の解釈（profile）は文章と注目点だけに使う。
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { Chip, Section } from "./fields";
import InfoTip from "./InfoTip";
import WinUpdates, { type WinScan } from "./WinUpdates";

type Op = "stop_service" | "block_port" | "block_ip" | "isolate";
interface Listen { id: string; proto: string; port: number; local_ip: string; exposure: "local" | "lan" | "all" | "internet"; process: string | null; pid: number | null; service: string | null; known: string | null }
interface UserF { id: string; name: string; type: string; admin: boolean; groups: string[]; last_logon?: string | null; logons_7d?: number; failures_7d?: number; logon_types?: Record<string, number>; sources?: string[] }
interface Profile { id: number; finished_at: string; model: string | null; tokens: number; facts: any; profile: any; diff: any }
interface Resp { host: any; capability: { ok: boolean; via: string; locked?: boolean; reason?: string; addon?: { version: string | null; min: string; checked_at: string | null; ok: boolean } }; latest: { id: number; status: string; stage: string | null; trigger: string; error: string | null; created_at: string; started_at: string | null; finished_at: string | null } | null; scan: Profile | null; actions: any[]; win_updates?: WinScan | null; addon_published?: string | null; pack_windows?: { latest: number | null; addon_only: number[]; same_as: number[]; addon_version: string | null } | null }

const EXPO: Record<string, { ja: string; tone: "rose" | "amber" | "teal" | "slate" }> = { internet: { ja: "外部から届く可能性", tone: "rose" }, all: { ja: "全インターフェース（LAN）", tone: "amber" }, lan: { ja: "LAN", tone: "teal" }, local: { ja: "このホストだけ", tone: "slate" } };
const STAGES: [string, string][] = [["collect", "集める"], ["normalize", "整える"], ["ai", "AI が解釈"], ["save", "保存"]];
const LOGON_JA: Record<string, string> = { "2": "対話", "3": "ネットワーク", "4": "バッチ", "5": "サービス", "7": "ロック解除", "8": "平文ネットワーク", "9": "別資格情報", "10": "RDP", "11": "キャッシュ", ssh: "SSH" };
const OP_JA: Record<Op, string> = { stop_service: "サービスを止める", block_port: "ポートを遮断", block_ip: "相手 IP を遮断", isolate: "インターネット通信遮断（Contain）" };
const STATUS_JA: Record<string, { ja: string; tone: "amber" | "rose" | "emerald" | "slate" | "sky" }> = { pending: { ja: "承認待ち", tone: "amber" }, active: { ja: "有効", tone: "rose" }, unconfirmed: { ja: "送信済み・結果未確認", tone: "sky" }, running: { ja: "実行中", tone: "sky" }, reverted: { ja: "解除済み", tone: "slate" }, failed: { ja: "失敗", tone: "rose" }, rejected: { ja: "却下", tone: "slate" }, done: { ja: "完了", tone: "emerald" }, cancelled: { ja: "取り消し済み", tone: "slate" } };
const CONTAIN_OPS = ["stop_service", "block_port", "block_ip", "isolate"];
const verGt = (a: string, b: string) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0); } return false; };
/** EDR-168: what the update / reboot action did, in one line */
const updSummary = (a: any) => { const p = a.params ?? {}; if (a.op === "reboot") return `${p.minutes ?? "?"} 分後`; if (a.op !== "update_install") return ""; const r = a.result?.detail ?? {}; return [p.wu && p.wu !== "none" ? `WU: ${p.wu}${p.kbs?.length ? ` ${p.kbs.join(",")}` : ""}` : "", p.apps ? `アプリ: ${p.apps === "all" ? "すべて" : p.apps.join(",")}` : "", r.installed ? `入った: ${r.installed}` : "", r.reboot_required === true || r.reboot_required === "true" ? "要再起動" : ""].filter(Boolean).join(" · "); };
const DAYS = ["日", "月", "火", "水", "木", "金", "土"];
const SEV_TONE: Record<string, "rose" | "amber" | "slate"> = { high: "rose", medium: "amber", low: "slate" };
const EXPO_RANK: Record<string, number> = { internet: 3, all: 2, lan: 1, local: 0 };
const RPC_PROCS = /^(svchost|lsass|services|wininit|spoolsv|system)(\.exe)?$/i;
interface PortRow { key: string; ids: string[]; proto: string; port: number; addrs: string[]; exposure: Listen["exposure"]; process: string | null; service: string | null; known: string | null }
/** EDR-141: one row per protocol/port (0.0.0.0 and :: together); Windows dynamic RPC ports and loopback-only ports are folded */
export function groupPorts(ports: Listen[], windows: boolean): { main: PortRow[]; dynamic: PortRow[]; local: PortRow[] } {
  const m = new Map<string, PortRow>();
  for (const l of ports) {
    const key = `${l.proto}/${l.port}`;
    const r = m.get(key);
    if (!r) m.set(key, { key, ids: [l.id], proto: l.proto, port: l.port, addrs: [l.local_ip], exposure: l.exposure, process: l.process, service: l.service, known: l.known });
    else {
      if (!r.ids.includes(l.id)) r.ids.push(l.id);
      if (!r.addrs.includes(l.local_ip)) r.addrs.push(l.local_ip);
      if (EXPO_RANK[l.exposure] > EXPO_RANK[r.exposure]) r.exposure = l.exposure;
      r.process ??= l.process; r.service ??= l.service; r.known ??= l.known;
    }
  }
  const rows = [...m.values()].sort((a, b) => EXPO_RANK[b.exposure] - EXPO_RANK[a.exposure] || a.port - b.port);
  const isDynamic = (r: PortRow) => windows && r.port >= 49152 && !r.known && (!r.process || RPC_PROCS.test(r.process));
  return { main: rows.filter((r) => r.exposure !== "local" && !isDynamic(r)), dynamic: rows.filter((r) => r.exposure !== "local" && isDynamic(r)), local: rows.filter((r) => r.exposure === "local") };
}

function ago(iso?: string | null) { if (!iso) return ""; const t = new Date(/Z|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso.replace(" ", "T") + "Z").getTime(); const s = (Date.now() - t) / 1000; return s < 60 ? "たった今" : s < 3600 ? `${Math.floor(s / 60)} 分前` : s < 86400 ? `${Math.floor(s / 3600)} 時間前` : `${Math.floor(s / 86400)} 日前`; }

function Heatmap({ m }: { m: number[][] }) {
  const max = Math.max(1, ...m.flat());
  return (
    <div className="overflow-x-auto">
      <div className="inline-grid gap-[2px]" style={{ gridTemplateColumns: `1.4rem repeat(24, 0.85rem)` }}>
        <span />{Array.from({ length: 24 }, (_, h) => <span key={h} className="text-center text-[9px] text-slate-500">{h % 3 === 0 ? h : ""}</span>)}
        {m.map((row, d) => [<span key={`d${d}`} className="text-[10px] text-slate-400">{DAYS[d]}</span>, ...row.map((v, h) => <span key={`${d}-${h}`} title={`${DAYS[d]} ${h}時: ${v} 件`} className="h-[0.85rem] rounded-[2px]" style={{ background: v ? `rgba(58,86,240,${0.18 + 0.82 * (v / max)})` : "#1E293B" }} />)])}
      </div>
      <div className="mt-1 text-[11px] text-slate-500">7 日間のアラート件数（JST、濃いほど多い）。操作した時間帯の目安。</div>
    </div>
  );
}

/** EDR-142: ⓘ next to the Contain button — short explanation + link to the per-host page (case studies, AI impact, consultation chat) */
export function ContainTip({ hostId }: { hostId: number }) {
  return (
    <InfoTip title="インターネット通信遮断（Contain）とは" href={`/hosts/${hostId}/contain`} linkLabel="詳しい説明と、この端末への影響" align="right">
      <b className="text-slate-100">押すと</b>: Wazuh（MamorAI）との通信だけを残して、この端末のインターネット・社内 LAN の通信をすべて止めます。端末の電源やアプリはそのままです。承認キューで承認されてから実行され、解除するまで続きます。<br />
      <b className="text-slate-100">使うとき</b>: ランサムウェアらしい動き、見覚えのない遠隔操作ソフト、怪しい宛先への通信、乗っ取りの疑いなど、「この端末から被害が広がりそう」なとき。ポート 1 つだけ止めれば済むなら、下の一覧の「遮断」を使います。
    </InfoTip>
  );
}

export function ContainButton({ enabled, why, onClick }: { enabled: boolean; why: string; onClick: () => void }) {
  return <button className="inline-flex min-h-[38px] shrink-0 items-center gap-1.5 rounded-[10px] bg-[#C62F38] px-3.5 text-[13px] font-bold text-white shadow hover:bg-[#D83A44] disabled:cursor-not-allowed disabled:opacity-50" disabled={!enabled} title={why || "Wazuh との通信だけを残して、この端末の通信をすべて止めます（承認が必要）"} onClick={onClick}>
    <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></svg>インターネット通信遮断（Contain）</button>;
}

function PortTr({ l, s, svcName, can, act }: { l: PortRow; s: any; svcName: string | null; can: boolean; act: (op: Op, params: any, reason?: string) => void }) {
  return (
    <tr className="border-t border-slate-700/60 align-top">
      <td className="py-1.5 pr-2"><div className="font-semibold text-slate-100">{s?.name ?? l.known ?? l.service ?? l.process ?? "?"}</div><div className="font-mono text-[11px] text-slate-500">{l.process}{l.service && l.service !== l.process ? ` / ${l.service}` : ""}</div></td>
      <td className="pr-2 font-mono text-slate-200">{l.proto}/{l.port}<div className="text-[10px] text-slate-500">{l.addrs.join(" ")}</div></td>
      <td className="pr-2"><Chip tone={EXPO[l.exposure].tone}>{EXPO[l.exposure].ja}</Chip></td>
      <td className="pr-2 text-slate-300">{s?.purpose ?? ""}{s?.exposure_note && <div className="text-[11px] text-amber-300">{s.exposure_note}</div>}</td>
      <td className="whitespace-nowrap">{can && <span className="flex flex-col gap-1">{svcName && <button className="rounded-md border border-slate-600 px-1.5 py-0.5 text-[11px] hover:bg-slate-700" onClick={() => act("stop_service", { service: svcName })}>止める</button>}<button className="rounded-md border border-[#4A1E24] px-1.5 py-0.5 text-[11px] text-[#FF9A9D] hover:bg-[#2A1216]" onClick={() => act("block_port", { proto: l.proto, port: l.port })}>遮断</button></span>}</td>
    </tr>
  );
}

export function ActionDialog({ hostId, hostName, init, onClose, onDone, admin }: { hostId: number; hostName: string; init: { op: Op; params: any; reason?: string }; onClose: () => void; onDone: (approvalId: number) => void; admin: boolean }) {
  const [p, setP] = useState<any>(init.params ?? {}); const [reason, setReason] = useState(init.reason ?? ""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const impact: Record<Op, string> = {
    stop_service: "このサービスが提供している機能が使えなくなります。再起動後に自動で起動する設定は変えません（「自動起動も無効化」を選んだ場合を除く）。",
    block_port: "このポートへの受信がすべて遮断されます。正規の利用者も使えなくなります。",
    block_ip: "この相手との通信（送受信）がすべて遮断されます。",
    isolate: "Wazuh manager との通信（と、SSH のホストでは MamorAI からの SSH、ノート PC では Tailscale）以外の通信がすべて止まります。利用者は作業できなくなります。自動では解除されません。",
  };
  const submit = async () => {
    setBusy(true); setErr("");
    try { const r = await api.post<{ approval_id: number }>(`/hosts/${hostId}/actions`, { op: init.op, params: p, reason: reason || undefined }); onDone(r.approval_id); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="遮断の依頼">
      <div className="flex w-full max-w-lg flex-col gap-3 rounded-2xl border border-slate-600 bg-slate-800 p-5">
        <h3 className="text-lg font-bold">{hostName}: {OP_JA[init.op]}</h3>
        {init.op === "stop_service" && <div className="text-sm">サービス: <code className="font-mono text-teal-200">{p.service}</code><label className="ml-3 inline-flex items-center gap-1.5 text-xs text-slate-300"><input type="checkbox" checked={!!p.disable} onChange={(e) => setP({ ...p, disable: e.target.checked })} />自動起動も無効化（Linux）</label></div>}
        {init.op === "block_port" && <div className="text-sm">受信を遮断: <code className="font-mono text-teal-200">{String(p.proto).toUpperCase()} {p.port}</code></div>}
        {init.op === "block_ip" && <div className="text-sm">送受信を遮断: <code className="font-mono text-teal-200">{p.ip}</code></div>}
        {init.op === "isolate" && <div className="flex flex-col gap-1.5 text-sm">
          <label className="inline-flex items-center gap-2"><input type="checkbox" checked={!!p.allow_dns} onChange={(e) => setP({ ...p, allow_dns: e.target.checked })} />DNS への通信は残す</label>
          <label className="inline-flex items-center gap-2"><input type="checkbox" checked={!!p.allow_ad} onChange={(e) => setP({ ...p, allow_ad: e.target.checked })} />AD（ドメインコントローラー）への通信は残す（Windows、ドメイン参加端末）</label>
          {!admin && <div className="text-xs text-rose-300">通信遮断（Contain）の依頼は管理者だけができます</div>}
        </div>}
        <div className="rounded-[10px] border border-[#6B5A19] bg-[#2A2410] px-3 py-2 text-[13px] leading-relaxed text-[#F5D98A]">{impact[init.op]}</div>
        <label className="text-xs text-slate-400">理由（承認する人に見えます）<textarea className="input mt-1 min-h-[4rem]" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="例: 不審な外部通信が続いているため一時的に遮断" /></label>
        <div className="text-xs text-slate-400">すぐには実行されません。承認キューに積まれ、人が承認したときに実行されます。解除もホスト画面から承認を通して行えます。</div>
        {err && <div className="text-sm text-rose-400">{err}</div>}
        <div className="flex justify-end gap-2"><button className="btn-secondary min-h-[38px] rounded-[10px] border border-slate-600 bg-transparent px-4" onClick={onClose}>やめる</button><button className="btn-primary min-h-[38px] rounded-[10px] px-4" disabled={busy || (init.op === "isolate" && !admin)} onClick={submit}>承認キューに積む</button></div>
      </div>
    </div>
  );
}

export default function HostKarte({ hostId, canAct, admin, onChanged, refreshKey }: { hostId: number; canAct: boolean; admin: boolean; onChanged?: () => void; refreshKey?: number }) {
  const nav = useNavigate();
  const [d, setD] = useState<Resp | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [msg, setMsg] = useState("");
  const [dlg, setDlg] = useState<{ op: Op; params: any; reason?: string } | null>(null);
  const [allPorts, setAllPorts] = useState(false); const [showDyn, setShowDyn] = useState(false); const [showLocal, setShowLocal] = useState(false); const [swq, setSwq] = useState(""); const [showExt, setShowExt] = useState(false);
  const timer = useRef<number | null>(null);
  const load = () => api.get<Resp>(`/hosts/${hostId}/profile`).then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { if (refreshKey) load(); }, [refreshKey]);
  useEffect(() => { setD(null); setMsg(""); load(); return () => { if (timer.current) window.clearTimeout(timer.current); }; }, [hostId]);
  const addonBusy = (d?.actions ?? []).find((a: any) => a.op === "addon_update" && a.status === "running");
  const packBusy = (d?.actions ?? []).find((a: any) => a.op === "pack_update" && a.status === "running");
  const resOf = (a: any) => (typeof a?.result === "string" ? (() => { try { return JSON.parse(a.result); } catch { return null; } })() : a?.result);
  // EDR-171: is the pack on this PC out of date? (a pack that differs only in the add-on is fine when the add-on is current)
  const packOld = (() => {
    const pw = d?.pack_windows; const rev = Number(d?.host?.pack_rev ?? 0); if (!pw?.latest || !rev || rev >= pw.latest) return false;
    if (pw.same_as.includes(rev)) return false;
    const av = d?.capability?.addon?.version; if (pw.addon_only.includes(rev) && av && pw.addon_version && !verGt(pw.addon_version, av)) return false;
    return true;
  })();
  const scanning = (d?.latest && ["queued", "running"].includes(d.latest.status)) || !!addonBusy || !!packBusy;
  const wasScanning = useRef(false);
  useEffect(() => {
    if (scanning) { wasScanning.current = true; timer.current = window.setTimeout(() => { load(); }, 3000); }
    else if (wasScanning.current) { wasScanning.current = false; onChanged?.(); }
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, [d]);
  const f = d?.scan?.facts; const pr = d?.scan?.profile ?? {}; const diff = d?.scan?.diff;
  const purposeOf = useMemo(() => { const m = new Map<string, any>(); for (const s of pr.services ?? []) for (const e of s.evidence ?? []) if (String(e).startsWith("port:")) m.set(e, s); return m; }, [pr]);
  const startScan = async () => { setBusy(true); setMsg(""); try { await api.post(`/hosts/${hostId}/scan`); await load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const checkAddon = async () => { setBusy(true); setMsg("端末に問い合わせ中…（最大 90 秒）"); try { const r = await api.post<{ message: string }>(`/hosts/${hostId}/addon-check`); setMsg(r.message); await load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const revert = async (a: any) => { if (!confirm(`「${a.label}」の解除を承認キューに積みますか？`)) return; try { const r = await api.post<{ approval_id: number }>(`/hosts/${hostId}/actions/${a.id}/revert`, {}); setMsg(`解除を承認キューに積みました（承認 #${r.approval_id}）`); load(); } catch (e: any) { setMsg(e.message); } };
  const can = canAct && !!d?.capability.ok;
  const act = (op: Op, params: any, reason?: string) => setDlg({ op, params, reason });

  if (err) return <div className="text-sm text-rose-400">{err}</div>;
  if (!d) return <div className="text-sm text-slate-500">カルテを読み込み中…</div>;
  const h = d.host; const cap = d.capability;
  const activeActions = d.actions.filter((a) => ["pending", "active", "unconfirmed", "failed"].includes(a.status));
  const iso = activeActions.find((a) => a.op === "isolate" && ["active", "unconfirmed"].includes(a.status));
  const ports: Listen[] = f?.listening ?? [];
  const pg = groupPorts(ports, h.os_family === "windows" || /windows/i.test(String(f?.system?.os ?? h.agent_os ?? "")));
  const sw = (f?.software?.items ?? []).filter((x: any) => !swq || x.name.toLowerCase().includes(swq.toLowerCase()));
  const users: UserF[] = f?.users ?? [];

  return (
    <div className="flex flex-col gap-3.5">
      {/* header */}
      <div className="flex flex-wrap items-center gap-2.5 rounded-[14px] border border-slate-700 bg-slate-800 px-4 py-3">
        <span className="text-[17px] font-bold">ホストカルテ</span>
        {d.scan ? <span className="text-xs text-slate-400">最終スキャン {fmtTs(d.scan.finished_at)}（{ago(d.scan.finished_at)}）{d.scan.model ? ` · ${d.scan.model}` : ""}</span> : <span className="text-xs text-slate-500">まだスキャンしていません</span>}
        {diff && !diff.first && <span className="flex flex-wrap gap-1">{diff.new_exposed_ports?.length > 0 && <Chip tone="rose">新しい公開ポート {diff.new_exposed_ports.length}</Chip>}{diff.new_admins?.length > 0 && <Chip tone="rose">新しい管理者 {diff.new_admins.length}</Chip>}{diff.new_remote_tools?.length > 0 && <Chip tone="rose">リモート操作ソフト {diff.new_remote_tools.length}</Chip>}{diff.new_software?.length > 0 && <Chip tone="amber">ソフト追加 {diff.new_software.length}</Chip>}{diff.new_services?.length > 0 && <Chip tone="amber">サービス追加 {diff.new_services.length}</Chip>}</span>}
        <div className="ml-auto flex items-center gap-2">
          {scanning && <span className="flex items-center gap-1.5 text-xs text-teal-200">{d.latest!.status === "queued" ? "順番待ち…" : STAGES.map(([k, ja]) => <span key={k} className={d.latest!.stage === k ? "font-bold text-white" : "text-slate-500"}>{ja}</span>).reduce((acc: any[], el, i) => (i ? [...acc, <span key={`s${i}`} className="text-slate-600">→</span>, el] : [el]), [])}</span>}
          {canAct && <button className="btn-primary min-h-[38px] rounded-[10px] px-3.5" disabled={busy || !!scanning} onClick={startScan}>{scanning ? "スキャン中…" : "ホストを AI でスキャン"}</button>}
          {canAct && !iso && cap.locked && <span className="inline-flex min-h-[38px] items-center gap-1.5 rounded-[10px] border border-slate-500 px-3 text-[13px] font-semibold text-slate-200">🛡 遮断の対象外<InfoTip title="このホストは遮断しません" align="right">{cap.reason}<br />ほかの端末の Contain では、このホストへの通信は止めずに残します。</InfoTip></span>}
          {canAct && !iso && !cap.locked && <span className="inline-flex items-center text-[#FF9A9D]"><ContainButton enabled={can && admin} why={!can ? (cap.reason ?? "この端末では遮断操作が使えません") : !admin ? "管理者だけが依頼できます" : ""} onClick={() => act("isolate", {})} /><ContainTip hostId={hostId} /></span>}
        </div>
      </div>
      {d.latest?.status === "failed" && <div className="rounded-[10px] border border-[#6B2329] bg-[#2A1216] px-3.5 py-2.5 text-[13px] text-[#FF9A9D]">前回のスキャンは失敗しました: {d.latest.error}</div>}
      {pr.note && <div className="rounded-[10px] border border-slate-600 bg-slate-900 px-3.5 py-2 text-[13px] text-slate-300">{pr.note}</div>}
      {msg && <div className="rounded-[10px] border border-slate-600 bg-slate-900 px-3.5 py-2 text-[13px] text-slate-200">{msg}</div>}
      {iso && <div className="flex flex-wrap items-center gap-3 rounded-[12px] border border-[#8A2A30] bg-[#3A1418] px-4 py-3 text-[14px] text-[#FFB3B6]"><b>通信遮断中（Contain）</b><span>{fmtTs(iso.applied_at)} から。Wazuh との通信だけ許可しています。</span>{h.os_family === "windows" && <span className="text-xs text-[#FF9A9D]">manager とつながらない場合は、端末で管理者が <code>mamorai-ar.cmd unisolate</code> を実行すると戻ります。</span>}{canAct && <button className="ml-auto rounded-lg border border-[#FF9A9D] px-3 py-1.5 text-[13px] hover:bg-[#4A1E24]" onClick={() => revert(iso)}>通信遮断を解除</button>}</div>}
      {!cap.ok && cap.locked && <div className="flex flex-wrap items-center gap-2 rounded-[10px] border border-slate-600 bg-slate-900 px-3.5 py-2 text-[13px] text-slate-300">🛡 {cap.reason}</div>}
      {!cap.ok && !cap.locked && <div className="flex flex-wrap items-center gap-2 rounded-[10px] border border-[#6B5A19] bg-[#2A2410] px-3.5 py-2 text-[13px] text-[#F5D98A]"><span>遮断操作: {cap.reason}</span>{cap.via === "wazuh_ar" && canAct && <button className="rounded-md border border-[#F5D98A]/60 px-2 py-0.5 text-xs hover:bg-[#3A3010]" disabled={busy} onClick={checkAddon}>アドオンの版を確認</button>}</div>}
      {h.os_family === "windows" && cap.via === "wazuh_ar" && <WinUpdates hostId={hostId} hostName={h.name} scan={d.win_updates ?? null} addonVersion={cap.addon?.version ?? h.ar_addon_version ?? null} canAct={canAct} onChanged={load} />}
      {!d.scan && !scanning && <div className="rounded-[14px] border border-dashed border-slate-600 px-5 py-6 text-sm leading-relaxed text-slate-400">「ホストを AI でスキャン」を押すと、Wazuh に集まっているインベントリ・ログ（SSH のホストは読み取り専用のコマンドも）から、<b className="text-slate-200">提供しているサービス・入っているソフト・ログインしているユーザー・使われ方</b>をここに並べます。読み取りだけなので承認は要りません。外部の AI に送るユーザー名は仮名に置き換えます。</div>}

      {f && <div className="grid gap-3.5 [overflow-wrap:anywhere] [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))] [&>*]:min-w-0">
        {/* ① 概要 */}
        <Section title="① 概要" icon="🔍">
          {pr.summary ? <p className="text-[14px] leading-relaxed text-slate-100">{pr.summary}</p> : <p className="text-xs text-slate-500">AI の要約はありません（事実だけ表示しています）</p>}
          <div className="flex flex-wrap gap-1.5">{(pr.role_tags ?? []).map((t: string) => <Chip key={t} tone="teal">#{t}</Chip>)}{typeof pr.confidence === "number" && pr.summary && <span className="text-[11px] text-slate-500">確度 {Math.round(pr.confidence * 100)}%</span>}</div>
          {pr.usage?.primary_use && <div className="text-[13px] text-slate-200">主な用途: {pr.usage.primary_use}</div>}
          {(pr.usage?.notes ?? []).length > 0 && <ul className="list-disc pl-5 text-[13px] text-slate-300">{pr.usage.notes.map((n: string, i: number) => <li key={i}>{n}</li>)}</ul>}
          <dl className="grid grid-cols-[5rem_minmax(0,1fr)] gap-x-2 gap-y-1 text-[12px]">
            <dt className="text-slate-400">OS</dt><dd className="text-slate-200">{f.system?.os ?? h.agent_os ?? "-"}</dd>
            <dt className="text-slate-400">CPU / メモリ</dt><dd className="text-slate-200">{f.system?.cpu ?? "-"}{f.system?.cores ? `（${f.system.cores} コア）` : ""}{f.system?.memory_gb ? ` / ${f.system.memory_gb} GB` : ""}</dd>
            <dt className="text-slate-400">IP</dt><dd className="font-mono text-slate-200">{(f.system?.ips ?? []).slice(0, 6).join(", ") || h.address}{f.system?.has_public_ip && <Chip tone="rose">グローバル IP あり</Chip>}</dd>
            <dt className="text-slate-400">設定監査</dt><dd className="text-slate-200">{(f.sca ?? []).map((s: any) => `${s.policy}: ${s.score}%（不合格 ${s.fail}）`).join(" / ") || "-"}</dd>
          </dl>
        </Section>

        {/* ② 提供サービス */}
        <Section title="② 提供サービス（待ち受けポート）" icon="🔌" count={pg.main.length}>
          <div className="text-[11px] text-slate-500">同じポートの IPv4 / IPv6 は 1 行にまとめています（全 {ports.length} 件）。</div>
          {pg.main.length ? <div className="overflow-x-auto"><table className="w-full text-[12px]"><thead><tr className="text-left text-slate-400"><th className="py-1 pr-2 font-normal">名前</th><th className="pr-2 font-normal">ポート</th><th className="pr-2 font-normal">公開範囲</th><th className="pr-2 font-normal">用途（AI）</th><th /></tr></thead>
            <tbody>{(allPorts ? pg.main : pg.main.slice(0, 10)).map((l) => <PortTr key={l.key} l={l} s={l.ids.map((i) => purposeOf.get(i)).find(Boolean)} svcName={l.service ?? (f.ssh?.units ?? []).find((u: any) => u.name === l.process)?.name ?? null} can={can} act={act} />)}</tbody></table>
            {pg.main.length > 10 && <button className="mt-1 text-xs text-teal-300 hover:underline" onClick={() => setAllPorts(!allPorts)}>{allPorts ? "たたむ" : `すべて表示（${pg.main.length}）`}</button>}</div> : <div className="text-xs text-slate-500">外から届く待ち受けポートはありません</div>}
          {pg.dynamic.length > 0 && <div className="text-[12px] text-slate-400"><button className="hover:text-slate-200" onClick={() => setShowDyn(!showDyn)}>Windows の動的ポート（RPC など、49152 以上）{pg.dynamic.length} 件 {showDyn ? "▾" : "▸"}</button>
            {showDyn && <div className="mt-1 flex flex-wrap gap-1">{pg.dynamic.map((l) => <span key={l.key} className="rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-300" title={`${l.process ?? ""} ${l.addrs.join(" ")}`}>{l.proto}/{l.port}</span>)}</div>}
            <div className="text-[11px] text-slate-500">Windows が自動で割り当てるポートで、普通は 1 つずつ止めるものではありません。</div></div>}
          {pg.local.length > 0 && <div className="text-[12px] text-slate-400"><button className="hover:text-slate-200" onClick={() => setShowLocal(!showLocal)}>このホストの中だけで待ち受け（127.0.0.1 など）{pg.local.length} 件 {showLocal ? "▾" : "▸"}</button>
            {showLocal && <div className="mt-1 flex flex-wrap gap-1">{pg.local.map((l) => <span key={l.key} className="rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-300" title={l.process ?? ""}>{l.proto}/{l.port}{l.process ? ` ${l.process}` : ""}</span>)}</div>}</div>}
          {(f.services ?? []).length > 0 && <details className="text-[12px] text-slate-300"><summary className="cursor-pointer text-slate-400">動いているサービス {f.services.length} 件{f.services_total ? `（全 ${f.services_total} 件中）` : ""}</summary><div className="mt-1 flex flex-wrap gap-1">{f.services.map((s: any) => <span key={s.id} className="inline-flex items-center gap-1 rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[11px]" title={s.display ?? ""}>{s.name}{can && <button className="text-slate-500 hover:text-rose-300" title="このサービスを止める" onClick={() => act("stop_service", { service: s.name })}>■</button>}</span>)}</div></details>}
          {f.ssh?.units?.length > 0 && <details className="text-[12px] text-slate-300"><summary className="cursor-pointer text-slate-400">systemd で動いているサービス {f.ssh.units.length} 件（SSH）</summary><div className="mt-1 flex flex-wrap gap-1">{f.ssh.units.map((u: any) => <span key={u.id} className="inline-flex items-center gap-1 rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[11px]">{u.name}{can && <button className="text-slate-500 hover:text-rose-300" title="このサービスを止める" onClick={() => act("stop_service", { service: u.name })}>■</button>}</span>)}</div></details>}
        </Section>

        {/* ③ ソフト */}
        <Section title="③ ソフト" icon="📖" count={f.software?.total ?? 0}>
          {(pr.software_highlights ?? []).length > 0 && <ul className="flex flex-col gap-1.5">{pr.software_highlights.map((s: any, i: number) => <li key={i} className="text-[13px]"><b className="text-slate-100">{s.name}</b>{s.category && <span className="ml-1.5"><Chip tone="amber">{s.category}</Chip></span>}<div className="text-xs text-slate-400">{s.why}</div></li>)}</ul>}
          <div className="text-[12px] text-slate-300">脆弱性: <b className="text-[#FF9A9D]">Critical {f.vulns?.by_severity?.Critical ?? 0}</b> / High {f.vulns?.by_severity?.High ?? 0} / 全 {f.vulns?.total ?? 0}{(f.vulns?.top_packages ?? []).length > 0 && <span className="text-slate-400"> — 多い順: {f.vulns.top_packages.slice(0, 5).map((p: any) => `${p.name}（${p.count}${p.critical ? `、C ${p.critical}` : ""}）`).join("、")}</span>}</div>
          {f.software?.hotfixes > 0 && <div className="text-[12px] text-slate-400">適用済みの更新 {f.software.hotfixes} 件（新しい順: {f.software.latest_hotfixes.slice(0, 4).join(", ")}）</div>}
          <input className="input min-h-[34px] text-[12px]" placeholder="ソフトを検索" value={swq} onChange={(e) => setSwq(e.target.value)} />
          <div className="max-h-48 overflow-y-auto rounded-lg bg-slate-900 p-2 text-[11px]">{sw.slice(0, 200).map((x: any) => <div key={x.id + x.version} className="flex justify-between gap-2 border-b border-slate-800 py-0.5"><span className="truncate text-slate-200">{x.name}</span><span className="shrink-0 font-mono text-slate-500">{x.version}</span></div>)}{!sw.length && <span className="text-slate-500">なし</span>}</div>
          {(f.software?.browser_extensions ?? []).length > 0 && <div className="text-[12px]"><button className="text-slate-400 hover:text-slate-200" onClick={() => setShowExt(!showExt)}>ブラウザ拡張 {f.software.browser_extensions.length} 件 {showExt ? "▾" : "▸"}</button>{showExt && <ul className="mt-1 max-h-40 overflow-y-auto text-[11px] text-slate-300">{f.software.browser_extensions.map((e: any) => <li key={e.id}>{e.name} <span className="text-slate-500">{e.browser}{e.from_store === false ? "・ストア外" : ""}{e.enabled === false ? "・無効" : ""}</span></li>)}</ul>}</div>}
        </Section>

        {/* ④ ユーザーとログイン */}
        <Section title="④ ユーザーとログイン（7 日）" icon="🛡️" count={users.length}>
          {(pr.users ?? []).length > 0 && <ul className="flex flex-col gap-1">{pr.users.map((u: any, i: number) => <li key={i} className="text-[13px]"><b className="font-mono text-slate-100">{u.name}</b> <span className="text-slate-300">{u.finding}</span></li>)}</ul>}
          <div className="overflow-x-auto"><table className="w-full text-[12px]"><thead><tr className="text-left text-slate-400"><th className="py-1 pr-2 font-normal">ユーザー</th><th className="pr-2 font-normal">最終ログイン</th><th className="pr-2 font-normal">方法</th><th className="pr-2 font-normal">成功/失敗</th><th className="font-normal">接続元</th></tr></thead>
            <tbody>{users.slice(0, 30).map((u) => <tr key={u.id} className="border-t border-slate-700/60 align-top"><td className="py-1 pr-2"><span className="font-mono text-slate-100">{u.name}</span>{u.admin && <span className="ml-1"><Chip tone="amber">管理者</Chip></span>}<div className="text-[10px] text-slate-500">{u.type === "seen_in_logs" ? "ログに出現" : u.type}</div></td><td className="pr-2 text-slate-300">{u.last_logon ? ago(u.last_logon) : "-"}</td><td className="pr-2 text-slate-300">{Object.entries(u.logon_types ?? {}).filter(([, n]) => n).map(([k, n]) => `${LOGON_JA[k] ?? k} ${n}`).join("・") || "-"}</td><td className="pr-2"><span className="text-slate-200">{u.logons_7d ?? 0}</span>{(u.failures_7d ?? 0) > 0 && <span className="text-[#FF9A9D]"> / {u.failures_7d}</span>}</td><td className="font-mono text-[11px] text-slate-400">{(u.sources ?? []).join(", ")}</td></tr>)}</tbody></table></div>
          {f.ssh?.logged_in?.length > 0 && <div className="text-[12px] text-slate-300">いまログイン中（SSH 確認）: <span className="font-mono">{f.ssh.logged_in.join(" / ")}</span></div>}
        </Section>

        {/* ⑤ 使われ方 */}
        <Section title="⑤ 使われ方" icon="📡">
          <Heatmap m={f.activity?.heatmap ?? Array.from({ length: 7 }, () => Array(24).fill(0))} />
          <div className="grid gap-3 sm:grid-cols-2">
            <div><div className="mb-1 text-[12px] text-slate-400">よく動いているプロセス</div><ul className="text-[12px] text-slate-200">{(f.processes ?? []).slice(0, 10).map((p: any) => <li key={p.id} className="flex justify-between gap-2"><span className="truncate font-mono" title={p.sample_cmd ?? ""}>{p.name}</span><span className="text-slate-500">×{p.count}</span></li>)}</ul></div>
            <div><div className="mb-1 text-[12px] text-slate-400">通信している相手（接続中）</div><ul className="text-[12px] text-slate-200">{(f.connections ?? []).slice(0, 10).map((c: any) => <li key={c.id + c.process} className="flex items-center justify-between gap-2"><span className="truncate font-mono" title={c.process ?? ""}>{c.remote_ip}:{c.remote_port}</span><span className="truncate text-[11px] text-slate-500">{c.process}</span>{can && <button className="shrink-0 rounded border border-[#4A1E24] px-1 text-[10px] text-[#FF9A9D] hover:bg-[#2A1216]" title="この相手との通信を遮断" onClick={() => act("block_ip", { ip: c.remote_ip })}>遮断</button>}</li>)}{!(f.connections ?? []).length && <li className="text-slate-500">なし</li>}</ul></div>
          </div>
          {f.ssh?.containers?.length > 0 && <div className="text-[12px] text-slate-300">コンテナ: {f.ssh.containers.map((c: any) => `${c.name}（${c.image}）`).join("、")}</div>}
          {f.ssh?.cron?.length > 0 && <details className="text-[12px]"><summary className="cursor-pointer text-slate-400">定期実行（cron）{f.ssh.cron.length} 件</summary><pre className="mt-1 max-h-40 overflow-y-auto whitespace-pre-wrap rounded bg-slate-900 p-2 font-mono text-[11px] text-slate-300">{f.ssh.cron.map((c: any) => c.line).join("\n")}</pre></details>}
          {(f.activity?.top_rules ?? []).length > 0 && <details className="text-[12px]"><summary className="cursor-pointer text-slate-400">多いアラート（7 日）</summary><ul className="mt-1 text-[11px] text-slate-300">{f.activity.top_rules.map((r: any) => <li key={r.id}>{r.id} L{r.level} ×{r.count} {r.description}</li>)}</ul></details>}
        </Section>

        {/* ⑥ リスクと提案 */}
        <Section title="⑥ リスクと提案（AI）" icon="🎯" count={(pr.risks ?? []).length}>
          {(pr.risks ?? []).length ? <ul className="flex flex-col gap-2.5">{pr.risks.map((r: any, i: number) => <li key={i} className="rounded-[10px] border border-slate-700 bg-slate-900 p-2.5 text-[13px]"><div className="flex flex-wrap items-center gap-2"><Chip tone={SEV_TONE[r.severity] ?? "slate"}>{r.severity === "high" ? "高" : r.severity === "low" ? "低" : "中"}</Chip><b className="text-slate-100">{r.title}</b></div><div className="mt-1 text-xs leading-relaxed text-slate-300">{r.detail}</div>{r.suggested_action && can && <button className="mt-1.5 rounded-md border border-teal-500 px-2 py-0.5 text-xs text-teal-200 hover:bg-teal-500/10" onClick={() => act(r.suggested_action, r.params ?? {}, `AI の提案: ${r.title}`)}>この対処を提案（{OP_JA[r.suggested_action as Op]}）</button>}</li>)}</ul> : <div className="text-xs text-slate-500">{pr.summary ? "目立ったリスクは挙がっていません" : "AI の解釈がありません"}</div>}
          {can && h.isolation_state !== "isolated" && <button className="self-start rounded-md border border-[#4A1E24] px-2.5 py-1 text-xs text-[#FF9A9D] hover:bg-[#2A1216]" onClick={() => act("isolate", {})}>インターネット通信遮断（Contain）…</button>}
        </Section>
      </div>}

      {/* 有効な遮断 */}
      {d.actions.length > 0 && <Section title="操作（遮断・更新・再起動）" icon="🚫" count={activeActions.length}>
        <ul className="flex flex-col gap-1.5">{d.actions.slice(0, 15).map((a) => { const st = STATUS_JA[a.status] ?? { ja: a.status, tone: "slate" as const }; const p = a.params ?? {}; return (
          <li key={a.id} className="flex flex-wrap items-center gap-2 text-[13px]"><Chip tone={st.tone}>{st.ja}</Chip><span className="text-slate-100">{a.label}</span><span className="font-mono text-xs text-slate-400">{p.service ?? (p.port ? `${p.proto}/${p.port}` : p.ip ?? "")}{updSummary(a)}</span><span className="text-xs text-slate-500">#{a.id}{a.applied_at ? ` · ${fmtTs(a.applied_at)}` : ""}</span>
            {a.status === "pending" && a.approval_id && <button className="text-xs text-teal-300 hover:underline" onClick={() => nav("/approvals")}>承認キューへ（#{a.approval_id}）</button>}
            {a.revert_approval?.decision === "pending" && <span className="text-xs text-amber-300">解除の承認待ち</span>}
            {canAct && (CONTAIN_OPS.includes(a.op) ? ["active", "unconfirmed", "failed"].includes(a.status) : (a.op === "reboot" && ["active", "running"].includes(a.status)) || (a.op === "update_install" && a.status === "running")) && a.revert_approval?.decision !== "pending" && <button className="ml-auto rounded-md border border-slate-600 px-2 py-0.5 text-xs hover:bg-slate-700" title={a.op === "update_install" ? "実行中の更新を止めます（承認が必要）。Windows が途中までの更新を元に戻すことがあり、しばらく重くなる場合があります" : undefined} onClick={() => revert(a)}>{a.op === "reboot" ? "予約を取り消す" : a.op === "update_install" ? "中止" : "解除"}</button>}
          </li>); })}</ul>
      </Section>}

      {dlg && <ActionDialog hostId={hostId} hostName={h.name} init={dlg} admin={admin} onClose={() => setDlg(null)} onDone={(id) => { setDlg(null); setMsg(`承認キューに積みました（承認 #${id}）。承認キューで承認すると実行されます。`); load(); }} />}
    </div>
  );
}
