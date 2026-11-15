/**
 * EDR-168: Windows Update / winget on the host screen.
 * The scan is read-only (no approval). Installing and restarting are proposed by Sidekick and always approved separately.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { Chip, Section } from "./fields";

export interface WinScan { checked_at?: string; wu_count: number; wu_security: number; updates: { kb: string | null; severity: string | null; security: boolean; categories: string; cves: number; size_mb: number; title: string }[]; app_count: number; apps: { id: string; version: string; available: string; name: string; via?: string }[]; winget: string | null; reboot_pending: boolean; wsus: string | null; boot: string | null }
const SEV_JA: Record<string, string> = { Critical: "緊急", Important: "重要", Moderate: "警告", Low: "注意" };
const SEV_TONE: Record<string, "rose" | "amber" | "slate"> = { Critical: "rose", Important: "amber" };

export default function WinUpdates({ hostId, hostName, scan, addonVersion, canAct, onChanged }: { hostId: number; hostName: string; scan: WinScan | null; addonVersion: string | null; canAct: boolean; onChanged: () => void }) {
  const nav = useNavigate();
  const [busy, setBusy] = useState(false); const [msg, setMsg] = useState("");
  const ready = !!addonVersion && addonVersion.localeCompare("1.2.1", undefined, { numeric: true }) >= 0;
  const run = async () => { setBusy(true); setMsg("端末で Windows Update を検索中…（1〜5 分）"); try { await api.post(`/hosts/${hostId}/win-updates`, {}); setMsg(""); onChanged(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const ask = () => nav("/sidekick", { state: { prefill: `${hostName} の Windows Update とアプリの更新を確認して、適用する計画を立てて（再起動はあとで相談）` } });
  return (
    <Section title="Windows Update・アプリの更新" icon="🧩" count={scan ? scan.wu_count + scan.app_count : undefined}>
      {!ready && <div className="text-[12px] text-[#F5D98A]">更新の確認と適用には自動対処アドオン v1.2.1 以上が必要です（今: {addonVersion ? `v${addonVersion}` : "未確認"}）。エージェントパックを入れ直してから「アドオンの版を確認」を押してください。</div>}
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-slate-400">
        {scan ? <span>最終確認 {fmtTs(scan.checked_at ?? "")}</span> : <span>まだ確認していません</span>}
        {scan?.reboot_pending && <Chip tone="amber">再起動待ちの更新あり</Chip>}
        {scan?.wsus && <Chip tone="slate">WSUS: {scan.wsus}</Chip>}
        {canAct && ready && <button className="ml-auto rounded-md border border-teal-500 px-2.5 py-1 text-xs text-teal-200 hover:bg-teal-500/10 disabled:opacity-50" disabled={busy} onClick={run}>{busy ? "確認中…" : "更新を確認"}</button>}
        {canAct && ready && scan && (scan.wu_count + scan.app_count > 0 || scan.reboot_pending) && <button className="rounded-md bg-teal-500 px-2.5 py-1 text-xs font-semibold text-white hover:bg-teal-400" onClick={ask}>Sidekick に適用を相談</button>}
      </div>
      {msg && <div className="text-[12px] text-slate-300">{msg}</div>}
      {scan && <>
        <div className="text-[13px] text-slate-200">Windows Update {scan.wu_count} 件（セキュリティ {scan.wu_security} 件）・アプリ {scan.app_count} 件{scan.winget && !["ok", "skipped"].includes(scan.winget) && <span className="text-[11px] text-slate-500">（アプリは確認できません: {scan.winget}）</span>}</div>
        {scan.updates.length > 0 && <ul className="flex flex-col gap-1 text-[12px]">{scan.updates.map((u, i) => <li key={i} className="flex flex-wrap items-center gap-1.5">{u.severity ? <Chip tone={SEV_TONE[u.severity] ?? "slate"}>{SEV_JA[u.severity] ?? u.severity}</Chip> : <Chip tone="slate">{u.security ? "セキュリティ" : "その他"}</Chip>}<span className="font-mono text-slate-300">{u.kb ?? ""}</span><span className="min-w-0 flex-1 truncate text-slate-200" title={u.title}>{u.title}</span><span className="text-[11px] text-slate-500">{u.cves ? `CVE ${u.cves} · ` : ""}{u.size_mb} MB</span></li>)}</ul>}
        {scan.apps.length > 0 && <details open className="text-[12px]"><summary className="cursor-pointer text-slate-400">更新できるアプリ {scan.app_count} 件</summary><ul className="mt-1 flex flex-col gap-0.5">{scan.apps.map((a) => <li key={a.id} className="flex flex-wrap gap-2"><span className="text-slate-200">{a.name}</span><span className="font-mono text-[11px] text-slate-500">{a.id}</span>{a.via === "recipe" ? <span title="ベンダー公式の署名付きインストーラーで更新（署名者を確認してから入れます）" className="rounded border border-teal-700 px-1 text-[10px] text-teal-200">ベンダー公式</span> : <span className="rounded border border-slate-600 px-1 text-[10px] text-slate-400">winget</span>}<span className="ml-auto font-mono text-[11px] text-slate-300">{a.version} → {a.available}</span></li>)}</ul></details>}
        <div className="text-[11px] text-slate-500">確認は読み取りだけ（承認なし）。インストールと再起動は、それぞれ承認キューで承認してから実行します。機能アップグレード（OS の版上げ）とドライバーは入れません。</div>
      </>}
    </Section>
  );
}
