/* EDR-171: agent maintenance in the "Wazuh エージェント" card — pack revision, MamorAI add-on, remote updates and their results.
 * Both updates run without an approval card (signed files through the Wazuh shared folder, checked on the PC). */
import { useEffect, useRef, useState } from "react";
import { api, fmtTs } from "../lib/api";

const verGt = (a: string, b: string) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0); } return false; };
const resOf = (a: any) => (typeof a?.result === "string" ? (() => { try { return JSON.parse(a.result); } catch { return null; } })() : a?.result);
const BTN = "rounded-md border border-teal-500 px-2 py-0.5 text-xs text-teal-200 hover:bg-teal-500/10 disabled:opacity-50";

interface Prof { host: any; capability: { ok: boolean; via: string; addon?: { version: string | null; checked_at: string | null } }; actions: any[]; addon_published?: string | null; pack_windows?: { latest: number | null; addon_only: number[]; same_as: number[]; addon_version: string | null } | null }

export default function AgentMaint({ hostId, canAct, agentVersion, onChanged }: { hostId: number; canAct: boolean; agentVersion?: string | null; onChanged?: () => void }) {
  const [d, setD] = useState<Prof | null>(null); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState(false);
  const load = () => api.get<Prof>(`/hosts/${hostId}/profile`).then(setD).catch(() => {});
  useEffect(() => { setD(null); setMsg(""); load(); }, [hostId]);
  const acts = d?.actions ?? [];
  const lastOf = (op: string) => acts.find((a: any) => a.op === op) ?? null;
  const addonAct = lastOf("addon_update"); const packAct = lastOf("pack_update");
  const running = [addonAct, packAct].some((a) => a?.status === "running");
  const was = useRef(false);
  useEffect(() => {
    if (running) { was.current = true; const t = window.setTimeout(load, 4000); return () => window.clearTimeout(t); }
    if (was.current) { was.current = false; onChanged?.(); }
  }, [d]);
  if (!d || d.capability.via !== "wazuh_ar") return null;
  const av = d.capability.addon?.version ?? d.host.ar_addon_version ?? null;
  const pub = d.addon_published ?? null;
  const pw = d.pack_windows; const rev = Number(d.host.pack_rev ?? 0) || null;
  const packOld = !!pw?.latest && !!rev && rev < pw.latest && !pw.same_as.includes(rev) && !(pw.addon_only.includes(rev) && !!av && !!pw.addon_version && !verGt(pw.addon_version, av));
  const addonOld = !!pub && !!av && verGt(pub, av);
  const tooOld = !!av && verGt("1.3.0", av);
  const run = async (path: string, note: string) => { setBusy(true); setMsg(""); try { await api.post(path, {}); setMsg(note); await load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const check = async () => { setBusy(true); setMsg("端末に問い合わせ中…（最大 90 秒）"); try { const r = await api.post<{ message: string }>(`/hosts/${hostId}/addon-check`); setMsg(r.message); await load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const status = (a: any, what: string) => {
    if (!a) return null;
    const r = resOf(a);
    if (a.status === "running") return <div className="text-xs text-sky-300">⟳ {what}を実行中{r?.progress ? `: ${r.progress}` : ""}</div>;
    if (a.status === "failed") return <div className="text-xs text-[#FF9A9D]">✕ 前回の{what}は失敗（{fmtTs(a.created_at)}）: {String(r?.log ?? "").split("\n")[0]}</div>;
    if (a.status === "done") return <div className="text-xs text-emerald-300">✓ {what}完了（{fmtTs(a.applied_at ?? a.created_at)}）</div>;
    return null;
  };
  return (
    <div className="mt-1 flex flex-col gap-2 border-t border-slate-700 pt-2.5">
      <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] items-center gap-x-2.5 gap-y-2 text-[13px]">
        <dt className="text-slate-400">パック</dt>
        <dd className="flex flex-wrap items-center gap-2 text-slate-200">
          <span className="font-mono">{rev ? `r${rev}` : "不明"}</span>
          {pw?.latest && rev && (packOld ? <span className="rounded-full border border-[#5A4A1A] px-2 py-px text-[11px] text-[#F5C542]">古い（最新 r{pw.latest}）</span> : <span className="text-xs text-emerald-300">最新</span>)}
          {canAct && packOld && !tooOld && packAct?.status !== "running" && <button className={BTN} disabled={busy || running} title="Wazuh の共有フォルダ経由で、インストーラーの更新モードを実行します（登録はそのまま）。最後に Wazuh エージェントが数十秒再起動します" onClick={() => run(`/hosts/${hostId}/pack-update`, `パックを r${pw!.latest} に更新しています（5〜15 分。最後に Wazuh エージェントが再起動します）`)}>r{pw!.latest} に更新</button>}
        </dd>
        <dt className="text-slate-400">アドオン</dt>
        <dd className="flex flex-wrap items-center gap-2 text-slate-200">
          <span className="font-mono">{av ? `v${av}` : "未確認"}</span>
          {pub && av && (addonOld ? <span className="rounded-full border border-[#5A4A1A] px-2 py-px text-[11px] text-[#F5C542]">古い（最新 v{pub}）</span> : <span className="text-xs text-emerald-300">最新</span>)}
          {d.capability.addon?.checked_at && <span className="text-[11px] text-slate-500">確認 {fmtTs(d.capability.addon.checked_at)}</span>}
          {canAct && <button className="text-xs text-teal-300 hover:underline disabled:opacity-50" disabled={busy || running} onClick={check}>再確認</button>}
          {canAct && addonOld && !tooOld && addonAct?.status !== "running" && <button className={BTN} disabled={busy || running} onClick={() => run(`/hosts/${hostId}/addon-update`, `アドオンを v${pub} に更新しています（署名と中身を確認して入れ替え、失敗したら元に戻します。1〜3 分）`)}>v{pub} に更新</button>}
        </dd>
      </dl>
      {tooOld && <div className="text-xs text-[#F5D98A]">アドオン v{av} はリモート更新に対応していません。今回だけエージェントパックを手で入れ直してください（v1.3.0 以降は MamorAI から更新できます）。</div>}
      {status(packAct, "パックの更新")}
      {status(addonAct, "アドオンの更新")}
      {msg && <div className="text-xs text-slate-300">{msg}</div>}
      <div className="text-[11px] leading-relaxed text-slate-500">更新は承認カードなしで実行します。端末が署名とハッシュを確かめてから入れ替えます。{agentVersion ? `Wazuh エージェント本体（${agentVersion}）はパックの更新で manager に合わせて上げます。` : ""}</div>
    </div>
  );
}
