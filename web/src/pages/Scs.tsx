/* EDR-175/176/177（SCS Phase 1）: SCS ダッシュボード・脆弱性台帳・資産台帳
 * MamorAI は評価機関ではない。画面は SCS評価制度の自己評価に使える証跡を集めるためのもの（「★取得を保証」等の表現は使わない）。 */
import { Fragment, useContext, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import { downloadFile } from "../components/SessionChat";

const CARD = "rounded-[14px] border border-slate-700 bg-slate-800 px-4 py-3.5";
const BTN = "inline-flex min-h-[34px] items-center gap-1.5 rounded-[9px] border border-slate-600 px-3 text-[13px] text-slate-100 hover:bg-slate-700 disabled:opacity-50";
const BTN_P = "inline-flex min-h-[34px] items-center gap-1.5 rounded-[9px] bg-teal-500 px-3 text-[13px] font-semibold text-white hover:bg-teal-400 disabled:opacity-50";
const INPUT = "w-full rounded-lg border border-slate-600 bg-slate-900 px-2.5 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:border-teal-400 focus:outline-none";
const PR_CLS: Record<string, string> = { P0: "bg-[#F2555A]/20 text-[#FF9A9D]", P1: "bg-[#F5C542]/15 text-[#F5C542]", P2: "bg-[#FB923C]/15 text-[#FDBA74]", P3: "bg-slate-700 text-slate-400" };
const ST_CLS: Record<string, string> = { 未対応: "bg-[#F2555A]/20 text-[#FF9A9D]", 計画中: "bg-teal-500/20 text-teal-200", 緩和策適用中: "bg-[#F5C542]/15 text-[#F5C542]", 適用済: "bg-[#3CCB8C]/15 text-[#3CCB8C]", 対象外: "bg-slate-700 text-slate-400" };
const CAT_JA: Record<string, string> = { pc: "PC", server: "サーバ", hypervisor: "ハイパーバイザ", smart_device: "スマートデバイス", network_device: "ネットワーク機器", other: "その他" };
const CLASS_OPTS: [string, string][] = [["pc_os", "PC / OS"], ["pc_browser", "PC / ブラウザ"], ["pc_office", "PC / Office"], ["server_os", "サーバ / OS"], ["server_middleware", "サーバ / ミドルウェア"], ["smart_os", "スマートデバイス / OS"], ["smart_app", "スマートデバイス / アプリ"], ["boundary_fw", "境界機器 / ファーム"], ["other", "14日対象外の種類"]];
const Chip = ({ cls, children, title }: { cls: string; children: React.ReactNode; title?: string }) => <span title={title} className={`inline-flex items-center whitespace-nowrap rounded-full px-2 py-px text-[11px] font-bold ${cls}`}>{children}</span>;
const Disclaimer = () => <div className="rounded-[10px] border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-400">MamorAI は評価機関ではありません。この画面は、SCS評価制度の自己評価（アセスメントシート）の根拠資料づくりを助けるものです。</div>;
const daysLeft = (iso: string | null) => { if (!iso) return null; return Math.ceil((Date.parse(iso) - Date.now()) / 86_400_000); };
const dueText = (iso: string | null) => { const d = daysLeft(iso); if (d === null) return "—"; const f = fmtTs(iso); const md = f.startsWith(String(new Date().getFullYear())) ? f.replace(/^\d{4}\//, "").slice(0, 5) : f.slice(0, 10); return d < 0 ? `${md}（${-d} 日超過）` : `${md}（あと ${d} 日）`; };
const dueCls = (iso: string | null) => { const d = daysLeft(iso); return d === null ? "text-slate-500" : d < 0 ? "text-[#FF9A9D]" : d <= 7 ? "text-[#F5C542]" : "text-slate-200"; };
function useCanAct() { const { user } = useContext(UserCtx); return user?.role === "admin" || user?.role === "operator"; }

// ======================================================================= ダッシュボード
interface Summary { enabled: boolean; sla: { compliance: number | null; came: number; in_time: number; backlog: number; overdue: number; overdue_p0: number; due7: number; next_due: string | null; open: number; open_cves: number; p0_open: number; undetermined_packages: number }; assets: Record<string, number>; feeds: { source: string; label: string; ok: boolean; at: string; fetched: number; added: number; error: string | null; total: number }[]; synced_at: string | null; feeds_at: string | null }
export function ScsDashboard() {
  const nav = useNavigate(); const canAct = useCanAct();
  const [s, setS] = useState<Summary | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [msg, setMsg] = useState("");
  const load = () => api.get<Summary>("/scs/summary").then(setS).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const sync = async (feeds: boolean) => { setBusy(true); setMsg(feeds ? "脅威情報と脆弱性を取り込み中…（1〜3 分）" : "脆弱性を取り込み中…（1〜2 分）"); try { const r = await api.post<any>("/scs/sync", { feeds }); setMsg(`取り込みました: 新規 ${r.vulns.created} ・ 解消 ${r.vulns.resolved} ・ 更新 ${r.vulns.updated}${r.vulns.complete ? "" : "（Wazuh を全件読めなかったので、解消の判定は見送りました）"}`); load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  if (err) return <div className="text-rose-300">{err}</div>;
  if (!s) return <div className="text-slate-500">読み込み中…</div>;
  const kpi = (label: string, v: React.ReactNode, sub: string, cls: string, to?: string) => <button className={`${CARD} flex-1 text-left ${to ? "hover:border-teal-500" : "cursor-default"}`} onClick={() => to && nav(to)}><div className="text-xs text-slate-400">{label}</div><div className={`mt-0.5 text-[30px] font-bold ${cls}`}>{v}</div><div className="text-[11.5px] text-slate-500">{sub}</div></button>;
  const assetTotal = Object.values(s.assets).reduce((a, b) => a + b, 0);
  return (
    <div className="flex flex-col gap-3.5">
      <div className="flex flex-wrap items-center gap-3"><h1 className="text-[22px] font-bold">SCS ダッシュボード</h1><span className="text-[12.5px] text-slate-400">SCS評価制度 ★3・★4 の自己評価に使える証跡</span>
        <span className="ml-auto text-xs text-slate-500">脆弱性の取り込み {s.synced_at ? fmtTs(s.synced_at) : "未実施"} ・ 脅威情報 {s.feeds_at ? fmtTs(s.feeds_at) : "未実施"}</span>
        {canAct && <><button className={BTN} disabled={busy} onClick={() => sync(false)}>今すぐ取り込む</button><button className={BTN} disabled={busy} onClick={() => sync(true)}>脅威情報も取り込む</button></>}</div>
      {msg && <div className="text-[13px] text-teal-200">{msg}</div>}
      {!s.enabled && <div className="rounded-[10px] border border-[#5A4A1A] bg-[#2A2410] px-3 py-2 text-[13px] text-[#F5D98A]">SCS 機能は設定でオフになっています（取り込みは止まっています）</div>}
      <div className="flex flex-wrap gap-3.5">
        {kpi("14日 SLA 遵守率（直近 90 日）", s.sla.compliance === null ? "—" : <>{s.sla.compliance}<span className="text-base">%</span></>, s.sla.came ? `期限内 ${s.sla.in_time} 件 / 期限が来た ${s.sla.came} 件（持ち越しは除く）` : "MamorAI が追い始めてから期限が来たものはまだありません", "text-[#3CCB8C]")}
        {kpi("期限超過", <>{s.sla.overdue}<span className="text-sm"> 件</span></>, `うち P0 ${s.sla.overdue_p0} 件 ・ 取り込み前からの持ち越し ${s.sla.backlog} 件`, s.sla.overdue ? "text-[#FF9A9D]" : "text-slate-100", "/scs/vulns?tab=overdue")}
        {kpi("7 日以内に期限", <>{s.sla.due7}<span className="text-sm"> 件</span></>, s.sla.next_due ? `最短 ${dueText(s.sla.next_due)}` : "なし", s.sla.due7 ? "text-[#F5C542]" : "text-slate-100", "/scs/vulns")}
        {kpi("要判定（対象区分が未決定）", <>{s.sla.undetermined_packages}<span className="text-sm"> 種類</span></>, "辞書にないソフト。14日対象かを決める", "text-slate-100", "/scs/vulns?tab=undetermined")}
      </div>
      <div className="grid gap-3.5 lg:grid-cols-[1.6fr_1fr]">
        <div className={CARD}>
          <div className="mb-2 text-sm font-bold">いまの状態 <span className="font-normal text-slate-500">（評価基準 4-4-4-2 / 3-2-1-4）</span></div>
          <table className="w-full text-[13px]"><tbody>
            {[["14日対象で未対応の脆弱性", `${s.sla.open} 件（CVE ${s.sla.open_cves} 種類）`, "/scs/vulns"], ["P0（悪用が確認されたもの）", `${s.sla.p0_open} 件`, "/scs/vulns?tab=p0"], ["期限超過", `${s.sla.overdue} 件`, "/scs/vulns?tab=overdue"], ["資産台帳の機器", `${assetTotal} 台（${Object.entries(s.assets).map(([k, n]) => `${CAT_JA[k] ?? k} ${n}`).join("・")}）`, "/scs/assets"]].map(([a, b, to]) =>
              <tr key={a} className="border-t border-slate-700/60"><td className="py-2 pr-3 text-slate-400">{a}</td><td className="py-2 font-semibold">{b}</td><td className="py-2 text-right"><button className="text-xs text-teal-300 hover:underline" onClick={() => nav(to)}>開く</button></td></tr>)}
          </tbody></table>
          <div className="mt-3"><button className="text-xs text-teal-300 hover:underline" onClick={() => downloadFile("/api/scs/export/vulns.csv", "scs-vulns.csv").catch((e) => setMsg(e.message))}>脆弱性の対応記録を CSV で出す</button></div>
        </div>
        <div className={CARD}>
          <div className="mb-2 text-sm font-bold">脅威情報フィード <span className="font-normal text-slate-500">（1-2-2-1・P0 の判定）</span></div>
          {s.feeds.length ? <table className="w-full text-[13px]"><tbody>{s.feeds.map((f) => <tr key={f.source} className="border-t border-slate-700/60"><td className="py-1.5 pr-2">{f.label}</td><td className="py-1.5 pr-2 font-mono text-xs">{f.total.toLocaleString()} 件</td><td className="whitespace-nowrap py-1.5 pr-2 text-xs text-slate-500">{fmtTs(f.at)}</td><td className="py-1.5 text-right">{f.ok ? <Chip cls="bg-[#3CCB8C]/15 text-[#3CCB8C]">OK</Chip> : <Chip cls="bg-[#F2555A]/20 text-[#FF9A9D]" title={f.error ?? ""}>失敗</Chip>}</td></tr>)}</tbody></table> : <div className="text-xs text-slate-500">まだ取り込んでいません（毎日 1 回。「脅威情報も取り込む」で今すぐ）</div>}
        </div>
      </div>
      <CriteriaTable />
      <ScaHosts />
      <Disclaimer />
    </div>
  );
}

// ======================================================================= 評価基準ごとの状態（EDR-174）
interface CItem { criteria_no: string; level: string; requirement_no: string; title: string; body: string; nist_function: string | null; mamorai_mode: "A" | "B" | "C"; mamorai_feature: string | null; annual_check: boolean; state: string; evidence: string; checked_at: string | null; link?: string }
const CS_CLS: Record<string, string> = { 適合: "bg-[#3CCB8C]/15 text-[#3CCB8C]", 要対応: "bg-[#F5C542]/15 text-[#F5C542]", 未接続: "bg-teal-500/15 text-teal-200", 対象外: "bg-slate-700 text-slate-400" };
const MODE_JA = { A: "自動証跡", B: "半自動", C: "対象外" } as const;
function CriteriaTable() {
  const nav = useNavigate(); const { user } = useContext(UserCtx);
  const [d, setD] = useState<{ version: string | null; items: CItem[]; counts: Record<string, Record<string, number>> | null } | null>(null);
  const [lv, setLv] = useState("★3"); const [st, setSt] = useState(""); const [open, setOpen] = useState<string | null>(null); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState(false);
  const load = () => api.get<any>("/scs/criteria").then(setD).catch((e) => setMsg(e.message));
  useEffect(() => { load(); }, []);
  const importIpa = async () => { setBusy(true); setMsg("IPA から評価基準（Excel）を取り込み中…"); try { const r = await api.post<any>("/scs/criteria/import", {}); setMsg(`取り込みました: ${r.version}・評価基準 ${r.total}（★3 ${r.star3} / ★4 ${r.star4}）・要求事項 ${r.requirements}`); load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const rows = useMemo(() => (d?.items ?? []).filter((i) => i.level === lv && (!st || i.state === st)), [d, lv, st]);
  if (!d) return <div className={CARD}><div className="text-xs text-slate-500">{msg || "評価基準を読み込み中…"}</div></div>;
  const c = d.counts?.[lv];
  return (
    <div className={CARD}>
      <div className="mb-2 flex flex-wrap items-center gap-2"><div className="text-sm font-bold">評価基準ごとの状態 <span className="font-normal text-slate-500">{d.version ? `（IPA SCS ★3・★4 要求事項・評価基準 ${d.version}）` : ""}</span></div>
        <div className="ml-auto flex gap-1.5">
          {d.version && <button className={BTN} onClick={() => downloadFile("/api/scs/export/criteria.csv", `scs-criteria-${d.version}.csv`).catch((e) => setMsg(e.message))}>CSV で出す</button>}
          {user?.role === "admin" && <button className={BTN} disabled={busy} onClick={importIpa}>{d.version ? "IPA から取り込み直す" : "IPA から取り込む"}</button>}</div></div>
      {msg && <div className="mb-2 text-[13px] text-teal-200">{msg}</div>}
      {!d.version ? <div className="text-xs leading-relaxed text-slate-500">評価基準マスタがまだありません。MamorAI が IPA の公開ページから Excel（SCS-400）を自動で取り込みます（数分以内）。急ぐ場合は管理者が「IPA から取り込む」を押してください。本文は IPA の配布物をそのまま使い、MamorAI には同梱していません。</div> : <>
        <div className="mb-2 flex flex-wrap items-center gap-1.5">
          {["★3", "★4"].map((l) => <button key={l} onClick={() => setLv(l)} className={`rounded-full px-3 py-1 text-[12.5px] ${lv === l ? "bg-teal-500 font-semibold text-white" : "border border-slate-600 text-slate-300 hover:bg-slate-700"}`}>{l}（{d.items.filter((i) => i.level === l).length}）</button>)}
          <span className="mx-1 h-4 w-px bg-slate-700" />
          {["", "適合", "要対応", "未接続", "対象外"].map((x) => <button key={x || "all"} onClick={() => setSt(x)} className={`rounded-full px-2.5 py-0.5 text-[12px] ${st === x ? "bg-slate-600 text-white" : "text-slate-400 hover:bg-slate-700"}`}>{x || "すべて"}{x && c ? ` ${c[x] ?? 0}` : ""}</button>)}
        </div>
        <div className="overflow-x-auto"><table className="w-full text-[13px]"><thead><tr className="text-left text-xs text-slate-500"><th className="py-1.5 pr-2 font-normal">評価基準</th><th className="py-1.5 pr-2 font-normal">要求事項</th><th className="py-1.5 pr-2 font-normal">MamorAI</th><th className="py-1.5 pr-2 font-normal">状態</th><th className="py-1.5 font-normal">根拠</th></tr></thead><tbody>
          {rows.map((i) => <Fragment key={i.criteria_no}>
            <tr className="cursor-pointer border-t border-slate-700/60 align-top hover:bg-slate-700/30" onClick={() => setOpen(open === i.criteria_no ? null : i.criteria_no)}>
              <td className="whitespace-nowrap py-2 pr-2 font-mono text-xs">{i.criteria_no}{i.annual_check && <span className="ml-1 rounded bg-slate-700 px-1 text-[10px] text-slate-300" title="1-4-1-1 で年次点検の対象">年次</span>}</td>
              <td className="py-2 pr-2">{i.title}</td>
              <td className="py-2 pr-2 text-xs text-slate-400"><div>{MODE_JA[i.mamorai_mode]}</div>{i.mamorai_feature && <div className="text-slate-500">{i.mamorai_feature}</div>}</td>
              <td className="py-2 pr-2"><Chip cls={CS_CLS[i.state] ?? CS_CLS.対象外}>{i.state}</Chip></td>
              <td className="py-2 text-xs text-slate-300">{i.evidence}{i.link && <button className="ml-1.5 text-teal-300 hover:underline" onClick={(e) => { e.stopPropagation(); nav(i.link!); }}>開く</button>}</td></tr>
            {open === i.criteria_no && <tr><td colSpan={5} className="whitespace-pre-wrap border-t border-slate-700/40 bg-slate-900/60 px-3 py-2 text-xs leading-relaxed text-slate-300"><div className="mb-1 text-slate-500">評価基準（IPA 原文）{i.nist_function ? ` ・ NIST CSF: ${i.nist_function}` : ""}{i.checked_at ? ` ・ 確認 ${fmtTs(i.checked_at)}` : ""}</div>{i.body}</td></tr>}
          </Fragment>)}
          {!rows.length && <tr><td colSpan={5} className="py-3 text-center text-xs text-slate-500">該当なし</td></tr>}
        </tbody></table></div>
        <div className="mt-2 text-[11.5px] leading-relaxed text-slate-500">「適合」は MamorAI が持つデータで確認できたもの、「要対応」は不足や手入力が要るもの、「未接続」は対応機能を今後つなぐもの、「対象外」は規程・体制など MamorAI では示せないもの（人が文書で示す）です。最終的な判定は自己評価の責任者が行ってください。</div>
      </>}
    </div>
  );
}

// ======================================================================= 端末ごとの設定（SCA / EDR-178）
const SCA_COLS: [string, string][] = [["4-1-4-1", "ログオン試行の制限"], ["4-1-4-2", "パスワード長"], ["4-4-1-2", "自動実行の無効化"], ["4-5-1-8", "FW 有効"], ["4-4-1-5", "既定 ID の停止"]];
const V_JA: Record<string, [string, string]> = { ok: ["満たす", "bg-[#3CCB8C]/15 text-[#3CCB8C]"], ng: ["満たさない", "bg-[#F2555A]/20 text-[#FF9A9D]"], check: ["要確認", "bg-[#F5C542]/15 text-[#F5C542]"], unknown: ["チェックなし", "bg-slate-700 text-slate-400"], na: ["—", "text-slate-500"], nodata: ["未取得", "bg-slate-700 text-slate-400"] };
function ScaHosts() {
  const canAct = useCanAct();
  const [d, setD] = useState<{ synced_at: string | null; hosts: any[] } | null>(null); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState(false); const [open, setOpen] = useState<number | null>(null);
  const load = () => api.get<any>("/scs/sca").then(setD).catch((e) => setMsg(e.message));
  useEffect(() => { load(); }, []);
  const sync = async () => { setBusy(true); setMsg("Wazuh から SCA の結果を取り込み中…"); try { const r = await api.post<any>("/scs/sca/sync", {}); setMsg(`取り込みました: ${r.agents} 台・新しい結果 ${r.saved} 件${r.errors ? `・失敗 ${r.errors} 台` : ""}`); load(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  if (!d) return null;
  return (
    <div className={CARD}>
      <div className="mb-2 flex flex-wrap items-center gap-2"><div className="text-sm font-bold">端末ごとの設定 <span className="font-normal text-slate-500">（Wazuh SCA / CIS ベンチマークから）</span></div>
        <span className="ml-auto text-xs text-slate-500">取り込み {d.synced_at ? fmtTs(d.synced_at) : "未実施"}（1 日 1 回）</span>{canAct && <button className={BTN} disabled={busy} onClick={sync}>今すぐ取り込む</button>}</div>
      {msg && <div className="mb-2 text-[13px] text-teal-200">{msg}</div>}
      <div className="overflow-x-auto"><table className="w-full text-[13px]"><thead><tr className="text-left text-xs text-slate-500"><th className="py-1.5 pr-2 font-normal">端末</th><th className="py-1.5 pr-2 font-normal">ポリシー</th>{SCA_COLS.map(([no, ja]) => <th key={no} className="py-1.5 pr-2 font-normal"><div>{ja}</div><div className="font-mono text-[10.5px]">{no}</div></th>)}</tr></thead><tbody>
        {d.hosts.map((h) => <Fragment key={h.asset_id}>
          <tr className="cursor-pointer border-t border-slate-700/60 hover:bg-slate-700/30" onClick={() => setOpen(open === h.asset_id ? null : h.asset_id)}>
            <td className="py-1.5 pr-2"><div>{h.name}</div><div className="text-[11px] text-slate-500">{h.os ?? ""}</div></td>
            <td className="py-1.5 pr-2 text-xs text-slate-400">{h.policy ?? "—"}{h.scan_end && <div className="text-[11px] text-slate-500">{fmtTs(h.scan_end)}</div>}</td>
            {SCA_COLS.map(([no]) => { const [ja, cls] = V_JA[h.verdicts[no]] ?? V_JA.na; return <td key={no} className="py-1.5 pr-2">{cls.startsWith("text-") ? <span className={cls}>{ja}</span> : <Chip cls={cls}>{ja}</Chip>}</td>; })}</tr>
          {open === h.asset_id && <tr><td colSpan={2 + SCA_COLS.length} className="border-t border-slate-700/40 bg-slate-900/60 px-3 py-2 text-xs text-slate-300">{h.checks.length ? <ul className="space-y-0.5">{h.checks.map((c: any) => <li key={c.id}><span className="font-mono text-slate-500">{c.id}</span> <span className={c.result === "passed" ? "text-[#3CCB8C]" : c.result === "failed" ? "text-[#FF9A9D]" : "text-slate-400"}>{c.result}</span> {c.title}</li>)}</ul> : "SCS に関係するチェックがありません"}</td></tr>}
        </Fragment>)}
      </tbody></table></div>
      <div className="mt-2 text-[11.5px] leading-relaxed text-slate-500">「要確認」は CIS の基準（ロックアウト 5 回以下・パスワード 14 文字以上）は満たさないが、SCS の基準（10 回・6 文字以上）は満たしている可能性があるものです。値まで見る独自ポリシーは配布前に実機で確認します。</div>
    </div>
  );
}

// ======================================================================= 脆弱性台帳
interface VItem { cve_id: string; priority: string; packages: string[]; package_count: number; classes: { key: string; ja: string }[]; severity: string | null; cvss: number | null; exploited: boolean; due_at: string | null; statuses: Record<string, number>; resolved_at: string | null; hosts_open: number; hosts_total: number; host_names: string[]; intel: string[] }
const TABS: [string, string][] = [["open", "対応中（14日対象）"], ["p0", "P0"], ["overdue", "期限超過"], ["plan", "計画中"], ["mitigated", "緩和策適用中"], ["undetermined", "要判定"], ["excluded", "対象外"], ["resolved", "適用済（90 日）"]];
export function ScsVulns() {
  const [sp, setSp] = useSearchParams(); const tab = sp.get("tab") ?? "open"; const sel = sp.get("cve");
  const [d, setD] = useState<{ items: VItem[]; total: number; counts: Record<string, number> } | null>(null); const [q, setQ] = useState(""); const [err, setErr] = useState("");
  const load = () => api.get<any>(`/scs/vulns?tab=${tab}${q ? `&q=${encodeURIComponent(q)}` : ""}`).then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [tab]);
  const set = (k: string, v: string | null) => { const n = new URLSearchParams(sp); if (v === null) n.delete(k); else n.set(k, v); setSp(n); };
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3"><h1 className="text-[22px] font-bold">脆弱性台帳</h1><span className="text-[12.5px] text-slate-400">重大な脆弱性を 14 日以内に適用（評価基準 4-4-4-2）／ 対応履歴（3-2-1-4）</span></div>
      <div className="flex flex-wrap items-center gap-1">
        {TABS.map(([k, l]) => <button key={k} onClick={() => set("tab", k)} className={`rounded-lg px-3 py-1.5 text-[12.5px] ${tab === k ? "bg-[#1A2547] font-bold text-white" : "text-slate-400 hover:text-slate-200"}`}>{l} {d?.counts?.[k] ?? ""}</button>)}
        <form className="ml-auto flex gap-2" onSubmit={(e) => { e.preventDefault(); load(); }}><input className={`${INPUT} w-72`} placeholder="CVE・パッケージ・ホストで検索" value={q} onChange={(e) => setQ(e.target.value)} /></form>
      </div>
      {err && <div className="text-rose-300">{err}</div>}
      {tab === "undetermined" ? <Undetermined onChanged={load} /> : (
        <div className={`${CARD} overflow-x-auto px-2 py-1`}>
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-[11px] text-slate-500">{["優先度", "CVE", "パッケージ / 対象区分", "端末（残 / 全）", "悪用情報", "期限（起点 + 14 日）", "状態"].map((h) => <th key={h} className="whitespace-nowrap px-2 py-2 font-bold">{h}</th>)}</tr></thead>
            <tbody>
              {!d ? <tr><td colSpan={7} className="p-4 text-slate-500">読み込み中…</td></tr> : !d.items.length ? <tr><td colSpan={7} className="p-4 text-slate-500">該当なし（取り込みがまだなら、SCS ダッシュボードの「今すぐ取り込む」）</td></tr> : d.items.map((v) => (
                <tr key={v.cve_id} className={`cursor-pointer border-t border-slate-700/60 hover:bg-[#141F3F] ${sel === v.cve_id ? "bg-[#141F3F]" : ""}`} onClick={() => set("cve", v.cve_id)}>
                  <td className="px-2 py-2"><Chip cls={PR_CLS[v.priority]}>{v.priority}</Chip></td>
                  <td className="px-2 py-2"><div className="font-mono">{v.cve_id}</div><div className="text-[11.5px] text-slate-500">{v.severity && v.severity !== "-" ? v.severity : "深刻度: 不明"}{v.cvss ? ` ・ CVSS ${v.cvss}` : ""}</div></td>
                  <td className="px-2 py-2"><div className="max-w-[340px] truncate" title={v.packages.join(", ")}>{v.packages[0]}{v.package_count > 1 ? ` 他 ${v.package_count - 1}` : ""}</div><div className="text-[11.5px] text-slate-500">{v.classes.map((c) => c.ja).join(" / ")}</div></td>
                  <td className="px-2 py-2 font-mono" title={v.host_names.join(", ")}>{tab === "resolved" ? 0 : v.hosts_open} / {v.hosts_total}</td>
                  <td className="px-2 py-2">{v.intel.length ? [...new Set(v.intel)].map((x) => <span key={x} className="mr-1"><Chip cls={PR_CLS.P0}>{x}</Chip></span>) : <span className="text-slate-600">—</span>}</td>
                  <td className={`whitespace-nowrap px-2 py-2 font-mono ${tab === "resolved" ? "text-slate-500" : dueCls(v.due_at)}`}>{tab === "resolved" ? `解消 ${fmtTs(v.resolved_at)}` : dueText(v.due_at)}</td>
                  <td className="px-2 py-2">{Object.entries(v.statuses).map(([k, n]) => <span key={k} className="mr-1"><Chip cls={ST_CLS[k] ?? ""}>{k}{n > 1 ? ` ${n}` : ""}</Chip></span>)}</td>
                </tr>))}
            </tbody>
          </table>
          {d && d.total > d.items.length && <div className="p-2 text-xs text-slate-500">先頭 {d.items.length} 件を表示（全 {d.total} 件。検索で絞り込めます）</div>}
        </div>)}
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-[10px] border border-slate-700 bg-slate-900 px-3 py-2 text-xs leading-relaxed text-slate-400">台帳に載せるのは 14 日 SLA の候補（Critical / High / 深刻度不明 / CVSS 7.0 以上）だけです。Medium / Low は Wazuh の脆弱性画面で見られます。</div>
        <div className="rounded-[10px] border border-slate-700 bg-slate-900 px-3 py-2 text-xs leading-relaxed text-slate-400">パッチを当てると、次の取り込み（毎時）で Wazuh の検知が消え、自動で「適用済」と履歴が残ります。</div>
      </div>
      {sel && <VulnDetail cve={sel} onClose={() => set("cve", null)} onChanged={load} />}
    </div>
  );
}

function Undetermined({ onChanged }: { onChanged: () => void }) {
  const canAct = useCanAct();
  const [rows, setRows] = useState<any[] | null>(null); const [msg, setMsg] = useState(""); const [pick, setPick] = useState<Record<string, string>>({});
  const load = () => api.get<{ items: any[] }>("/scs/packages/undetermined").then((r) => setRows(r.items)).catch((e) => setMsg(e.message));
  useEffect(() => { load(); }, []);
  const save = async (pkg: string) => { const c = pick[pkg]; if (!c) return; try { const r = await api.put<{ rows: number }>("/scs/packages/class", { package_name: pkg, target_class: c }); setMsg(`${pkg}: ${r.rows} 件の区分を決めました`); load(); onChanged(); } catch (e: any) { setMsg(e.message); } };
  return (
    <div className={`${CARD} px-2 py-1`}>
      <div className="px-2 py-2 text-xs leading-relaxed text-slate-400">辞書に無いソフトです。14 日 SLA の対象（OS・ブラウザ・Office・サーバのミドルウェア など）か、対象外の種類かを決めてください。決めた区分は同じソフトの全端末に効き、履歴に残ります。</div>
      {msg && <div className="px-2 pb-2 text-[13px] text-teal-200">{msg}</div>}
      <table className="w-full text-[13px]"><thead><tr className="text-left text-[11px] text-slate-500">{["ソフト", "端末の区分", "端末", "CVE 件数", "最大 CVSS", "区分を決める"].map((h) => <th key={h} className="px-2 py-2">{h}</th>)}</tr></thead>
        <tbody>{!rows ? <tr><td colSpan={6} className="p-3 text-slate-500">読み込み中…</td></tr> : !rows.length ? <tr><td colSpan={6} className="p-3 text-slate-500">要判定はありません</td></tr> : rows.map((r) => (
          <tr key={r.package_name + r.category} className="border-t border-slate-700/60"><td className="px-2 py-1.5">{r.package_name}</td><td className="px-2 py-1.5 text-slate-400">{CAT_JA[r.category] ?? r.category}</td><td className="px-2 py-1.5 font-mono">{r.hosts}</td><td className="px-2 py-1.5 font-mono">{r.cves}</td><td className="px-2 py-1.5 font-mono">{r.cvss ?? "—"}</td>
            <td className="px-2 py-1.5">{canAct && <span className="flex gap-2"><select className={`${INPUT} w-52`} value={pick[r.package_name] ?? ""} onChange={(e) => setPick({ ...pick, [r.package_name]: e.target.value })}><option value="">選んでください</option>{CLASS_OPTS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select><button className={BTN} disabled={!pick[r.package_name]} onClick={() => save(r.package_name)}>決める</button></span>}</td></tr>))}</tbody></table>
    </div>
  );
}

function VulnDetail({ cve, onClose, onChanged }: { cve: string; onClose: () => void; onChanged: () => void }) {
  const canAct = useCanAct(); const nav = useNavigate();
  const [d, setD] = useState<any>(null); const [err, setErr] = useState(""); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState(false);
  const [edit, setEdit] = useState<any>(null); const [basis, setBasis] = useState<{ date: string; text: string } | null>(null);
  const load = () => api.get<any>(`/scs/vulns/cve/${cve}`).then((r) => { setD(r); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { setD(null); setEdit(null); setBasis(null); setMsg(""); load(); }, [cve]);
  const openRows = useMemo(() => (d?.rows ?? []).filter((r: any) => !r.resolved_at), [d]);
  const first = openRows[0] ?? d?.rows?.[0];
  const intelLabels = [...new Set((d?.intel ?? []).map((i: any) => i.label))] as string[];
  const missing = edit && ((edit.status === "緩和策適用中" && !edit.mitigation_type) ? "緩和策の種類を選ぶまで保存できません" : (edit.status === "対象外" && (edit.exclusion_reason ?? "").trim().length < 5) ? "対象外の理由を書くまで保存できません" : (edit.status === "計画中" && (!edit.plan_due_at || !(edit.plan_reason ?? "").trim())) ? "予定日と理由を入れるまで保存できません" : "");
  const saveState = async () => {
    setBusy(true); setMsg("");
    try { for (const id of edit.ids) await api.patch(`/scs/vulns/${id}`, { status: edit.status, mitigation_type: edit.status === "緩和策適用中" ? edit.mitigation_type : undefined, mitigation_note: edit.mitigation_note || undefined, exclusion_reason: edit.status === "対象外" ? edit.exclusion_reason : undefined, plan_due_at: edit.plan_due_at ? new Date(edit.plan_due_at + "T23:59:00+09:00").toISOString() : undefined, plan_reason: edit.plan_reason || undefined });
      setMsg(`${edit.ids.length} 台の状態を変えました`); setEdit(null); load(); onChanged(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  };
  const saveBasis = async () => { if (!basis || !first) return; setBusy(true); try { await api.patch(`/scs/vulns/${first.id}/basis`, { fix_released_at: new Date(basis.date + "T00:00:00+09:00").toISOString(), basis: basis.text, apply_same_cve: true }); setBasis(null); load(); onChanged(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const requestPatch = async () => { setBusy(true); try { const r = await api.post<{ session_id: number }>(`/scs/vulns/cve/${cve}/request-patch`, {}); nav(`/sidekick/${r.session_id}`); } catch (e: any) { setMsg(e.message); setBusy(false); } };
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <div className="flex h-full w-full max-w-[760px] flex-col gap-3 overflow-y-auto border-l border-slate-700 bg-[#0D1428] p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex flex-wrap items-center gap-2">{first && <Chip cls={PR_CLS[first.priority]}>{first.priority}</Chip>}<b className="font-mono text-[17px]">{cve}</b>{intelLabels.map((l) => <Chip key={l} cls={PR_CLS.P0}>{l}</Chip>)}{first?.cvss_base && <Chip cls="bg-slate-700 text-slate-300">CVSS {first.cvss_base}</Chip>}<button className="ml-auto text-slate-400 hover:text-white" onClick={onClose} aria-label="閉じる">✕</button></div>
        {err && <div className="text-rose-300">{err}</div>}
        {!d ? <div className="text-slate-500">読み込み中…</div> : <>
          {d.info?.description && <div className="rounded-[10px] border border-slate-700 bg-slate-900 px-3 py-2 text-[12.5px] leading-relaxed text-slate-300">{d.info.description}{d.info.reference?.length ? <div className="mt-1 flex flex-wrap gap-2 text-xs">{d.info.reference.slice(0, 3).map((u: string) => <a key={u} href={u} target="_blank" rel="noreferrer" className="truncate text-teal-300 hover:underline">{u.replace(/^https?:\/\//, "").slice(0, 60)}</a>)}</div> : null}</div>}
          {d.intel?.length > 0 && <div className="text-xs text-slate-400">掲載: {d.intel.map((i: any) => <a key={i.id} href={i.url ?? "#"} target="_blank" rel="noreferrer" className="mr-3 text-teal-300 hover:underline">{i.label}（{i.listed_at ?? "-"}）</a>)}</div>}
          {first && <div className="grid grid-cols-2 gap-3">
            <div className={CARD}><div className="text-xs text-slate-400">期限の起点（修正版のリリース）</div><div className="text-xl font-bold">{first.fix_released_at ? fmtTs(first.fix_released_at).slice(0, 10) : "—"}</div><div className="text-[11.5px] text-slate-500">{first.fix_released_source === "manual" ? `根拠: ${first.fix_released_basis}` : "自動（公開日と検知日の早い方）。根拠があれば直してください"}</div>{canAct && !basis && <button className="mt-1 text-xs text-teal-300 hover:underline" onClick={() => setBasis({ date: (first.fix_released_at ?? "").slice(0, 10), text: first.fix_released_basis ?? "" })}>起点日を直す</button>}</div>
            <div className={CARD}><div className="text-xs text-slate-400">期限{first.sla_target ? "（起点 + 14 日）" : ""}</div><div className={`text-xl font-bold ${dueCls(first.due_at)}`}>{first.due_at ? dueText(first.due_at) : "—"}</div><div className="text-[11.5px] text-slate-500">{first.sla_target ? (first.priority === "P0" ? "延長不可（悪用確認あり）" : "延ばすときは計画（予定日と理由）が必要") : "14日 SLA の対象外"}</div></div>
          </div>}
          {basis && <div className={`${CARD} flex flex-col gap-2`}><div className="text-sm font-bold">期限の起点日を直す（この CVE・同じソフトの全端末）</div><div className="flex gap-2"><input type="date" className={`${INPUT} w-44`} value={basis.date} onChange={(e) => setBasis({ ...basis, date: e.target.value })} /><input className={INPUT} placeholder="根拠（ベンダーの告知 URL など）" value={basis.text} onChange={(e) => setBasis({ ...basis, text: e.target.value })} /></div><div className="flex gap-2"><button className={BTN_P} disabled={busy || !basis.date || basis.text.trim().length < 3} onClick={saveBasis}>保存</button><button className={BTN} onClick={() => setBasis(null)}>やめる</button></div></div>}
          <div><div className="mb-1 text-sm font-bold">対象端末</div>
            <table className="w-full text-[13px]"><thead><tr className="text-left text-[11px] text-slate-500"><th className="py-1.5">端末</th><th>パッケージ</th><th>対象区分</th><th>状態</th><th>解消</th></tr></thead>
              <tbody>{d.rows.map((r: any) => <tr key={r.id} className="border-t border-slate-700/60"><td className="py-1.5 pr-2">{r.asset_name}</td><td className="pr-2 font-mono text-xs">{r.package_name} {r.package_version}</td><td className="pr-2 text-xs text-slate-400">{r.class_ja}</td><td className="pr-2"><Chip cls={ST_CLS[r.status] ?? ""}>{r.status}</Chip>{r.mitigation_type && <div className="text-[11px] text-slate-500">{r.mitigation_type}</div>}</td><td className="text-xs text-slate-500">{r.resolved_at ? `${fmtTs(r.resolved_at)} 自動` : "—"}</td></tr>)}</tbody></table></div>
          {canAct && openRows.length > 0 && <div className={`${CARD} flex flex-col gap-2`}>
            <div className="flex items-center gap-2"><div className="text-sm font-bold">状態を変える（未解消の {openRows.length} 台）</div><button className={`${BTN_P} ml-auto`} disabled={busy} onClick={requestPatch} title="Sidekick が各ホストの更新を確認し、承認カードを出します">パッチ適用を依頼（Sidekick）</button></div>
            {!edit ? <button className={`${BTN} self-start`} onClick={() => setEdit({ ids: openRows.map((r: any) => r.id), status: openRows[0].status })}>状態を変える</button> : <>
              <div className="grid grid-cols-2 gap-2">
                <label className="text-xs text-slate-400">状態<select className={INPUT} value={edit.status} onChange={(e) => setEdit({ ...edit, status: e.target.value })}>{["未対応", "計画中", "緩和策適用中", "対象外"].map((x) => <option key={x}>{x}</option>)}</select></label>
                {edit.status === "緩和策適用中" && <label className="text-xs text-slate-400">緩和策の種類（必須）<select className={`${INPUT} ${edit.mitigation_type ? "" : "border-[#F2555A]"}`} value={edit.mitigation_type ?? ""} onChange={(e) => setEdit({ ...edit, mitigation_type: e.target.value || null })}><option value="">選んでください</option>{d.mitigations.map((m: string) => <option key={m}>{m}</option>)}</select></label>}
                {edit.status === "計画中" && <label className="text-xs text-slate-400">予定日（必須）<input type="date" className={INPUT} value={edit.plan_due_at ?? ""} onChange={(e) => setEdit({ ...edit, plan_due_at: e.target.value })} /></label>}
              </div>
              {edit.status === "計画中" && <input className={INPUT} placeholder="理由（必須。例: 業務時間外の 11/15 22:00 に適用）" value={edit.plan_reason ?? ""} onChange={(e) => setEdit({ ...edit, plan_reason: e.target.value })} />}
              {edit.status === "緩和策適用中" && <input className={INPUT} placeholder="メモ（例: WAF で該当パスを遮断・11/10 適用）" value={edit.mitigation_note ?? ""} onChange={(e) => setEdit({ ...edit, mitigation_note: e.target.value })} />}
              {edit.status === "対象外" && <input className={INPUT} placeholder="対象外の理由（必須。例: この機能を使っておらず無効化済み）" value={edit.exclusion_reason ?? ""} onChange={(e) => setEdit({ ...edit, exclusion_reason: e.target.value })} />}
              <div className="flex items-center gap-2"><button className={BTN_P} disabled={busy || !!missing} onClick={saveState}>保存</button><button className={BTN} onClick={() => setEdit(null)}>やめる</button>{missing && <span className="text-xs text-[#FF9A9D]">{missing}</span>}</div>
            </>}
          </div>}
          {msg && <div className="text-[13px] text-teal-200">{msg}</div>}
          <div><div className="mb-1 text-sm font-bold">対応履歴</div>
            <div className="flex flex-col gap-1 text-[12.5px]">{d.history.length ? d.history.map((h: any) => <div key={h.id}><span className="font-mono text-slate-500">{fmtTs(h.changed_at)}</span>　{h.changed_by}　{h.asset_name}: {({ status: "状態", priority: "優先度", due_at: "期限", fix_released_at: "起点日", target_class: "対象区分", mitigation_type: "緩和策", plan_due_at: "予定日", exclusion_reason: "対象外の理由", request: "依頼" } as Record<string, string>)[h.field] ?? h.field} {h.from_value ? `${String(h.from_value).slice(0, 25)} → ` : ""}{String(h.to_value ?? "").slice(0, 40)}{h.note ? <span className="text-slate-400">（{h.note}）</span> : null}</div>) : <div className="text-slate-500">なし</div>}</div></div>
        </>}
      </div>
    </div>
  );
}

// ======================================================================= 資産台帳
export function ScsAssets() {
  const canAct = useCanAct();
  const [d, setD] = useState<{ items: any[]; counts: Record<string, number>; last_inspection: any } | null>(null); const [err, setErr] = useState(""); const [edit, setEdit] = useState<any>(null); const [msg, setMsg] = useState("");
  const load = () => api.get<any>("/scs/assets").then(setD).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const save = async () => {
    try { const { id, source, ...b } = edit; const body = Object.fromEntries(Object.entries(b).filter(([k]) => ["name", "category", "manufacturer", "model", "serial", "os_name", "os_version", "firmware", "location", "purpose", "maintainer", "is_boundary", "important_system", "cpe", "open_ports", "in_scope", "out_of_scope_reason"].includes(k)).map(([k, v]) => [k, v === "" ? null : k === "open_ports" && v !== null ? Number(v) : v]));
      if (id) await api.patch(`/scs/assets/${id}`, body); else await api.post("/scs/assets", body); setEdit(null); setMsg("保存しました"); load(); }
    catch (e: any) { setMsg(e.message); }
  };
  if (err) return <div className="text-rose-300">{err}</div>;
  return (
    <div className="flex flex-col gap-3.5">
      <div className="flex flex-wrap items-center gap-3"><h1 className="text-[22px] font-bold">資産台帳</h1><span className="text-[12.5px] text-slate-400">機器・OS・台数の把握（3-1-1-1 / 3-1-1-2 / 3-1-2-1・2）</span>
        {canAct && <button className={`${BTN} ml-auto`} onClick={() => setEdit({ category: "network_device", name: "", is_boundary: false, important_system: false, in_scope: true })}>＋ 機器を手で追加</button>}</div>
      {msg && <div className="text-[13px] text-teal-200">{msg}</div>}
      <div className="flex flex-wrap gap-3.5">{["pc", "server", "hypervisor", "network_device", "smart_device"].map((k) => <div key={k} className={`${CARD} flex-1`}><div className="text-xs text-slate-400">{CAT_JA[k]}</div><div className="text-[30px] font-bold">{d?.counts?.[k] ?? 0}<span className="text-sm"> 台</span></div></div>)}</div>
      <div className={`${CARD} overflow-x-auto px-2 py-1`}>
        <table className="w-full text-[13px]"><thead><tr className="text-left text-[11px] text-slate-500">{["名前", "区分", "製造元・モデル", "OS / ファームウェア", "", "14日対象（未対応）", "最終確認", "出所", ""].map((h, i) => <th key={i} className="whitespace-nowrap px-2 py-2">{h}</th>)}</tr></thead>
          <tbody>{!d ? <tr><td colSpan={9} className="p-4 text-slate-500">読み込み中…</td></tr> : d.items.map((a) => (
            <tr key={a.id} className={`border-t border-slate-700/60 ${a.in_scope ? "" : "opacity-50"}`}>
              <td className="px-2 py-1.5">{a.name}</td>
              <td className="px-2 py-1.5"><Chip cls="bg-teal-500/20 text-teal-200">{CAT_JA[a.category] ?? a.category}</Chip>{a.category_source === "manual" && a.source === "wazuh" && <span className="ml-1 text-[10px] text-slate-500">手で変更</span>}</td>
              <td className="px-2 py-1.5 text-xs">{[a.manufacturer, a.model].filter(Boolean).join(" ") || <span className="text-slate-600">未入力</span>}</td>
              <td className="px-2 py-1.5 text-xs">{[a.os_name, a.os_version].filter(Boolean).join(" ") || a.firmware || "—"}{a.firmware && a.os_name ? ` / ${a.firmware}` : ""}</td>
              <td className="px-2 py-1.5">{a.is_boundary && <Chip cls={PR_CLS.P2}>境界</Chip>} {a.important_system && <Chip cls="bg-slate-700 text-slate-300">重要</Chip>}</td>
              <td className={`px-2 py-1.5 font-mono text-xs ${dueCls(a.sla_next_due)}`}>{a.sla_open ? `${a.sla_open} 件・${dueText(a.sla_next_due)}` : "—"}</td>
              <td className="whitespace-nowrap px-2 py-1.5 font-mono text-xs text-slate-500">{fmtTs(a.last_seen_at)}</td>
              <td className="px-2 py-1.5 text-xs">{a.source === "wazuh" ? "Wazuh" : "手入力"}</td>
              <td className="px-2 py-1.5 text-right">{canAct && <button className="text-xs text-teal-300 hover:underline" onClick={() => setEdit({ ...a })}>編集</button>}</td>
            </tr>))}</tbody></table>
      </div>
      <div className="rounded-[10px] border border-slate-700 bg-slate-900 px-3 py-2 text-xs leading-relaxed text-slate-400">区分は OS 名から自動で決め、編集で上書きできます（上書きした区分は自動で戻りません）。製造元・モデルは Wazuh から取れないので手で入れてください。Wazuh から消えた機器も台帳には残し、年次点検で差分として出します。</div>
      <Disclaimer />
      {edit && <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/50 p-6" onClick={() => setEdit(null)}><div className="w-full max-w-[640px] rounded-2xl border border-slate-700 bg-[#0D1428] p-5" onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 text-lg font-bold">{edit.id ? `${edit.name} を編集` : "機器を手で追加"}</div>
        <div className="grid grid-cols-2 gap-2.5 text-xs text-slate-400">
          <label>名前<input className={INPUT} disabled={edit.source === "wazuh"} value={edit.name ?? ""} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></label>
          <label>区分<select className={INPUT} value={edit.category} onChange={(e) => setEdit({ ...edit, category: e.target.value })}>{Object.entries(CAT_JA).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
          {[["manufacturer", "製造元"], ["model", "モデル"], ["serial", "シリアル"], ["firmware", "ファームウェア版"], ["location", "設置場所"], ["maintainer", "保守事業者"], ["cpe", "CPE（脆弱性の照合用）"], ["open_ports", "公開ポート数"]].map(([k, l]) => <label key={k}>{l}<input className={INPUT} value={edit[k] ?? ""} onChange={(e) => setEdit({ ...edit, [k]: e.target.value })} /></label>)}
          {edit.source !== "wazuh" && [["os_name", "OS"], ["os_version", "OS の版"]].map(([k, l]) => <label key={k}>{l}<input className={INPUT} value={edit[k] ?? ""} onChange={(e) => setEdit({ ...edit, [k]: e.target.value })} /></label>)}
          <label className="col-span-2">用途<input className={INPUT} value={edit.purpose ?? ""} onChange={(e) => setEdit({ ...edit, purpose: e.target.value })} /></label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={!!edit.is_boundary} onChange={(e) => setEdit({ ...edit, is_boundary: e.target.checked })} />インターネットとの境界にある機器</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={!!edit.important_system} onChange={(e) => setEdit({ ...edit, important_system: e.target.checked })} />重要システムの機器</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={!!edit.in_scope} onChange={(e) => setEdit({ ...edit, in_scope: e.target.checked })} />評価の対象に含める</label>
          {!edit.in_scope && <label className="col-span-2">対象外の理由（必須）<input className={INPUT} value={edit.out_of_scope_reason ?? ""} onChange={(e) => setEdit({ ...edit, out_of_scope_reason: e.target.value })} /></label>}
        </div>
        <div className="mt-4 flex gap-2"><button className={BTN_P} disabled={!edit.name || (!edit.in_scope && !(edit.out_of_scope_reason ?? "").trim())} onClick={save}>保存</button><button className={BTN} onClick={() => setEdit(null)}>やめる</button>
          {edit.id && edit.source === "manual" && <button className={`${BTN} ml-auto`} onClick={async () => { if (!confirm(`${edit.name} を台帳から外しますか？（記録は年次点検の差分のために残ります）`)) return; await api.del(`/scs/assets/${edit.id}`); setEdit(null); load(); }}>台帳から外す</button>}</div>
      </div></div>}
    </div>
  );
}
