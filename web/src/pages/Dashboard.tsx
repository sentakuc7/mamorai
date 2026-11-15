import { useEffect, useState } from "react";
import { onServerEvent } from "../lib/events";
import { Link } from "react-router-dom";
import { fmtTs, api } from "../lib/api";
import { t } from "../lib/i18n";
import { useMode } from "../lib/mode";
import { handlingOf, loadHandling } from "../lib/handling";
import { TRIAGE, TRIAGE_ORDER, triageOf, type RuleNote, type Triage } from "../lib/triage";

interface Wazuh { id: number; name: string; archives_enabled: boolean }
interface Node { id: string | null; name: string; status: string; ip: string | null; os: string | null; platform: string | null; version: string | null; last_keepalive: string | null; counts: { total: number; critical: number; high: number; medium: number; low: number }; last_alert: string | null; role: "server" | "client"; role_source: "auto" | "manual"; host_id: number | null; cloud: { name: string; service: string; region: string } | null }
interface Summary { total: number; severity: Record<string, number>; topRules: { id: string; count: number; description: string; level: number }[]; agents: { name: string; count: number }[]; histogram: { t: string; c: number }[] }

/** 重大度（Wazuh level）: 緊急 / 高 / 中 / 低 — alerts page と同じ言葉（EDR-156）. Shown in 詳細表示 only. */
const SEV: { k: "critical" | "high" | "medium" | "low"; label: string; color: string }[] = [
  { k: "critical", label: "dash.critical", color: "#F2555A" },
  { k: "high", label: "dash.high", color: "#FF8A3D" },
  { k: "medium", label: "dash.medium", color: "#F5C542" },
  { k: "low", label: "dash.low", color: "#9AA6BF" },
];

const Ico = ({ d, className = "text-teal-300", size = 16 }: { d: string; className?: string; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={`shrink-0 ${className}`}><path d={d} /></svg>
);
const I = {
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20 20l-4-4",
  approve: "M9 12l2 2 4-4M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  board: "M4 4h5v16H4zM10 4h5v10h-5zM16 4h4v7h-4z",
  clock: "M12 8v4l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z",
  chat: "M21 12a8 8 0 0 1-11.5 7.2L4 21l1.8-5.5A8 8 0 1 1 21 12z",
  cloud: "M7 18a5 5 0 1 1 1-9.9A6 6 0 0 1 19 10a4 4 0 0 1-1 8z",
  server: "M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01",
  laptop: "M4 5h16v10H4zM2 19h20",
  alert: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v6M12 16.5h.01",
  warn: "M12 3l10 18H2zM12 10v4M12 17h.01",
  ok: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM8 12l3 3 5-6",
};
const num = "font-display font-semibold tabular-nums";

export default function Dashboard() {
  const { mode } = useMode();
  const [wz, setWz] = useState<Wazuh[]>([]); const [sel, setSel] = useState<number | null>(null);
  const [sum, setSum] = useState<Summary | null>(null); const [err, setErr] = useState("");
  // 未対応の緊急/高アラート（対応済み・調査中を差し引く）
  const [open, setOpen] = useState<{ critical: number; high: number; handled: number; investigating: number; tri: Record<Triage, number>; sessions: { id: number; label: string; n: number }[] } | null>(null);
  // ノード俯瞰（サーバー / クライアント）
  const [nodes, setNodes] = useState<Node[] | null>(null); const [agentOpen, setAgentOpen] = useState<Record<string, { critical: number; high: number; investigating: number; handled: number }>>({});
  const loadNodes = () => { if (sel == null) return; api.get<{ items: Node[] }>(`/wazuh/${sel}/nodes`).then((r) => setNodes(r.items)).catch(() => setNodes([])); };
  useEffect(() => { setNodes(null); loadNodes(); }, [sel]);
  const setRole = async (n: Node, role: string) => { await api.put(`/nodes/${encodeURIComponent(n.name)}/role`, { role }); loadNodes(); };
  // 運用キュー: 承認待ち / Action 未処理 / スケジュール / 返答待ちセッション
  const [ops, setOps] = useState<{ approvals: number; actions: number; followups: number; schedules: number; nextRun: string | null; waiting: number; external: number; running: number } | null>(null);
  const loadOps = () => Promise.all([
    api.get<{ items: any[] }>("/approvals?decision=pending&limit=200"), api.get<{ items: any[] }>("/next-actions?limit=200"), api.get<{ items: any[] }>("/schedules"), api.get<{ items: any[] }>("/sessions?limit=200"),
  ]).then(([ap, na, sc, se]) => {
    const openA = na.items.filter((a) => ["proposed", "blocked", "approved", "executing"].includes(a.status));
    const act = sc.items.filter((x) => x.state === "active" && x.enabled);
    setOps({ approvals: ap.items.length, actions: openA.length, followups: openA.filter((a) => a.kind === "followup").length, schedules: act.length, nextRun: act.map((x) => x.next_run_at).filter(Boolean).sort()[0] ?? null, waiting: se.items.filter((x) => x.status === "waiting_user").length, external: se.items.filter((x) => x.status === "waiting_external").length, running: se.items.filter((x) => ["running", "waiting_approval"].includes(x.status)).length });
  }).catch(() => setOps(null));
  useEffect(() => { loadOps(); const off = onServerEvent(["approval", "next_actions", "status", "schedule"], loadOps); return off; }, []);
  useEffect(() => { api.get<{ items: Wazuh[] }>("/wazuh").then((r) => { setWz(r.items); if (r.items[0]) setSel(r.items[0].id); }); }, []);
  useEffect(() => { if (sel == null) return; setSum(null); setErr(""); api.get<Summary>(`/wazuh/${sel}/summary`).then(setSum).catch((e) => setErr(e.message)); }, [sel]);
  useEffect(() => {
    if (sel == null) return; setOpen(null);
    Promise.all([api.get<{ items: any[] }>(`/wazuh/${sel}/alerts?minLevel=12&size=500&window=now-24h`), loadHandling()]).then(async ([r, h]) => {
      // AI の判定（アラート画面と同じ: ルール説明の triage → 無ければ level から仮置き）
      const ids = [...new Set(r.items.map((a) => String(a.rule.id)))];
      const notes = ids.length ? await api.get<{ items: Record<string, RuleNote> }>(`/rule-notes?ids=${ids.join(",")}`).then((n) => n.items).catch(() => ({})) : {};
      // 対応済み → 除外、調査中（Sidekick が進行中）→ 「調査中」カードへ、それ以外 → 未対応
      const o = { critical: 0, high: 0, handled: 0, investigating: 0, tri: { danger: 0, check: 0, benign_likely: 0 } as Record<Triage, number>, sessions: [] as { id: number; label: string; n: number }[] };
      const bySess = new Map<number, { id: number; label: string; n: number }>();
      const perAgent: Record<string, { critical: number; high: number; investigating: number; handled: number }> = {};
      for (const a of r.items) {
        const hd = handlingOf(a, h); const st = hd?.state;
        const ag = a.agent?.name ?? "?"; const pa = (perAgent[ag] ??= { critical: 0, high: 0, investigating: 0, handled: 0 });
        if (st === "done") { o.handled++; pa.handled++; }
        else if (st === "investigating") { o.investigating++; pa.investigating++; const sid = hd!.h.session_id ?? 0; const e = bySess.get(sid) ?? { id: sid, label: hd!.h.label, n: 0 }; e.n++; bySess.set(sid, e); }
        else { o.tri[triageOf(a, notes)]++; if (a.rule.level >= 15) { o.critical++; pa.critical++; } else { o.high++; pa.high++; } }
      }
      o.sessions = [...bySess.values()].sort((x, y) => y.n - x.n);
      setOpen(o); setAgentOpen(perAgent);
    }).catch(() => setOpen(null));
  }, [sel]);
  if (wz.length === 0) return <div className="text-slate-400">{t("dash.noWazuh")} <Link className="text-teal-300 underline" to="/settings">{t("nav.settings")}</Link></div>;
  const max = Math.max(1, ...(sum?.histogram.map((h) => h.c) ?? [1]));
  const hFirst = sum?.histogram[0]?.t, hMid = sum?.histogram[Math.floor((sum?.histogram.length ?? 0) / 2)]?.t, hLast = sum?.histogram[(sum?.histogram.length ?? 1) - 1]?.t;
  const card = "rounded-2xl border border-slate-700 bg-slate-800";
  return (
    <div className="mx-auto max-w-[1600px] space-y-5">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="flex-1 text-[26px] font-bold">{t("nav.dashboard")} <span className="text-[15px] font-normal text-slate-400">· {t("dash.last24h")}</span></h1>
        {wz.length > 1 && <>{/* Wazuh が 1 台なら選ぶものが無いので出さない（EDR-156） */}
          <label htmlFor="dash-wz" className="text-[13px] text-slate-400">Wazuh</label>
          <select id="dash-wz" className="input w-auto min-h-[40px] rounded-lg" value={sel ?? ""} onChange={(e) => setSel(Number(e.target.value))}>{wz.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select>
        </>}
      </header>
      {err && <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{t("common.error")}: {err}</div>}
      {!sum && !err && <div className="text-slate-400">{t("common.loading")}</div>}

      {sum && mode === "simple" && (() => {
        // かんたん表示は「AI の判定」で話す（アラート画面のカードと同じ言葉・同じ件数）
        if (!open) return null;
        const d = open.tri.danger, c = open.tri.check, b = open.tri.benign_likely;
        const tone = d > 0 ? { d: I.alert, ic: "text-[#F2555A]", box: "border-[#6B2329] bg-[#2A1216]", msg: `AI が「危険」と判定した未対応のアラートが ${d} 件あります。すぐ確認してください` }
          : c > 0 ? { d: I.warn, ic: "text-[#F5C542]", box: "border-[#5A4318] bg-[#241A0F]", msg: `AI が「要確認」と判定した未対応のアラートが ${c} 件あります。Sidekick に「未対応のアラートを見て」と頼むと要約します` }
          : { d: I.ok, ic: "text-[#3CCB8C]", box: "border-[#1D4A36] bg-[#0F2219]", msg: b > 0 ? `確認が必要なアラートはありません（「おそらく正常」が ${b} 件）` : open.handled > 0 ? `未対応のアラートはありません（この 24 時間で ${open.handled} 件を対応済み）` : "この 24 時間、確認が必要なアラートはありません" };
        return (
          <section aria-label="状態" className={`flex items-center gap-4 rounded-2xl border px-5 py-4 ${tone.box}`}>
            <Ico d={tone.d} className={tone.ic} size={28} />
            <div className="space-y-1">
              <div className="text-[17px] font-semibold">{tone.msg}</div>
              <div className="text-[13px] text-slate-300">監視中の端末 {sum.agents.length} 台{open.investigating > 0 && ` · 調査中 ${open.investigating} 件`}{open.handled > 0 && ` · 対応済み ${open.handled} 件`}</div>
            </div>
          </section>
        );
      })()}

      {sum && (<>
        <section aria-label="アラートの件数" className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(190px,1fr))]">
          {open && (
            <div className={`${card} flex flex-col gap-1.5 border-[#2A4A7A] px-[18px] py-4`}>
              <div className="flex items-center gap-2 text-[13px] text-slate-400"><Ico d={I.search} size={15} /><span className="font-semibold text-slate-100">調査中</span><span>Sidekick 進行中</span><Link to="/alerts" className="ml-auto text-xs text-teal-300 hover:text-teal-200">一覧 →</Link></div>
              <div className={`${num} text-[32px] text-teal-300`}>{open.investigating.toLocaleString()}</div>
              <div className="space-y-0.5">
                {open.sessions.slice(0, 3).map((s) => <div key={s.id} className="truncate text-xs text-slate-300" title={s.label}><Link to={`/sidekick/${s.id}`} className="font-mono text-teal-300 hover:text-teal-200">#{s.id}</Link> {s.label} <span className="text-slate-400">×{s.n}</span></div>)}
                {open.sessions.length > 3 && <div className="text-xs text-slate-400">ほか {open.sessions.length - 3} セッション</div>}
                {open.investigating === 0 && <div className="text-xs text-slate-400">進行中の調査はありません</div>}
              </div>
            </div>
          )}
          {mode === "simple" && open && TRIAGE_ORDER.map((k) => (
            <Link to={`/alerts?tri=${k}`} key={k} className={`${card} flex flex-col gap-1.5 px-[18px] py-4 transition hover:border-slate-500/60`}>
              <div className="flex items-center gap-2 text-[13px] text-slate-400"><span className="h-2 w-2 rounded-full" style={{ background: TRIAGE[k].dot }} /><span className="text-slate-200">{TRIAGE[k].label}</span><span className="rounded-full border border-slate-600 px-2 text-[11px] text-slate-300">未対応</span><span className="ml-auto text-[11px]">AI の判定</span></div>
              <div className={`${num} text-[30px] ${TRIAGE[k].num}`}>{open.tri[k].toLocaleString()}</div>
              <div className="text-xs text-slate-400">{TRIAGE[k].desc}</div>
            </Link>
          ))}
          {mode === "detail" && SEV.map(({ k, label, color }) => {
            const isOpen = !!open && (k === "critical" || k === "high"); const rec = sum.severity[k] ?? 0; const v = isOpen ? open![k as "critical" | "high"] : rec;
            return (
              <Link to="/alerts" key={k} className={`${card} flex flex-col gap-1.5 px-[18px] py-4 transition hover:border-slate-500/60`}>
                <div className="flex items-center gap-2 text-[13px] text-slate-400"><span className="h-2 w-2 rounded-full" style={{ background: color }} />重大度 {t(label)}{isOpen && <span className="rounded-full border border-slate-600 px-2 text-[11px] text-slate-300">未対応</span>}</div>
                {isOpen ? (
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="text-[13px] text-slate-400" title="Wazuh に記録された件数（直近 24 時間）">記録 {rec.toLocaleString()}</span><span className="text-slate-400">→</span>
                    <span className={`${num} text-[30px]`} style={{ color }} title="対応済みを除いた未対応の件数">{v.toLocaleString()}</span>
                  </div>
                ) : <div className={`${num} text-[30px]`} style={{ color: k === "low" ? "#E6EAF2" : color }}>{v.toLocaleString()}</div>}
                {isOpen && rec !== v && <div className="text-[11px] leading-relaxed text-slate-400">対応済み・調査中 {(rec - v).toLocaleString()} 件を除外（Wazuh の表示は記録件数）</div>}
              </Link>
            );
          })}
        </section>

        {ops && (
          <section aria-label="運用キュー" className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(220px,1fr))]">
            <Link to="/approvals" className={`${card} flex flex-col gap-1.5 px-[18px] py-4 transition hover:border-slate-500/60 ${ops.approvals ? "border-teal-500" : ""}`}>
              <div className="flex items-center gap-2 text-sm font-semibold"><Ico d={I.approve} />承認待ち</div>
              <div className={`${num} text-[30px] ${ops.approvals ? "text-teal-300" : ""}`}>{ops.approvals}</div>
              <div className="text-xs text-slate-400">{ops.approvals ? "人間の承認で実行されます" : "承認を待っている作業はありません"}</div>
            </Link>
            <Link to="/next-actions" className={`${card} flex flex-col gap-1.5 px-[18px] py-4 transition hover:border-slate-500/60`}>
              <div className="flex items-center gap-2 text-sm font-semibold"><Ico d={I.board} />Action 未処理</div>
              <div className="flex items-baseline gap-2.5"><span className={`${num} text-[30px]`}>{ops.actions}</span>{ops.followups > 0 && <span className="rounded-full border border-slate-600 px-2 text-xs text-slate-300">残タスク {ops.followups}</span>}</div>
              <div className="text-xs text-slate-400">未対応 + 承認済・待ち + 実行中</div>
            </Link>
            {mode === "detail" && <Link to="/schedules" className={`${card} flex flex-col gap-1.5 px-[18px] py-4 transition hover:border-slate-500/60`}>
              <div className="flex items-center gap-2 text-sm font-semibold"><Ico d={I.clock} />スケジュール</div>
              <div className={`${num} text-[30px]`}>{ops.schedules}</div>
              <div className="text-xs text-slate-400">{ops.nextRun ? `次回 ${fmtTs(ops.nextRun)}` : "有効なスケジュールはありません"}</div>
            </Link>}
            {mode === "detail" && <Link to="/sidekick" className={`${card} flex flex-col gap-1.5 px-[18px] py-4 transition hover:border-slate-500/60`}>
              <div className="flex items-center gap-2 text-sm font-semibold"><Ico d={I.chat} />Sidekick</div>
              <div className="flex flex-wrap items-baseline gap-2">
                <span className={`${num} text-[30px] ${ops.waiting ? "text-[#3CCB8C]" : ""}`}>{ops.waiting}</span><span className="text-[13px] text-slate-400">返答待ち</span>
                {ops.external > 0 && <span className="rounded-full border border-violet-500/40 px-2 text-xs text-violet-200">対応待ち {ops.external}</span>}
                {ops.running > 0 && <span className="rounded-full border border-sky-500/40 px-2 text-xs text-sky-300">実行中 {ops.running}</span>}
              </div>
              <div className="text-xs text-slate-400">AI があなたの返事を待っているセッション</div>
            </Link>}
          </section>
        )}

        {mode === "detail" && <section aria-labelledby="hist-h" className={`${card} space-y-3 px-5 py-[18px]`}>
          <h2 id="hist-h" className="text-[15px] font-semibold">24 時間の記録イベント {sum.total.toLocaleString()} 件 <span className="text-[13px] font-normal text-slate-400">（時間別・累計の記録であり対応状況とは無関係）</span></h2>
          <div role="img" aria-label="24 時間の時間別記録イベント数" className="flex h-[120px] items-end gap-1 border-b border-slate-600">
            {sum.histogram.map((h) => <div key={h.t} title={`${h.t}: ${h.c}`} className="flex-1 rounded-t-[3px] bg-teal-500/85 transition hover:bg-teal-300" style={{ height: `${Math.max(2, (h.c / max) * 100)}%` }} />)}
          </div>
          {hFirst && <div className="flex justify-between font-mono text-xs text-slate-400"><span>{fmtTs(hFirst).slice(5).replace(/:\d\d$/, "")}</span><span>{hMid ? fmtTs(hMid).slice(5).replace(/:\d\d$/, "") : ""}</span><span>{hLast ? fmtTs(hLast).slice(5).replace(/:\d\d$/, "") : ""}</span></div>}
        </section>}

        {/* ノード俯瞰: 左=サーバー / 右=クライアント */}
        <div className="flex flex-wrap items-start gap-5">
          {(["server", "client"] as const).map((role) => {
            const list = (nodes ?? []).filter((n) => n.role === role).map((n) => ({ ...n, open: agentOpen[n.name] ?? { critical: 0, high: 0, investigating: 0, handled: 0 } }))
              .sort((a, b) => (b.open.critical * 1000 + b.open.high * 10 + b.open.investigating) - (a.open.critical * 1000 + a.open.high * 10 + a.open.investigating) || b.counts.total - a.counts.total);
            const openSum = list.reduce((x, n) => x + n.open.critical + n.open.high, 0);
            return (
              <section key={role} aria-label={role === "server" ? "サーバー" : "クライアント端末"} className={`${card} flex min-w-0 flex-[1_1_420px] flex-col gap-2.5 px-5 py-[18px]`}>
                <div className="flex flex-wrap items-baseline gap-2.5">
                  <h2 className="flex items-center gap-2 text-base font-semibold"><Ico d={role === "server" ? I.server : I.laptop} />{role === "server" ? "サーバー" : "クライアント端末"} <span className="text-[13px] font-normal text-slate-400">{list.length} 台</span></h2>
                  <span className="ml-auto text-xs text-slate-400">未対応 {openSum} · 稼働 {list.filter((n) => n.status === "active").length} / 切断 {list.filter((n) => n.status === "disconnected").length}</span>
                  {nodes === null && <span className="text-xs text-slate-400">読み込み中…</span>}
                </div>
                {list.length === 0 && nodes !== null && <div className="text-sm text-slate-400">{role === "server" ? "サーバーに分類されたノードはありません" : "クライアントに分類されたノードはありません"}</div>}
                <div className="max-h-[520px] space-y-1.5 overflow-auto pr-1">
                  {list.map((n) => {
                    const openN = n.open.critical + n.open.high;
                    const tone = n.status === "disconnected" ? "border-slate-600 opacity-60" : n.open.critical ? "border-[#6B2329] bg-[#1A1018]" : n.open.high ? "border-[#6B4419] bg-[#1A1610]" : n.open.investigating ? "border-[#2A4A7A] bg-[#0F1830]" : "border-slate-600";
                    return (
                      <div key={n.name} className={`grid items-center gap-2.5 rounded-xl border px-2.5 py-2 ${mode === "detail" ? "min-w-[560px] [grid-template-columns:10px_minmax(120px,1.4fr)_16px_minmax(80px,1fr)_70px_56px_110px_36px]" : "min-w-[440px] [grid-template-columns:10px_minmax(120px,1.4fr)_16px_minmax(80px,1fr)_70px_56px_36px]"} ${tone}`}>
                        <span title={`エージェント ${n.status}`} className={`h-2 w-2 rounded-full ${n.status === "active" ? "bg-[#3CCB8C]" : "bg-slate-500"}`} />
                        <Link to={`/alerts?q=${encodeURIComponent(n.name)}`} title={`${n.os ?? "OS 不明"}${n.ip ? ` · ${n.ip}` : ""} — アラートを見る`} className="truncate font-mono text-[13px] text-slate-100 hover:text-teal-200">{n.name}</Link>
                        <span>{n.cloud && <span title={`${n.cloud.service} · ${n.cloud.region}`}><Ico d={I.cloud} size={14} /></span>}</span>
                        <span className="truncate text-xs text-slate-400">{(n.os ?? "").replace(/^Microsoft /, "")}</span>
                        <span title="未対応（重大度 緊急・高）" className={`text-[13px] font-semibold ${n.open.critical ? "text-[#F2555A]" : n.open.high ? "text-[#FF8A3D]" : "text-slate-400"}`}>{openN} <span className="text-[11px] font-normal text-slate-400">未対応</span></span>
                        <span title="調査中" className="text-xs text-teal-300">{n.open.investigating ? `${n.open.investigating} 調査中` : ""}</span>
                        {mode === "detail" && <span title="24h の記録件数（重大度 緊急 / 高 / 中 / 低）" className="font-mono text-xs text-slate-400"><span className="text-[#F2555A]">{n.counts.critical}</span>/<span className="text-[#FF8A3D]">{n.counts.high}</span>/<span className="text-[#F5C542]">{n.counts.medium}</span>/<span>{n.counts.low}</span></span>}
                        <button aria-label="サーバーとクライアントを入れ替え" title={(n.role_source === "manual" ? "手動分類" : "自動分類") + "（クリックで反対側へ）"} onClick={() => setRole(n, role === "server" ? "client" : "server")} className="min-h-[28px] rounded-lg border border-slate-600 text-[13px] text-slate-400 hover:text-slate-100">⇄</button>
                      </div>
                    );
                  })}
                </div>
                <div className="text-[11px] text-slate-400">{mode === "detail" ? "右の数字は 24h の記録件数（重大度 緊急/高/中/低）。" : ""}⇄ でサーバー⇔クライアントを入れ替え</div>
              </section>
            );
          })}
        </div>

        {mode === "detail" && <details className={`${card} px-5 py-3.5`}>
          <summary className="cursor-pointer text-sm">{t("dash.topRules")} <span className="text-slate-400">（参考）</span></summary>
          <div className="overflow-x-auto pt-2.5">
            {sum.topRules.map((r) => (
              <div key={r.id} className="grid min-w-[420px] gap-3 border-t border-slate-700 py-2 text-[13px] [grid-template-columns:72px_minmax(0,1fr)_80px]">
                <span className="font-mono text-slate-400">{r.id}</span>
                <span><span className="mr-2 rounded border border-slate-600 px-1.5 text-[11px] text-slate-300">L{r.level}</span>{r.description}</span>
                <span className="text-right font-mono">{r.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </details>}
      </>)}
    </div>
  );
}
