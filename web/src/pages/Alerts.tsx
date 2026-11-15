import { useContext, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { useMode } from "../lib/mode";
import { UserCtx } from "../main";
import { Field } from "../components/fields";
import { handlingOf, loadHandling as fetchHandling, programOf, scopeMatch, SCOPE_JA, type Handling, type Scope } from "../lib/handling";
import { Ico, I } from "../components/Icon";
import { defaultTriage, LEVEL_JA, TRIAGE, TRIAGE_ORDER, triageOf as triageWith, type RuleNote, type Triage } from "../lib/triage";
import { groupKeyOf, isVuln, SEV_LABEL, vulnBreakdown, vulnOf, vulnTextOf } from "../lib/vuln";

type Note = RuleNote;
const ago = (iso: string) => { const s = (Date.now() - new Date(iso).getTime()) / 1000; return s < 60 ? "たった今" : s < 3600 ? `${Math.floor(s / 60)} 分前` : s < 86400 ? `${Math.floor(s / 3600)} 時間前` : `${Math.floor(s / 86400)} 日前`; };
const base = (p?: string) => (p ? p.split(/[\\/]/).pop() : undefined);

/** Human-readable "what/where" line from the alert's data, in Japanese. */
function subject(a: any): { main: string; sub?: string } {
  const ev = a.data?.win?.eventdata;
  if (ev?.image) return { main: `プログラム: ${base(ev.image)}`, sub: ev.parentImage ? `起動元: ${base(ev.parentImage)}${ev.user ? ` · ユーザー: ${ev.user}` : ""}` : ev.user ? `ユーザー: ${ev.user}` : undefined };
  if (ev?.targetFilename) return { main: `ファイル: ${base(ev.targetFilename)}` };
  if (a.data?.srcip) return { main: `送信元 IP: ${a.data.srcip}`, sub: [a.data.srcuser && `ユーザー名: ${a.data.srcuser}`, a.data.url && `要求: ${String(a.data.url).slice(0, 80)}`, a.data.id && `応答: ${a.data.id}`].filter(Boolean).join(" · ") || undefined };
  return { main: String(a.full_log ?? "").slice(0, 100) };
}

export default function Alerts() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const { mode } = useMode();
  const nav = useNavigate(); const [sp] = useSearchParams();
  const [wz, setWz] = useState<{ id: number; name: string }[]>([]); const [sel, setSel] = useState<number | null>(null);
  const [minLevel, setMinLevel] = useState(12); const [window_, setWindow] = useState("now-24h");
  const [items, setItems] = useState<any[]>([]); const [notes, setNotes] = useState<Record<string, Note>>({}); const [err, setErr] = useState(""); const [loading, setLoading] = useState(false); const [explaining, setExplaining] = useState(false);
  const [open, setOpen] = useState<string | null>(null); const [tri, setTri] = useState<"all" | Triage>(() => { const v = sp.get("tri"); return v && v in TRIAGE ? (v as Triage) : "all"; }); const [q, setQ] = useState(sp.get("q") ?? ""); const [group, setGroup] = useState(true);
  const [editing, setEditing] = useState<Note | null>(null);
  const [handling, setHandling] = useState<Handling[]>([]); const [view, setView] = useState<"open" | "history">("open");
  const loadHandling = () => fetchHandling().then(async (h) => {
    setHandling(h);
    // rule notes for history-only rules (outside the current window)
    const ids = [...new Set(h.filter((x) => x.alert?.rule?.id).map((x) => String(x.alert.rule.id)))].filter((id) => !notes[id]);
    if (ids.length) { const n = await api.get<{ items: Record<string, Note> }>(`/rule-notes?ids=${ids.join(",")}`); setNotes((prev) => ({ ...prev, ...n.items })); }
  }).catch(() => {});

  useEffect(() => { api.get<{ items: any[] }>("/wazuh").then((r) => { setWz(r.items); if (r.items[0]) setSel(r.items[0].id); }); }, []);
  const load = async () => {
    if (sel == null) return; setErr(""); setLoading(true);
    try {
      const r = await api.get<{ items: any[] }>(`/wazuh/${sel}/alerts?minLevel=${minLevel}&size=200&window=${window_}`);
      setItems(r.items); loadHandling();
      const ids = [...new Set(r.items.map((a) => String(a.rule.id)))];
      const n = await api.get<{ items: Record<string, Note> }>(`/rule-notes?ids=${ids.join(",")}`);
      setNotes(n.items);
      // EDR-80: 脆弱性ルールは CVE ごとに文言が違うので rule.id 単位の AI 説明を作らない
      const vulnIds = new Set(r.items.filter(isVuln).map((a) => String(a.rule.id)));
      const unknown = ids.filter((id) => !n.items[id] && !vulnIds.has(id)).slice(0, 20);
      if (unknown.length) {
        setExplaining(true);
        const rules = unknown.map((id) => { const a = r.items.find((x) => String(x.rule.id) === id); return { id, description: String(a.rule.description ?? "").slice(0, 300), level: Number(a.rule.level), groups: (a.rule.groups ?? []).slice(0, 12), sample: JSON.stringify({ image: a.data?.win?.eventdata?.image, cmd: String(a.data?.win?.eventdata?.commandLine ?? "").slice(0, 200), srcip: a.data?.srcip, url: a.data?.url }).slice(0, 600) }; });
        api.post("/rule-notes/explain", { rules }).then(() => api.get<{ items: Record<string, Note> }>(`/rule-notes?ids=${ids.join(",")}`)).then((n2) => setNotes(n2.items)).catch(() => {}).finally(() => setExplaining(false));
      }
    } catch (e: any) { setErr(e.message); } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, [sel, minLevel, window_]);

  // EDR-80: 脆弱性アラートは rule_notes（rule.id 単位）を使わず、data.vulnerability から確定的に組み立てた文言を使う
  const noteOf = (a: any): Note | undefined => (isVuln(a) ? undefined : notes[String(a.rule.id)]);
  const triageOf = (a: any): Triage => triageWith(a, notes);
  const hOf = (a: any) => handlingOf(a, handling);
  // EDR-80: 脆弱性は CVE 単位で対応済みにするので、まとめ行を一度に片付ける範囲（group=この行の CVE 全部 / allvuln=表示中の脆弱性すべて）を用意する
  type MarkScope = Scope | "group" | "allvuln";
  const [marking, setMarking] = useState<{ a: any; scope: MarkScope; note: string; quiet: number; group: any[] } | null>(null);
  const [markBusy, setMarkBusy] = useState("");
  const markHandled = (a: any, group: any[] = [a]) => setMarking({ a, group, scope: isVuln(a) ? (group.length > 1 ? "group" : "agent") : programOf(a) ? "program" : "agent", note: "", quiet: isVuln(a) ? 7 : 0 });
  /** 一括対象: 未対応の脆弱性アラートを 端末+CVE+パッケージ で重複排除 */
  const vulnTargets = (scope: "group" | "allvuln", m: { group: any[] }) => {
    const src = (scope === "group" ? m.group : items.filter(isVuln)).filter((x) => hOf(x)?.state !== "done");
    const seen = new Set<string>(); return src.filter((x) => { const v = vulnOf(x); const k = `${x.agent?.id}|${v?.cve}|${v?.package}`; if (!v || seen.has(k)) return false; seen.add(k); return true; });
  };
  const submitMark = async () => {
    if (!marking) return; const { a, scope, note, quiet } = marking;
    const until = new Date(Date.now() + quiet * 86_400_000).toISOString();
    const post = (x: any, sc: Scope) => api.post("/alerts/handling", { rule_id: String(x.rule.id), agent_id: String(x.agent?.id ?? ""), scope: sc, program: programOf(x), until, note: note || undefined, alert: x, vuln_cve: vulnOf(x)?.cve, vuln_package: vulnOf(x)?.package });
    try {
      if (scope === "group" || scope === "allvuln") {
        const t = vulnTargets(scope, marking);
        for (let i = 0; i < t.length; i += 8) { setMarkBusy(`${Math.min(i + 8, t.length)} / ${t.length} 件を登録中…`); await Promise.all(t.slice(i, i + 8).map((x) => post(x, "agent"))); }
      } else await post(a, scope);
    } finally { setMarkBusy(""); }
    setMarking(null); loadHandling();
  };
  const similarCount = (a: any, scope: Scope) => items.filter((x) => scopeMatch(x, { rule_id: String(a.rule.id), agent_id: String(a.agent?.id ?? ""), scope, program: programOf(a), vuln_cve: vulnOf(a)?.cve ?? null, vuln_package: vulnOf(a)?.package ?? null }) && hOf(x)?.state !== "done").length;
  const scopeLabel = (a: any, sc: Scope) => (isVuln(a) ? ({ agent: "この端末のこの CVE だけ", program: SCOPE_JA.program, rule: "この CVE・全端末" } as Record<Scope, string>)[sc] : SCOPE_JA[sc]);
  const unmark = async (id: number) => { await api.del(`/alerts/handling/${id}`); loadHandling(); };

  // grouping: 脆弱性 = 同じ端末×深刻度（パッケージ別内訳を表示）、それ以外 = 同じ rule + 同じ agent → 1 行（最新を代表に）
  // 履歴: 対応済みの元アラート（Sidekick の alert_ref / 手動マークのスナップショット）＋ 今の期間で対応済みになっているもの
  const history = useMemo(() => {
    const m = new Map<string, any>();
    for (const h of handling) if (h.status === "done" && h.alert?._id && h.alert?.rule) m.set(h.alert._id, h.alert);
    for (const a of items) if (hOf(a)?.state === "done") m.set(a._id, a);
    return [...m.values()].sort((x, y) => new Date(y.timestamp).getTime() - new Date(x.timestamp).getTime());
  }, [handling, items]);
  const rows = useMemo(() => {
    const src = view === "history" ? history : items.filter((a) => hOf(a)?.state !== "done");
    const list = src.filter((a) => (tri === "all" || triageOf(a) === tri) && (!q || [a.rule.description, noteOf(a)?.title_ja ?? "", a.agent?.name ?? "", String(a.rule.id), subject(a).main, subject(a).sub ?? "", a.GeoLocation?.country_name ?? "", a.data?.srcip ?? "", vulnOf(a)?.cve ?? "", a.data?.vulnerability?.package?.name ?? ""].some((v) => String(v).toLowerCase().includes(q.toLowerCase()))));
    if (!group) return list.map((a) => ({ a, count: 1, others: [] as any[] }));
    const m = new Map<string, { a: any; count: number; others: any[] }>();
    for (const a of list) { const k = groupKeyOf(a); const g = m.get(k); if (g) { g.count++; g.others.push(a); } else m.set(k, { a, count: 1, others: [] }); }
    return [...m.values()];
  }, [items, notes, tri, q, group, handling, view, history]);
  const counts = useMemo(() => { const c: Record<string, number> = { danger: 0, check: 0, benign_likely: 0, handled: 0, open: 0 }; for (const a of items) { if (hOf(a)?.state === "done") c.handled++; else { c.open++; c[triageOf(a)]++; } } return c; }, [items, notes, handling]);

  const investigate = (a: any) => nav("/sidekick", { state: { prefill: `このアラートを調査して: ${a.agent?.name} rule ${a.rule.id} (level ${a.rule.level}) ${a.rule.description}`, alert: a } });
  const saveNote = async () => { if (!editing) return; const r = await api.put<Note>(`/rule-notes/${editing.rule_id}`, editing); setNotes({ ...notes, [r.rule_id]: r }); setEditing(null); };

  const sel_ = "rounded-[10px] border border-[#24314D] bg-slate-800 px-3 text-sm text-slate-100 min-h-[40px] focus:border-teal-400 focus:outline-none";
  const btnOut = "inline-flex min-h-[40px] items-center justify-center gap-1.5 rounded-[10px] border border-[#24314D] px-3.5 text-sm text-slate-100 transition hover:bg-slate-700 disabled:opacity-50";
  const btnPri = "inline-flex min-h-[40px] items-center justify-center gap-1.5 rounded-[10px] bg-teal-500 px-3.5 text-sm font-semibold text-white transition hover:bg-teal-400";
  const btnDone = "inline-flex min-h-[40px] items-center justify-center gap-1.5 rounded-[10px] border border-[#1F4A36] px-3.5 text-sm text-[#7FE0B0] transition hover:bg-[#12301F]";
  const pill = "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5";
  const EXPLAIN: { h: string; c: string; d: string }[] = [
    { h: "何が起きたか", c: "text-teal-300", d: I.search },
    { h: "考えられる原因", c: "text-[#F5C542]", d: "M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.8.8 1 1.5 1 2.5h6c0-1 .2-1.7 1-2.5A6 6 0 0 0 12 3z" },
    { h: "放置した場合の影響", c: "text-[#FF8A3D]", d: I.alerts },
    { h: "推奨する対応", c: "text-[#3CCB8C]", d: I.check },
  ];
  const SEV_FG: Record<string, string> = { Critical: "text-[#FF9A9D]", High: "text-[#FFC27A]", Medium: "text-[#F5C542]", Low: "text-slate-300" };

  return (
    <div className="mx-auto max-w-[1600px] space-y-[18px]">
      <header className="flex flex-wrap items-center gap-2.5">
        <h1 className="mr-1.5 flex items-center gap-2.5 text-2xl font-bold"><Ico d={I.alerts} size={22} className="text-[#F2555A]" />アラート</h1>
        {wz.length > 1 && <><label className="sr-only" htmlFor="al-wz">Wazuh</label>
        <select id="al-wz" className={sel_} value={sel ?? ""} onChange={(e) => setSel(Number(e.target.value))}>{wz.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select></>}
        <label className="sr-only" htmlFor="al-lv">重大度</label>
        <select id="al-lv" className={sel_} value={minLevel} onChange={(e) => setMinLevel(Number(e.target.value))}><option value={15}>緊急のみ（level 15+）</option><option value={12}>高以上（level 12+）</option><option value={7}>中以上（level 7+）</option><option value={0}>すべて</option></select>
        <label className="sr-only" htmlFor="al-win">期間</label>
        <select id="al-win" className={sel_} value={window_} onChange={(e) => setWindow(e.target.value)}><option value="now-24h">直近 24 時間</option><option value="now-7d">直近 7 日</option><option value="now-30d">直近 30 日</option></select>
        <div className="flex min-h-[40px] flex-[1_1_220px] items-center gap-2 rounded-[10px] border border-[#24314D] bg-slate-800 px-3 focus-within:border-teal-400">
          <Ico d={I.search} size={16} className="text-slate-400" />
          <label className="sr-only" htmlFor="al-q">検索</label>
          <input id="al-q" className="min-w-0 flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 outline-none" placeholder="検索（ホスト・内容・ルール番号）" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <label className="flex min-h-[40px] items-center gap-2 text-sm text-slate-300"><input type="checkbox" className="h-4 w-4 accent-[#3A56F0]" checked={group} onChange={(e) => setGroup(e.target.checked)} /> 同じ種類をまとめる</label>
        <div role="group" aria-label="表示" className="flex overflow-hidden rounded-[10px] border border-[#24314D]">
          <button className={`min-h-[40px] px-3.5 text-sm ${view === "open" ? "bg-teal-500 text-white" : "text-slate-400 hover:text-slate-200"}`} onClick={() => setView("open")}>未対応 {counts.open}</button>
          <button className={`flex min-h-[40px] items-center gap-1.5 px-3.5 text-sm ${view === "history" ? "bg-teal-500 text-white" : "text-slate-400 hover:text-slate-200"}`} onClick={() => setView("history")} title="対応済みになったアラートの履歴。カードを開くと当時の内容をそのまま確認できます"><Ico d={I.history} size={14} className="" />対応済みの履歴 {history.length}</button>
        </div>
        <button className={btnOut} onClick={load} disabled={loading}><Ico d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" size={14} className="" />{loading ? "読み込み中…" : "更新"}</button>
      </header>

      {view === "history" && <div className="rounded-xl border border-[#24314D] bg-slate-800 px-4 py-3 text-sm leading-relaxed text-slate-300"><strong className="text-slate-100">対応済みの履歴</strong>　Sidekick で対処が完了したもの・手動で対応済みにしたものを、発生時の内容のまま保存しています（期間フィルタの対象外）。カードを開くと未対応時と同じ詳細が見られます。{rows.length === 0 && <span className="text-slate-500">— まだ履歴はありません</span>}</div>}

      {view === "open" && <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1"><h2 className="text-[15px] font-semibold">AI の判定</h2><span className="text-[12.5px] text-slate-400">未対応のアラートを、AI が「危険 / 要確認 / おそらく正常」に仕分けています。カードを押すとその判定だけに絞り込みます。各カードの「重大度（緊急 / 高 / 中 / 低）」は Wazuh が付けた値です</span></div>}
      {view === "open" && <section aria-label="AI の判定" className="grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(200px,1fr))]">
        <button onClick={() => setTri("all")} className={`flex flex-col gap-1.5 rounded-[14px] border bg-slate-800 px-[18px] py-4 text-left transition ${tri === "all" ? "border-teal-500" : "border-slate-700 hover:border-slate-500/60"}`}>
          <span className="flex items-center gap-2 text-sm text-slate-300"><span className="h-2.5 w-2.5 rounded-full bg-teal-300" />未対応</span>
          <span className="font-display text-[32px] font-semibold leading-tight text-slate-100">{counts.open}<span className="ml-1 font-sans text-sm font-normal text-slate-400">件</span></span>
          <span className="text-xs text-slate-400">対応済み {counts.handled} 件は除外</span>
        </button>
        {TRIAGE_ORDER.map((k) => <button key={k} onClick={() => setTri(tri === k ? "all" : k)} className={`flex flex-col gap-1.5 rounded-[14px] border bg-slate-800 px-[18px] py-4 text-left transition ${tri === k ? "border-teal-500" : "border-slate-700 hover:border-slate-500/60"}`}>
          <span className="flex items-center gap-2 text-sm text-slate-300"><span className="h-2.5 w-2.5 rounded-full" style={{ background: TRIAGE[k].dot }} />{TRIAGE[k].label}</span>
          <span className={`font-display text-[32px] font-semibold leading-tight ${TRIAGE[k].num}`}>{counts[k]}<span className="ml-1 font-sans text-sm font-normal text-slate-400">件</span></span>
          <span className="text-xs text-slate-400">{TRIAGE[k].desc}</span>
        </button>)}
      </section>}
      {explaining && <div className="flex items-center gap-2.5 rounded-xl border border-[#2B3F8F] bg-[#14204A] px-4 py-2.5 text-sm text-[#B9C6FF]"><span className="h-2 w-2 animate-pulse rounded-full bg-teal-300" />初めて見るアラートの説明を AI が作成中…</div>}
      {err && <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{err}</div>}

      <section aria-label="アラート一覧" className="flex flex-col gap-3">
        {rows.map(({ a, count, others }) => {
          const n = noteOf(a); const t = triageOf(a); const T = TRIAGE[t]; const sub = subject(a); const ev = a.data?.win?.eventdata; const key = a._id; const isOpen = open === key;
          const hd = hOf(a); const isDone = hd?.state === "done";
          const vt = isVuln(a) ? vulnTextOf(a) : null; const vb = vt ? vulnBreakdown([a, ...others]) : null; const vg = !!vt && count > 1;
          const pkgLine = vb ? vb.pkgs.slice(0, 5).map(([p, c]) => `${p} ×${c}`).join(" / ") + (vb.pkgs.length > 5 ? ` …ほか ${vb.pkgs.length - 5} 種類` : "") : "";
          const border = isOpen ? "border-teal-500" : t === "danger" && !isDone ? "border-[#3A2026]" : "border-slate-700";
          return (
            <article key={key} className={`flex overflow-hidden rounded-[14px] border bg-slate-800 transition hover:border-slate-500/60 ${border} ${isDone && view === "open" ? "opacity-70" : ""}`}>
              <div className={`w-[5px] shrink-0 ${isDone ? "bg-slate-600" : T.bar}`} />
              <div className="flex min-w-0 flex-1 flex-col gap-3.5 px-[18px] py-4">
                <div className="flex flex-wrap gap-4">
                  <div className="flex min-w-0 flex-[1_1_420px] cursor-pointer flex-col gap-1.5" onClick={() => setOpen(isOpen ? null : key)}>
                    <div className="flex flex-wrap items-center gap-2 text-[13px]">
                      {isDone ? <><span className={`${pill} border-[#1F4A36] bg-[#12301F] font-bold text-[#7FE0B0]`}><Ico d={I.check} size={12} className="" />対応済み</span><span className={`${pill} text-[11px] opacity-80 ${T.chip}`} title="対応前の判定">当時 {T.label}</span></> : <span className={`${pill} font-bold ${T.chip}`}>{T.label}</span>}
                      {vt && <span className="rounded-full bg-[#1A2547] px-2.5 py-0.5 text-[#B9C6FF]">脆弱性</span>}
                      {hd?.state === "investigating" && <button className={`${pill} animate-pulse border-[#2B3F8F] bg-[#14204A] text-[#B9C6FF]`} title="Sidekick の相談を開く" onClick={(e) => { e.stopPropagation(); if (hd.h.session_id) nav(`/sidekick/${hd.h.session_id}`); }}>調査中 → Sidekick #{hd.h.session_id}</button>}
                      {hd && hd.state !== "investigating" && <button className={`${pill} border-[#2B3F8F] bg-[#14204A] text-[#B9C6FF] hover:bg-[#1A2547]`} onClick={(e) => { e.stopPropagation(); if (hd.h.session_id) nav(`/sidekick/${hd.h.session_id}`); }} title={hd.h.label}>{hd.h.kind === "session" ? `Sidekick #${hd.h.session_id}` : "手動"} · {hd.h.label.slice(0, 40)}{hd.h.scope !== "agent" && <span className="ml-1 text-slate-400">（{SCOPE_JA[hd.h.scope]}）</span>}</button>}
                      <span className="font-mono text-slate-300">{a.agent?.name}</span>
                      {count > 1 && !vt && <span className="rounded-full bg-[#1A2547] px-2.5 py-0.5 text-[#B9C6FF]">同じ種類 ×{count}</span>}
                      <span className="text-slate-400" title={fmtTs(a.timestamp)}>{ago(a.timestamp)}{mode === "detail" && ` · ${fmtTs(a.timestamp)}`}</span>
                      <span className="text-slate-400">重大度 {LEVEL_JA(a.rule.level)}{mode === "detail" && ` (${a.rule.level})`}</span>
                    </div>
                    {vt ? <>
                      <h2 className="text-[17px] font-semibold leading-normal text-slate-100">{vg ? `${a.agent?.name} に${SEV_LABEL[vt.severity] ?? vt.severity}の脆弱性が ${count} 件` : vt.title}</h2>
                      {vg && vb ? <div className="flex flex-wrap gap-1.5">{vb.pkgs.slice(0, 5).map(([p, c]) => <span key={p} className="rounded-lg border border-[#24314D] bg-slate-900 px-2.5 py-0.5 font-mono text-[13px] text-slate-200">{p} <span className="text-slate-400">×{c}</span></span>)}{vb.pkgs.length > 5 && <span className="self-center text-xs text-slate-400">…ほか {vb.pkgs.length - 5} 種類</span>}</div>
                        : <p className="text-sm leading-relaxed text-slate-300">{vt.plain}</p>}
                      {!vg && <div className="font-mono text-[13px] text-slate-400">{vt.detail}</div>}
                    </> : <>
                      <h2 className="text-[17px] font-semibold leading-normal text-slate-100">{n?.title_ja ?? a.rule.description}</h2>
                      <p className="text-sm leading-relaxed text-slate-300">{n?.meaning ?? "（この種類のアラートの説明はまだありません。展開すると技術情報を表示します）"}</p>
                      <div className="truncate font-mono text-[13px] text-slate-400">{sub.main}{sub.sub && <> · {sub.sub}</>}</div>
                    </>}
                  </div>
                  <div className="flex flex-[0_0_200px] flex-col gap-2">
                    {hd?.h.kind === "session" && hd.h.session_id
                      ? <><button className={btnPri} onClick={() => nav(`/sidekick/${hd.h.session_id}`)}>{hd.state === "investigating" ? "調査チャットを開く" : "調査結果を見る"}</button>
                        <button className={btnOut} title="このアラートについて新しい調査セッションを始める" onClick={() => investigate(a)}>新しく調査させる</button></>
                      : <button className={btnPri} onClick={() => investigate(a)}><Ico d={I.ai} size={14} className="" />AI に調査させる</button>}
                    {!isDone ? <button className={btnDone} onClick={() => markHandled(a, [a, ...others])}>対応済みにする</button>
                      : hd?.h.kind === "manual" && hd.h.mark_id ? <button className={btnOut} onClick={() => unmark(hd.h.mark_id!)}><Ico d={I.undo} size={14} className="" />未対応に戻す</button> : null}
                    <button className="min-h-[36px] text-[13px] text-slate-400 hover:text-slate-200" onClick={() => setOpen(isOpen ? null : key)}>{isOpen ? "閉じる ▴" : "詳しく ▾"}</button>
                  </div>
                </div>

                {isOpen && <>
                  {vt && vb && <div className="overflow-x-auto rounded-[10px] border border-slate-700">
                    <div className="flex items-center gap-2 bg-slate-900 px-3 py-2 text-xs font-semibold text-slate-200">CVE 一覧（{vb.cves.length} 件）<span className="font-normal text-slate-400">文言は data.vulnerability から生成（AI 不使用）</span></div>
                    <table className="w-full min-w-[640px] text-[13px]"><thead><tr className="bg-slate-900 text-left text-slate-400"><th className="px-3 py-2 font-medium">CVE</th><th className="px-3 py-2 font-medium">パッケージ</th><th className="px-3 py-2 font-medium">版</th><th className="px-3 py-2 font-medium">深刻度</th><th className="px-3 py-2 font-medium">CVSS</th><th className="px-3 py-2 font-medium">状態</th><th className="px-3 py-2 font-medium">検知</th></tr></thead>
                      <tbody>{vb.cves.map((c, i) => <tr key={i} className="border-t border-slate-700"><td className="px-3 py-2 font-mono text-teal-300">{c.ref ? <a className="hover:underline" href={c.ref} target="_blank" rel="noreferrer">{c.cve}</a> : c.cve}</td><td className="px-3 py-2 font-mono">{c.pkg}</td><td className="px-3 py-2 font-mono text-slate-300">{c.version}</td><td className={`px-3 py-2 font-semibold ${SEV_FG[c.severity] ?? "text-slate-300"}`}>{SEV_LABEL[c.severity] ?? c.severity}</td><td className="px-3 py-2">{c.score}</td><td className="px-3 py-2 text-slate-300">{c.status}</td><td className="px-3 py-2 text-slate-400">{fmtTs(c.ts).slice(5)}</td></tr>)}</tbody></table>
                  </div>}
                  <div className="grid gap-2.5 [grid-template-columns:repeat(auto-fit,minmax(220px,1fr))]">
                    {(vt ? [vg ? `${a.agent?.name} で ${count} 件の既知の脆弱性（${SEV_LABEL[vt.severity] ?? vt.severity}）が見つかっています。内訳: ${pkgLine}` : vt.plain, "ソフトや OS が、脆弱性が修正される前のバージョンのままになっています。", "公開済みの脆弱性なので、攻撃に悪用される可能性があります。", vg ? "パッケージごとに最新版へ更新してください（Windows は Windows Update、Linux は apt/dnf で更新）。次回の脆弱性スキャンで自動的に消えます。" : vt.action] : [n?.meaning, n?.cause, n?.impact, n?.action]).map((v, i) => (
                      <div key={i} className="flex flex-col gap-1.5 rounded-[10px] border border-slate-700 bg-slate-900 px-3.5 py-3">
                        <div className={`flex items-center gap-2 text-[13px] font-semibold ${EXPLAIN[i].c}`}><Ico d={EXPLAIN[i].d} size={15} className="" />{EXPLAIN[i].h}</div>
                        <div className="whitespace-pre-wrap text-sm leading-relaxed text-slate-200">{v ?? <span className="text-slate-500">説明なし</span>}</div>
                      </div>))}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {(ev?.processGuid || (a.data?.audit?.id && a.data?.audit?.pid)) && <button className="inline-flex min-h-[40px] items-center gap-2 rounded-[10px] border border-[#1F4A36] bg-[#12301F] px-3.5 text-sm font-semibold text-[#7FE0B0] hover:bg-[#173d28]" onClick={() => nav(`/process-tree?wazuh=${sel}&agent=${a.agent?.id}&guid=${encodeURIComponent(ev?.processGuid ?? `audit:${a.data.audit.id}`)}&from=${encodeURIComponent(new Date(new Date(a.timestamp).getTime() - 6 * 3600e3).toISOString())}&to=${encodeURIComponent(new Date(new Date(a.timestamp).getTime() + 6 * 3600e3).toISOString())}`)}><Ico d={I.tree} size={15} className="" />プロセスの流れを見る（前後 6 時間）</button>}
                    {a.GeoLocation?.country_name && <button className={btnOut} onClick={() => nav(`/overview?country=${encodeURIComponent(a.GeoLocation.country_name)}`)}><Ico d={I.globe} size={14} className="" />攻撃可視化でこの国を見る（{a.GeoLocation.country_name}）</button>}
                    {admin && !vt && <button className={`${btnOut} text-slate-300`} onClick={() => setEditing(n ?? { rule_id: String(a.rule.id), title_ja: a.rule.description, meaning: "", cause: "", impact: "", action: "", triage: defaultTriage(a), source: "user" })}><Ico d={I.edit} size={14} className="" />説明を編集</button>}
                    {n && <span className="text-xs text-slate-400">説明の出所: {n.source === "builtin" ? "同梱辞書" : n.source === "ai" ? "AI 生成" : "手動編集"}</span>}
                  </div>
                  {!vt && count > 1 && <div className="text-xs text-slate-400">同じ種類の他の発生: {others.slice(0, 10).map((o: any) => fmtTs(o.timestamp).slice(5)).join("、")}{others.length > 10 && ` …ほか ${others.length - 10} 件`}</div>}
                  <details className="rounded-[10px] border border-slate-700 bg-slate-900 px-3.5 py-2.5" open={mode === "detail"}>
                    <summary className="cursor-pointer text-[13px] text-slate-300">技術的な詳細</summary>
                    <dl className="mt-2.5 grid grid-cols-[120px_minmax(0,1fr)] gap-x-3.5 gap-y-1.5 text-[13px]">
                      <dt className="text-slate-400">ルール</dt><dd className="font-mono text-slate-200">{a.rule.id} · level {a.rule.level} · {a.rule.description}</dd>
                      {a.rule.groups && <><dt className="text-slate-400">分類</dt><dd className="font-mono text-slate-200">{(a.rule.groups ?? []).join(", ")}</dd></>}
                      {a.rule.mitre?.id && <><dt className="text-slate-400">MITRE ATT&CK</dt><dd className="font-mono text-slate-200">{(a.rule.mitre.id ?? []).join(", ")} {(a.rule.mitre.technique ?? []).join(" / ")}</dd></>}
                      {ev?.image && <><dt className="text-slate-400">実行ファイル</dt><dd className="break-all font-mono text-slate-200">{ev.image}</dd></>}
                      {ev?.commandLine && <><dt className="text-slate-400">コマンドライン</dt><dd className="break-all font-mono text-slate-200">{ev.commandLine}</dd></>}
                      {ev?.parentImage && <><dt className="text-slate-400">親プロセス</dt><dd className="break-all font-mono text-slate-200">{ev.parentImage}</dd></>}
                      {ev?.parentCommandLine && <><dt className="text-slate-400">親コマンド</dt><dd className="break-all font-mono text-slate-200">{ev.parentCommandLine}</dd></>}
                      {ev?.targetFilename && <><dt className="text-slate-400">対象ファイル</dt><dd className="break-all font-mono text-slate-200">{ev.targetFilename}</dd></>}
                      {ev?.hashes && <><dt className="text-slate-400">ハッシュ</dt><dd className="break-all font-mono text-slate-200">{ev.hashes}</dd></>}
                      {a.data?.srcip && <><dt className="text-slate-400">送信元 IP</dt><dd className="font-mono text-slate-200">{a.data.srcip}</dd></>}
                      {a.data?.url && <><dt className="text-slate-400">URL</dt><dd className="break-all font-mono text-slate-200">{a.data.url}</dd></>}
                      {a.full_log && <><dt className="text-slate-400">元ログ</dt><dd className="break-all font-mono text-xs text-slate-300">{String(a.full_log).slice(0, 600)}</dd></>}
                    </dl>
                    {mode === "detail" && <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-700 bg-[#070B15] p-3 text-[11px] text-slate-400">{JSON.stringify(a, null, 2)}</pre>}
                  </details>
                </>}
              </div>
            </article>
          );
        })}
        {!rows.length && !loading && <div className="rounded-[14px] border border-slate-700 bg-slate-800 p-6 text-center text-sm text-slate-400">該当するアラートはありません</div>}
      </section>

      {marking && (
        <div className="fixed inset-0 z-40 flex items-start justify-center bg-[rgba(5,8,16,0.72)] p-4 pt-[12vh] backdrop-blur-sm" onClick={() => setMarking(null)}>
          <div role="dialog" aria-modal="true" aria-labelledby="mk-h" className="flex w-full max-w-[560px] flex-col gap-4 rounded-[18px] border border-[#24314D] bg-slate-800 p-6 shadow-[0_24px_60px_rgba(0,0,0,.5)]" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-2.5"><Ico d={I.check} size={20} className="text-[#3CCB8C]" /><h2 id="mk-h" className="text-lg font-semibold">対応済みにする</h2></div>
            <div className="text-[15px] leading-relaxed">{isVuln(marking.a) ? vulnTextOf(marking.a).detail : noteOf(marking.a)?.title_ja ?? marking.a.rule.description}<span className="text-[13px] text-slate-400">（ルール {marking.a.rule.id}{programOf(marking.a) ? ` · ${programOf(marking.a)}` : ""} · {marking.a.agent?.name}）</span></div>
            <fieldset className="flex flex-col gap-2">
              <legend className="mb-1.5 text-[13px] text-slate-400">どこまで対応済みにしますか</legend>
              {isVuln(marking.a) && (["group", "allvuln"] as const).filter((sc) => sc !== "group" || marking.group.length > 1).map((sc) => (
                <label key={sc} className={`flex min-h-[44px] cursor-pointer items-start gap-2.5 rounded-[10px] border px-3 py-2.5 ${marking.scope === sc ? "border-teal-500 bg-[#14204A]" : "border-[#24314D] bg-slate-900 hover:border-slate-500/60"}`}>
                  <input type="radio" className="mt-1 accent-[#3A56F0]" checked={marking.scope === sc} onChange={() => setMarking({ ...marking, scope: sc })} />
                  <span className="flex-1 text-sm leading-normal">{sc === "group" ? <>この行の CVE すべて<span className="block text-xs text-slate-400">{marking.a.agent?.name} の{SEV_LABEL[vulnTextOf(marking.a).severity] ?? ""}な脆弱性（まとめ行ごと消える・推奨）</span></> : <>表示中の脆弱性すべて<span className="block text-xs text-slate-400">全端末・全深刻度（今出ている CVE だけ。新しい CVE は次回スキャンで出る）</span></>}</span>
                  <span className="whitespace-nowrap text-xs text-slate-300">{vulnTargets(sc, marking).length} 件</span>
                </label>
              ))}
              {(["agent", "program", "rule"] as Scope[]).filter((sc) => sc !== "program" || (programOf(marking.a) && !isVuln(marking.a))).map((sc) => (
                <label key={sc} className={`flex min-h-[44px] cursor-pointer items-start gap-2.5 rounded-[10px] border px-3 py-2.5 ${marking.scope === sc ? "border-teal-500 bg-[#14204A]" : "border-[#24314D] bg-slate-900 hover:border-slate-500/60"}`}>
                  <input type="radio" className="mt-1 accent-[#3A56F0]" checked={marking.scope === sc} onChange={() => setMarking({ ...marking, scope: sc })} />
                  <span className="flex-1 text-sm leading-normal">{scopeLabel(marking.a, sc)}{sc === "program" && <span className="block text-xs text-slate-400">他の端末の {programOf(marking.a)} も同じ扱い（推奨）</span>}{sc === "rule" && <span className="block text-xs text-slate-400">{isVuln(marking.a) ? "他の端末の同じ CVE（同じパッケージ）も対応済みにする" : "プログラムを問わず、このルールの今までの発生すべて"}</span>}</span>
                  <span className="whitespace-nowrap text-xs text-slate-300">今の一覧で {similarCount(marking.a, sc)} 件</span>
                </label>
              ))}
            </fieldset>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="mk-q" className="text-[13px] text-slate-400">この後の同種アラートを無視する期間</label>
              <select id="mk-q" className="min-h-[40px] rounded-[10px] border border-[#24314D] bg-slate-900 px-3 text-sm text-slate-100" value={marking.quiet} onChange={(e) => setMarking({ ...marking, quiet: Number(e.target.value) })}>
                <option value={0}>なし — 今より後に再発したら未対応に戻す（対処が効いたかの確認用）</option>
                <option value={1}>1 日（対処直後の揺り戻しを無視）</option>
                <option value={7}>7 日（脆弱性検知など、再スキャンまで同じアラートが続くもの）</option>
                <option value={30}>30 日</option>
                <option value={3650}>無期限（この種類はもう見ない）</option>
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="mk-n" className="text-[13px] text-slate-400">メモ（任意）</label>
              <input id="mk-n" className="min-h-[40px] rounded-[10px] border border-[#24314D] bg-slate-900 px-3 text-sm text-slate-100 placeholder-slate-500" value={marking.note} onChange={(e) => setMarking({ ...marking, note: e.target.value })} placeholder="例: Edge の自動更新による正常動作" />
            </div>
            <div className="flex items-center justify-end gap-2.5">
              {markBusy && <span className="text-xs text-slate-400">{markBusy}</span>}
              <button className="min-h-[44px] rounded-[10px] border border-[#24314D] px-[18px] text-sm text-slate-100 hover:bg-slate-700" onClick={() => setMarking(null)}>キャンセル</button>
              <button className="min-h-[44px] rounded-[10px] bg-[#1E8A5C] px-[18px] text-sm font-bold text-white hover:bg-[#23a06b] disabled:opacity-50" onClick={submitMark} disabled={!!markBusy}>対応済みにする</button>
            </div>
          </div>
        </div>
      )}
      {editing && (
        <div className="fixed inset-0 z-40 flex items-start justify-center bg-[rgba(5,8,16,0.72)] p-4 pt-[8vh] backdrop-blur-sm" onClick={() => setEditing(null)}>
          <div role="dialog" aria-modal="true" className="flex w-full max-w-2xl flex-col gap-3 rounded-[18px] border border-[#24314D] bg-slate-800 p-6 shadow-[0_24px_60px_rgba(0,0,0,.5)]" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-2.5"><Ico d={I.edit} size={18} /><h2 className="text-lg font-semibold">ルール {editing.rule_id} の説明を編集</h2></div>
            <Field label="わかりやすい題名"><input className="input" value={editing.title_ja} onChange={(e) => setEditing({ ...editing, title_ja: e.target.value })} /></Field>
            <Field label="AI の判定"><select className="input" value={editing.triage} onChange={(e) => setEditing({ ...editing, triage: e.target.value as Triage })}><option value="benign_likely">おそらく正常</option><option value="check">要確認</option><option value="danger">危険</option></select></Field>
            {(["meaning", "cause", "impact", "action"] as const).map((k) => <Field key={k} label={{ meaning: "何が起きたか", cause: "考えられる原因", impact: "放置した場合の影響", action: "推奨する対応" }[k]}><textarea className="input h-16" value={(editing as any)[k]} onChange={(e) => setEditing({ ...editing, [k]: e.target.value })} /></Field>)}
            <div className="flex justify-end gap-2.5"><button className="min-h-[44px] rounded-[10px] border border-[#24314D] px-[18px] text-sm hover:bg-slate-700" onClick={() => setEditing(null)}>キャンセル</button><button className="min-h-[44px] rounded-[10px] bg-teal-500 px-[18px] text-sm font-semibold text-white hover:bg-teal-400" onClick={saveNote}>保存</button></div>
          </div>
        </div>
      )}
    </div>
  );
}
