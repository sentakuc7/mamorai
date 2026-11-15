import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { useMode } from "../lib/mode";
import { Ico, I } from "../components/Icon";

interface Node { guid: string; pid?: number; image: string; commandLine?: string; user?: string; parentGuid?: string; start?: string; end?: string; endEstimated: boolean; maxLevel: number; alerts: { ruleId: string; level: number; description: string; ts: string }[]; events: { eid: number; ts: string; detail: string }[]; children: Node[]; depth: number; isFocus: boolean; hashes?: string; signed?: string; os?: "windows" | "linux"; failed?: boolean; exitCode?: string; errno?: string; cwd?: string; ppid?: number; callerImage?: string; inferred?: boolean; hint?: string }
interface Tree { agentId: string; agentName?: string; index: string; focusGuid: string; root: Node | null; nodes: number; truncated: boolean; window: { from: string; to: string }; os?: "windows" | "linux" }

const base = (p: string) => p.split(/[\\/]/).pop() ?? p;
/** Everyday-Japanese role of well-known programs. */
const ROLE: Record<string, { role: string; icon: string; risky?: boolean }> = {
  "powershell.exe": { role: "コマンド実行ツール", icon: "🧰", risky: true }, "pwsh.exe": { role: "コマンド実行ツール", icon: "🧰", risky: true }, "cmd.exe": { role: "コマンドプロンプト", icon: "🧰", risky: true },
  "wscript.exe": { role: "スクリプト実行", icon: "📜", risky: true }, "cscript.exe": { role: "スクリプト実行", icon: "📜", risky: true }, "mshta.exe": { role: "HTML アプリ実行", icon: "📜", risky: true },
  "rundll32.exe": { role: "DLL 実行", icon: "⚙️", risky: true }, "regsvr32.exe": { role: "DLL 登録", icon: "⚙️", risky: true }, "certutil.exe": { role: "証明書ツール", icon: "⚙️", risky: true }, "bitsadmin.exe": { role: "ダウンロードツール", icon: "⚙️", risky: true },
  "explorer.exe": { role: "デスクトップ", icon: "🖥️" }, "svchost.exe": { role: "Windows サービス", icon: "🪟" }, "services.exe": { role: "サービス管理", icon: "🪟" }, "taskhostw.exe": { role: "バックグラウンド処理", icon: "🪟" }, "backgroundtaskhost.exe": { role: "バックグラウンド処理", icon: "🪟" }, "dllhost.exe": { role: "COM 実行", icon: "🪟" }, "winlogon.exe": { role: "ログオン処理", icon: "🪟" }, "userinit.exe": { role: "ログオン処理", icon: "🪟" }, "runtimebroker.exe": { role: "アプリ権限仲介", icon: "🪟" }, "sihost.exe": { role: "シェル基盤", icon: "🪟" },
  "msedge.exe": { role: "ブラウザ", icon: "🌐" }, "chrome.exe": { role: "ブラウザ", icon: "🌐" }, "firefox.exe": { role: "ブラウザ", icon: "🌐" }, "msedgewebview2.exe": { role: "アプリ内ブラウザ", icon: "🌐" },
  "winword.exe": { role: "Word", icon: "📄" }, "excel.exe": { role: "Excel", icon: "📊" }, "powerpnt.exe": { role: "PowerPoint", icon: "📑" }, "outlook.exe": { role: "メール", icon: "✉️" }, "acrord32.exe": { role: "PDF 閲覧", icon: "📄" },
  "msiexec.exe": { role: "インストーラー", icon: "📦" }, "setup.exe": { role: "インストーラー", icon: "📦" }, "microsoftedgeupdate.exe": { role: "更新プログラム", icon: "🔄" }, "googleupdate.exe": { role: "更新プログラム", icon: "🔄" },
  "chatgpt.exe": { role: "チャットアプリ", icon: "💬" }, "teams.exe": { role: "チャットアプリ", icon: "💬" }, "slack.exe": { role: "チャットアプリ", icon: "💬" }, "discord.exe": { role: "チャットアプリ", icon: "💬" },
  "node.exe": { role: "Node.js 実行", icon: "🟩" }, "python.exe": { role: "Python 実行", icon: "🐍" }, "java.exe": { role: "Java 実行", icon: "☕" }, "code.exe": { role: "エディタ", icon: "📝" },
  // Linux (auditd, EDR-79)
  sh: { role: "シェル", icon: "🧰", risky: true }, dash: { role: "シェル", icon: "🧰", risky: true }, bash: { role: "シェル", icon: "🧰", risky: true }, zsh: { role: "シェル", icon: "🧰", risky: true }, busybox: { role: "多機能コマンド", icon: "🧰", risky: true },
  curl: { role: "ダウンロードツール", icon: "⬇️", risky: true }, wget: { role: "ダウンロードツール", icon: "⬇️", risky: true }, nc: { role: "通信ツール", icon: "🔌", risky: true }, ncat: { role: "通信ツール", icon: "🔌", risky: true }, socat: { role: "通信ツール", icon: "🔌", risky: true },
  python3: { role: "Python 実行", icon: "🐍", risky: true }, python: { role: "Python 実行", icon: "🐍", risky: true }, perl: { role: "Perl 実行", icon: "📜", risky: true }, php: { role: "PHP 実行", icon: "🐘", risky: true }, base64: { role: "エンコード", icon: "⚙️", risky: true },
  httpd: { role: "Webサーバー", icon: "🌍" }, apache2: { role: "Webサーバー", icon: "🌍" }, nginx: { role: "Webサーバー", icon: "🌍" }, "php-fpm": { role: "PHP 実行（Web）", icon: "🐘" },
  sendmail: { role: "メール送信", icon: "✉️" }, postfix: { role: "メール送信", icon: "✉️" }, sshd: { role: "SSH サーバー", icon: "🔑" }, sudo: { role: "管理者権限で実行", icon: "🛡️", risky: true }, cron: { role: "定期実行", icon: "⏰" }, crond: { role: "定期実行", icon: "⏰" }, crontab: { role: "定期実行の登録", icon: "⏰", risky: true }, systemd: { role: "OS 起動管理", icon: "🐧" }, ausearch: { role: "監査ログ検索", icon: "🔎" }, id: { role: "ユーザー確認", icon: "🔎", risky: true }, whoami: { role: "ユーザー確認", icon: "🔎", risky: true }, uname: { role: "OS 情報確認", icon: "🔎", risky: true },
  "msmpeng.exe": { role: "Windows Defender", icon: "🛡️" }, "wmiprvse.exe": { role: "WMI プロバイダ", icon: "🪟", risky: true }, "schtasks.exe": { role: "タスク登録", icon: "⏰", risky: true }, "net.exe": { role: "ネットワーク設定", icon: "⚙️", risky: true }, "whoami.exe": { role: "ユーザー確認", icon: "🔎", risky: true },
};
const roleOf = (image: string) => ROLE[base(image).toLowerCase()] ?? ROLE[base(image).toLowerCase().replace(/[\d.]+$/, "")] ?? (/^Webサーバー（/.test(image) ? { role: "Webサーバー（推定）", icon: "🌍" } : { role: "プログラム", icon: "▫️" });
/** Role line on a card: failed / inferred nodes say so instead of the program's role. */
const roleLine = (n: Node) => (n.failed ? `起動失敗: ${n.errno ?? `exit ${n.exitCode}`}` : n.inferred ? "起動記録なし（推定）" : roleOf(n.image).role);
const EID = {
  3: { name: "通信", icon: "🌐", color: "#60a5fa", verb: (p: string, d: string) => `「${p}」が ${d} へ通信した` },
  22: { name: "名前解決", icon: "🔍", color: "#c084fc", verb: (p: string, d: string) => `「${p}」が ${d} のアドレスを調べた（DNS）` },
  11: { name: "ファイル作成", icon: "📄", color: "#2dd4bf", verb: (p: string, d: string) => `「${p}」がファイル ${base(d)} を作成した` },
  12: { name: "レジストリ", icon: "🔧", color: "#fb923c", verb: (p: string, d: string) => `「${p}」がレジストリ ${d} を変更した` },
  13: { name: "レジストリ", icon: "🔧", color: "#fb923c", verb: (p: string, d: string) => `「${p}」がレジストリ ${d} を変更した` },
  8: { name: "コード注入", icon: "💉", color: "#f87171", verb: (p: string, d: string) => `「${p}」が別のプロセス ${d} にコードを送り込んだ（危険な手口）` },
  10: { name: "メモリ参照", icon: "🧠", color: "#f87171", verb: (p: string, d: string) => `「${p}」が ${d} のメモリを読み取った` },
  100: { name: "監査イベント", icon: "📋", color: "#a3e635", verb: (p: string, d: string) => `「${p}」の動きが監査ログに記録された（${d}）` },
  7: { name: "部品の読み込み", icon: "🧩", color: "#64748b", verb: (p: string, d: string) => `「${p}」が部品 ${base(d)} を読み込んだ` },
} as Record<number, { name: string; icon: string; color: string; verb: (p: string, d: string) => string }>;

function flatten(n: Node, out: Node[] = []): Node[] { out.push(n); n.children.forEach((c) => flatten(c, out)); return out; }

interface Step { ts: number; kind: "start" | "event" | "alert"; node: Node; text: string; icon: string; color: string; danger?: boolean; edge?: [string, string] }

/** Chronological story of what happened, in plain Japanese. */
function buildStory(rows: Node[], showLoad: boolean): Step[] {
  const byGuid = new Map(rows.map((n) => [n.guid, n]));
  const steps: Step[] = [];
  for (const n of rows) {
    const p = base(n.image); const parent = n.parentGuid ? byGuid.get(n.parentGuid) : undefined;
    if (n.start && n.failed) steps.push({ ts: new Date(n.start).getTime(), kind: "start", node: n, icon: "⛔", color: "#fbbf24", text: `「${parent ? base(parent.image) : base(n.callerImage ?? "?")}」が「${p}」を起動しようとして失敗した（${n.errno ?? `exit ${n.exitCode}`}）`, edge: parent ? [parent.guid, n.guid] : undefined });
    else if (n.start && n.inferred) steps.push({ ts: new Date(n.start).getTime() - 1, kind: "start", node: n, icon: roleOf(n.image).icon, color: "#64748b", text: `「${p}」（${roleOf(n.image).role}）が動いていた（起動の記録はこの期間にない）` });
    else if (n.start) steps.push({ ts: new Date(n.start).getTime(), kind: "start", node: n, icon: roleOf(n.image).icon, color: "#2dd4bf", text: parent ? `「${base(parent.image)}」（${roleOf(parent.image).role}）が「${p}」（${roleOf(n.image).role}）を起動した` : `「${p}」（${roleOf(n.image).role}）が動き始めた`, edge: parent ? [parent.guid, n.guid] : undefined });
    for (const e of n.events) { if (e.eid === 7 && !showLoad) continue; const m = EID[e.eid]; if (!m) continue; steps.push({ ts: new Date(e.ts).getTime(), kind: "event", node: n, icon: m.icon, color: m.color, text: m.verb(p, e.detail.length > 80 ? e.detail.slice(0, 80) + "…" : e.detail), danger: e.eid === 8 }); }
    for (const a of n.alerts) steps.push({ ts: new Date(a.ts).getTime(), kind: "alert", node: n, icon: "🚨", color: "#f87171", danger: a.level >= 12, text: `検知: ${a.description}（重大度 ${a.level >= 15 ? "緊急" : a.level >= 12 ? "高" : a.level >= 7 ? "中" : "低"}）` });
  }
  return steps.sort((a, b) => a.ts - b.ts || (a.kind === "start" ? -1 : 1));
}

/** Layered left→right layout. */
function layout(rows: Node[]) {
  const W = 230, H = 96, GX = 90, GY = 22;
  const cols = new Map<number, Node[]>();
  for (const n of rows) { if (!cols.has(n.depth)) cols.set(n.depth, []); cols.get(n.depth)!.push(n); }
  const pos = new Map<string, { x: number; y: number }>();
  const maxRows = Math.max(...[...cols.values()].map((c) => c.length));
  const totalH = maxRows * (H + GY);
  for (const [d, list] of cols) { const colH = list.length * (H + GY); list.forEach((n, i) => pos.set(n.guid, { x: 20 + d * (W + GX), y: (totalH - colH) / 2 + i * (H + GY) + 30 })); }
  const depthMax = Math.max(...rows.map((n) => n.depth));
  return { pos, W, H, width: 40 + (depthMax + 1) * (W + GX) - GX, height: totalH + 50 };
}

export default function ProcessTree() {
  const [sp] = useSearchParams(); const nav = useNavigate(); const { mode } = useMode();
  const wazuh = sp.get("wazuh") ?? "1"; const agent = sp.get("agent") ?? ""; const guid = sp.get("guid") ?? ""; const from = sp.get("from") ?? "now-24h"; const to = sp.get("to") ?? "now";
  const [tree, setTree] = useState<Tree | null>(null); const [err, setErr] = useState(""); const [sel, setSel] = useState<Node | null>(null); const [loading, setLoading] = useState(false);
  const [showLoad, setShowLoad] = useState(false);
  const [showGraph, setShowGraph] = useState(false);
  const [cursor, setCursor] = useState<number>(-1); const [playing, setPlaying] = useState(false); const timer = useRef<number | null>(null);
  useEffect(() => {
    if (!agent || !guid) return; setLoading(true); setErr(""); setTree(null); setCursor(-1); setPlaying(false);
    api.get<Tree>(`/wazuh/${wazuh}/process-tree?agentId=${encodeURIComponent(agent)}&guid=${encodeURIComponent(guid)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`).then((t) => { setTree(t); const f = t.root ? flatten(t.root) : []; setSel(f.find((n) => n.isFocus) ?? f[0] ?? null); }).catch((e) => setErr(e.message)).finally(() => setLoading(false));
  }, [wazuh, agent, guid, from, to]);

  const rows = useMemo(() => (tree?.root ? flatten(tree.root) : []), [tree]);
  const story = useMemo(() => buildStory(rows, showLoad), [rows, showLoad]);
  const lay = useMemo(() => (rows.length ? layout(rows) : null), [rows]);
  const shown = cursor < 0 ? story.length : cursor + 1; // how many steps are "revealed"
  const revealed = useMemo(() => { const s = new Set<string>(); const e = new Set<string>(); story.slice(0, shown).forEach((st) => { s.add(st.node.guid); if (st.edge) { e.add(st.edge.join(">")); s.add(st.edge[0]); } }); return { nodes: s, edges: e }; }, [story, shown]);
  const current = cursor >= 0 ? story[cursor] : null;

  useEffect(() => {
    if (!playing) { if (timer.current) window.clearTimeout(timer.current); return; }
    // 最後まで再生したら 2 秒置いて「全部表示」に戻す
    if (cursor >= story.length - 1) { timer.current = window.setTimeout(() => { setPlaying(false); setCursor(-1); }, 2000); return () => { if (timer.current) window.clearTimeout(timer.current); }; }
    timer.current = window.setTimeout(() => setCursor((c) => c + 1), 1100);
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, [playing, cursor, story.length]);
  const play = () => { if (cursor >= story.length - 1 || cursor < 0) setCursor(0); setPlaying(true); };
  // 開いたら自動で流れを再生する（MamorAI デザイン v0.2）
  useEffect(() => { if (tree?.root && story.length > 1) { setCursor(0); setPlaying(true); } }, [tree]);
  // 再生位置（時刻）と、そこまでに起きた検知
  const alertsOn = useMemo(() => { const s = new Set<string>(); story.slice(0, shown).forEach((st) => { if (st.kind === "alert") s.add(st.node.guid); }); return s; }, [story, shown]);
  const dangerShown = story.slice(0, shown).filter((s) => s.danger).length;

  const [tMin, tMax] = useMemo(() => { const ts = rows.flatMap((n) => [n.start, n.end, ...n.events.map((e) => e.ts)]).filter(Boolean).map((s) => new Date(s!).getTime()); if (!ts.length) return [0, 1]; const a = Math.min(...ts), b = Math.max(...ts); return [a, Math.max(b, a + 60_000)]; }, [rows]);
  const xp = (s?: string) => (s ? ((new Date(s).getTime() - tMin) / (tMax - tMin)) * 100 : 0);
  const counts = (n: Node) => { const c: Record<string, number> = {}; for (const e of n.events) { if (e.eid === 7 && !showLoad) continue; const nm = EID[e.eid]?.name ?? String(e.eid); c[nm] = (c[nm] ?? 0) + 1; } return c; };
  const dangerCount = story.filter((s) => s.danger).length;
  const phTs = current ? current.ts : tMax; const ph = Math.min(100, Math.max(0, ((phTs - tMin) / (tMax - tMin)) * 100));
  const playingView = cursor >= 0;

  if (!agent || !guid) return <div className="card text-sm text-slate-400">アラート一覧で行を展開して「プロセスの流れを見る」を押してください。</div>;
  return (
    <div className="space-y-3">
      <style>{`@keyframes dashflow{to{stroke-dashoffset:-24}} @keyframes pulse-ring{0%{stroke-opacity:.9;stroke-width:3}70%{stroke-opacity:0;stroke-width:14}100%{stroke-opacity:0;stroke-width:14}} .edge{stroke-dasharray:8 6;animation:dashflow 1s linear infinite} .ring{animation:pulse-ring 1.6s ease-out infinite;transform-origin:center} .appear{animation:appear .5s ease-out} @keyframes appear{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}`}</style>
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <div className="text-[13px] text-slate-400"><button className="text-teal-300 hover:text-teal-200" onClick={() => nav("/alerts")}>アラート</button> / プロセスの流れ</div>
          <h1 className="flex items-center gap-2 text-[26px] font-bold"><Ico d={I.tree} size={22} />プロセスの流れ</h1>
          {tree && <div className="text-[13px] text-slate-400">{(() => { const f = rows.find((x) => x.isFocus); const a = f?.alerts.slice().sort((x, y) => y.level - x.level)[0]; return a ? <>起点: <span className={a.level >= 12 ? "font-semibold text-[#F2555A]" : "font-semibold text-[#FF8A3D]"}>{a.level >= 15 ? "緊急" : a.level >= 12 ? "高" : "中"}</span> {a.description}（rule {a.ruleId}）· </> : null; })()}<span className="font-mono text-slate-200">{tree.agentName ?? tree.agentId}</span> · {tree.nodes} 個のプログラム · {fmtTs(tree.window.from)} 〜 {fmtTs(tree.window.to)}{tree.truncated ? "（一部省略）" : ""}</div>}
        </div>
        <label className="ml-auto flex items-center gap-1 text-xs text-slate-400"><input type="checkbox" checked={showLoad} onChange={(e) => setShowLoad(e.target.checked)} /> 部品の読み込みも表示</label>
        <button className="btn-secondary" onClick={() => nav("/sidekick", { state: { prefill: guid.startsWith("audit:") ? `agent ${agent} の Linux 監査レコード ${guid} のプロセスツリー（process_tree に process_guid="${guid}" を渡す）を見て、何が起きたか説明して` : `agent ${agent} のプロセス ${guid} のツリーを見て、何が起きたか説明して` } })}>🕵️ AI に説明させる</button>
      </div>
      {loading && <div className="animate-pulse text-slate-400">読み込み中…</div>}
      {err && <div className="card text-rose-400">{err}</div>}
      {tree && !tree.root && <div className="card text-slate-400">{tree.os === "linux" ? "この監査レコード（auditd）が期間内に見つかりません。期間を広げるか、対象ホストの auditd に execve の監視ルールがあるか確認してください。" : "このプロセスの起動記録が期間内に見つかりません（archives が無効、または期間外）。"}</div>}
      {tree?.root && lay && (
        <>
          {/* summary strip */}
          <div className="grid gap-2 md:grid-cols-4">
            <div className="rounded-2xl border border-slate-700 bg-slate-800 p-3"><div className="text-xs text-slate-400">関わったプログラム</div><div className="font-display text-2xl font-semibold tabular-nums">{playingView ? `${revealed.nodes.size} / ` : ""}{rows.length}<span className="ml-1 text-xs font-normal text-slate-500">個</span></div></div>
            <div className="rounded-2xl border border-slate-700 bg-slate-800 p-3"><div className="text-xs text-slate-400">起きたこと</div><div className="font-display text-2xl font-semibold tabular-nums">{playingView ? `${shown} / ` : ""}{story.length}<span className="ml-1 text-xs font-normal text-slate-500">件</span></div></div>
            <div className={`rounded-2xl border p-3 ${dangerCount ? "border-rose-500/60 bg-rose-500/10" : "border-slate-700 bg-slate-800"}`}><div className="text-xs text-slate-400">検知・危険な動き</div><div className={`font-display text-2xl font-semibold tabular-nums ${dangerShown ? "text-rose-300" : ""}`}>{playingView ? dangerShown : dangerCount}<span className="ml-1 text-xs font-normal text-slate-500">件</span></div></div>
            <div className="rounded-2xl border border-slate-700 bg-slate-800 p-3"><div className="text-xs text-slate-400">{playingView ? "再生位置" : "期間"}</div><div className="font-mono text-sm font-semibold">{playingView ? fmtTs(new Date(phTs).toISOString()).slice(5) : <>{fmtTs(new Date(tMin).toISOString()).slice(5)} 〜 {fmtTs(new Date(tMax).toISOString()).slice(11)}</>}</div></div>
          </div>

          {/* MamorAI v0.2: ツリー行 × 時間の帯（再生位置の線が動く） */}
          <div className="card overflow-hidden p-0">
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-700 px-4 py-3">
              <span className="text-sm font-semibold">どう動いたか</span>
              <span className="text-[11px] text-slate-400">行の帯 = 動いていた時間 · 目印 = その時の出来事 · 赤い輪 = 検知あり · 行をクリックで詳細</span>
              <div className="ml-auto flex items-center gap-1.5">
                <button className="btn-primary px-3 py-1.5 text-xs" onClick={playing ? () => setPlaying(false) : play}><Ico d={playing ? I.pause : I.play} size={13} className="" />{playing ? "一時停止" : "流れを再生"}</button>
                <button className="btn-secondary px-2.5 py-1.5 text-xs" aria-label="1 つ戻る" disabled={cursor <= 0} onClick={() => { setPlaying(false); setCursor(Math.max(0, cursor - 1)); }}>‹</button>
                <button className="btn-secondary px-2.5 py-1.5 text-xs" aria-label="1 つ進む" disabled={cursor >= story.length - 1} onClick={() => { setPlaying(false); setCursor(Math.min(story.length - 1, cursor + 1)); }}>›</button>
                <button className="btn-secondary px-2.5 py-1.5 text-xs" onClick={() => { setPlaying(false); setCursor(-1); }}>全部表示</button>
                <button className={`btn-secondary px-2.5 py-1.5 text-xs ${showGraph ? "ring-1 ring-teal-400" : ""}`} onClick={() => setShowGraph(!showGraph)}><Ico d={I.tree} size={13} className="" />図で見る</button>
              </div>
            </div>
            <div className="overflow-x-auto">
              <div className="min-w-[860px]">
                <div className="grid grid-cols-[300px_minmax(0,1fr)] border-b border-slate-700 font-mono text-[11px] text-slate-400">
                  <div className="px-4 py-2">プロセス</div>
                  <div className="flex justify-between px-4 py-2">{[0, 1, 2, 3].map((k) => <span key={k}>{fmtTs(new Date(tMin + ((tMax - tMin) * k) / 3).toISOString()).slice(11)}</span>)}</div>
                </div>
                <div className="relative">
                  {playingView && <div aria-hidden="true" className="pointer-events-none absolute inset-y-0 left-[300px] right-0 z-10 mx-4"><div className="absolute inset-y-0 w-0.5 bg-teal-300 shadow-[0_0_12px_#3A56F0]" style={{ left: `${ph}%`, transition: "left 1s linear" }} /></div>}
                  {rows.map((n) => {
                    const r = roleOf(n.image); const on = !playingView || revealed.nodes.has(n.guid); const isSel = sel?.guid === n.guid; const hot = playingView && current?.node.guid === n.guid;
                    const alertOn = n.alerts.length > 0 && (cursor < 0 || alertsOn.has(n.guid));
                    const lv = n.alerts.length ? "#F2555A" : n.maxLevel >= 12 ? "#FF8A3D" : n.maxLevel >= 7 ? "#F5C542" : "#4A5578";
                    const x0 = xp(n.start), x1 = Math.max(xp(n.end ?? n.start), x0 + 0.6); const w = !playingView ? x1 - x0 : on ? Math.max(0.6, Math.min(x1, ph) - x0) : 0;
                    return (
                      <div key={n.guid} onClick={() => setSel(n)} className={`grid cursor-pointer grid-cols-[300px_minmax(0,1fr)] border-b border-slate-700/60 ${hot ? "bg-[#1A2547]" : isSel ? "bg-[#141E36]" : "hover:bg-slate-700/40"}`} style={{ opacity: on ? 1 : 0.18, transition: "opacity .5s ease, background-color .3s ease" }}>
                        <div className="flex min-h-[48px] min-w-0 items-center gap-2.5 py-2 pr-4" style={{ paddingLeft: 16 + n.depth * 20 }}>
                          <span className="relative h-2.5 w-2.5 shrink-0"><span className="absolute inset-0 rounded-full" style={{ background: lv }} />{alertOn && <span className="absolute inset-0 animate-ping rounded-full border-2 border-[#F2555A]" />}</span>
                          <div className="min-w-0">
                            <div className={`truncate font-mono text-sm ${isSel ? "font-bold text-white" : "text-slate-100"} ${n.failed ? "text-amber-300" : ""}`}>{base(n.image)}</div>
                            <div className={`truncate text-[11px] ${n.failed || (r.risky && !n.inferred) ? "text-[#F5C542]" : "text-slate-400"}`}>{!n.failed && !n.inferred && r.risky ? "要注意 · " : ""}{roleLine(n)}</div>
                          </div>
                          {alertOn && <span className="ml-auto shrink-0 rounded-full bg-[#F2555A] px-2 text-[11px] font-bold text-white">検知 {n.alerts.length}</span>}
                        </div>
                        <div className="relative mx-4 h-12">
                          <div className="absolute top-[17px] h-3.5 rounded" style={{ left: `${x0}%`, width: `${w}%`, background: n.isFocus ? "#3A56F0" : lv === "#4A5578" ? "#2A3756" : lv, opacity: n.endEstimated ? 0.6 : 1, transition: "width 1s linear" }} />
                          {n.events.filter((e) => showLoad || e.eid !== 7).map((e, k) => { const vis = !playingView || new Date(e.ts).getTime() <= phTs; const c = EID[e.eid]?.color ?? "#94a3b8"; return <div key={k} title={`${EID[e.eid]?.name ?? e.eid} ${fmtTs(e.ts)} ${e.detail}`} className="absolute top-[10px] -ml-[3px] h-7 w-1.5 rounded" style={{ left: `${xp(e.ts)}%`, background: c, boxShadow: `0 0 8px ${c}`, opacity: vis ? 1 : 0, transform: vis ? "scaleY(1)" : "scaleY(0)", transition: "opacity .35s ease, transform .35s ease" }} />; })}
                          {n.alerts.map((a, k) => { const vis = !playingView || new Date(a.ts).getTime() <= phTs; return <div key={"a" + k} title={a.description} className="absolute top-[3px] -ml-[6px] h-0 w-0 border-x-[6px] border-b-[10px] border-x-transparent border-b-[#F2555A]" style={{ left: `${xp(a.ts)}%`, opacity: vis ? 1 : 0, transition: "opacity .35s ease" }} />; })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
            <div className="flex flex-wrap gap-4 border-t border-slate-700 px-4 py-3 text-xs text-slate-300">
              <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-[#3A56F0]" />起点のプロセス</span>
              {Object.entries(EID).filter(([k]) => (showLoad || k !== "7") && k !== "12").map(([k, v]) => <span key={k} className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: v.color }} />{v.name}</span>)}
              <span className="flex items-center gap-1.5"><span className="h-0 w-0 border-x-[5px] border-b-[8px] border-x-transparent border-b-[#F2555A]" />検知</span>
              <span className="text-[#F5C542]">黄色の役割 = 攻撃にもよく使われるプログラム</span>
            </div>
          </div>

          {showGraph && (
            <div className="card min-w-0 p-3">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold">どう動いたか（左 → 右の順に起動）</span>
                <span className="text-[11px] text-slate-500">クリックで詳細 · 赤い輪 = 検知あり</span>
                <div className="ml-auto flex items-center gap-1">
                  <button className="btn-primary px-3 py-1.5 text-xs" onClick={playing ? () => setPlaying(false) : play}><Ico d={playing ? I.pause : I.play} size={13} className="" />{playing ? "一時停止" : "流れを再生"}</button>
                  <button className="btn-secondary px-2.5 py-1.5 text-xs" disabled={cursor <= 0} onClick={() => { setPlaying(false); setCursor(Math.max(0, cursor - 1)); }}>‹</button>
                  <button className="btn-secondary px-2.5 py-1.5 text-xs" disabled={cursor >= story.length - 1} onClick={() => { setPlaying(false); setCursor(Math.min(story.length - 1, cursor + 1)); }}>›</button>
                  <button className="btn-secondary px-2.5 py-1.5 text-xs" onClick={() => { setPlaying(false); setCursor(-1); }}>全部表示</button>
                </div>
              </div>
              <div className="w-full overflow-x-auto">
                <svg viewBox={`0 0 ${lay.width} ${lay.height}`} width={lay.width * 1.35} height={lay.height * 1.35} className="block">
                  <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#8EA2FF" /></marker></defs>
                  {rows.map((n) => { if (!n.parentGuid) return null; const a = lay.pos.get(n.parentGuid), b = lay.pos.get(n.guid); if (!a || !b) return null; const on = revealed.edges.has(`${n.parentGuid}>${n.guid}`) || cursor < 0; const x1 = a.x + lay.W, y1 = a.y + lay.H / 2, x2 = b.x, y2 = b.y + lay.H / 2; const mx = (x1 + x2) / 2; const hot = current?.edge && current.edge[0] === n.parentGuid && current.edge[1] === n.guid; return <g key={n.guid} opacity={on ? 1 : 0.12}><path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2 - 10},${y2}`} fill="none" stroke={hot ? "#B9C6FF" : n.failed ? "#f59e0b" : "#5eead4"} strokeWidth={hot ? 4 : 2.5} className={n.failed ? "" : "edge"} strokeDasharray={n.failed ? "3 5" : undefined} markerEnd="url(#arrow)" /><text x={mx} y={(y1 + y2) / 2 - 8} textAnchor="middle" fontSize="12" fill={n.failed ? "#fbbf24" : "#94a3b8"}>{n.failed ? "起動失敗" : "起動"}</text></g>; })}
                  {rows.map((n) => {
                    const p = lay.pos.get(n.guid)!; const r = roleOf(n.image); const on = revealed.nodes.has(n.guid) || cursor < 0; const isSel = sel?.guid === n.guid; const alert = n.alerts.length > 0; const hot = current?.node.guid === n.guid; const c = counts(n); const alertOn = alert && (cursor < 0 || alertsOn.has(n.guid));
                    const stroke = alert ? "#f87171" : n.isFocus ? "#8EA2FF" : n.failed ? "#f59e0b" : r.risky ? "#fbbf24" : "#475569"; const dashed = n.failed || n.inferred;
                    return (
                      <g key={n.guid} transform={`translate(${p.x},${p.y})`} opacity={on ? 1 : 0.12} style={{ transition: "opacity .5s ease" }} className="cursor-pointer" onClick={() => setSel(n)}>
                        {alertOn && <rect x={-6} y={-6} width={lay.W + 12} height={lay.H + 12} rx={18} fill="none" stroke="#f87171" className="ring" />}
                        <rect width={lay.W} height={lay.H} rx={14} fill={hot ? "#1A2547" : n.failed ? "#1c1917" : "#0E1526"} stroke={isSel ? "#B9C6FF" : stroke} strokeWidth={isSel || hot ? 4 : 2.5} strokeDasharray={dashed ? "7 5" : undefined} />
                        <circle cx={26} cy={26} r={7} fill={n.failed ? "#F5C542" : alertOn ? "#F2555A" : r.risky ? "#F5C542" : "#4A5578"} />
                        <text x={54} y={30} fontSize="17" fontWeight="700" fill={alert ? "#fecaca" : "#f1f5f9"}>{base(n.image).length > 20 ? base(n.image).slice(0, 19) + "…" : base(n.image)}</text>
                        <text x={54} y={50} fontSize="12" fill={n.failed ? "#fbbf24" : r.risky ? "#fde68a" : "#94a3b8"}>{!n.failed && !n.inferred && r.risky ? "要注意 · " : ""}{roleLine(n)}</text>
                        {n.os === "linux" && n.commandLine && !Object.keys(c).length && <text x={14} y={80} fontSize="11" fill="#64748b" fontFamily="monospace">{n.commandLine.length > 30 ? n.commandLine.slice(0, 29) + "…" : n.commandLine}</text>}
                        {Object.entries(c).slice(0, 4).map(([k, v], i) => { const m = Object.values(EID).find((e) => e.name === k); return <g key={k} transform={`translate(${12 + i * 54},${64})`}><rect width={50} height={22} rx={11} fill="#1e293b" stroke={m?.color ?? "#64748b"} /><text x={25} y={15} textAnchor="middle" fontSize="11" fill="#e2e8f0">{m?.name?.slice(0, 2)} {v}</text></g>; })}
                        {alertOn && <g transform={`translate(${lay.W - 34},${-14})`} className="appear"><circle r={14} fill="#ef4444" /><text textAnchor="middle" y={5} fontSize="14" fill="#fff" fontWeight="700">{n.alerts.length}</text></g>}
                      </g>
                    );
                  })}
                </svg>
              </div>
              <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-slate-400">
                {Object.entries(EID).filter(([k]) => (showLoad || k !== "7") && k !== "12").map(([k, v]) => <span key={k} className="flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: v.color }} />{v.icon} {v.name}</span>)}
                <span>赤い数字 = 検知の件数</span>{tree.os === "linux" && <span className="text-amber-300">点線 = 起動に失敗（プログラムは動いていない）· 点線の灰色 = 起動記録なし（推定）</span>}<span className="text-amber-300">黄色の枠 = 攻撃にもよく使われるプログラム</span>
              </div>
            </div>
          )}

          <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
            {/* story list */}
            <div className="card flex max-h-[560px] min-w-0 flex-col p-3">
              <div className="mb-2 text-sm font-semibold">何が起きたか（時間順）</div>
              <ol className="relative min-h-0 flex-1 space-y-1.5 overflow-y-auto pr-1">
                {story.map((s, i) => {
                  const on = cursor < 0 || i <= cursor; const cur = i === cursor;
                  return (
                    <li key={i} ref={cur ? (el) => { const p = el?.parentElement; if (el && p) { const top = el.offsetTop; if (top < p.scrollTop || top > p.scrollTop + p.clientHeight - el.clientHeight) p.scrollTo({ top: Math.max(0, top - 60), behavior: "smooth" }); } } : undefined} onClick={() => { setPlaying(false); setCursor(i); setSel(s.node); }} className={`flex cursor-pointer gap-2 rounded-lg border p-2 text-sm transition ${cur ? "border-teal-400 bg-teal-500/15" : s.danger ? "border-rose-500/50 bg-rose-500/5" : s.kind === "alert" ? "border-amber-500/40 bg-slate-800" : "border-slate-700 bg-slate-900/50"} ${on ? "" : "opacity-30"}`}>
                      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-bold text-slate-950" style={{ background: s.color }}>{i + 1}</span>
                      <div className="min-w-0"><div className="text-slate-100">{s.text}</div><div className="text-[10px] text-slate-500">{fmtTs(new Date(s.ts).toISOString())}</div></div>
                    </li>
                  );
                })}
                {!story.length && <li className="text-xs text-slate-500">記録された動きがありません</li>}
              </ol>
            </div>
            <div className="min-w-0">
          {/* selected process */}
          {sel && (
            <div className="card space-y-3 p-5">
              <div className="flex flex-wrap items-center gap-2.5">
                <h2 className="font-mono text-[17px] font-bold text-slate-50">{base(sel.image)}</h2>
                <span className={`text-[13px] ${sel.failed || (roleOf(sel.image).risky && !sel.inferred) ? "text-[#F5C542]" : "text-slate-400"}`}>{!sel.failed && !sel.inferred && roleOf(sel.image).risky ? "要注意 · " : ""}{roleLine(sel)}</span>
                {sel.alerts.length > 0 && (() => { const a = sel.alerts.slice().sort((x, y) => y.level - x.level)[0]; return <span className="rounded-full bg-[#3A1418] px-2.5 py-0.5 text-xs font-bold text-[#FF9A9D]">level {a.level} · rule {a.ruleId}</span>; })()}
                <span className="ml-auto text-xs text-slate-400">開始 {fmtTs(sel.start)} · 終了 {sel.end ? fmtTs(sel.end) : "不明"}{sel.endEstimated ? "（推定）" : ""}</span>
              </div>
              {sel.failed && <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-2.5 text-sm text-amber-100">「{base(sel.callerImage ?? "?")}」が <span className="font-mono">{sel.image}</span> を実行しようとしましたが、{sel.errno ?? `exit ${sel.exitCode}`} で失敗しました。このプログラムは起動していません。</div>}
              {sel.inferred && sel.hint && <div className="rounded-lg border border-slate-600 bg-slate-900/50 p-2.5 text-xs text-slate-300">{sel.hint}</div>}
              {sel.alerts.length > 0 && <div className="space-y-1 rounded-lg border border-[#4A1E24] bg-[#1A1014] p-2.5">{sel.alerts.map((a, i) => <div key={i} className="flex flex-wrap items-baseline gap-2 text-sm text-rose-100"><Ico d={I.alerts} size={13} className="self-center text-[#F2555A]" />{a.description}<span className="text-[11px] text-slate-400">重大度 {a.level} · ルール {a.ruleId} · {fmtTs(a.ts)}</span></div>)}</div>}
              <div className="text-[13px] text-slate-400">コマンドライン</div>
              <pre className="whitespace-pre-wrap break-all rounded-lg border border-slate-700 bg-[#070B15] p-3 font-mono text-[13px] leading-relaxed text-slate-200">{sel.commandLine ?? "(コマンドラインなし)"}</pre>
              <dl className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
                <dt className="text-slate-400">実行ファイル</dt><dd className="break-all font-mono text-slate-200">{sel.image}</dd>
                {sel.user && <><dt className="text-slate-400">ユーザー</dt><dd className="font-mono text-slate-200">{sel.user}</dd></>}
                <dt className="text-slate-400">{sel.os === "linux" ? "pid / id" : "pid / guid"}</dt><dd className="break-all font-mono text-slate-200">pid {sel.pid ?? "?"}{sel.ppid ? ` · ppid ${sel.ppid}` : ""} · {sel.guid}</dd>
                {sel.cwd && <><dt className="text-slate-400">cwd</dt><dd className="break-all font-mono text-slate-200">{sel.cwd}</dd></>}
                <dt className="text-slate-400">出来事</dt><dd className="text-slate-200">{sel.events.filter((e) => showLoad || e.eid !== 7).length ? `${sel.events.filter((e) => showLoad || e.eid !== 7).length} 件` : "なし"}</dd>
                {(sel.hashes || sel.signed) && <><dt className="text-slate-400">ハッシュ</dt><dd className="break-all font-mono text-xs text-slate-300">{sel.hashes}{sel.signed ? ` · 署名 ${sel.signed}` : ""}</dd></>}
              </dl>
              {sel.events.length > 0 && <details open={mode === "detail"}><summary className="cursor-pointer text-xs text-slate-400">出来事の一覧</summary>
                <div className="mt-2 max-h-56 space-y-0.5 overflow-auto">{sel.events.filter((e) => showLoad || e.eid !== 7).map((e, i) => <div key={i} className="font-mono text-[11px] text-slate-300"><span className="mr-1 inline-block h-2 w-2 rounded-sm align-middle" style={{ background: EID[e.eid]?.color }} /><span style={{ color: EID[e.eid]?.color }}>{EID[e.eid]?.name ?? e.eid}</span> <span className="text-slate-500">{fmtTs(e.ts)}</span> {e.detail}</div>)}</div>
              </details>}
            </div>
          )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
