/**
 * EDR-142: /hosts/:id/contain — what "インターネット通信遮断（Contain）" is, case studies, the AI's impact analysis for THIS host
 * (with a diagram drawn from the AI's JSON), and a consultation chat that answers with diagrams.
 */
import { AgentTitle } from "../components/AgentIntro";
import { useContext, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import SessionChat from "../components/SessionChat";
import Diagram, { type DiagramSpec } from "../components/Diagram";
import { ActionDialog, ContainButton } from "../components/HostKarte";

const H2 = "mt-3 text-[18px] font-bold text-slate-100";
const P = "text-[14px] leading-[1.9] text-slate-300";
const CARD = "rounded-[14px] border border-slate-700 bg-slate-800 px-5 py-4";
const SEV_JA: Record<string, string> = { high: "影響大", medium: "影響中", low: "影響小" };
const SEV_CLS: Record<string, string> = { high: "bg-[#F0566E] text-[#0B1220]", medium: "bg-[#F2B33D] text-[#0B1220]", low: "bg-slate-500 text-white" };
const GROUP_JA: Record<string, string> = { internet: "インターネット", lan: "社内 LAN・共有", inbound: "この端末へのアクセス", users: "利用者", other: "その他" };

type Impact = { summary: string; use_now_if: string[]; avoid_if: string[]; keeps: { name: string; why: string }[]; stops: { name: string; impact: string; who: string; severity: string; group: string }[]; before: string[]; during: string[]; restore: string[]; platform?: string };
type ImpactResp = { note: { id: number; scan_id: number; content: Impact; model: string | null; created_at: string } | null; scan_id: number | null; stale: boolean };

const FLOW: DiagramSpec = {
  layout: "flow", title: "遮断から解除までの流れ",
  nodes: [
    { id: "a", label: "怪しい動きに気づく", tone: "warn", sub: "アラート・利用者の連絡" },
    { id: "b", label: "Contain を依頼", tone: "bad", sub: "承認キューへ" },
    { id: "c", label: "承認 → 通信遮断", tone: "bad", sub: "Wazuh との通信だけ残る" },
    { id: "d", label: "MamorAI で調査", tone: "info", sub: "ログ・プロセス・スキャン" },
    { id: "e", label: "原因を取り除く", tone: "info", sub: "駆除・パスワード変更など" },
    { id: "f", label: "解除（承認）", tone: "good", sub: "元のルールに戻る" },
  ],
  edges: [{ from: "a", to: "b" }, { from: "b", to: "c" }, { from: "c", to: "d" }, { from: "d", to: "e" }, { from: "e", to: "f", label: "安全を確認" }],
};

const CASES_USE = [
  { t: "ランサムウェアらしい動き", sign: "ファイルが短時間に大量に書き換わる・拡張子が変わる・身代金のメモが出る", why: "共有フォルダや他の端末へ暗号化が広がるのを止めます。電源は切らずに遮断すると、メモリ上の証拠も残せます。" },
  { t: "社内の別の端末へ広がっている（横展開）", sign: "この端末から他の端末への SMB・RDP・WinRM のログインが急に増える", why: "乗っ取られた端末を踏み台にされるのを止めます。" },
  { t: "外部の怪しい宛先と定期的に通信（C2）", sign: "決まった間隔で同じ海外の IP / ドメインに通信する・脅威情報に載っている宛先", why: "攻撃者からの指示が届かなくなり、情報も持ち出せなくなります。" },
  { t: "見覚えのない遠隔操作ソフト", sign: "AnyDesk・TeamViewer などを誰も入れた覚えがない／夜中に操作されている", why: "外から操作されている状態を、まず切り離します。" },
  { t: "情報の持ち出しが疑われる", sign: "クラウドストレージや不明なサーバーへの大量アップロード", why: "持ち出しをその場で止めます。" },
];
const CASES_AVOID = [
  { t: "多くの人が使うサーバー（ファイルサーバー・業務システム・DC）", why: "全員の仕事が止まります。まず怪しいポートや宛先だけを止める（ポートの「遮断」・IP 遮断）ことを検討してください。" },
  { t: "1 つのポート・1 つの宛先だけ止めれば済むとき", why: "ホストカルテの待ち受けポート一覧の「遮断」や、IP 遮断のほうが影響が小さく済みます。" },
  { t: "誤検知かもしれず、利用者が大事な作業中のとき", why: "まず利用者に連絡し、作業を保存してもらってから判断します。迷ったら下のチャットで相談してください。" },
];

function ImpactView({ c, host }: { c: Impact; host?: string }) {
  const spec: DiagramSpec = { layout: "contain", title: "この端末を遮断すると", host, keeps: c.keeps.map((k) => k.name), stops: c.stops.map((s) => ({ label: s.name, severity: s.severity as any, group: s.group })) };
  const List = ({ title, items, tone }: { title: string; items: string[]; tone: string }) => items.length ? <div className={CARD}><div className={`mb-1 text-[13px] font-semibold ${tone}`}>{title}</div><ul className={`${P} list-disc pl-5`}>{items.map((x, i) => <li key={i}>{x}</li>)}</ul></div> : null;
  return (
    <>
      <div className={`${CARD} ${P}`}>{c.summary}</div>
      <Diagram spec={spec} />
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(300px,1fr))]">
        <div className={CARD}>
          <div className="mb-1 text-[13px] font-semibold text-[#2FBF8F]">✓ 残る通信</div>
          {c.keeps.map((k, i) => <div key={i} className="border-t border-slate-700 py-1.5 first:border-t-0"><div className="text-[13.5px] font-semibold text-slate-100">{k.name}</div><div className="text-[12.5px] text-slate-400">{k.why}</div></div>)}
        </div>
        <div className={CARD}>
          <div className="mb-1 text-[13px] font-semibold text-[#F0566E]">✕ 止まる通信と、困る人</div>
          {c.stops.map((s, i) => (
            <div key={i} className="border-t border-slate-700 py-1.5 first:border-t-0">
              <div className="flex flex-wrap items-center gap-1.5"><span className="text-[13.5px] font-semibold text-slate-100">{s.name}</span><span className={`rounded-full px-1.5 text-[10px] font-bold ${SEV_CLS[s.severity] ?? SEV_CLS.low}`}>{SEV_JA[s.severity] ?? s.severity}</span><span className="text-[11px] text-slate-500">{GROUP_JA[s.group] ?? ""}</span></div>
              <div className="text-[12.5px] text-slate-300">{s.impact}</div>{s.who && <div className="text-[12px] text-slate-400">困る人: {s.who}</div>}
            </div>))}
        </div>
      </div>
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(260px,1fr))]">
        <List title="この端末で「すぐ押す」サイン" items={c.use_now_if} tone="text-[#FF9A9D]" />
        <List title="この端末で押さないほうがいいとき" items={c.avoid_if} tone="text-[#F5D98A]" />
      </div>
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(240px,1fr))]">
        <List title="① 押す前に" items={c.before} tone="text-slate-100" />
        <List title="② 遮断している間に" items={c.during} tone="text-slate-100" />
        <List title="③ 解除するとき" items={c.restore} tone="text-slate-100" />
      </div>
    </>
  );
}

export default function ContainHelp() {
  const { id = "" } = useParams(); const hostId = Number(id);
  const { user } = useContext(UserCtx); const canAct = user?.role === "admin" || user?.role === "operator"; const admin = user?.role === "admin";
  const [prof, setProf] = useState<any>(null); const [imp, setImp] = useState<ImpactResp | null>(null);
  const [err, setErr] = useState(""); const [gen, setGen] = useState(false); const [msg, setMsg] = useState("");
  const [dlg, setDlg] = useState(false);
  const [sid, setSid] = useState<number | null>(null); const [past, setPast] = useState<{ id: number; title: string; created_at: string }[]>([]);
  const loadProf = () => api.get<any>(`/hosts/${hostId}/profile`).then(setProf).catch((e) => setErr(e.message));
  const loadImp = () => api.get<ImpactResp>(`/hosts/${hostId}/contain-impact`).then(setImp).catch((e) => setErr(e.message));
  const h = prof?.host;
  const loadPast = (name: string) => api.get<{ items: any[] }>(`/sessions?limit=20&kind=contain_consult&q=${encodeURIComponent(name)}`).then((r) => setPast(r.items.filter((s) => s.title === `通信遮断の相談: ${name}`)));
  useEffect(() => { loadProf(); loadImp(); }, [hostId]);
  useEffect(() => { if (h?.name) loadPast(h.name); }, [h?.name]);

  const generate = async () => { setGen(true); setErr(""); try { setImp(await api.post<ImpactResp>(`/hosts/${hostId}/contain-impact`, {})); } catch (e: any) { setErr(e.message); } finally { setGen(false); } };
  const create = async (text: string) => { const r = await api.post<{ id: number }>("/sessions", { kind: "contain_consult", context: { host_id: hostId }, message: text.trim() || undefined }); setSid(r.id); if (h?.name) loadPast(h.name); return r.id; };
  const ask = async (q: string) => { try { if (sid) await api.post(`/sessions/${sid}/message`, { message: q }); else await create(q); document.getElementById("consult")?.scrollIntoView({ behavior: "smooth" }); } catch (e: any) { setErr(e.message); } };

  const cap = prof?.capability; const can = canAct && !!cap?.ok;
  const iso = (prof?.actions ?? []).find((a: any) => a.op === "isolate" && ["active", "unconfirmed"].includes(a.status));
  const QUICK = ["遮断すると、この端末を使っている人は何ができなくなる？", "ポートだけ止めるのと、Contain の違いは？", "遮断中に MamorAI で何を調べればいい？", "解除するときの確認手順は？"];

  return (
    <div className="mx-auto flex max-w-[1000px] flex-col gap-3.5">
      <div className="text-xs text-slate-400"><Link className="hover:underline" to="/hosts">管理ホスト</Link> › {h ? <Link className="hover:underline" to={`/hosts?id=${hostId}`}>{h.name}</Link> : `#${hostId}`} › インターネット通信遮断（Contain）</div>
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="m-0 text-[24px] font-bold">インターネット通信遮断（Contain）{h ? <span className="text-slate-400"> — {h.name}</span> : null}</h1>
        <div className="ml-auto">{iso ? <span className="rounded-lg border border-[#8A2A30] bg-[#3A1418] px-3 py-1.5 text-[13px] font-bold text-[#FFB3B6]">通信遮断中（{fmtTs(iso.applied_at)} から）</span>
          : canAct && prof && <ContainButton enabled={can && admin} why={!can ? (cap?.reason ?? "この端末では遮断操作が使えません") : !admin ? "管理者だけが依頼できます" : ""} onClick={() => setDlg(true)} />}</div>
      </div>
      {err && <div className="text-sm text-rose-400">{err}</div>}
      {msg && <div className="rounded-[10px] border border-slate-600 bg-slate-900 px-3.5 py-2 text-[13px] text-slate-200">{msg}</div>}

      <div className={`${CARD} ${P}`}>
        <b className="text-slate-100">要点</b>: Contain を押すと、<b className="text-slate-100">Wazuh（MamorAI）との通信だけを残して</b>、この端末のインターネットと社内 LAN の通信をすべて止めます。電源・アプリ・ファイルはそのままなので、証拠を残したまま被害の広がりを止められます。
        <br />すぐには実行されず、承認キューで人が承認したときに実行されます。解除するまで続き、解除も承認制です（元のファイアウォールのルールに戻ります）。
        <div className="mt-2 rounded-[10px] border border-[#2B4A7A] bg-[#132245] px-3 py-2 text-[13.5px] text-[#D6E0FF]">💬 わからないことがあれば、<a href="#consult" className="font-semibold text-teal-300 hover:underline">このページの下の「AIエージェントに相談」</a>で聞いてください。この端末の状況をもとに、図（ポンチ絵）を付けて説明します。</div>
      </div>
      <Diagram spec={FLOW} />

      <h2 className={H2}>この端末への影響（AI 分析）</h2>
      {!imp ? <div className="text-sm text-slate-500">読み込み中…</div>
        : imp.note ? <>
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span>{fmtTs(imp.note.created_at)} に作成（スキャン #{imp.note.scan_id}{imp.note.model ? ` · ${imp.note.model}` : ""}）</span>
            {imp.stale && <span className="rounded bg-[#2D2410] px-1.5 py-0.5 text-[#F5D98A]">新しいスキャン結果があります。作り直すと最新の状態で説明します</span>}
            {canAct && <button className="ml-auto rounded-md border border-slate-600 px-2.5 py-1 text-[12px] hover:bg-slate-700" disabled={gen} onClick={generate}>{gen ? "AI が分析中…（30 秒ほど）" : "作り直す"}</button>}
          </div>
          <ImpactView c={imp.note.content} host={h?.name} />
        </>
        : <div className={`${CARD} ${P}`}>
          {imp.scan_id ? <>この端末の最新スキャン（#{imp.scan_id}）をもとに、遮断すると何が止まり、誰が困るかを AI が説明します。</> : <>まだスキャンしていません。先にホストカルテで「ホストを AI でスキャン」を実行してください。</>}
          {canAct && imp.scan_id && <div className="mt-2"><button className="btn-primary min-h-[38px] rounded-[10px] px-4" disabled={gen} onClick={generate}>{gen ? "AI が分析中…（30 秒ほど）" : "この端末への影響を AI で分析する"}</button></div>}
        </div>}

      <h2 className={H2}>使うべきとき（ケーススタディ）</h2>
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(280px,1fr))]">
        {CASES_USE.map((c) => <div key={c.t} className={CARD}><div className="text-[14.5px] font-semibold text-[#FF9A9D]">{c.t}</div><div className="mt-1 text-[12.5px] text-slate-400">サイン: {c.sign}</div><div className="mt-1 text-[13.5px] leading-relaxed text-slate-300">{c.why}</div></div>)}
      </div>
      <h2 className={H2}>使わないほうがいいとき</h2>
      <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(280px,1fr))]">
        {CASES_AVOID.map((c) => <div key={c.t} className={CARD}><div className="text-[14.5px] font-semibold text-[#F5D98A]">{c.t}</div><div className="mt-1 text-[13.5px] leading-relaxed text-slate-300">{c.why}</div></div>)}
      </div>

      <h2 id="consult" className={H2}>AIエージェントに相談する</h2>
      <section className="flex flex-col overflow-hidden rounded-2xl border border-slate-600 bg-slate-800" style={{ height: "70vh", minHeight: "28rem" }}>
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-700 px-4 py-2.5 text-[13px]">
          <AgentTitle context={`通信遮断${h ? ` · ${h.name}` : ""}`} size="sm" />
          {past.length > 0 && <span className="ml-auto flex flex-wrap items-center gap-1.5 text-xs text-slate-400">前の相談:{past.slice(0, 4).map((s) => <button key={s.id} className={`rounded border px-1.5 py-0.5 ${sid === s.id ? "border-teal-400 text-teal-200" : "border-slate-600 hover:bg-slate-700"}`} onClick={() => setSid(s.id)}>#{s.id} {fmtTs(s.created_at).slice(5, 16)}</button>)}{sid && <button className="rounded border border-slate-600 px-1.5 py-0.5 hover:bg-slate-700" onClick={() => setSid(null)}>＋ 新しく相談</button>}</span>}
        </div>
        {canAct ? <SessionChat key={sid ?? "new"} sid={sid} create={(t) => create(t)} showProposal={false} className="min-h-0 flex-1 px-3 pb-2 pt-3"
          placeholder={sid ? "続けて質問" : "気になることを書いてください（空のまま送ると、AI がこの端末の状況から説明を始めます）"}
          emptyHint={<div className="flex flex-col gap-2 text-sm leading-relaxed text-slate-400"><div>この端末の最新スキャンと、上の影響分析をもとに AI が答えます。答えには図（ポンチ絵）が付きます。遮断することに決めたら、AI が承認キューに依頼を積むこともできます（実行は人の承認後）。</div><div className="flex flex-wrap gap-1.5">{QUICK.map((q) => <button key={q} className="rounded-full border border-slate-600 px-3 py-1 text-[12.5px] text-slate-200 hover:bg-slate-700" onClick={() => ask(q)}>{q}</button>)}</div></div>} />
          : <div className="p-4 text-sm text-slate-400">相談チャットは operator 以上が使えます。</div>}
      </section>

      {dlg && h && <ActionDialog hostId={hostId} hostName={h.name} init={{ op: "isolate", params: {} }} admin={admin} onClose={() => setDlg(false)} onDone={(aid) => { setDlg(false); setMsg(`承認キューに積みました（承認 #${aid}）。承認キューで承認すると実行されます。`); loadProf(); }} />}
    </div>
  );
}
