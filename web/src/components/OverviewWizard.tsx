import { useContext, useEffect, useMemo, useState } from "react";
import AgentIntro, { AgentTitle } from "./AgentIntro";
import { api } from "../lib/api";
import { UserCtx } from "../main";
import SessionChat, { type PendingFile, type SessionRow, SESSION_STATUS_CLS, SESSION_STATUS_JA } from "./SessionChat";
import SessionHistory from "./SessionHistory";
import { Field } from "./fields";
import { Ico, I } from "./Icon";

/** 攻撃可視化 セットアップ・ウィザード（EDR-74）。Wazuh を入れた直後の人が、地図が描けるところまで辿り着くための構造化ステップ＋AI チャット。 */

export interface Setup {
  wazuh_instance_id: number; manager_addr: string | null;
  state: { assets: string[]; vendors: Record<string, string>; step: number; completed: boolean; skipped: boolean; demo: boolean; manager_addr: string | null };
  readiness: { ok: boolean; level: "ready" | "partial" | "empty" | "error"; window: string; indexer: { ok: boolean; error?: string }; geo_rate: number | null; total_src: number; profiles: { id: string; name: string; total: number; with_geo: number; agents: string[]; error?: string }[]; agents: { name: string; status: string; ip: string | null }[]; manager_remote: boolean | null; hints: string[] };
  recipes: { assets: any[]; vendors: Record<string, { label: string; stock: boolean; howto: string }> };
  sites: { id: number; name: string; lat: number; lon: number; kind: string; is_default: boolean; members: string[] }[];
  hosts: { id: number; name: string; address: string; agent_id: string | null; environment: string }[];
}

const CITIES: [string, number, number][] = [["東京", 35.68, 139.76], ["大阪", 34.69, 135.50], ["名古屋", 35.18, 136.91], ["福岡", 33.59, 130.40], ["札幌", 43.06, 141.35], ["仙台", 38.27, 140.87], ["シンガポール", 1.35, 103.82], ["ソウル", 37.57, 126.98], ["台北", 25.03, 121.57], ["米国バージニア（us-east-1）", 38.9, -77.4], ["米国オレゴン（us-west-2）", 45.5, -122.7], ["フランクフルト", 50.11, 8.68], ["ロンドン", 51.51, -0.13], ["シドニー", -33.87, 151.21]];
const STEPS = ["診断", "守っているもの", "ログの取り込み", "拠点", "確認"];
const render = (t: string, vars: Record<string, string>) => t.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k] ?? `{{${k}}}`);

function Copy({ text }: { text: string }) { const [ok, setOk] = useState(false); return <button className="btn-secondary px-2 py-0.5 text-[11px]" onClick={() => { navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1500); }); }}>{ok ? "✓ コピーした" : "コピー"}</button>; }
function Snip({ title, text, path, restart }: { title?: string; text: string; path?: string; restart?: string }) {
  return <div className="mt-1 rounded-md border border-slate-600 bg-slate-950">
    <div className="flex items-center gap-2 border-b border-slate-700 px-2 py-1 text-[11px] text-slate-400"><span className="flex-1 truncate">{title ?? path ?? ""}{title && path && <span className="ml-2 text-slate-500">{path}</span>}</span><Copy text={text} /></div>
    <pre className="max-h-56 overflow-auto whitespace-pre-wrap p-2 font-mono text-[11px] text-slate-200">{text}</pre>
    {restart && <div className="border-t border-slate-700 px-2 py-1 text-[11px] text-slate-400">反映: <code className="text-slate-200">{restart}</code></div>}
  </div>;
}

export default function OverviewWizard({ setup, onReload, onClose, onDemo }: { setup: Setup; onReload: () => Promise<void>; onClose: () => void; onDemo: () => void }) {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin"; const chatOk = admin || user?.role === "operator";
  const [step, setStep] = useState(setup.state.step || 0);
  const [assets, setAssets] = useState<string[]>(setup.state.assets ?? []);
  const [vendors, setVendors] = useState<Record<string, string>>(setup.state.vendors ?? {});
  const [manager, setManager] = useState(setup.state.manager_addr ?? setup.manager_addr ?? "");
  const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const [chatOpen, setChatOpen] = useState(false); const [sid, setSid] = useState<number | null>(null); const [sessions, setSessions] = useState<(SessionRow & { label?: string | null })[]>([]); const [hist, setHist] = useState(false);
  const [pack, setPack] = useState<{ decoders: string; rules: string } | null>(null);
  const [site, setSite] = useState<{ name: string; city: number; members: string[]; is_default: boolean }>({ name: "", city: 0, members: [], is_default: setup.sites.length === 0 });
  const r = setup.readiness; const vars = { MANAGER: manager || "<manager のアドレス>", DEVICE_IP: "<機器の IP>" };
  const loadList = () => api.get<{ items: (SessionRow & { label?: string | null })[] }>("/sessions?limit=20&kind=overview_setup").then((x) => setSessions(x.items)).catch(() => {});
  useEffect(() => { loadList(); }, []);

  const save = async (patch: any) => { if (!admin) return; try { await api.put("/overview/setup", { wazuh_instance_id: setup.wazuh_instance_id, ...patch }); } catch (e: any) { setErr(e.message); } };
  const go = async (n: number) => { setStep(n); await save({ step: n, assets, vendors, manager_addr: manager || null }); };
  const reprobe = async () => { setBusy(true); try { await onReload(); } finally { setBusy(false); } };
  const startChat = async (message: string) => {
    if (!admin) return; setErr("");
    await save({ assets, vendors, manager_addr: manager || null, step });
    try { const x = await api.post<{ id: number }>("/sessions", { kind: "overview_setup", message, wazuh_instance_id: setup.wazuh_instance_id }); setSid(x.id); setChatOpen(true); loadList(); } catch (e: any) { setErr(e.message); }
  };
  const create = async (text: string, attachments: PendingFile[]) => { const x = await api.post<{ id: number }>("/sessions", { kind: "overview_setup", message: text.trim() || undefined, attachments: attachments.length ? attachments : undefined, wazuh_instance_id: setup.wazuh_instance_id }); setSid(x.id); loadList(); return x.id; };
  const profileOf = (id: string) => r.profiles.find((p) => p.id === id);
  const checkOk = (check?: string): boolean | null => {
    if (!check) return null;
    if (check === "agent_present") return r.agents.length > 0;
    if (check === "manager_remote") return r.manager_remote;
    if (check.startsWith("profile:")) return (profileOf(check.slice(8))?.total ?? 0) > 0;
    return null;
  };
  const selectedAssets = useMemo(() => setup.recipes.assets.filter((a) => assets.includes(a.id)), [assets, setup.recipes]);
  const cur = sessions.find((s) => s.id === sid);

  return (
    <div className="absolute inset-0 z-20 flex items-stretch justify-center bg-[#050a14]/80 p-4 backdrop-blur-sm md:p-8">
      <div className={`flex w-full max-w-[1200px] gap-4 ${chatOpen ? "" : "justify-center"}`}>
        <div className={`card flex max-h-full flex-col overflow-hidden border-teal-500/30 ${chatOpen ? "w-[58%]" : "w-full max-w-[760px]"}`}>
          <div className="flex items-center gap-3">
            <h2 className="flex items-center gap-2 text-base font-semibold"><Ico d={I.globe} size={18} />攻撃可視化のセットアップ</h2>
            <span className="text-xs text-slate-500">Wazuh に攻撃のログを運ぶところまで案内します</span>
            <div className="ml-auto flex gap-1">
              {chatOk && <button className="btn-secondary px-3 py-1.5 text-xs" onClick={() => setHist(true)}><Ico d={I.history} size={13} className="" />履歴{sessions.length ? ` (${sessions.length})` : ""}</button>}
              {chatOk && !chatOpen && <button className="btn-secondary px-3 py-1.5 text-xs" onClick={() => { setChatOpen(true); if (!sid && sessions[0]) setSid(sessions[0].id); }}><Ico d={I.ai} size={13} className="" />AIエージェントに相談</button>}
              <button className="btn-secondary px-3 py-1.5 text-xs" onClick={onClose} title="あとでやる（右下の「セットアップ」からいつでも再開）">閉じる</button>
            </div>
          </div>
          <div className="mt-2 flex items-center gap-1 text-[11px]">
            {STEPS.map((s, i) => <button key={s} onClick={() => go(i)} className={`rounded-full px-2.5 py-0.5 ${i === step ? "bg-teal-500/20 text-teal-200" : i < step ? "text-teal-400" : "text-slate-500"}`}>{i < step ? "✓" : i + 1} {s}</button>)}
            <span className="ml-auto text-slate-500">{r.level === "ready" ? "描画できる状態です" : r.level === "partial" ? "一部のデータだけあります" : r.level === "error" ? "indexer に接続できません" : "まだデータがありません"}</span>
          </div>
          {err && <div className="mt-1 text-xs text-rose-400">{err}</div>}
          <div className="mt-3 flex-1 overflow-y-auto pr-1 text-sm">
            {/* STEP 0 診断 */}
            {step === 0 && <div className="space-y-3">
              <p className="text-slate-300">攻撃可視化は、Wazuh に入っているアラートのうち「外部の送信元 IP を持つもの」だけを使います。Wazuh のダッシュボードを作る必要はありません。今のデータを診断しました。</p>
              {!r.indexer.ok && <div className="rounded-md border border-rose-700/50 bg-rose-500/10 p-2 text-xs text-rose-300">indexer に接続できません: {r.indexer.error}。設定 › Wazuh 接続を確認してください。</div>}
              <table className="w-full text-xs"><thead><tr className="text-slate-500"><th className="py-1 text-left">攻撃の種類</th><th className="text-right">直近 24h の件数</th><th className="text-right">国情報あり</th><th className="text-left pl-3">出どころ</th></tr></thead><tbody>
                {r.profiles.filter((p) => p.id !== "blocked").map((p) => <tr key={p.id} className="border-t border-slate-700"><td className="py-1"><span className={p.total > 0 ? "text-[#3CCB8C]" : "text-rose-300"}>{p.total > 0 ? "✓" : "✗"}</span> {p.name}</td><td className="text-right tabular-nums">{p.total.toLocaleString()}</td><td className="text-right tabular-nums text-slate-400">{p.total ? Math.round((p.with_geo / p.total) * 100) + "%" : "-"}</td><td className="pl-3 text-slate-400">{p.agents.slice(0, 4).join(", ")}{p.agents.length > 4 && " …"}</td></tr>)}
              </tbody></table>
              <div className="grid gap-2 text-xs md:grid-cols-3">
                <div className="rounded-md border border-slate-600 p-2"><div className="text-slate-500">エージェント</div><div className="text-slate-200">{r.agents.length} 台（稼働 {r.agents.filter((a) => a.status === "active").length}）</div></div>
                <div className="rounded-md border border-slate-600 p-2"><div className="text-slate-500">manager の syslog 受信</div><div className="text-slate-200">{r.manager_remote == null ? "不明（API 未設定）" : r.manager_remote ? "有効" : "無効"}</div></div>
                <div className="rounded-md border border-slate-600 p-2"><div className="text-slate-500">GeoLocation の付与率</div><div className="text-slate-200">{r.geo_rate == null ? "-" : r.geo_rate + "%"}</div></div>
              </div>
              {r.hints.map((h, i) => <div key={i} className="rounded-md border border-amber-700/40 bg-amber-500/10 p-2 text-xs text-amber-200">{h}</div>)}
              <div className="flex flex-wrap gap-2 pt-1">
                {r.level === "ready" && <button className="btn-primary px-3 py-1 text-sm" onClick={async () => { await save({ completed: true, step: 4 }); onClose(); }}>このまま地図を見る</button>}
                <button className="btn-primary px-3 py-1 text-sm" onClick={() => go(1)}>{r.level === "ready" ? "取り込みを増やす →" : "セットアップを始める →"}</button>
                <button className="btn-secondary px-3 py-1 text-sm" onClick={reprobe} disabled={busy}>{busy ? "診断中…" : "↻ 再診断"}</button>
                <button className="btn-secondary px-3 py-1 text-sm" onClick={onDemo} title="サンプルデータで画面の雰囲気だけ見ます（『デモ』と表示されます）">デモデータで見る</button>
              </div>
            </div>}
            {/* STEP 1 守っているもの */}
            {step === 1 && <div className="space-y-3">
              <p className="text-slate-300">インターネットに公開しているものを選んでください（複数可）。これで必要な作業が決まります。</p>
              <div className="grid gap-2 md:grid-cols-2">
                {setup.recipes.assets.map((a) => <label key={a.id} className={`flex cursor-pointer gap-2 rounded-lg border p-2 ${assets.includes(a.id) ? "border-teal-400/70 bg-teal-500/10" : "border-slate-600 hover:border-slate-500"}`}>
                  <input type="checkbox" className="mt-1" checked={assets.includes(a.id)} onChange={(e) => setAssets(e.target.checked ? [...assets.filter((x) => x !== "home_router" || a.id === "home_router"), a.id] : assets.filter((x) => x !== a.id))} />
                  <div><div className="font-medium text-slate-100">{a.icon} {a.label}</div><div className="text-xs text-slate-400">{a.desc}</div>{a.profiles.some((p: string) => (profileOf(p)?.total ?? 0) > 0) && <div className="mt-0.5 text-[11px] text-teal-300">✓ すでにデータがあります</div>}</div>
                </label>)}
              </div>
              <Field label="エージェントや機器から見た Wazuh manager のアドレス" hint="インストールコマンドと syslog 設定に埋め込みます。クラウドのサーバーからは自宅の manager に直接届かないことが多いので、Tailscale 等の VPN アドレスか、公開したアドレスを入れてください。"><input className="input" value={manager} onChange={(e) => setManager(e.target.value)} placeholder="例: 100.64.x.x（Tailscale）/ wazuh.example.com" /></Field>
              <div className="flex gap-2"><button className="btn-secondary px-3 py-1 text-sm" onClick={() => go(0)}>← 戻る</button><button className="btn-primary px-3 py-1 text-sm" disabled={!assets.length} onClick={() => go(2)}>次へ →</button></div>
            </div>}
            {/* STEP 2 取り込み */}
            {step === 2 && <div className="space-y-3">
              <p className="text-slate-300">選んだものごとに、Wazuh へログを運ぶ手順です。✓ は診断で確認できたもの。設定ファイルは全文なのでそのまま貼れます。手順どおりにやっても出ない時は「AI に相談」でログを貼ってください。</p>
              {!selectedAssets.length && <div className="text-xs text-slate-500">前のステップで対象を選んでください。</div>}
              {selectedAssets.map((a) => <details key={a.id} open className="rounded-lg border border-slate-600">
                <summary className="cursor-pointer px-3 py-2 font-medium text-slate-100">{a.icon} {a.label} <span className="ml-2 text-xs text-slate-500">{a.profiles.map((p: string) => `${profileOf(p)?.name ?? p} ${(profileOf(p)?.total ?? 0).toLocaleString()} 件`).join(" · ")}</span></summary>
                <div className="space-y-3 border-t border-slate-700 p-3">
                  {a.vendors && <Field label="機器の種類"><select className="input w-auto" value={vendors[a.id] ?? ""} onChange={(e) => setVendors({ ...vendors, [a.id]: e.target.value })}><option value="">選んでください</option>{a.vendors.map((v: string) => <option key={v} value={v}>{setup.recipes.vendors[v]?.label ?? v}{setup.recipes.vendors[v]?.stock ? "（Wazuh 標準ルールで解析）" : ""}</option>)}</select></Field>}
                  {a.vendors && vendors[a.id] && <div className="rounded-md border border-slate-600 bg-slate-900/50 p-2 text-xs text-slate-300"><div className="mb-1 text-slate-500">{setup.recipes.vendors[vendors[a.id]].label} の設定</div>{render(setup.recipes.vendors[vendors[a.id]].howto, vars)}</div>}
                  {a.steps.map((st: any, i: number) => { const ok = checkOk(st.check); return <div key={st.id} className="rounded-md border border-slate-700 p-2">
                    <div className="flex items-center gap-2 text-sm"><span className={`rounded-full px-1.5 text-[11px] ${ok === true ? "bg-teal-500/20 text-teal-300" : ok === false ? "bg-amber-500/20 text-amber-300" : "bg-slate-600/60 text-slate-400"}`}>{ok === true ? "✓" : i + 1}</span><span className="font-medium text-slate-100">{st.title}</span>{st.optional && <span className="text-[10px] text-slate-500">任意</span>}{ok === true && <span className="text-[11px] text-teal-300">確認済み</span>}</div>
                    {st.detail && <div className="mt-1 text-xs text-slate-400">{render(st.detail, vars)}</div>}
                    {st.kind === "agent_install" && <Snip title="Debian / Ubuntu" text={`curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb && sudo WAZUH_MANAGER='${vars.MANAGER}' WAZUH_AGENT_NAME='$(hostname)' dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb && sudo systemctl enable --now wazuh-agent`} />}
                    {st.kind === "agent_install" && <Snip title="RHEL / Amazon Linux / Rocky" text={`curl -sO https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.2-1.x86_64.rpm && sudo WAZUH_MANAGER='${vars.MANAGER}' WAZUH_AGENT_NAME='$(hostname)' rpm -ihv wazuh-agent-4.9.2-1.x86_64.rpm && sudo systemctl enable --now wazuh-agent`} />}
                    {st.snippet && <Snip text={render(st.snippet, vars)} path={st.snippet_path} restart={st.restart} />}
                    {st.kind === "decoder_pack" && <div className="mt-1 space-y-1">
                      {!pack ? <button className="btn-secondary px-3 py-1.5 text-xs" onClick={() => api.get<{ decoders: string; rules: string }>("/overview/decoder-pack").then(setPack)}>同梱のデコーダ / ルールを表示</button> : <><Snip title="デコーダ" text={pack.decoders} path="/var/ossec/etc/decoders/edr-fw-decoders.xml" /><Snip title="ルール（100650〜）" text={pack.rules} path="/var/ossec/etc/rules/edr-fw-rules.xml" restart="sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager" /></>}
                      {chatOk && <button className="btn-primary px-3 py-1.5 text-xs" onClick={() => startChat(`攻撃可視化のセットアップ: 「${a.label}」${vendors[a.id] ? `（機器: ${setup.recipes.vendors[vendors[a.id]].label}）` : ""}のために、manager（${manager || "アドレス未設定"}）に同梱のデコーダ/ルール（get_decoder_pack）と syslog 受信設定（<remote>）を入れたい。manager がホスト登録されていれば apply_change で適用して（承認する）。登録されていなければ手順を教えて。`)}><Ico d={I.ai} size={13} className="" />AI に manager へ適用させる（承認付き）</button>}
                    </div>}
                    {st.kind === "manager_remote" && chatOk && <button className="btn-primary mt-1 px-2 py-1 text-xs" onClick={() => startChat(`攻撃可視化のセットアップ: manager（${manager || "アドレス未設定"}）で syslog を受信できるように <remote> を追加したい（機器の IP は聞いて）。manager がホスト登録されていれば apply_change で適用して。`)}><Ico d={I.ai} size={13} className="" />AI に manager へ適用させる（承認付き）</button>}
                  </div>; })}
                </div>
              </details>)}
              <div className="flex flex-wrap gap-2"><button className="btn-secondary px-3 py-1 text-sm" onClick={() => go(1)}>← 戻る</button><button className="btn-secondary px-3 py-1 text-sm" onClick={reprobe} disabled={busy}>{busy ? "診断中…" : "↻ 再診断（設定後に押す）"}</button><button className="btn-primary px-3 py-1 text-sm" onClick={() => go(3)}>次へ（拠点）→</button></div>
            </div>}
            {/* STEP 3 拠点 */}
            {step === 3 && <div className="space-y-3">
              <p className="text-slate-300">攻撃の矢印が飛んでくる先（あなたの拠点）です。ホストがどの都市にあるかだけ教えてください（住所は保存しません）。未設定のホストは「既定」の拠点に描かれます。</p>
              {setup.sites.length > 0 && <div className="space-y-1 text-xs">{setup.sites.map((s) => <div key={s.id} className="flex items-center gap-2 rounded-md border border-slate-600 px-2 py-1"><span className="font-medium text-slate-100">{s.name}</span>{s.is_default && <span className="rounded bg-teal-500/20 px-1 text-[10px] text-teal-300">既定</span>}<span className="text-slate-500">{s.lat.toFixed(2)}, {s.lon.toFixed(2)}</span><span className="flex-1 truncate text-slate-400">{s.members.join(", ") || "（ホスト未割当）"}</span>{admin && <button className="text-slate-500 hover:text-rose-300" onClick={async () => { await api.del(`/sites/${s.id}`); await onReload(); }} aria-label="削除"><Ico d={I.trash} size={13} className="" /></button>}</div>)}</div>}
              {admin && <div className="rounded-lg border border-slate-600 p-3">
                <div className="grid gap-2 md:grid-cols-2">
                  <Field label="拠点の名前"><input className="input" value={site.name} onChange={(e) => setSite({ ...site, name: e.target.value })} placeholder="例: 自宅 / Lightsail 東京" /></Field>
                  <Field label="都市"><select className="input" value={site.city} onChange={(e) => setSite({ ...site, city: Number(e.target.value) })}>{CITIES.map((c, i) => <option key={c[0]} value={i}>{c[0]}</option>)}</select></Field>
                </div>
                <div className="label mt-2">この拠点にあるホスト</div>
                <div className="flex flex-wrap gap-1">{[...new Set([...r.agents.map((a) => a.name), ...setup.hosts.map((h) => h.name)])].map((n) => <button key={n} className={`rounded-md border px-2 py-0.5 text-xs ${site.members.includes(n) ? "border-teal-400 text-teal-200" : "border-slate-600 text-slate-400"}`} onClick={() => setSite({ ...site, members: site.members.includes(n) ? site.members.filter((x) => x !== n) : [...site.members, n] })}>{n}</button>)}</div>
                <label className="mt-2 flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={site.is_default} onChange={(e) => setSite({ ...site, is_default: e.target.checked })} /> 未設定のホストはこの拠点に描く（既定）</label>
                <button className="btn-primary mt-2 px-3 py-1 text-sm" disabled={!site.name} onClick={async () => { const c = CITIES[site.city]; await api.post("/sites", { name: site.name, lat: c[1], lon: c[2], kind: /lightsail|aws|gcp|cloud|azure|vps/i.test(site.name) ? "cloud" : "home", is_default: site.is_default, members: site.members }); setSite({ name: "", city: 0, members: [], is_default: false }); await onReload(); }}>＋ 拠点を追加</button>
              </div>}
              <div className="flex gap-2"><button className="btn-secondary px-3 py-1 text-sm" onClick={() => go(2)}>← 戻る</button><button className="btn-primary px-3 py-1 text-sm" onClick={() => go(4)}>次へ（確認）→</button></div>
            </div>}
            {/* STEP 4 確認 */}
            {step === 4 && <div className="space-y-3">
              {r.level === "ready" ? <div className="rounded-lg border border-teal-500/40 bg-teal-500/10 p-3"><div className="text-base font-semibold text-teal-200">攻撃可視化を描ける状態です</div><div className="mt-1 text-xs text-slate-300">直近 24 時間で外部からの攻撃通信 {r.total_src.toLocaleString()} 件、国情報の付与率 {r.geo_rate}%。</div></div>
                : <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3"><div className="text-base font-semibold text-amber-200">まだ外部からの攻撃データが {r.total_src ? "少ない" : "無い"}状態です</div><div className="mt-1 text-xs text-slate-300">設定が済んでいれば、攻撃は数分〜数時間で入ってきます。しばらくしてから「再診断」を押してください。公開サーバーもルーターの syslog も無い場合は、そもそも描くものが無いので「デモデータ」で画面を確認できます。</div></div>}
              <div className="flex flex-wrap gap-2">
                <button className="btn-secondary px-3 py-1 text-sm" onClick={reprobe} disabled={busy}>{busy ? "診断中…" : "↻ 再診断"}</button>
                {r.level !== "empty" && admin && <button className="btn-primary px-3 py-1 text-sm" onClick={async () => { await save({ completed: true, step: 4, demo: false }); onClose(); }}>完了して地図を見る</button>}
                <button className="btn-secondary px-3 py-1 text-sm" onClick={onDemo}>デモデータで見る</button>
                {admin && <button className="btn-secondary px-3 py-1 text-sm" onClick={async () => { await save({ skipped: true }); onClose(); }} title="データが入ったら自動で描画されます">あとで（ウィザードを閉じる）</button>}
                <button className="btn-secondary px-3 py-1 text-sm" onClick={() => go(2)}>← 取り込みに戻る</button>
              </div>
            </div>}
          </div>
        </div>
        {chatOpen && <div className="card flex w-[42%] flex-col border-teal-500/30">
          <div className="flex items-center gap-2 text-sm"><AgentTitle context="攻撃可視化" size="sm" />{cur && <><span className={`rounded px-1.5 text-[10px] ${SESSION_STATUS_CLS[cur.status] ?? ""}`}>{SESSION_STATUS_JA[cur.status] ?? cur.status}</span><span className="truncate text-xs text-slate-400">#{cur.id} {cur.label || cur.title}</span></>}<button className="ml-auto text-xs text-slate-400 hover:text-slate-200" onClick={() => setChatOpen(false)}>たたむ ▸</button></div>
          <SessionChat key={sid ?? "new"} sid={sid} create={create} showProposal={false} className="mt-2 flex-1" onEvent={(type, data) => { loadList(); if (type === "tool_result" && ["set_site", "update_setup_state", "apply_change"].includes(data?.tool_call?.tool)) onReload(); }}
            placeholder={sid ? "返信" : "例: Yamaha RTX1300 の syslog を送りたい / このログを解析して: ..."}
            emptyHint={<AgentIntro compact lead={<>AI がデータを診断して、足りないログの取り込み手順を環境に合わせて案内します。受信設定やデコーダの投入は、承認をもらってから AI が実行します。ログを 1 行貼ると、その機器用のデコーダも作ります。</>} examples={["何が足りないか診断して", "Yamaha ルーターの syslog を送りたい", "Sophos XG のログを取り込みたい", "このログ 1 行のデコーダを作って"]} onPick={(t) => { create(t, []).catch(() => {}); }} />} />
        </div>}
      </div>
      {hist && <SessionHistory kind="overview_setup" title="攻撃可視化セットアップの相談履歴" currentId={sid} canAct={!!chatOk} onOpen={(id) => { setSid(id); setChatOpen(true); loadList(); }} onClose={() => setHist(false)} />}
    </div>
  );
}
