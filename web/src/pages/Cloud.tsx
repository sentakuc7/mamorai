import { useContext, useEffect, useMemo, useState } from "react";
import AgentIntro, { AgentTitle } from "../components/AgentIntro";
import { useNavigate } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import { Field } from "../components/fields";
import SessionChat, { type PendingFile, type SessionRow, SESSION_STATUS_CLS, SESSION_STATUS_JA } from "../components/SessionChat";
import SessionHistory from "../components/SessionHistory";
import { Ico, I } from "../components/Icon";

/** クラウド管理（EDR-76）: IaaS プロバイダの登録と台帳、承認キュー経由のスナップショット / 電源 / 隔離。 */

interface Provider { id: number; kind: string; name: string; config: any; capability: "inventory" | "ops" | "isolate"; status: string; last_error: string | null; last_sync_at: string | null; has_secret: boolean; instances: number }
interface Inst { id: number; provider_id: number; provider_kind: string; provider_name: string; service: string; external_id: string; name: string; state: string; public_ip: string | null; private_ip: string | null; region: string | null; zone: string | null; machine_type: string | null; os: string | null; tags: Record<string, string>; raw: any; host_id: number | null; host_name: string | null; agent_name: string | null; seen_at: string }

const KIND_COLOR: Record<string, string> = { aws: "#FF9900", gce: "#4285F4", hyperv: "#A78BFA", esxi: "#94A3B8", azure: "#0EA5E9", proxmox: "#E57000" };
const KindIcon = ({ k }: { k: string }) => <span aria-hidden="true" className="inline-block h-3 w-3 shrink-0 rounded-[3px]" style={{ background: KIND_COLOR[k] ?? "#7F8BA6" }} />;
const CAP_JA: Record<string, string> = { inventory: "台帳のみ", ops: "台帳＋スナップショット・電源", isolate: "台帳＋電源＋ネットワーク隔離" };
const STATE_CLS = (s: string) => /running/.test(s) ? "bg-[#12301F] text-[#7FE0B0]" : /stop|terminated/.test(s) ? "bg-slate-700 text-slate-300" : "bg-[#3A2A10] text-[#FFC27A]";
const OB = "inline-flex items-center gap-1.5 rounded-lg border border-[#24314D] bg-transparent text-slate-100 hover:border-slate-500 disabled:opacity-50";
const DANGER = "inline-flex items-center gap-1.5 rounded-lg border border-[#4A1E24] bg-transparent text-[#FF9A9D] hover:bg-[#1A1014]";
const PHASE2 = ["hyperv", "esxi", "azure", "proxmox"];

export default function Cloud() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin"; const canAct = user?.role === "admin" || user?.role === "operator";
  const nav = useNavigate();
  const [providers, setProviders] = useState<Provider[]>([]); const [kinds, setKinds] = useState<Record<string, string>>({}); const [policies, setPolicies] = useState<any>(null);
  const [instances, setInstances] = useState<Inst[]>([]); const [hosts, setHosts] = useState<{ id: number; name: string }[]>([]);
  const [err, setErr] = useState(""); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState<string | null>(null);
  const [form, setForm] = useState<null | { id?: number; kind: string; name: string; capability: string; config: any; secret: any }>(null);
  const [filter, setFilter] = useState<number | "all">("all"); const [q, setQ] = useState("");
  const [showPolicy, setShowPolicy] = useState<string | null>(null);
  const [secretFor, setSecretFor] = useState<Provider | null>(null); const [secret, setSecret] = useState<any>({});
  const saveSecret = async () => { if (!secretFor) return; try { await api.put(`/cloud/providers/${secretFor.id}`, { secret }); setSecretFor(null); setSecret({}); setMsg(`${secretFor.name} の資格情報を保存しました（暗号化・再表示不可）。接続テストを実行してください。`); await load(); } catch (e: any) { setErr(e.message); } };

  const load = async () => {
    setErr("");
    try {
      const p = await api.get<{ items: Provider[]; kinds: Record<string, string>; policies: any }>("/cloud/providers"); setProviders(p.items); setKinds(p.kinds); setPolicies(p.policies);
      const i = await api.get<{ items: Inst[] }>("/cloud/instances"); setInstances(i.items);
      const h = await api.get<{ items: any[] }>("/hosts"); setHosts(h.items.map((x) => ({ id: x.id, name: x.name })));
    } catch (e: any) { setErr(e.message); }
  };
  useEffect(() => { load(); }, []);

  const save = async () => {
    if (!form) return; setErr("");
    try {
      const body: any = { kind: form.kind, name: form.name, capability: form.capability, config: form.config };
      if (form.secret && Object.values(form.secret).some((v) => v)) body.secret = form.secret;
      if (form.id) await api.put(`/cloud/providers/${form.id}`, body); else await api.post("/cloud/providers", body);
      setForm(null); await load();
    } catch (e: any) { setErr(e.message); }
  };
  const test = async (p: Provider) => { setBusy(`test-${p.id}`); try { const r = await api.post<{ ok: boolean; message: string }>(`/cloud/providers/${p.id}/test`); setMsg(`${p.name}: ${r.message}`); await load(); } catch (e: any) { setErr(e.message); } finally { setBusy(null); } };
  const sync = async (p: Provider) => { setBusy(`sync-${p.id}`); try { const r = await api.post<{ count: number; linked: number }>(`/cloud/providers/${p.id}/sync`); setMsg(`${p.name}: ${r.count} 台を取得、${r.linked} 台を管理ホスト / エージェントに突合`); await load(); } catch (e: any) { setErr(e.message); } finally { setBusy(null); } };
  const del = async (p: Provider) => { if (!window.confirm(`${p.name} を削除します（台帳も消えます。クラウド側には何もしません）`)) return; await api.del(`/cloud/providers/${p.id}`); await load(); };
  const request = async (i: Inst, op: "snapshot" | "power" | "isolate", extra: any = {}) => {
    const reason = window.prompt(`${op === "snapshot" ? "スナップショット作成" : op === "power" ? `電源操作（${extra.power}）` : "ネットワーク隔離"}: ${i.name}\n理由（承認カードに表示）:`, ""); if (reason === null) return;
    try { const r = await api.post<{ approval_id: number }>(`/cloud/instances/${i.id}/request`, { op, reason, ...extra }); setMsg(`承認 #${r.approval_id} を作成しました。承認キューで承認すると実行されます。`); }
    catch (e: any) { setErr(e.message); }
  };
  const link = async (i: Inst, host_id: number | null) => { await api.put(`/cloud/instances/${i.id}/link`, { host_id }); await load(); };

  const shown = useMemo(() => instances.filter((i) => (filter === "all" || i.provider_id === filter) && (!q || [i.name, i.external_id, i.public_ip, i.private_ip, i.host_name, i.agent_name, i.region, i.os].some((v) => String(v ?? "").toLowerCase().includes(q.toLowerCase())))), [instances, filter, q]);
  const capOf = (i: Inst) => providers.find((p) => p.id === i.provider_id)?.capability ?? "inventory";
  // AI 相談中は上の台帳・プロバイダを薄く畳んでチャットを広げる（手動で展開も可）
  const [chatActive, setChatActive] = useState(false); const [pinOpen, setPinOpen] = useState(false);
  const dim = chatActive && !pinOpen;

  return (
    <div className="flex flex-col gap-[18px]">
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="flex items-center gap-2 font-display text-2xl font-bold"><Ico d={I.cloud} size={22} className="text-teal-300" />クラウド管理</h1>
        <span className="flex-[1_1_360px] text-sm leading-relaxed text-slate-400">IaaS を登録すると、台帳の自動突合と、スナップショット / 電源 / 隔離を承認付きで AI と人間が実行できます。削除系の操作は存在しません。</span>
        {admin && <button className="btn-primary min-h-[40px] rounded-[10px] px-4 text-sm font-semibold" onClick={() => setForm({ kind: "aws", name: "", capability: "ops", config: { regions: ["ap-northeast-1"], use_ec2: true, use_lightsail: true }, secret: {} })}>＋ プロバイダを登録</button>}
      </header>
      {err && <div className="rounded-[10px] border border-[#4A1E24] bg-[#1A1014] px-3.5 py-2.5 text-sm text-[#FF9A9D]">{err}</div>}
      {msg && <div className="flex items-center gap-2 rounded-[10px] border border-teal-500 bg-[#1A2547] px-3.5 py-2.5 text-sm text-[#B9C6FF]"><span className="flex-1">{msg}</span>{/承認 #/.test(msg) && <button className={`${OB} min-h-[34px] px-3 text-xs`} onClick={() => nav("/approvals")}>承認キューへ</button>}<button className="min-h-[34px] px-2 text-xs text-slate-400 hover:text-slate-200" aria-label="閉じる" onClick={() => setMsg("")}>閉じる</button></div>}

      {dim && (
        <div className="flex flex-wrap items-center gap-3 rounded-[14px] border border-slate-700 bg-slate-800 px-4 py-2.5 text-[13px] text-slate-400 transition-all">
          <span>プロバイダ {providers.length} 件（{providers.map((p) => `${p.name}: ${p.status === "ok" ? "接続 OK" : p.status}`).join(" · ") || "なし"}）</span>
          <span>· 台帳 {instances.length} 台（running {instances.filter((i) => /running/.test(i.state)).length}）</span>
          <button className="ml-auto text-teal-300 hover:underline" onClick={() => setPinOpen(true)}>▾ 台帳を展開</button>
        </div>
      )}
      {/* providers */}
      <div className={`grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))] ${dim ? "hidden" : ""}`}>
        {providers.map((p) => (
          <article key={p.id} className={`flex flex-col gap-2.5 rounded-[14px] border bg-slate-800 p-4 ${p.status === "error" ? "border-[#4A1E24]" : "border-slate-700"}`}>
            <div className="flex items-center gap-3"><span aria-hidden="true" className="flex h-9 w-9 flex-none items-center justify-center rounded-[10px] text-white" style={{ background: KIND_COLOR[p.kind] ?? "#7F8BA6" }}><Ico d={I.cloud} size={18} className="" /></span><div className="min-w-0 flex-1"><div className="truncate text-[15px] font-semibold text-slate-100">{p.name}</div><div className="text-xs text-slate-400">{kinds[p.kind] ?? p.kind} · {CAP_JA[p.capability]}</div></div><span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-bold ${p.status === "ok" ? "bg-[#12301F] text-[#7FE0B0]" : p.status === "error" ? "bg-[#3A1418] text-[#FF9A9D]" : p.status === "needs_secret" || !p.has_secret ? "bg-[#3A2A10] text-[#FFC27A]" : "bg-slate-700 text-slate-300"}`}>{(p.status === "needs_secret" || !p.has_secret) && p.status !== "ok" && p.status !== "error" && <Ico d={I.key} size={12} className="" />}{p.status === "ok" ? "接続 OK" : p.status === "error" ? "エラー" : p.status === "needs_secret" || !p.has_secret ? "鍵が未入力" : "未テスト"}</span></div>
            <div className="text-[13px] text-slate-300">{p.kind === "aws" ? `リージョン: ${(p.config.regions ?? []).join(", ")} · ${[p.config.use_ec2 !== false && "EC2", p.config.use_lightsail !== false && "Lightsail"].filter(Boolean).join(" + ")}` : p.kind === "gce" ? `プロジェクト: ${p.config.project_id || "(サービスアカウントから)"}${p.config.zones?.length ? ` · ゾーン ${p.config.zones.join(", ")}` : ""}` : ""}</div>
            <div className="text-xs text-slate-400">台帳 {p.instances} 台{p.last_sync_at && ` · 同期 ${fmtTs(p.last_sync_at)}`}</div>
            {p.last_error && <div className="rounded-lg border border-[#4A1E24] bg-[#1A1014] px-2.5 py-2 text-xs text-[#FF9A9D]">{p.last_error}</div>}
            <div className="flex flex-wrap gap-1.5">
              {admin && !p.has_secret && <button className="btn-primary inline-flex min-h-[34px] items-center gap-1.5 rounded-lg px-3 text-xs font-semibold" onClick={() => { setSecretFor(p); setSecret({}); }}><Ico d={I.key} size={13} className="" />資格情報を入力</button>}
              {admin && <button className={`${OB} min-h-[34px] px-3 text-xs`} disabled={busy === `test-${p.id}` || !p.has_secret} onClick={() => test(p)}>{busy === `test-${p.id}` ? "テスト中…" : "接続テスト"}</button>}
              {canAct && <button className={`${OB} min-h-[34px] px-3 text-xs`} disabled={busy === `sync-${p.id}`} onClick={() => sync(p)}>{busy === `sync-${p.id}` ? "同期中…" : "↻ 台帳を同期"}</button>}
              {admin && <button className={`${OB} min-h-[34px] px-3 text-xs`} onClick={() => setForm({ id: p.id, kind: p.kind, name: p.name, capability: p.capability, config: p.config, secret: {} })}><Ico d={I.edit} size={13} className="" />編集</button>}
              <button className={`${OB} min-h-[34px] px-3 text-xs !text-teal-300 ${showPolicy === p.kind ? "!border-teal-500" : ""}`} aria-pressed={showPolicy === p.kind} onClick={() => setShowPolicy(showPolicy === p.kind ? null : p.kind)}><Ico d={I.lock} size={13} className="" />最小権限</button>
              {admin && <button className={`${DANGER} min-h-[34px] w-[34px] justify-center`} onClick={() => del(p)} aria-label={`${p.name} を削除`}><Ico d={I.trash} size={13} className="" /></button>}
            </div>
          </article>
        ))}
        {!providers.length && <div className="rounded-[14px] border border-slate-700 bg-slate-800 p-4 text-sm text-slate-400">まだプロバイダがありません。AWS（EC2 / Lightsail）と GCE から登録できます。</div>}
        <article className="flex flex-col justify-center gap-2 rounded-[14px] border border-dashed border-[#24314D] p-4">
          <div className="text-sm font-semibold text-slate-300">Hyper-V / ESXi / Azure / Proxmox</div>
          <div className="text-[13px] leading-relaxed text-slate-400">次のフェーズで追加します（EDR-78）。登録フォームでは「（次フェーズ）」として選べない状態で表示されます。</div>
        </article>
      </div>
      {providers.some((p) => !p.has_secret) && admin && !secretFor && <div className="flex flex-wrap items-center gap-2 rounded-[14px] border border-[#4A3A1E] bg-[#3A2A10]/60 px-4 py-3 text-sm text-[#FFC27A]"><Ico d={I.key} size={15} className="" /><span>資格情報が未入力のプロバイダがあります。キーはこのフォームから入力してください（AI チャットには貼らないでください）。</span>{providers.filter((p) => !p.has_secret).map((p) => <button key={p.id} className="btn-primary min-h-[34px] rounded-lg px-3 text-xs font-semibold" onClick={() => { setSecretFor(p); setSecret({}); }}>{p.name} の鍵を入力</button>)}</div>}
      {showPolicy && policies && <section aria-label="最小権限ポリシー" className="flex flex-col gap-2.5 rounded-[14px] border border-teal-500 bg-slate-800 p-4">
        <div className="flex flex-wrap items-center gap-2.5"><span className="flex-[1_1_360px] text-sm font-semibold text-slate-100">{showPolicy === "aws" ? "AWS: MamorAI 用 IAM ユーザーに付けるポリシー（Isolate の Statement は隔離を使わないなら外してください）" : "GCP: サービスアカウントに付けるロール"}</span><button className={`${OB} min-h-[34px] px-3 text-xs`} onClick={() => navigator.clipboard?.writeText(showPolicy === "aws" ? JSON.stringify(policies.aws_iam_policy, null, 2) : policies.gcp_roles.join("\n"))}>コピー</button><button className="min-h-[34px] px-2 text-[13px] text-slate-400 hover:text-slate-200" onClick={() => setShowPolicy(null)}>閉じる</button></div>
        <pre className="max-h-[260px] overflow-auto whitespace-pre-wrap rounded-[10px] border border-slate-700 bg-[#070B15] px-3.5 py-3 font-mono text-xs leading-[1.7] text-[#D6DDF0]">{showPolicy === "aws" ? JSON.stringify(policies.aws_iam_policy, null, 2) : policies.gcp_roles.join("\n")}</pre>
      </section>}

      {/* instances */}
      <section aria-labelledby="inv-h" className={`flex flex-col gap-3 rounded-2xl border border-slate-700 bg-slate-800 p-[18px] transition-opacity ${dim ? "hidden" : ""} ${chatActive && pinOpen ? "opacity-80" : ""}`}>
        <div className="flex flex-wrap items-center gap-2.5">
          <h2 id="inv-h" className="flex-[1_1_200px] text-[17px] font-semibold">台帳（インスタンス）</h2>
          {chatActive && pinOpen && <button className="text-xs text-slate-400 hover:text-slate-200" onClick={() => setPinOpen(false)}>▴ たたんでチャットを広げる</button>}
          <select aria-label="プロバイダで絞り込み" className="min-h-[36px] rounded-lg border border-[#24314D] bg-slate-900 px-2.5 text-[13px] text-slate-100" value={filter} onChange={(e) => setFilter(e.target.value === "all" ? "all" : Number(e.target.value))}><option value="all">すべてのプロバイダ</option>{providers.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
          <input aria-label="台帳を検索" className="min-h-[36px] min-w-[220px] rounded-lg border border-[#24314D] bg-slate-900 px-2.5 text-[13px] text-slate-100 placeholder:text-slate-500" placeholder="検索（名前・IP・ホスト・リージョン）" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="text-[13px] text-slate-400">{shown.length} 台</span>
        </div>
        {!shown.length ? <div className="py-6 text-center text-[13px] text-slate-400">台帳が空です。プロバイダの「台帳を同期」を押してください。</div> : (
          <div className="overflow-x-auto"><table className="w-full min-w-[980px] border-collapse text-[13px]"><thead><tr className="text-left text-xs text-slate-400"><th className="px-2.5 py-2 font-medium border-b border-[#24314D]">インスタンス</th><th className="px-2.5 py-2 font-medium border-b border-[#24314D]">状態</th><th className="px-2.5 py-2 font-medium border-b border-[#24314D]">IP</th><th className="px-2.5 py-2 font-medium border-b border-[#24314D]">場所</th><th className="px-2.5 py-2 font-medium border-b border-[#24314D]">管理ホスト / エージェント</th><th className="px-2.5 py-2 font-medium border-b border-[#24314D]">操作（承認付き）</th></tr></thead><tbody>
            {shown.map((i) => <tr key={i.id} className="border-b border-slate-700 align-top">
              <td className="px-2.5 py-3"><div className="flex items-center gap-2 font-mono font-semibold text-slate-100"><KindIcon k={i.provider_kind} />{i.name}</div><div className="mt-1 text-xs text-slate-400">{i.provider_name} · {i.service} · {i.external_id}{i.machine_type && ` · ${i.machine_type}`}{i.os && ` · ${i.os}`}</div></td>
              <td className="px-2.5 py-3"><span className={`rounded-full px-2.5 py-0.5 text-xs font-bold ${STATE_CLS(i.state)}`}>{i.state}</span></td>
              <td className="px-2.5 py-3 font-mono text-slate-100">{i.public_ip && <div>{i.public_ip}</div>}{i.private_ip && <div className="text-xs text-slate-400">{i.private_ip}</div>}</td>
              <td className="px-2.5 py-3 text-slate-100">{i.region}{i.zone && i.zone !== i.region && <div className="text-xs text-slate-400">{i.zone}</div>}</td>
              <td className="px-2.5 py-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  {i.host_name ? <button className="rounded-full bg-[#1A2547] px-2 py-px font-mono text-xs text-teal-300 hover:text-[#B9C6FF]" onClick={() => nav(`/hosts?host=${i.host_id}`)}>{i.host_name}</button> : <span className="text-xs text-slate-400">未登録</span>}
                  {i.agent_name && <span className="rounded-full bg-[#12301F] px-2 py-px text-xs text-[#7FE0B0]">agent {i.agent_name}</span>}
                  {canAct && <select aria-label={`${i.name} を管理ホストに紐づけ`} className="min-h-[30px] rounded-lg border border-[#24314D] bg-slate-900 px-1.5 text-xs text-slate-300" value={i.host_id ?? ""} onChange={(e) => link(i, e.target.value ? Number(e.target.value) : null)}><option value="">— 紐づけ —</option>{hosts.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}</select>}
                </div>
              </td>
              <td className="px-2.5 py-3">{canAct && capOf(i) !== "inventory" && <div className="flex flex-wrap gap-1.5">
                <button className={`${OB} min-h-[32px] px-2.5 text-xs`} onClick={() => request(i, "snapshot")}>スナップショット</button>
                <button className={`${OB} min-h-[32px] px-2.5 text-xs`} onClick={() => request(i, "power", { power: "reboot" })}>再起動</button>
                {/running/.test(i.state) ? <button className={`${OB} min-h-[32px] px-2.5 text-xs`} onClick={() => request(i, "power", { power: "stop" })}>停止</button> : <button className={`${OB} min-h-[32px] px-2.5 text-xs`} onClick={() => request(i, "power", { power: "start" })}>▶ 起動</button>}
                {admin && capOf(i) === "isolate" && <button className="inline-flex min-h-[32px] items-center rounded-lg border border-[#4A3A1E] bg-transparent px-2.5 text-xs text-[#FFC27A] hover:bg-[#3A2A10]" onClick={() => { const c = window.prompt("隔離後も SSH を許可する管理用 CIDR（カンマ区切り、空なら全遮断）", ""); if (c === null) return; request(i, "isolate", { allow_cidrs: c.split(",").map((x) => x.trim()).filter(Boolean) }); }}>隔離</button>}
              </div>}{capOf(i) === "inventory" && <span className="text-xs text-slate-400">台帳のみ</span>}</td>
            </tr>)}
          </tbody></table></div>
        )}
        <div className="text-xs text-slate-400">操作ボタンは承認カードを作るだけです。承認キューで承認すると実行されます。隔離は admin のみ・プロバイダの許可範囲が「台帳＋電源＋ネットワーク隔離」のときだけ表示されます。</div>
      </section>

      {/* AI 相談（常に一番下。相談が始まると上を畳んで広がる） */}
      <AiPanel onChanged={load} active={chatActive} compactAbove={dim} onActive={setChatActive} />

      {secretFor && <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" onClick={() => setSecretFor(null)}>
        <div role="dialog" aria-modal="true" className="flex w-full max-w-[520px] flex-col gap-3.5 rounded-2xl border border-teal-500 bg-slate-800 p-[22px]" onClick={(e) => e.stopPropagation()}>
          <h2 className="flex items-center gap-2 text-lg font-semibold"><Ico d={I.key} size={18} className="text-teal-300" />{secretFor.name} の資格情報</h2>
          <div className="text-[13px] leading-[1.7] text-slate-300">暗号化して保存され、画面にも AI にも二度と表示されません。MamorAI 専用の IAM ユーザー / サービスアカウントの鍵を使ってください。</div>
          {secretFor.kind === "aws" && <div className="grid gap-2 md:grid-cols-2">
            <Field label="アクセスキー ID"><input className="input font-mono" autoComplete="off" value={secret.access_key_id ?? ""} onChange={(e) => setSecret({ ...secret, access_key_id: e.target.value.trim() })} /></Field>
            <Field label="シークレットアクセスキー"><input className="input font-mono" type="password" autoComplete="new-password" value={secret.secret_access_key ?? ""} onChange={(e) => setSecret({ ...secret, secret_access_key: e.target.value.trim() })} /></Field>
          </div>}
          {secretFor.kind === "gce" && <Field label="サービスアカウントの JSON キー（ファイルの中身を貼る）"><textarea className="input h-36 font-mono text-[11px]" value={secret.service_account_json ?? ""} onChange={(e) => setSecret({ ...secret, service_account_json: e.target.value })} placeholder='{"type":"service_account", ...}' /></Field>}
          <div className="flex justify-end gap-2"><button className={`${OB} min-h-[40px] rounded-[10px] px-4 text-sm`} onClick={() => setSecretFor(null)}>キャンセル</button><button className="btn-primary min-h-[40px] rounded-[10px] px-4 text-sm font-semibold" disabled={!Object.values(secret).some((v) => v)} onClick={saveSecret}>保存</button></div>
        </div>
      </div>}
      {/* provider form */}
      {form && <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" onClick={() => setForm(null)}>
        <div role="dialog" aria-modal="true" className="flex w-full max-w-xl flex-col gap-3 rounded-2xl border border-teal-500 bg-slate-800 p-[22px]" onClick={(e) => e.stopPropagation()}>
          <h2 className="text-lg font-semibold">{form.id ? "プロバイダを編集" : "プロバイダを登録"}</h2>
          <div className="grid gap-2 md:grid-cols-2">
            <Field label="種類"><select className="input" value={form.kind} disabled={!!form.id} onChange={(e) => setForm({ ...form, kind: e.target.value, config: e.target.value === "aws" ? { regions: ["ap-northeast-1"], use_ec2: true, use_lightsail: true } : { project_id: "", zones: [] }, secret: {} })}>{Object.entries(kinds).map(([k, v]) => <option key={k} value={k} disabled={PHASE2.includes(k)}>{v}{PHASE2.includes(k) ? "（次フェーズ）" : ""}</option>)}</select></Field>
            <Field label="表示名"><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="例: AWS 本番 / GCP 本番" /></Field>
          </div>
          <Field label="MamorAI に許可する操作" hint="AI も人間もこの範囲を超える操作は依頼できません。隔離は admin の承認が必要です。"><select className="input" value={form.capability} onChange={(e) => setForm({ ...form, capability: e.target.value })}>{Object.entries(CAP_JA).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
          {form.kind === "aws" && <>
            <Field label="リージョン（カンマ区切り）"><input className="input" value={(form.config.regions ?? []).join(",")} onChange={(e) => setForm({ ...form, config: { ...form.config, regions: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) } })} placeholder="ap-northeast-1,us-east-1" /></Field>
            <div className="flex gap-4 text-xs text-slate-300"><label className="flex items-center gap-1"><input type="checkbox" checked={form.config.use_ec2 !== false} onChange={(e) => setForm({ ...form, config: { ...form.config, use_ec2: e.target.checked } })} /> EC2</label><label className="flex items-center gap-1"><input type="checkbox" checked={form.config.use_lightsail !== false} onChange={(e) => setForm({ ...form, config: { ...form.config, use_lightsail: e.target.checked } })} /> Lightsail</label></div>
            <div className="grid gap-2 md:grid-cols-2">
              <Field label={`アクセスキー ID${form.id ? "（変更時のみ）" : ""}`}><input className="input font-mono" autoComplete="off" value={form.secret.access_key_id ?? ""} onChange={(e) => setForm({ ...form, secret: { ...form.secret, access_key_id: e.target.value } })} /></Field>
              <Field label="シークレットアクセスキー"><input className="input font-mono" type="password" autoComplete="new-password" value={form.secret.secret_access_key ?? ""} onChange={(e) => setForm({ ...form, secret: { ...form.secret, secret_access_key: e.target.value } })} /></Field>
            </div>
            <div className="text-[11px] text-slate-500">MamorAI 専用の IAM ユーザーを作り、「最小権限」のポリシーだけを付けてください。キーは暗号化して保存され、画面には二度と表示されません。</div>
          </>}
          {form.kind === "gce" && <>
            <div className="grid gap-2 md:grid-cols-2">
              <Field label="プロジェクト ID（空ならサービスアカウントの値）"><input className="input" value={form.config.project_id ?? ""} onChange={(e) => setForm({ ...form, config: { ...form.config, project_id: e.target.value } })} /></Field>
              <Field label="ゾーン（空なら全ゾーン、カンマ区切り）"><input className="input" value={(form.config.zones ?? []).join(",")} onChange={(e) => setForm({ ...form, config: { ...form.config, zones: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) } })} placeholder="asia-northeast1-b" /></Field>
            </div>
            <Field label={`サービスアカウントの JSON キー${form.id ? "（変更時のみ）" : ""}`}><textarea className="input h-28 font-mono text-[11px]" value={form.secret.service_account_json ?? ""} onChange={(e) => setForm({ ...form, secret: { ...form.secret, service_account_json: e.target.value } })} placeholder='{"type":"service_account", ...}' /></Field>
          </>}
          <div className="flex justify-end gap-2"><button className={`${OB} min-h-[40px] rounded-[10px] px-4 text-sm`} onClick={() => setForm(null)}>キャンセル</button><button className="btn-primary min-h-[40px] rounded-[10px] px-4 text-sm font-semibold" disabled={!form.name} onClick={save}>{form.id ? "保存" : "登録"}</button></div>
        </div>
      </div>}
    </div>
  );
}


function AiPanel({ onChanged, active, compactAbove, onActive }: { onChanged: () => void; active: boolean; compactAbove: boolean; onActive: (v: boolean) => void }) {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin"; const chatOk = admin || user?.role === "operator"; const canAct = admin || user?.role === "operator";
  const [sessions, setSessions] = useState<(SessionRow & { label?: string | null })[]>([]); const [sid, setSid] = useState<number | null>(null); const [err, setErr] = useState(""); const [hist, setHist] = useState(false);
  const loadList = () => api.get<{ items: (SessionRow & { label?: string | null })[] }>("/sessions?limit=20&kind=cloud_setup").then((r) => setSessions(r.items)).catch(() => {});
  useEffect(() => { loadList(); }, []);
  const start = async (opts: { message?: string; title?: string }) => { setErr(""); try { const r = await api.post<{ id: number }>("/sessions", { kind: "cloud_setup", ...opts }); setSid(r.id); onActive(true); loadList(); } catch (e: any) { setErr(e.message); } };
  const create = async (text: string, attachments: PendingFile[]) => { const r = await api.post<{ id: number }>("/sessions", { kind: "cloud_setup", message: text.trim() || undefined, attachments: attachments.length ? attachments : undefined }); setSid(r.id); onActive(true); loadList(); return r.id; };
  const cur = sessions.find((s) => s.id === sid);
  const end = () => { setSid(null); onActive(false); };
  return (
    // 高さ: 上を畳んでいるときは画面に収まる最大（ヘッダー + サマリ行ぶんを引く）、台帳を展開中は控えめ。ブラウザからはみ出さない
    <section aria-label="AIエージェントに相談（クラウド管理）" className={`flex flex-col overflow-hidden rounded-2xl border border-[#24314D] bg-slate-800 transition-all ${active ? "min-h-[18rem]" : ""}`} style={{ height: active ? (compactAbove ? "calc(100vh - 9.5rem)" : "min(45vh, calc(100vh - 9.5rem))") : undefined, maxHeight: "calc(100vh - 7rem)" }}
      onFocusCapture={() => { if (!active) onActive(true); }}>
      <div className="flex flex-wrap items-center gap-2.5 border-b border-slate-700 px-4 py-3">
        <AgentTitle context="クラウド管理" />
        {cur && <><span className={`rounded-full px-2 py-px text-[11px] font-bold ${SESSION_STATUS_CLS[cur.status] ?? ""}`}>{SESSION_STATUS_JA[cur.status] ?? cur.status}</span><span className="truncate text-xs text-slate-400">#{cur.id} {cur.label || cur.title}</span></>}
        {!cur && !active && <span className="flex-[1_1_260px] text-xs text-slate-400">登録のガイド、台帳内のサーバーの点検・メンテ計画、スナップショット / 再起動の依頼、残タスクの登録（Action ボード）</span>}
        <div className="ml-auto flex flex-wrap gap-2">
          {chatOk && <button className={`${OB} min-h-[36px] px-3 text-[13px]`} onClick={() => start({ title: "AWS を登録（AI ガイド）", message: "AWS（Lightsail / EC2）を登録したい。最小権限の IAM ユーザーの作り方から案内して。" })}><KindIcon k="aws" />AWS を登録</button>}
          {chatOk && <button className={`${OB} min-h-[36px] px-3 text-[13px]`} onClick={() => start({ title: "GCE を登録（AI ガイド）", message: "Google Compute Engine を登録したい。サービスアカウントの作り方から案内して。" })}><KindIcon k="gce" />GCE を登録</button>}
          {canAct && <button className="btn-primary inline-flex min-h-[36px] items-center gap-1.5 rounded-lg px-3 text-[13px] font-semibold" onClick={() => start({})}><Ico d={I.chat} size={13} className="" />相談 / 対処</button>}
          <button className={`${OB} min-h-[36px] px-3 text-[13px]`} onClick={() => setHist(true)}><Ico d={I.history} size={13} className="" />履歴{sessions.length ? ` (${sessions.length})` : ""}</button>
          {active && <button className={`${OB} min-h-[36px] px-3 text-[13px]`} onClick={end} title="チャットを閉じて台帳を戻す">たたむ ▾</button>}
        </div>
      </div>
      {err && <div className="px-4 pt-2 text-xs text-[#FF9A9D]">{err}</div>}
      {hist && <SessionHistory kind="cloud_setup" title="クラウド管理の相談履歴" currentId={sid} canAct={!!chatOk} onOpen={(id) => { setSid(id); onActive(true); loadList(); }} onClose={() => setHist(false)} />}
      <SessionChat key={sid ?? "new"} sid={sid} create={create} showProposal={false} className={`flex-1 px-3 pb-2 pt-3 ${active ? "" : "max-h-28"}`} onEvent={(type, data) => { loadList(); if (type === "status" && /cloud provider changed/.test(data?.detail ?? "")) onChanged(); if (type === "tool_result" && ["register_cloud_provider", "update_cloud_provider", "test_cloud_provider", "sync_cloud_inventory", "link_cloud_instance", "cloud_list"].includes(data?.tool_call?.tool)) onChanged(); }}
        placeholder={sid ? "返信" : "例: web01 を再起動する前にスナップショットを取って / Lightsail 3 台の apt update 状況を見て / GCP のプロジェクトを追加"}
        emptyHint={active ? <AgentIntro compact lead={<>台帳のサーバーの点検・メンテ計画・パッチ当ての相談、クラウドの登録など、なんでもどうぞ。スナップショット・電源・隔離や設定変更は承認キューを通ります。あとに残る作業は、AI が Action ボードにタスクとして登録します。</>} examples={["Lightsail 3 台の状態と更新の有無を一覧にして", "再起動の前にスナップショットを取りたい", "今月のメンテナンス計画を立てて", "GCP のプロジェクトを追加したい"]} onPick={(t) => { create(t, []).catch((e) => setErr(e.message)); }} note="鍵そのものはチャットに貼らず、「資格情報を入力」フォームから入れてください。" /> : null} />
    </section>
  );
}
