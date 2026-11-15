/* EDR-130: agent packs — download dialog (host screen) and the settings tab */
import { useContext, useEffect, useState } from "react";
import { api, fmtTs } from "../lib/api";
import { UserCtx } from "../main";
import InfoTip from "./InfoTip";

const TS_TIP = "キーは最長 90 日で期限が切れます（Tailscale の仕様）。切れても、つながっている端末には影響しません。ただし、そのあとに作ったパックで入れる新しい端末は、ブラウザでの承認が必要になります。期限の 14 日前になったら、新しいキーを作って貼り替えてください（5 分ほど）。";
const TsTip = ({ align }: { align?: "left" | "right" }) => <InfoTip title="Tailscale の認証キーの期限" href="/help/tailscale-key" linkLabel="入れ替えの手順を見る" align={align}>{TS_TIP}</InfoTip>;

export interface PackInfo { rev: number | null; created_at: string | null; up_to_date: boolean; wazuh_version: string | null; addon_version: string | null; problems: string[]; files: string[]; history: { rev: number; created_at: string; reason: string; changes: string[] }[] }
export interface SecretStatus { tailscale: { set: boolean; hint: string | null; expires_at: string | null; days_left: number | null }; registration: { set: boolean }; updated_at: string | null }
export interface TsJoin { bridge: boolean; pending: boolean; result: { ok: boolean; ip?: string | null; error?: string | null; message?: string; at?: string } | null }
export interface PackOverview { settings: any; ssh_key: { id: number; name: string; fingerprint: string } | null; secrets: SecretStatus; packs: { windows: PackInfo; linux: PackInfo }; manager_tailscale?: TsJoin }

const CARD = "rounded-[14px] border border-slate-700 bg-slate-800 px-5 py-4";
const NOTE = "rounded-xl border border-slate-700 bg-slate-800 px-4 py-3 text-[13px] leading-[1.8] text-slate-300";
const BTN = "inline-flex min-h-[40px] items-center justify-center gap-1.5 rounded-[10px] px-4 text-sm transition disabled:cursor-not-allowed disabled:opacity-50";
const BTN_P = `${BTN} bg-teal-500 font-semibold text-white hover:bg-teal-400`;
const BTN_S = `${BTN} border border-slate-600 text-slate-100 hover:bg-slate-700`;
const INPUT = "w-full rounded-lg border border-slate-600 bg-slate-900 px-2.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-teal-400 focus:outline-none";
const ERR = "rounded-[10px] border border-[#6B2329] bg-[#2A1216] px-3.5 py-2.5 text-[13px] text-[#FF9A9D]";
const WARN = "rounded-[10px] border border-[#5A4A1A] bg-[#2A2410] px-3.5 py-2.5 text-[13px] text-[#F5C542]";
const OS_JA = { windows: "Windows", linux: "Linux" } as const;
const blocking = (p: string[]) => p.filter((x) => !x.startsWith("（注意）"));

export function usePackOverview(): [PackOverview | null, () => void, string] {
  const [o, setO] = useState<PackOverview | null>(null); const [err, setErr] = useState("");
  const load = () => { api.get<PackOverview>("/agent-pack").then((r) => { setO(r); setErr(""); }).catch((e) => setErr(e.message)); };
  useEffect(load, []);
  return [o, load, err];
}

/** small chip for a host: which pack revision it has, compared with the latest one */
export function PackRevChip({ rev, latest, same }: { rev: number | null | undefined; latest: number | null | undefined; same?: number[] }) {
  if (!rev) return null;
  const old = !!latest && rev < latest && !(same ?? []).includes(rev); // EDR-168: same content as the latest → not old
  return <span title={old ? `最新は r${latest}。パックを配り直すと更新されます` : rev !== latest && latest ? `中身は最新の r${latest} と同じです（配り直し不要）` : "最新のパック"} className={`rounded-full border px-2 py-px text-[11px] ${old ? "border-[#5A4A1A] text-[#F5C542]" : "border-slate-600 text-slate-300"}`}>パック r{rev}{old ? "（古い）" : ""}</span>;
}

async function download(os: "windows" | "linux", body: Record<string, unknown>): Promise<{ name: string; rev: string | null; sha: string | null; password: string | null }> {
  const res = await fetch(`/api/agent-pack/${os}/download`, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-Requested-With": "edr-console" }, body: JSON.stringify(body) });
  if (!res.ok) { let m = `${res.status}`; try { m = (await res.json()).error ?? m; } catch { /* not json */ } throw new Error(m); }
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") ?? ""; const name = cd.match(/filename="([^"]+)"/)?.[1] ?? `MamorAI-Agent-${os}.zip`;
  const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 10_000);
  return { name, rev: res.headers.get("X-Pack-Rev"), sha: res.headers.get("X-Pack-Sha256"), password: res.headers.get("X-Pack-Password") };
}

function saveText(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" })); const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 5_000);
}

function SecretLine({ os, settings, secrets }: { os: "windows" | "linux"; settings: any; secrets: SecretStatus }) {
  const usesTs = os === "windows" ? !!settings.manager.tailnet : !!settings.linux.tailscale;
  const ts = secrets.tailscale;
  return (
    <div className="flex flex-col gap-1 rounded-[10px] border border-slate-700 bg-slate-900 px-3 py-2.5 text-[13px] text-slate-300">
      <div className="text-xs text-slate-400">自動で入る秘密情報（zip は暗号化されます）</div>
      {usesTs && <div>Tailscale の認証キー<TsTip />: {ts.set ? <span className="text-[#3CCB8C]">入ります（{ts.hint}{ts.expires_at ? ` · ${fmtTs(ts.expires_at).split(" ")[0]} まで` : ""}）</span> : <span className="text-[#F5C542]">未登録（端末でブラウザログインになります）</span>}</div>}
      <div>Wazuh の登録パスワード: {secrets.registration.set ? <span className="text-[#3CCB8C]">入ります</span> : <span className="text-[#F5C542]">未登録（新規インストールの途中で入力）</span>}</div>
      {(!secrets.registration.set || (usesTs && !ts.set)) && <a className="text-xs text-teal-300 hover:underline" href="/settings/agentpack">設定 › エージェントパック › 秘密情報 で登録</a>}
    </div>
  );
}

function PackCard({ os, p, settings, secrets }: { os: "windows" | "linux"; p: PackInfo; settings: any; secrets: SecretStatus }) {
  const [offline, setOffline] = useState(false);
  const [busy, setBusy] = useState(false); const [err, setErr] = useState(""); const [done, setDone] = useState<{ name: string; sha: string | null; password: string | null } | null>(null); const [copied, setCopied] = useState(false);
  const bl = blocking(p.problems);
  const go = async () => {
    setBusy(true); setErr(""); setDone(null); setCopied(false);
    try { setDone(await download(os, { offline: os === "windows" ? offline : undefined })); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const copy = async () => { if (!done?.password) return; try { await navigator.clipboard.writeText(done.password); setCopied(true); } catch { /* clipboard blocked */ } };
  return (
    <section aria-label={`${OS_JA[os]} 用パック`} className={`${CARD} flex min-w-0 flex-1 basis-[340px] flex-col gap-3`}>
      <div className="flex flex-wrap items-baseline gap-2"><span className="text-[17px] font-bold">{OS_JA[os]}</span>{p.rev ? <span className="font-mono text-[15px] text-teal-300">r{p.rev}</span> : <span className="text-sm text-slate-500">未作成</span>}{p.created_at && <span className="text-xs text-slate-400">{fmtTs(p.created_at)} 更新</span>}</div>
      <div className="text-[13px] leading-relaxed text-slate-300">
        Wazuh エージェント {p.wazuh_version ?? "?"}{os === "windows" && <> · アドオン {p.addon_version ? `v${p.addon_version}` : <span className="text-[#F5C542]">なし</span>} · Sysmon {settings.windows.sysmon ? "あり" : "なし"}</>}{os === "linux" && <> · auditd {settings.linux.auditd ? "あり" : "なし"} · MamorAI 用 SSH {settings.linux.ssh.offer ? "選択式" : "なし"}</>}
        <br />manager: <span className="font-mono">{[settings.manager.lan, settings.manager.tailnet, settings.manager.public].filter(Boolean).join(" / ") || "-"}</span>
      </div>
      {p.history[0] && <div className="text-xs text-slate-400">この版の変更: {p.history[0].changes.join("、")}</div>}
      {p.problems.map((x) => <div key={x} className={x.startsWith("（注意）") ? WARN : ERR}>{x.replace("（注意）", "")}{x.includes("Tailscale の認証キー") && <TsTip />}</div>)}
      <SecretLine os={os} settings={settings} secrets={secrets} />
      {os === "windows" && <label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" checked={offline} onChange={(e) => setOffline(e.target.checked)} />オフライン版（Wazuh エージェントと Sysmon を同梱。インターネットに出られない端末用、約 10 MB）</label>}
      {err && <div className={ERR}>{err}</div>}
      {done && <div className="flex flex-col gap-2 rounded-[10px] border border-teal-700 bg-[#0E2230] px-3 py-2.5 text-[13px]">
        <div className="text-[#3CCB8C]">{done.name} をダウンロードしました</div>
        {done.password ? <>
          <div className="text-slate-300">解凍パスワード（この画面にだけ表示します）</div>
          <div className="flex flex-wrap items-center gap-2"><code className="select-all rounded-md bg-[#070B15] px-2.5 py-1.5 font-mono text-[15px] tracking-wide text-slate-100">{done.password}</code>
            <button className={BTN_S} onClick={copy}>{copied ? "コピーしました" : "コピー"}</button>
            <button className={BTN_S} onClick={() => saveText(done.name.replace(/\.zip$/, "-PASSWORD.txt"), `${done.name}\r\npassword: ${done.password}\r\n`)}>テキストで保存</button></div>
          <div className="text-xs text-slate-400">エクスプローラーの「すべて展開」/ unzip でこのパスワードを入れます。インストールが終わると、展開したフォルダと zip は自動で消えます。</div>
        </> : <div className="text-xs text-slate-400">秘密情報が入っていないので、暗号化していません。</div>}
        {done.sha && <span className="break-all font-mono text-[11px] text-slate-500">SHA-256 {done.sha}</span>}
      </div>}
      <div className="flex flex-wrap items-center gap-2">
        <button className={BTN_P} disabled={busy || !!bl.length} onClick={go}>{busy ? "作成中…" : `${OS_JA[os]} 用パックをダウンロード`}</button>
        <span className="text-xs text-slate-500">{os === "windows" ? "解凍して Install-EdrAgent.bat をダブルクリック。GPO が無くても、共有フォルダから -Mode update -Unattended で配れます" : "解凍して sudo ./install-edr-agent-linux.sh（--mode update --yes で無人実行）"}</span>
      </div>
      {p.history.length > 1 && <details className="text-xs text-slate-400"><summary className="cursor-pointer">版の履歴</summary><ul className="mt-1.5 flex flex-col gap-1">{p.history.map((h) => <li key={h.rev}><span className="font-mono text-slate-300">r{h.rev}</span> {fmtTs(h.created_at)} — {h.changes.join("、")}</li>)}</ul></details>}
    </section>
  );
}

/** EDR-169: Windows add-on per host +「全てのエージェントを更新」(no approval card: signed, same certificate, self-test, rollback) */
interface AddonStatus { published: string | null; bulk_running: boolean; pack: { latest: number | null; addon_only: number[]; remote: { bridge: boolean; pending: boolean; published_rev: number | null; ok: boolean | null; message: string | null }; bulk_running: boolean }; hosts: { id: number; name: string; version: string | null; checked_at: string | null; pack_rev: number | null; last: { id: number; status: string; target: string | null; at: string; note: string | null } | null; last_pack: { id: number; status: string; rev: number | null; at: string; note: string | null } | null }[] }
const vGt = (a: string, b: string) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0); } return false; };
export function AddonUpdateSection() {
  const { user } = useContext(UserCtx); const canAct = user?.role === "admin" || user?.role === "operator";
  const [a, setA] = useState<AddonStatus | null>(null); const [err, setErr] = useState(""); const [msg, setMsg] = useState(""); const [busy, setBusy] = useState(false);
  const load = () => api.get<AddonStatus>("/agent-pack/addon").then((r) => { setA(r); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const running = !!a && (a.bulk_running || a.pack.bulk_running || a.hosts.some((h) => h.last?.status === "running" || h.last_pack?.status === "running"));
  useEffect(() => { if (!running) return; const t = setInterval(load, 5000); return () => clearInterval(t); }, [running]);
  if (!a) return err ? <div className={ERR}>{err}</div> : null;
  const pub = a.published;
  const state = (h: AddonStatus["hosts"][number]) => {
    if (h.last?.status === "running") return { t: `更新中${h.last.note ? `（${h.last.note}）` : ""}`, c: "text-sky-300" };
    if (!h.version) return { t: "版を未確認", c: "text-slate-400" };
    if (pub && !vGt(pub, h.version)) return { t: "最新", c: "text-emerald-300" };
    if (vGt("1.3.0", h.version)) return { t: "パックの入れ直しが必要（1.3.0 より前は自動更新できません）", c: "text-[#F5C542]" };
    if (h.last?.status === "failed" && h.last.target === pub) return { t: `前回失敗: ${h.last.note ?? ""}`, c: "text-[#FF9A9D]" };
    return { t: `v${pub} に更新できます`, c: "text-[#F5C542]" };
  };
  const targets = a.hosts.filter((h) => pub && (!h.version || (vGt(pub, h.version) && !vGt("1.3.0", h.version))));
  const L = a.pack.latest;
  const packOld = (h: AddonStatus["hosts"][number]) => !!L && !!h.pack_rev && h.pack_rev < L && !(a.pack.addon_only.includes(h.pack_rev) && !!pub && !!h.version && !vGt(pub, h.version));
  const packState = (h: AddonStatus["hosts"][number]) => {
    if (h.last_pack?.status === "running") return { t: `更新中${h.last_pack.note ? `（${h.last_pack.note}）` : ""}`, c: "text-sky-300" };
    if (!h.pack_rev) return { t: "不明", c: "text-slate-400" };
    if (!packOld(h)) return { t: "最新", c: "text-emerald-300" };
    if (h.version && vGt("1.3.0", h.version)) return { t: "手で入れ直しが必要", c: "text-[#F5C542]" };
    if (h.last_pack?.status === "failed" && h.last_pack.rev === L) return { t: `前回失敗: ${h.last_pack.note ?? ""}`, c: "text-[#FF9A9D]" };
    return { t: `r${L} に更新できます`, c: "text-[#F5C542]" };
  };
  const packTargets = a.hosts.filter((h) => packOld(h) && !(h.version && vGt("1.3.0", h.version)));
  const rm = a.pack.remote;
  const runPackAll = async () => {
    if (!confirm(`古いパックの端末 ${packTargets.length} 台を r${L} に更新します（2 台ずつ）。\n各端末でインストーラーの更新モードが動き、最後に Wazuh エージェントが数十秒再起動します。アドオンが古い端末は先にアドオンを更新します。よろしいですか？`)) return;
    setBusy(true); setMsg("");
    try { const r = await api.post<{ queued: string[]; skipped: { name: string; reason: string }[] }>("/agent-pack/windows/update-all", {}); setMsg(`${r.queued.length} 台のパック更新を始めました${r.skipped.length ? `（対象外: ${r.skipped.map((x) => `${x.name} ${x.reason}`).join(", ")}）` : ""}`); load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  };
  const runAll = async () => {
    if (!confirm(`Windows の自動対処アドオンを v${pub} に更新します（対象 ${targets.length} 台、3 台ずつ）。\n各端末で署名と中身を確認してから入れ替え、失敗したら元に戻します。よろしいですか？`)) return;
    setBusy(true); setMsg("");
    try { const r = await api.post<{ queued: string[]; skipped: { name: string; reason: string }[] }>("/agent-pack/addon/update-all", {}); setMsg(`${r.queued.length} 台の更新を始めました${r.skipped.length ? `（対象外 ${r.skipped.length} 台: ${r.skipped.map((x) => x.name).join(", ")}）` : ""}`); load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  };
  return (
    <section aria-label="Windows 端末のリモート更新" className={`${CARD} flex flex-col gap-3`}>
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="m-0 text-base font-bold">Windows 端末のリモート更新</h3>
        <span className="text-xs text-slate-400">パック r{L ?? "-"}（共有フォルダ {rm.published_rev ? `r${rm.published_rev}` : "未配置"}{rm.pending ? "・配置中" : ""}）／ アドオン {pub ? `v${pub}` : "なし"}</span>
        {canAct && <span className="ml-auto flex flex-wrap gap-2">
          {pub && <button className={BTN_S} disabled={busy || running || !targets.length} onClick={runAll}>{targets.length ? `全てのエージェントを更新（アドオン ${targets.length} 台）` : "アドオンは全て最新"}</button>}
          {L && <button className={BTN_P} disabled={busy || running || !packTargets.length || rm.published_rev !== L} title={rm.published_rev !== L ? "共有フォルダにパックを置いているところです（1〜2 分）" : undefined} onClick={runPackAll}>{running ? "更新中…" : packTargets.length ? `古いパックを全部更新（${packTargets.length} 台）` : "パックは全て最新"}</button>}
        </span>}
      </div>
      <div className="text-xs leading-relaxed text-slate-400">承認カードは使いません。どちらも Wazuh の共有フォルダ経由で、端末が「ハッシュ一致・今のアドオンと同じ証明書の署名」を確かめてから実行します。パックの更新はインストーラーの更新モード（登録はそのまま。Wazuh エージェントが古ければ上げ、最後に数十秒再起動）。登録パスワードと Tailscale キーは共有フォルダに置きません。電源が切れている端末は失敗になるので、あとでもう一度押してください。</div>
      {!rm.bridge && <div className={WARN}>ホストブリッジ（installer/modules/62-host-bridge.sh）が無いため、パックを共有フォルダに置けません。アドオンの更新だけ使えます。</div>}
      {rm.ok === false && rm.message && <div className={ERR}>共有フォルダへの配置に失敗: {rm.message}</div>}
      {msg && <div className="text-[13px] text-teal-200">{msg}</div>}
      {err && <div className={ERR}>{err}</div>}
      <div className="overflow-x-auto">
        <table className="w-full text-[13px]">
          <thead><tr className="text-left text-xs text-slate-500"><th className="py-1 pr-3 font-normal">ホスト</th><th className="py-1 pr-3 font-normal">パック</th><th className="py-1 pr-3 font-normal">パックの状態</th><th className="py-1 pr-3 font-normal">アドオン</th><th className="py-1 font-normal">アドオンの状態</th></tr></thead>
          <tbody>{a.hosts.map((h) => { const s = state(h); const ps = packState(h); return <tr key={h.id} className="border-t border-slate-700/60"><td className="py-1.5 pr-3">{h.name}</td><td className="py-1.5 pr-3 font-mono text-xs">{h.pack_rev ? `r${h.pack_rev}` : "—"}</td><td className={`py-1.5 pr-3 ${ps.c}`}>{ps.t}</td><td className="py-1.5 pr-3 font-mono text-xs">{h.version ? `v${h.version}` : "—"}</td><td className={`py-1.5 ${s.c}`}>{s.t}</td></tr>; })}</tbody>
        </table>
      </div>
    </section>
  );
}

export function AgentPackDialog({ onClose }: { onClose: () => void }) {
  const [o, load, err] = usePackOverview();
  return (
    <div role="dialog" aria-modal="true" aria-label="エージェントパック" className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4" onClick={onClose}>
      <div className="mt-10 flex w-full max-w-[1100px] flex-col gap-3.5 rounded-2xl border border-slate-700 bg-[#0D1428] p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3"><h2 className="m-0 text-[20px] font-bold">エージェントパック</h2><button className={`${BTN_S} ml-auto`} onClick={load}>再読み込み</button><button className={BTN_S} onClick={onClose}>閉じる</button></div>
        <div className={NOTE}>端末に Wazuh エージェントと MamorAI のアドオンを入れるための一式です。新しい端末にはインストール、すでに入っている端末には更新として、同じパックを使えます（インストーラーが選びます）。MamorAI 側の設定やアドオンが変わると、パックは自動で新しい版（rN）になります。中身は <a className="text-teal-300 hover:underline" href="/settings/agentpack">設定 › エージェントパック</a> で変えられます。</div>
        {err && <div className={ERR}>{err}</div>}
        {!o ? <div className="text-sm text-slate-500">読み込み中…</div> : <div className="flex flex-wrap gap-3.5">{(["windows", "linux"] as const).map((os) => <PackCard key={os} os={os} p={o.packs[os]} settings={o.settings} secrets={o.secrets} />)}</div>}
        <AddonUpdateSection />
      </div>
    </div>
  );
}

/* ---- settings tab ---- */
function Field({ label, hint, children }: { label: React.ReactNode; hint?: string; children: React.ReactNode }) { return <div className="min-w-0"><label className="mb-1 block text-xs text-slate-400">{label}</label>{children}{hint && <div className="mt-1 text-[11px] text-slate-500">{hint}</div>}</div>; }

export function AgentPackSettings() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [o, load, err0] = usePackOverview();
  const [s, setS] = useState<any>(null); const [err, setErr] = useState(""); const [ok, setOk] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { if (o) setS(JSON.parse(JSON.stringify(o.settings))); }, [o]);
  if (!o || !s) return <div className={NOTE}>{err0 || "読み込み中…"}</div>;
  const up = (path: string[], v: any) => { const n = JSON.parse(JSON.stringify(s)); let c = n; for (const k of path.slice(0, -1)) c = c[k]; c[path[path.length - 1]] = v; setS(n); setOk(""); };
  const save = async () => {
    setBusy(true); setErr(""); setOk("");
    try {
      const body = { ...s, linux: { ...s.linux, ssh: { ...s.linux.ssh, allow_from: String(s.linux.ssh.allow_from_text ?? s.linux.ssh.allow_from.join(", ")).split(/[,\s]+/).map((x: string) => x.trim()).filter(Boolean) } } };
      delete body.linux.ssh.allow_from_text;
      const r = await api.put<any>("/agent-pack/settings", body);
      const made = Object.entries(r.refreshed ?? {}).filter(([, v]: any) => v.created).map(([k, v]: any) => `${OS_JA[k as "windows"]} r${v.rev}`);
      setOk(made.length ? `保存しました。新しい版: ${made.join("、")}` : "保存しました（パックの中身は変わっていません）"); load();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const fromSuggest = [s.manager.lan, s.manager.tailnet].filter(Boolean);
  return (
    <div className="flex flex-col gap-3.5">
      <div className={NOTE}>ホスト管理画面の「エージェントパック」に入る中身です。保存すると、変わった OS のパックが新しい版になります。登録パスワードや Tailscale のキーはここには保存しません（ダウンロードするときに、必要なら入れます）。</div>
      {(err || err0) && <div className={ERR}>{err || err0}</div>}
      <AddonUpdateSection />
      <SecretsSection o={o} admin={admin} onSaved={load} />
      <section aria-label="manager" className={`${CARD} flex flex-col gap-3`}>
        <div className="text-[15px] font-semibold">Wazuh manager（エージェントの接続先）</div>
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="LAN のアドレス" hint="社内 / 自宅の LAN から"><input className={INPUT} disabled={!admin} value={s.manager.lan} onChange={(e) => up(["manager", "lan"], e.target.value)} placeholder="10.20.30.10" /></Field>
          <Field label="Tailscale のアドレス" hint="使わないなら空のまま"><input className={INPUT} disabled={!admin} value={s.manager.tailnet} onChange={(e) => up(["manager", "tailnet"], e.target.value)} placeholder="100.x.y.z" /></Field>
          <Field label="インターネットからのアドレス" hint="公開している場合だけ（DNS 名も可）"><input className={INPUT} disabled={!admin} value={s.manager.public} onChange={(e) => up(["manager", "public"], e.target.value)} placeholder="wazuh.example.com" /></Field>
        </div>
        <Field label="Wazuh エージェントの版" hint={`auto = manager と同じ版（今は ${o.packs.windows.wazuh_version ?? "取得できません"}）。エージェントは manager より新しくできません`}><input className={`${INPUT} w-48`} disabled={!admin} value={s.wazuh_version} onChange={(e) => up(["wazuh_version"], e.target.value)} placeholder="auto" /></Field>
      </section>
      <section aria-label="Windows" className={`${CARD} flex flex-col gap-3`}>
        <div className="text-[15px] font-semibold">Windows</div>
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="グループ（ノート PC）" hint="Wazuh のエージェントグループ。カンマ区切りで複数"><input className={INPUT} disabled={!admin} value={s.windows.group_laptop} onChange={(e) => up(["windows", "group_laptop"], e.target.value)} /></Field>
          <Field label="グループ（デスクトップ）"><input className={INPUT} disabled={!admin} value={s.windows.group_desktop} onChange={(e) => up(["windows", "group_desktop"], e.target.value)} /></Field>
          <Field label="端末の種類"><select className={INPUT} disabled={!admin} value={s.windows.device_type} onChange={(e) => up(["windows", "device_type"], e.target.value)}><option value="ask">インストール時に聞く</option><option value="laptop">すべてノート PC</option><option value="desktop">すべてデスクトップ</option></select></Field>
        </div>
        <label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" disabled={!admin} checked={s.windows.sysmon} onChange={(e) => up(["windows", "sysmon"], e.target.checked)} />Sysmon を入れる（プロセスの起動・通信を記録。EDR として推奨）</label>
        <Field label="Sysmon の設定ファイル（URL）"><input className={INPUT} disabled={!admin || !s.windows.sysmon} value={s.windows.sysmon_config_url} onChange={(e) => up(["windows", "sysmon_config_url"], e.target.value)} /></Field>
        <div className="text-xs text-slate-400">MamorAI アドオン: {o.packs.windows.addon_version ? `v${o.packs.windows.addon_version}（自動で同梱）` : "見つかりません（installer/windows/build-addon.sh --out ./addon で作ると、自動で同梱されます）"}</div>
      </section>
      <section aria-label="Linux" className={`${CARD} flex flex-col gap-3`}>
        <div className="text-[15px] font-semibold">Linux</div>
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="グループ"><input className={INPUT} disabled={!admin} value={s.linux.group} onChange={(e) => up(["linux", "group"], e.target.value)} /></Field>
          <Field label="Docker の監視（docker-listener）"><select className={INPUT} disabled={!admin} value={s.linux.docker} onChange={(e) => up(["linux", "docker"], e.target.value)}><option value="auto">Docker があれば有効</option><option value="yes">常に有効</option><option value="no">使わない</option></select></Field>
        </div>
        <label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" disabled={!admin} checked={s.linux.tailscale} onChange={(e) => up(["linux", "tailscale"], e.target.checked)} />Tailscale 経由でつなぐ（クラウドのサーバーなど、LAN の外にあるとき）</label>
        <label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" disabled={!admin} checked={s.linux.auditd} onChange={(e) => up(["linux", "auditd"], e.target.checked)} />auditd を入れる（ログインユーザーのコマンド実行を記録。プロセスツリーに使う）</label>
        <div className="flex flex-col gap-2.5 rounded-[10px] border border-slate-700 bg-slate-900 px-3 py-2.5">
          <label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" disabled={!admin} checked={s.linux.ssh.offer} onChange={(e) => up(["linux", "ssh", "offer"], e.target.checked)} />「MamorAI から操作できるようにする」をインストール時に選べるようにする（既定の答えは「いいえ」）</label>
          {s.linux.ssh.offer && <div className="grid gap-3 md:grid-cols-3">
            <Field label="ユーザー名"><input className={INPUT} disabled={!admin} value={s.linux.ssh.user} onChange={(e) => up(["linux", "ssh", "user"], e.target.value)} /></Field>
            <Field label="sudo" hint="なし = スキャンは一般ユーザーで読める範囲だけ。遮断操作は使えません"><select className={INPUT} disabled={!admin} value={s.linux.ssh.sudo} onChange={(e) => up(["linux", "ssh", "sudo"], e.target.value)}><option value="full">あり（スキャン＋遮断操作）</option><option value="none">なし（読み取りだけ）</option></select></Field>
            <Field label="MamorAI の接続元アドレス（必須）" hint={fromSuggest.length ? `MamorAI が manager と同じサーバーなら: ${fromSuggest.join(", ")}` : "authorized_keys の from= に入ります"}><input className={INPUT} disabled={!admin} value={s.linux.ssh.allow_from_text ?? s.linux.ssh.allow_from.join(", ")} onChange={(e) => up(["linux", "ssh", "allow_from_text"], e.target.value)} placeholder="10.20.30.10, 100.x.y.z" /></Field>
          </div>}
          {s.linux.ssh.offer && <div className="text-xs text-slate-400">鍵: {o.ssh_key ? <>#{o.ssh_key.id} {o.ssh_key.name} <span className="font-mono">{o.ssh_key.fingerprint}</span></> : "保存すると専用の鍵を作ります"}。サーバーに入れたあと、ホスト画面でそのサーバーを開いて「パックで準備した SSH を使う」を押してください。</div>}
        </div>
      </section>
      {admin && <div className="flex items-center gap-3"><button className={BTN_P} disabled={busy} onClick={save}>保存</button>{ok && <span className="text-[13px] text-[#3CCB8C]">{ok}</span>}</div>}
    </div>
  );
}

/* EDR-137: Tailscale auth key / enrollment password kept by MamorAI (write-only) */
/** EDR-149: the MamorAI server itself joins the tailnet with the stored key (host bridge, installer module 62) */
function ManagerJoin({ o, admin, onChanged }: { o: PackOverview; admin: boolean; onChanged: () => void }) {
  const [j, setJ] = useState<TsJoin | undefined>(o.manager_tailscale); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  useEffect(() => { setJ(o.manager_tailscale); }, [o.manager_tailscale]);
  // poll while the host is working on it
  useEffect(() => {
    if (!j?.pending) return;
    const t = setInterval(() => api.get<TsJoin>("/agent-pack/tailscale-join").then((x) => { setJ(x); if (!x.pending) onChanged(); }).catch(() => {}), 3000);
    return () => clearInterval(t);
  }, [j?.pending]);
  if (!j?.bridge && !o.settings?.manager?.tailnet) return null;
  const retry = async () => { setBusy(true); setErr(""); try { setJ(await api.post<TsJoin>("/agent-pack/tailscale-join", {})); } catch (e: any) { setErr(e.message); } finally { setBusy(false); } };
  const tip = o.settings?.manager?.tailnet as string | undefined;
  let line: React.ReactNode;
  if (j?.pending) line = <span className="text-[#F5D98A]">⏳ このサーバーを Tailscale に参加させています…</span>;
  else if (j?.result?.ok || tip) line = <span className="text-[#3CCB8C]">✔ このサーバー（MamorAI / Wazuh manager）は Tailscale に参加しています{(j?.result?.ip || tip) ? `（${j?.result?.ip || tip}）` : ""}。パックの接続先にも入っています</span>;
  else if (j?.result && !j.result.ok) line = <span className="text-[#FF9A9D]">✘ Tailscale への参加に失敗しました: {j.result.error ?? j.result.message}</span>;
  else line = <span className="text-slate-400">このサーバーはまだ Tailscale に参加していません。キーを保存すると参加します</span>;
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-[10px] border border-slate-700 bg-slate-900/60 px-3 py-2 text-[13px]">
      {line}
      {admin && j?.bridge && o.secrets.tailscale.set && !j.pending && !(j.result?.ok || tip) && <button className={BTN_S} disabled={busy} onClick={retry}>もう一度参加させる</button>}
      {err && <span className="text-[#FF9A9D]">{err}</span>}
    </div>
  );
}

function SecretsSection({ o, admin, onSaved }: { o: PackOverview; admin: boolean; onSaved: () => void }) {
  const [ts, setTs] = useState(""); const [exp, setExp] = useState(o.secrets.tailscale.expires_at ? o.secrets.tailscale.expires_at.slice(0, 10) : ""); const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false); const [err, setErr] = useState(""); const [ok, setOk] = useState("");
  const send = async (body: Record<string, unknown>, msg: string) => {
    setBusy(true); setErr(""); setOk("");
    try { await api.put("/agent-pack/secrets", body); setTs(""); setPw(""); setOk(msg); onSaved(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const st = o.secrets;
  const expIso = exp ? new Date(`${exp}T23:59:59`).toISOString() : null;
  return (
    <section aria-label="秘密情報" className={`${CARD} flex flex-col gap-3`}>
      <div className="text-[15px] font-semibold">秘密情報（パックに自動で入ります）</div>
      <div className="text-xs leading-relaxed text-slate-400">MamorAI の中に暗号化して保存します。画面には表示しません。DL したパックは暗号化 ZIP になり、端末でインストールが終わると展開したデータは自動で消えます。キーを入れ替えると、パックは自動で新しい版になります。</div>
      {err && <div className={ERR}>{err}</div>}
      <div className="grid gap-3 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_auto] md:items-end">
        <Field label={<>Tailscale の認証キー（今: {st.tailscale.set ? st.tailscale.hint : "未登録"}）<TsTip /></>} hint="Tailscale の管理画面 › Settings › Keys で「Reusable」をオンにして発行したもの"><input className={INPUT} type="password" autoComplete="off" disabled={!admin} value={ts} onChange={(e) => setTs(e.target.value)} placeholder="tskey-auth-…" /></Field>
        <Field label="キーの有効期限" hint={st.tailscale.days_left !== null ? (st.tailscale.days_left < 0 ? "期限切れです。新しいキーに替えてください" : `あと ${st.tailscale.days_left} 日${st.tailscale.days_left <= 14 ? "（そろそろ入れ替えてください）" : ""}`) : "期限を入れると、14 日前から知らせます"}><input className={INPUT} type="date" disabled={!admin} value={exp} onChange={(e) => setExp(e.target.value)} /></Field>
        {admin && <div className="flex gap-2"><button className={BTN_P} disabled={busy || (!ts && expIso === (st.tailscale.expires_at ? new Date(`${st.tailscale.expires_at.slice(0, 10)}T23:59:59`).toISOString() : null))} onClick={() => send({ ...(ts ? { tailscale_auth_key: ts.trim() } : {}), tailscale_expires_at: expIso }, ts && o.manager_tailscale?.bridge ? "Tailscale のキーを保存しました。このサーバーを Tailscale に参加させています" : "Tailscale のキーを保存しました")}>保存</button>{st.tailscale.set && <button className={BTN_S} disabled={busy} onClick={() => confirm("Tailscale のキーを消しますか？") && send({ tailscale_auth_key: null }, "消しました")}>消す</button>}</div>}
      </div>
      <ManagerJoin o={o} admin={admin} onChanged={onSaved} />
      <div className="grid gap-3 md:grid-cols-[minmax(0,2fr)_auto] md:items-end">
        <Field label={`Wazuh の登録パスワード（今: ${st.registration.set ? "登録済み" : "未登録"}）`} hint="manager の /var/ossec/etc/authd.pass と同じもの"><input className={INPUT} type="password" autoComplete="off" disabled={!admin} value={pw} onChange={(e) => setPw(e.target.value)} placeholder="登録パスワード" /></Field>
        {admin && <div className="flex gap-2"><button className={BTN_P} disabled={busy || !pw} onClick={() => send({ registration_password: pw }, "登録パスワードを保存しました")}>保存</button>{st.registration.set && <button className={BTN_S} disabled={busy} onClick={() => confirm("登録パスワードを消しますか？") && send({ registration_password: null }, "消しました")}>消す</button>}</div>}
      </div>
      {ok && <div className="text-[13px] text-[#3CCB8C]">{ok}</div>}
    </section>
  );
}
