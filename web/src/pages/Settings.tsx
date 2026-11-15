import { useContext, useEffect, useState } from "react";
import { NavLink, Routes, Route, Navigate } from "react-router-dom";
import { api, fmtTs } from "../lib/api";
import { t } from "../lib/i18n";
import { UserCtx } from "../main";
import { AgentPackSettings } from "../components/AgentPack";

/* ---- MamorAI デザイン v0.2（Settings.dc.html）の部品スタイル ---- */
const CARD = "rounded-[14px] border border-slate-700 bg-slate-800 px-5 py-4";
const EDIT_CARD = "rounded-[14px] border border-teal-500 bg-slate-800 px-5 py-[18px]";
const NOTE = "rounded-xl border border-slate-700 bg-slate-800 px-4 py-3 text-[13px] leading-[1.8] text-slate-300";
const BTN = "inline-flex min-h-[40px] items-center justify-center gap-1.5 rounded-[10px] px-4 text-sm transition disabled:cursor-not-allowed disabled:opacity-50";
const BTN_P = `${BTN} bg-teal-500 font-semibold text-white hover:bg-teal-400`;
const BTN_S = `${BTN} border border-slate-600 text-slate-100 hover:bg-slate-700`;
const BTN_D = `${BTN} border border-[#4A1E24] text-[#FF9A9D] hover:bg-[#2A1216]`;
const BTN_ADD = `${BTN} border border-dashed border-teal-500 text-teal-300 hover:bg-teal-500/10`;
const BTN_SM = "inline-flex min-h-[30px] items-center rounded-md border border-slate-600 px-2.5 text-xs text-slate-100 hover:bg-slate-700";
const INPUT = "w-full rounded-lg border border-slate-600 bg-slate-900 px-2.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-teal-400 focus:outline-none";
const TEXTAREA = `${INPUT} font-mono text-xs`;
const PRE = "m-0 whitespace-pre-wrap break-all rounded-[10px] border border-slate-700 bg-[#070B15] px-3 py-2.5 font-mono text-xs leading-relaxed text-[#D6DDF0]";
const ERR = "rounded-[10px] border border-[#6B2329] bg-[#2A1216] px-3.5 py-2.5 text-[13px] text-[#FF9A9D]";
const TH = "px-4 py-3 text-left text-xs font-medium text-slate-400";
const TD = "px-4 py-3 align-top";

function Tabs() {
  const tabs = [["account", "自分のアカウント"], ["wazuh", t("settings.wazuh")], ["keys", t("settings.keys")], ["protected", "保護アドレス"], ["sentinel", "Sentinel"], ["hostscan", "ホストスキャン"], ["agentpack", "エージェントパック"], ["users", t("settings.users")]];
  return (
    <div role="tablist" aria-label="設定の項目" className="flex flex-wrap gap-1 border-b border-slate-700">
      {tabs.map(([p, l]) => <NavLink key={p} to={p} role="tab" className={({ isActive }) => `-mb-px border-b-2 px-3.5 py-2.5 text-sm transition ${isActive ? "border-teal-300 font-semibold text-white" : "border-transparent text-slate-400 hover:text-slate-200"}`}>{l}</NavLink>)}
    </div>
  );
}

function useList<T>(path: string): [T[], () => Promise<void>] {
  const [items, setItems] = useState<T[]>([]);
  const reload = async () => { const r = await api.get<{ items: T[] }>(path); setItems(r.items); };
  useEffect(() => { reload(); }, [path]);
  return [items, reload];
}

function Field({ label, children }: { label: string; children: React.ReactNode }) { return <div className="min-w-0"><label className="mb-1 block text-xs text-slate-400">{label}</label>{children}</div>; }

// ---------------- Wazuh ----------------
function WazuhTab() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [items, reload] = useList<any>("/wazuh");
  const [edit, setEdit] = useState<any | null>(null); const [test, setTest] = useState<Record<number, any>>({}); const [err, setErr] = useState("");
  const blank = { name: "", indexer_url: "https://127.0.0.1:9200", indexer_user: "edr-console-ro", indexer_password: "", api_url: "https://127.0.0.1:55000", api_user: "edr-console-ro", api_password: "", ca_pem: "", tls_verify: true, notes: "" };
  const save = async () => {
    setErr("");
    try {
      const body: any = { ...edit }; if (!body.indexer_password) delete body.indexer_password; if (!body.api_password) delete body.api_password; if (!body.ca_pem) body.ca_pem = null;
      if (edit.id) await api.put(`/wazuh/${edit.id}`, body); else await api.post("/wazuh", body);
      setEdit(null); await reload();
    } catch (e: any) { setErr(e.message); }
  };
  const runTest = async (id: number) => { setTest((s) => ({ ...s, [id]: { loading: true } })); try { setTest((s) => ({ ...s, [id]: {} })); const r = await api.post(`/wazuh/${id}/test`); setTest((s) => ({ ...s, [id]: r })); await reload(); } catch (e: any) { setTest((s) => ({ ...s, [id]: { error: e.message } })); } };
  return (
    <div className="flex flex-col gap-3.5">
      {items.map((w) => (
        <article key={w.id} className={`${CARD} flex flex-wrap gap-4 py-[18px]`}>
          <div className="flex min-w-0 flex-[1_1_420px] flex-col gap-1.5">
            <div className="text-base font-semibold">{w.name} <span className="font-mono text-xs font-normal text-slate-400">#{w.id}</span></div>
            <div className="break-all font-mono text-[13px] text-slate-300">indexer: {w.indexer_url} ({w.indexer_user}) · api: {w.api_url ?? "-"} ({w.api_user ?? "-"})</div>
            <div className="text-xs text-slate-400">TLS 検証: indexer={String(w.tls_verify)} api={String(w.api_tls_verify)} · CA: {w.has_ca ? "あり" : "なし"} · archives: {w.archives_enabled ? "有効" : "不明/無効"} · {fmtTs(w.updated_at)}</div>
            {test[w.id] && !test[w.id].loading && <pre className={`${PRE} mt-1.5 max-w-3xl`}>{JSON.stringify(test[w.id], null, 2)}</pre>}
          </div>
          <div className="flex min-w-[120px] flex-col gap-2">
            <button className={BTN_P} onClick={() => runTest(w.id)}>{t("common.test")}</button>
            {admin && <button className={BTN_S} onClick={() => setEdit({ ...w, indexer_password: "", api_password: "", ca_pem: "" })}>編集</button>}
            {admin && <button className={BTN_D} onClick={async () => { if (confirm(`${t("common.delete")}: ${w.name}?`)) { await api.del(`/wazuh/${w.id}`); await reload(); } }}>{t("common.delete")}</button>}
          </div>
        </article>
      ))}
      {edit && (
        <section aria-label="Wazuh 接続の編集" className={`${EDIT_CARD} flex flex-col gap-3`}>
          <div className="text-[15px] font-semibold">{edit.id ? `編集: ${edit.name}` : "Wazuh 接続を追加"}</div>
          <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(240px,1fr))]">
            <Field label="名前"><input className={INPUT} value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
            <Field label="TLS 検証（indexer / API）"><div className="flex gap-2"><select aria-label="indexer の TLS 検証" className={INPUT} value={String(edit.tls_verify)} onChange={(e) => setEdit({ ...edit, tls_verify: e.target.value === "true" })}><option value="true">indexer: 検証する</option><option value="false">indexer: 検証しない</option></select><select aria-label="API の TLS 検証" className={INPUT} value={String(edit.api_tls_verify ?? false)} onChange={(e) => setEdit({ ...edit, api_tls_verify: e.target.value === "true" })}><option value="true">API: 検証する</option><option value="false">API: 検証しない（既定の自己署名証明書）</option></select></div></Field>
            <Field label="Indexer URL"><input className={INPUT} value={edit.indexer_url} onChange={(e) => setEdit({ ...edit, indexer_url: e.target.value })} /></Field>
            <Field label="Indexer ユーザー"><input className={INPUT} value={edit.indexer_user} onChange={(e) => setEdit({ ...edit, indexer_user: e.target.value })} /></Field>
            <Field label="Indexer パスワード（空なら変更しない）"><input className={INPUT} type="password" value={edit.indexer_password} onChange={(e) => setEdit({ ...edit, indexer_password: e.target.value })} /></Field>
            <div />
            <Field label="API URL"><input className={INPUT} value={edit.api_url ?? ""} onChange={(e) => setEdit({ ...edit, api_url: e.target.value || null })} /></Field>
            <Field label="API ユーザー"><input className={INPUT} value={edit.api_user ?? ""} onChange={(e) => setEdit({ ...edit, api_user: e.target.value || null })} /></Field>
            <Field label="API パスワード（空なら変更しない）"><input className={INPUT} type="password" value={edit.api_password} onChange={(e) => setEdit({ ...edit, api_password: e.target.value })} /></Field>
          </div>
          <Field label="CA 証明書（PEM、任意。空なら変更しない）"><textarea className={`${TEXTAREA} h-24`} placeholder="-----BEGIN CERTIFICATE-----" value={edit.ca_pem ?? ""} onChange={(e) => setEdit({ ...edit, ca_pem: e.target.value })} /></Field>
          <Field label="メモ"><input className={INPUT} value={edit.notes ?? ""} onChange={(e) => setEdit({ ...edit, notes: e.target.value })} /></Field>
          {err && <div className={ERR}>{err}</div>}
          <div className="flex gap-2.5"><button className={`${BTN_P} min-h-[44px] px-5`} onClick={save}>{t("common.save")}</button><button className={`${BTN_S} min-h-[44px] px-5`} onClick={() => setEdit(null)}>{t("common.cancel")}</button></div>
        </section>
      )}
      {admin && !edit && <button className={`${BTN_ADD} self-start`} onClick={() => setEdit(blank)}>{t("common.add")}</button>}
    </div>
  );
}

// ---------------- Keys ----------------
function KeysTab() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [items, reload] = useList<any>("/ssh-keys");
  const [name, setName] = useState(""); const [priv, setPriv] = useState(""); const [err, setErr] = useState("");
  return (
    <div className="flex flex-col gap-3.5">
      {items.map((k) => (
        <article key={k.id} className={`${CARD} flex flex-wrap items-start gap-3.5`}>
          <div className="flex min-w-0 flex-[1_1_420px] flex-col gap-1.5">
            <div className="text-[15px] font-semibold">{k.name} <span className="font-mono text-xs font-normal text-slate-400">#{k.id} · {k.fingerprint}</span></div>
            <pre className={PRE}>{k.public_key}</pre>
            <div className="text-xs text-slate-400">対象ホストの <code className="font-mono text-slate-300">~/.ssh/authorized_keys</code> にこの公開鍵を追加してください</div>
          </div>
          {admin && <button className={BTN_D} onClick={async () => { if (confirm(`${t("common.delete")}: ${k.name}?`)) { await api.del(`/ssh-keys/${k.id}`); await reload(); } }}>{t("common.delete")}</button>}
        </article>
      ))}
      {admin && (
        <section aria-label="SSH 鍵の追加" className={`${CARD} flex flex-col gap-3 py-[18px]`}>
          <div className="max-w-[420px]"><Field label="鍵の名前"><input className={INPUT} value={name} onChange={(e) => setName(e.target.value)} placeholder="edr-console-lab" /></Field></div>
          <button className={`${BTN_P} min-h-[44px] self-start px-[18px]`} onClick={async () => { setErr(""); try { await api.post("/ssh-keys/generate", { name }); setName(""); await reload(); } catch (e: any) { setErr(e.message); } }}>ed25519 鍵を生成</button>
          <Field label="…または既存の秘密鍵を取り込む（OpenSSH 形式）"><textarea className={`${TEXTAREA} h-24`} placeholder="OpenSSH 形式の秘密鍵を貼り付け（-----BEGIN OPENSSH … で始まるもの）" value={priv} onChange={(e) => setPriv(e.target.value)} /></Field>
          <button className={`${BTN_S} min-h-[44px] self-start px-[18px]`} onClick={async () => { setErr(""); try { await api.post("/ssh-keys/import", { name, private_key: priv }); setName(""); setPriv(""); await reload(); } catch (e: any) { setErr(e.message); } }}>取り込む</button>
          {err && <div className={ERR}>{err}</div>}
        </section>
      )}
    </div>
  );
}

// ---------------- Users ----------------
const ROLE_JA: Record<string, string> = { admin: "管理者（設定変更可）", operator: "オペレーター（調査・承認可）", viewer: "閲覧のみ" };
/* EDR-119: API（トークン）アクセスの全体スイッチ */
function ApiAccessCard() {
  const [st, setSt] = useState<{ on: boolean; updated_at: string | null; reason: string | null } | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const load = async () => { try { setSt(await api.get("/settings/api-access")); } catch (e: any) { setErr(e.message); } };
  useEffect(() => { load(); }, []);
  const flip = async () => {
    if (!st) return;
    const next = !st.on;
    if (!confirm(next ? "API を有効にしますか？\n発行済みのトークンがまた使えるようになります。" : "API を止めますか？\n発行済みのトークンはすべて使えなくなります（トークン自体は消えません。画面での操作はそのまま使えます）。")) return;
    setErr(""); setBusy(true);
    try { setSt(await api.put("/settings/api-access", { on: next })); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <section aria-label="API アクセス" className={`${CARD} flex flex-wrap items-center gap-4`}>
      <div className="min-w-0 flex-1">
        <div className="text-[15px] font-semibold">API アクセス（トークン認証）: {st ? (st.on ? <span className="text-[#3CCB8C]">有効</span> : <span className="text-[#FF9A9D]">停止中</span>) : "…"}</div>
        <div className="mt-1 text-[13px] leading-relaxed text-slate-400">{st && !st.on ? "発行済みのトークンでのアクセスはすべて 403 になります。画面での操作には影響しません。" : "止めると、発行済みのトークンでのアクセスをまとめて拒否します。トークンは消えないので、戻せばそのまま使えます。"}{st?.updated_at && <span className="ml-1 text-slate-500">（最終変更 {fmtTs(st.updated_at)}）</span>}</div>
        {err && <div className={`${ERR} mt-2`}>{err}</div>}
      </div>
      {st && <button className={st.on ? BTN_D : BTN_P} disabled={busy} onClick={flip}>{st.on ? "API を止める" : "API を有効にする"}</button>}
    </section>
  );
}

/* EDR-120: 自動ログアウトまでの時間（最後に操作してから） */
const TIMEOUT_JA: Record<string, string> = { "1h": "1 時間", "6h": "6 時間", "12h": "12 時間", "24h": "24 時間（既定）", "7d": "7 日", none: "なし（自動ログアウトしない）" };
function SessionTimeoutCard() {
  const [st, setSt] = useState<{ key: string; updated_at: string | null; options: string[] } | null>(null); const [sel, setSel] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [ok, setOk] = useState(false);
  const load = async () => { try { const r = await api.get<any>("/settings/session-timeout"); setSt(r); setSel(r.key); } catch (e: any) { setErr(e.message); } };
  useEffect(() => { load(); }, []);
  const save = async () => {
    if (sel === "none" && !confirm("自動ログアウトを「なし」にしますか？\nPC を離れたときや cookie を盗まれたときに、そのまま使われる危険があります。おすすめしません。")) return;
    setErr(""); setOk(false); setBusy(true);
    try { const r = await api.put<any>("/settings/session-timeout", { timeout: sel }); setSt(r); setSel(r.key); setOk(true); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <section aria-label="自動ログアウト" className={`${CARD} flex flex-wrap items-end gap-4`}>
      <div className="min-w-0 flex-1">
        <div className="text-[15px] font-semibold">自動ログアウト</div>
        <div className="mt-1 text-[13px] leading-relaxed text-slate-400">最後に操作してからこの時間がたつと、自動でログアウトします。操作するたびに延びます。短くすると、ログイン中の人にもすぐ反映されます。{st?.updated_at && <span className="ml-1 text-slate-500">（最終変更 {fmtTs(st.updated_at)}）</span>}</div>
        {sel === "none" && <div className="mt-2 text-[13px] text-[#F5C542]">「なし」はおすすめしません。PC を離れたときや cookie を盗まれたときに、そのまま使われる危険があります。</div>}
        {err && <div className={`${ERR} mt-2`}>{err}</div>}
      </div>
      <div className="flex items-center gap-2">
        <select aria-label="自動ログアウトまでの時間" className="rounded-lg border border-slate-600 bg-slate-900 px-2.5 py-2 text-sm text-slate-100 focus:border-teal-400 focus:outline-none" value={sel} onChange={(e) => { setSel(e.target.value); setOk(false); }}>
          {(st?.options ?? Object.keys(TIMEOUT_JA)).map((k) => <option key={k} value={k}>{TIMEOUT_JA[k] ?? k}</option>)}
        </select>
        <button className={BTN_P} disabled={busy || !st || sel === st.key} onClick={save}>保存</button>
        {ok && <span className="text-[13px] text-[#3CCB8C]">保存しました</span>}
      </div>
    </section>
  );
}

function UsersTab() {
  const { user } = useContext(UserCtx);
  const [items, reload] = useList<any>("/users");
  const [f, setF] = useState({ email: "", name: "", password: "", role: "operator", must_change_password: true }); const [err, setErr] = useState("");
  const [tokenFor, setTokenFor] = useState<any | null>(null); const [tokName, setTokName] = useState(""); const [tokDays, setTokDays] = useState("90"); const [tokIps, setTokIps] = useState(""); const [issued, setIssued] = useState<any | null>(null);
  const [mfaFor, setMfaFor] = useState<any | null>(null);
  const [expFor, setExpFor] = useState<{ uid: number; tid: number } | null>(null); const [expDate, setExpDate] = useState("");
  const [pwFor, setPwFor] = useState<any | null>(null); const [pw, setPw] = useState("");
  if (user?.role !== "admin") return <div className={NOTE}>管理者のみ</div>;
  const run = async (fn: () => Promise<unknown>) => { setErr(""); try { await fn(); await reload(); } catch (e: any) { setErr(e.message); } };
  return (
    <div className="flex flex-col gap-3.5">
      <ApiAccessCard />
      <SessionTimeoutCard />
      <div className={NOTE}>ロールはいつでも変更できます。管理者＝設定・ユーザー・ホスト・プレイブックの変更、オペレーター＝調査の実行と承認、閲覧＝見るだけ。API トークンを発行すると、そのユーザーの権限で外部ツール（AI エージェントの自動テストなど）が <code className="font-mono text-teal-200">Authorization: Bearer</code> で API を使えます。</div>
      {err && <div className={ERR}>{err}</div>}
      <div className="overflow-x-auto rounded-[14px] border border-slate-700 bg-slate-800">
        <table className="w-full min-w-[1040px] border-collapse text-[13px]">
          <thead><tr><th className={TH}>Email</th><th className={TH}>名前</th><th className={TH}>ロール</th><th className={TH}>状態</th><th className={TH}>MFA</th><th className={TH}>API トークン</th><th className={TH}>作成</th><th className={TH}></th></tr></thead>
          <tbody>{items.map((u) => {
            const me = u.id === user.id;
            return (
              <tr key={u.id} className={`border-t border-slate-700 align-top ${u.disabled ? "opacity-50" : ""}`}>
                <td className={`${TD} font-mono`}>{u.email}{me && <span className="ml-1.5 font-sans text-[11px] text-teal-300">(自分)</span>}</td>
                <td className={TD}>{u.name}</td>
                <td className="px-4 py-2"><select aria-label="ロール" className="rounded-lg border border-slate-600 bg-slate-900 px-2 py-1 text-[13px] text-slate-100 focus:border-teal-400 focus:outline-none disabled:opacity-60" value={u.role} disabled={me} title={ROLE_JA[u.role]} onChange={(e) => run(() => api.put(`/users/${u.id}`, { role: e.target.value }))}><option value="admin">admin</option><option value="operator">operator</option><option value="viewer">viewer</option></select></td>
                <td className={TD}>{u.disabled ? <span className="text-[#FF9A9D]">無効</span> : <span className="text-[#3CCB8C]">有効</span>}{u.must_change_password && <span className="ml-1.5 text-[11px] text-[#F5C542]">(初回PW変更待ち)</span>}</td>
                <td className={TD}>{u.mfa_enabled ? <span className="text-[#3CCB8C]">登録済み</span> : <span className="text-[#F5C542]">未登録（次回ログインで登録）</span>}{u.mfa_enabled && !me && <button className="ml-2 inline-flex min-h-[26px] items-center rounded-md border border-slate-600 px-2 text-[11px] text-slate-200 hover:bg-slate-700" onClick={() => setMfaFor(u)}>リセット</button>}</td>
                <td className="px-4 py-2.5">
                  {(u.tokens ?? []).map((t: any) => <div key={t.id} className="mb-1.5 flex flex-wrap items-center gap-2"><code className="font-mono text-teal-200">{t.prefix}…</code><span>{t.name}</span><span className="text-[11px] text-slate-400">{t.last_used_at ? "使用 " + fmtTs(t.last_used_at) : "未使用"}</span>{(() => { const e = t.expires_at ? new Date(Number(t.expires_at) || t.expires_at) : null; const left = e ? Math.ceil((e.getTime() - Date.now()) / 86400_000) : null; return <span className={`text-[11px] ${left === null ? "text-[#F5C542]" : left <= 0 ? "font-semibold text-[#FF9A9D]" : left <= 14 ? "text-[#F5C542]" : "text-slate-400"}`} title="この日時を過ぎると使えなくなる">{e ? (left! <= 0 ? "期限切れ " : "期限 ") + fmtTs(e) : "期限なし"}</span>; })()}{expFor?.tid === t.id ? <span className="inline-flex items-center gap-1"><input type="date" aria-label="新しい期限" className="rounded-md border border-slate-600 bg-slate-900 px-1.5 py-0.5 text-[11px] text-slate-100 focus:border-teal-400 focus:outline-none" value={expDate} min={new Date(Date.now() + 86400_000).toISOString().slice(0, 10)} onChange={(e) => setExpDate(e.target.value)} /><button className="inline-flex min-h-[26px] items-center rounded-md bg-teal-500 px-2 text-[11px] font-semibold text-white hover:bg-teal-400 disabled:opacity-50" disabled={!expDate} onClick={() => run(async () => { await api.patch(`/users/${u.id}/tokens/${t.id}`, { expires_at: new Date(expDate + "T23:59:59").toISOString() }); setExpFor(null); })}>保存</button><button className="inline-flex min-h-[26px] items-center rounded-md border border-slate-600 px-2 text-[11px] text-slate-200 hover:bg-slate-700" onClick={() => setExpFor(null)}>やめる</button></span> : <button className="inline-flex min-h-[26px] items-center rounded-md border border-slate-600 px-2 text-[11px] text-slate-200 hover:bg-slate-700" onClick={() => { const e = t.expires_at ? new Date(Number(t.expires_at) || t.expires_at) : new Date(Date.now() + 90 * 86400_000); setExpDate((e.getTime() > Date.now() ? e : new Date(Date.now() + 90 * 86400_000)).toISOString().slice(0, 10)); setExpFor({ uid: u.id, tid: t.id }); }}>期限変更</button>}{t.allowed_ips ? <span className="font-mono text-[11px] text-slate-400" title="この接続元からだけ使える">{t.allowed_ips}</span> : <span className="text-[11px] text-[#F5C542]" title="EDR-90 以前に発行。期限と接続元を付けて再発行してください">接続元制限なし</span>}<button className="inline-flex min-h-[26px] items-center rounded-md border border-[#4A1E24] px-2 text-[11px] text-[#FF9A9D] hover:bg-[#2A1216]" onClick={() => { if (confirm(`トークン ${t.name} を失効しますか？`)) run(() => api.del(`/users/${u.id}/tokens/${t.id}`)); }}>失効</button></div>)}
                  {!u.disabled && <button className="inline-flex min-h-[28px] items-center rounded-md border border-dashed border-teal-500 px-2.5 text-xs text-teal-300 hover:bg-teal-500/10" onClick={() => { setTokenFor(u); setTokName(""); setIssued(null); }}>+ 発行</button>}
                </td>
                <td className={`${TD} font-mono text-xs text-slate-400`}>{fmtTs(u.created_at)}</td>
                <td className="px-4 py-2.5">
                  <div className="flex flex-wrap justify-end gap-1.5">
                    <button className={BTN_SM} onClick={() => { setPwFor(u); setPw(""); }}>PW再設定</button>
                    {!me && <button className={BTN_SM} onClick={() => run(() => api.put(`/users/${u.id}`, { disabled: !u.disabled }))}>{u.disabled ? "有効化" : "無効化"}</button>}
                    {!me && <button className="inline-flex min-h-[30px] items-center rounded-md border border-[#4A1E24] px-2.5 text-xs text-[#FF9A9D] hover:bg-[#2A1216]" onClick={() => { if (confirm(`${u.email} を削除しますか？（監査ログは残ります）`)) run(() => api.del(`/users/${u.id}`)); }}>削除</button>}
                  </div>
                </td>
              </tr>
            );
          })}</tbody>
        </table>
      </div>
      {tokenFor && (
        <section aria-label="API トークンを発行" className={`${EDIT_CARD} flex flex-col gap-2.5`}>
          <div className="text-[15px] font-semibold">API トークンを発行: {tokenFor.email} <span className="text-[13px] font-normal text-slate-400">（権限 = {tokenFor.role}）</span></div>
          {!issued ? (
            <div className="flex flex-wrap items-end gap-3">
              <Field label="用途・名前"><input className={INPUT} value={tokName} onChange={(e) => setTokName(e.target.value)} placeholder="claude-api-test" /></Field>
              <Field label="有効期間（日、最長 365）"><input className={`${INPUT} w-32`} inputMode="numeric" value={tokDays} onChange={(e) => setTokDays(e.target.value.replace(/\D/g, ""))} /></Field>
              <div className="w-72 max-w-full"><Field label="使える接続元（IP か CIDR、カンマ区切り）"><input className={`${INPUT} font-mono`} value={tokIps} onChange={(e) => setTokIps(e.target.value)} placeholder="10.20.30.0/24, 100.64.0.0/10" /></Field></div>
              <button className={BTN_P} onClick={() => run(async () => { const r = await api.post(`/users/${tokenFor.id}/tokens`, { name: tokName, expires_days: Number(tokDays || 0), allowed_ips: tokIps.split(",").map((x) => x.trim()).filter(Boolean) }); setIssued(r); })}>発行</button>
              <button className={BTN_S} onClick={() => setTokenFor(null)}>閉じる</button>
            </div>
          ) : (
            <>
              <div className="rounded-[10px] border border-[#6B5A19] bg-[#2A2410] px-3.5 py-2.5 text-[13px] leading-relaxed text-[#F5D98A]">このトークンは今だけ表示されます。安全な場所（.env.secrets など）に保存してください。チャットや Jira には貼らないこと。</div>
              <pre className={`${PRE} select-all text-[13px] text-teal-200`}>{issued.token}</pre>
              <pre className={PRE}>{`curl -sk -H "Authorization: Bearer ${issued.token}" ${location.origin}/api/auth/me`}</pre>
              <button className={`${BTN_S} self-start`} onClick={() => setTokenFor(null)}>閉じる</button>
            </>
          )}
        </section>
      )}
      {mfaFor && (
        <section aria-label="MFA をリセット" className={`${EDIT_CARD} flex flex-col gap-3`}>
          <div className="text-[15px] font-semibold">MFA をリセット: {mfaFor.email}</div>
          <div className="text-[13px] text-slate-300">スマホの紛失や機種変更のときに使います。リセットすると、この人は次のログインで認証アプリを登録し直します。</div>
          <div className="flex flex-wrap items-end gap-3">
            <button className={BTN_D} onClick={() => run(async () => { await api.post(`/users/${mfaFor.id}/mfa/reset`, {}); setMfaFor(null); })}>リセットする</button>
            <button className={BTN_S} onClick={() => setMfaFor(null)}>閉じる</button>
          </div>
        </section>
      )}
      {pwFor && (
        <section aria-label="パスワード再設定" className={`${EDIT_CARD} flex flex-col gap-3`}>
          <div className="text-[15px] font-semibold">パスワード再設定: {pwFor.email}</div>
          <div className="flex flex-wrap items-end gap-3">
            <div className="w-80 max-w-full"><Field label="新しいパスワード（12文字以上、次回ログイン時に本人が変更）"><input className={INPUT} type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></Field></div>
            <button className={BTN_P} onClick={() => run(async () => { await api.post(`/users/${pwFor.id}/reset-password`, { password: pw, must_change_password: true }); setPwFor(null); })}>設定</button>
            <button className={BTN_S} onClick={() => setPwFor(null)}>キャンセル</button>
          </div>
        </section>
      )}
      <section aria-label="ユーザーを追加" className={`${CARD} flex flex-col gap-3 py-[18px]`}>
        <div className="text-[15px] font-semibold">ユーザーを追加</div>
        <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(200px,1fr))]">
          <Field label="Email"><input className={INPUT} type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
          <Field label="名前"><input className={INPUT} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="初期パスワード (12+)"><input className={INPUT} type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
          <Field label="ロール"><select className={INPUT} value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}><option value="admin">admin</option><option value="operator">operator</option><option value="viewer">viewer</option></select></Field>
          <Field label="初回ログイン時にPW変更"><select className={INPUT} value={String(f.must_change_password)} onChange={(e) => setF({ ...f, must_change_password: e.target.value === "true" })}><option value="true">必須（人間用）</option><option value="false">不要（サービスアカウント用）</option></select></Field>
        </div>
        <div className="flex items-center gap-3"><button className={`${BTN_P} min-h-[44px] px-5`} onClick={() => run(async () => { await api.post("/users", f); setF({ email: "", name: "", password: "", role: "operator", must_change_password: true }); })}>{t("common.add")}</button><span className="text-xs text-slate-400">{ROLE_JA[f.role]}</span></div>
      </section>
    </div>
  );
}

// ---------------- Protected ranges ----------------
function ProtectedTab() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [items, reload] = useList<any>("/protected-ranges");
  const [f, setF] = useState({ cidr: "", label: "", reason: "" }); const [err, setErr] = useState("");
  return (
    <div className="flex flex-col gap-3.5">
      <div className="rounded-xl border border-[#2A4A7A] bg-[#0F1830] px-4 py-3 text-sm leading-[1.7] text-[#D6DDF0]">ここに登録した IP / CIDR を含む変更コマンドは、承認カードで「block」となり、編集しない限り承認できません（カメラ回線・ignoreip・tailnet・LAN など）。</div>
      <div className="overflow-x-auto rounded-[14px] border border-slate-700 bg-slate-800">
        <table className="w-full min-w-[620px] border-collapse text-sm">
          <thead><tr><th className={TH}>CIDR</th><th className={TH}>ラベル</th><th className={TH}>理由</th><th className={TH}></th></tr></thead>
          <tbody>{items.map((r) => <tr key={r.id} className="border-t border-slate-700"><td className={`${TD} font-mono`}>{r.cidr}</td><td className={TD}>{r.label}</td><td className={`${TD} text-slate-300`}>{r.reason}</td><td className={`${TD} text-right`}>{admin && <button className="inline-flex min-h-[32px] items-center rounded-lg border border-[#4A1E24] px-3 text-[13px] text-[#FF9A9D] hover:bg-[#2A1216]" onClick={async () => { await api.del(`/protected-ranges/${r.id}`); await reload(); }}>削除</button>}</td></tr>)}</tbody>
        </table>
      </div>
      {admin && (
        <section aria-label="保護アドレスの追加" className={`${CARD} grid items-end gap-3 [grid-template-columns:repeat(auto-fit,minmax(200px,1fr))]`}>
          <Field label="CIDR / IP"><input className={INPUT} value={f.cidr} onChange={(e) => setF({ ...f, cidr: e.target.value })} placeholder="100.64.0.0/10" /></Field>
          <Field label="ラベル"><input className={INPUT} value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} placeholder="tailnet" /></Field>
          <Field label="理由"><input className={INPUT} value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} /></Field>
          <button className={BTN_P} onClick={async () => { setErr(""); try { await api.post("/protected-ranges", { ...f, reason: f.reason || null }); setF({ cidr: "", label: "", reason: "" }); await reload(); } catch (e: any) { setErr(e.message); } }}>追加</button>
          {err && <div className={`${ERR} col-span-full`}>{err}</div>}
        </section>
      )}
    </div>
  );
}

// ---------------- Sentinel triggers ----------------
function SentinelTab() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [items, reload] = useList<any>("/triggers");
  const [status, setStatus] = useState<any>(null); const [edit, setEdit] = useState<any | null>(null); const [err, setErr] = useState("");
  const loadStatus = () => api.get("/sentinel/status").then(setStatus);
  useEffect(() => { loadStatus(); }, []);
  const toggle = async (t: any) => { await api.put(`/triggers/${t.id}`, { enabled: !t.enabled }); await reload(); };
  const save = async () => { setErr(""); try { let cfg: any; try { cfg = JSON.parse(edit.configText); } catch { throw new Error("config は JSON で入力してください"); } await api.put(`/triggers/${edit.id}`, { name: edit.name, config: cfg, dedupe_window_sec: Number(edit.dedupe_window_sec), priority: Number(edit.priority) }); setEdit(null); await reload(); } catch (e: any) { setErr(e.message); } };
  return (
    <div className="flex flex-col gap-3.5">
      <div className={`${CARD} text-sm leading-[1.8] text-[#D6DDF0]`}>
        Sentinel はアラートを {status?.pollSec ?? "?"} 秒ごとにポーリングし、有効なトリガーに一致した新規アラートごとに調査セッションを自動起動します。
        全体の有効/無効は環境変数 <code className="font-mono text-teal-200">SENTINEL_ENABLED</code>（現在: <strong className={status?.enabled ? "text-[#3CCB8C]" : "text-[#FF9A9D]"}>{status?.enabled ? "有効" : "無効"}</strong>）。1 時間あたりの上限は <code className="font-mono text-teal-200">LLM_MAX_SESSIONS_PER_HOUR</code>。
        最終実行: {status?.lastRun ? `${fmtTs(status.lastRun.at)} / checked ${status.lastRun.checked} / started ${status.lastRun.started}${status.lastRun.error ? " / error: " + status.lastRun.error : ""}` : "-"}
        {admin && <div className="mt-2.5"><button className="inline-flex min-h-[40px] items-center rounded-[10px] border border-teal-500 px-4 text-sm text-teal-300 hover:bg-teal-500/10" onClick={async () => { await api.post("/sentinel/run"); loadStatus(); }}>今すぐ 1 回実行</button></div>}
      </div>
      {items.map((t) => (
        <article key={t.id} className="flex flex-col gap-2 rounded-[14px] border border-slate-700 bg-slate-800 px-[18px] py-3.5">
          <div className="flex flex-wrap items-center gap-3">
            <button aria-pressed={!!t.enabled} className={`min-h-[32px] min-w-[56px] rounded-full border text-xs font-bold disabled:cursor-default ${t.enabled ? "border-[#1F5A3A] bg-[#12301F] text-[#7FE0B0]" : "border-slate-600 text-slate-400"}`} disabled={!admin} onClick={() => toggle(t)}>{t.enabled ? "ON" : "OFF"}</button>
            <span className="text-[15px] font-semibold">{t.name}</span>
            <span className="font-mono text-xs text-slate-400">{t.kind} · dedupe {t.dedupe_window_sec}s · priority {t.priority}</span>
            {admin && <button className="ml-auto inline-flex min-h-[34px] items-center rounded-lg border border-slate-600 px-3 text-[13px] text-slate-100 hover:bg-slate-700" onClick={() => setEdit({ ...t, configText: JSON.stringify(t.config, null, 2) })}>編集</button>}
          </div>
          <pre className="m-0 overflow-hidden text-ellipsis whitespace-nowrap rounded-lg border border-slate-700 bg-[#070B15] px-3 py-2 font-mono text-xs text-slate-300" title={JSON.stringify(t.config)}>{JSON.stringify(t.config)}</pre>
        </article>
      ))}
      {edit && (
        <section aria-label="トリガーの編集" className={`${EDIT_CARD} flex flex-col gap-3`}>
          <div className="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(200px,1fr))]">
            <Field label="名前"><input className={INPUT} value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
            <Field label="重複抑制（秒）"><input className={INPUT} type="number" value={edit.dedupe_window_sec} onChange={(e) => setEdit({ ...edit, dedupe_window_sec: e.target.value })} /></Field>
            <Field label="優先度（1=高）"><input className={INPUT} type="number" value={edit.priority} onChange={(e) => setEdit({ ...edit, priority: e.target.value })} /></Field>
          </div>
          <Field label="設定（JSON）: min_level / rule_ids / rule_groups / exclude_rule_ids / agents / dedupe_fields / prompt"><textarea className={`${TEXTAREA} h-40`} value={edit.configText} onChange={(e) => setEdit({ ...edit, configText: e.target.value })} /></Field>
          {err && <div className={ERR}>{err}</div>}
          <div className="flex gap-2.5"><button className={`${BTN_P} min-h-[44px] px-5`} onClick={save}>保存</button><button className={`${BTN_S} min-h-[44px] px-5`} onClick={() => setEdit(null)}>キャンセル</button></div>
        </section>
      )}
    </div>
  );
}

/* EDR-117: 自分の MFA 状態とリカバリーコードの作り直し（ログイン後のワンタイム確認はしない方針） */
function AccountTab() {
  const { user } = useContext(UserCtx);
  const [st, setSt] = useState<{ mfa_enabled: boolean; recovery_codes_remaining: number } | null>(null);
  const [codes, setCodes] = useState<string[]>([]); const [saved, setSaved] = useState(false); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const load = async () => { try { setSt(await api.get("/auth/mfa/status")); } catch (e: any) { setErr(e.message); } };
  useEffect(() => { load(); }, []);
  const regen = async () => {
    if (!confirm("リカバリーコードを作り直しますか？\n今までのコードはすべて使えなくなります。")) return;
    setErr(""); setBusy(true);
    try { const r = await api.post<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", {}); setCodes(r.recovery_codes); setSaved(false); await load(); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const copy = async () => { try { await navigator.clipboard.writeText(codes.join("\n")); } catch { /* manual copy */ } };
  const low = st && st.mfa_enabled && st.recovery_codes_remaining <= 3;
  return (
    <div className="flex flex-col gap-3.5">
      {err && <div className={ERR}>{err}</div>}
      <section aria-label="自分のアカウント" className={`${CARD} flex flex-col gap-2 text-[13px]`}>
        <div className="text-[15px] font-semibold">{user?.email}</div>
        <div className="text-slate-300">ロール: {user?.role}</div>
        <div className="text-slate-300">2 段階認証（認証アプリ）: {st ? (st.mfa_enabled ? <span className="text-[#3CCB8C]">登録済み</span> : <span className="text-[#F5C542]">未登録</span>) : "…"}</div>
        {st?.mfa_enabled && <div className="text-slate-300">使えるリカバリーコード: <span className={low ? "font-semibold text-[#F5C542]" : "text-slate-100"}>{st.recovery_codes_remaining} 個</span>{low && <span className="ml-2 text-[#F5C542]">残りが少なくなっています。作り直してください。</span>}</div>}
      </section>
      {st?.mfa_enabled && codes.length === 0 && (
        <section aria-label="リカバリーコードを作り直す" className={`${CARD} flex flex-col gap-3`}>
          <div className="text-[15px] font-semibold">リカバリーコードを作り直す</div>
          <div className="text-[13px] leading-relaxed text-slate-300">スマホをなくしたときにログインするための 10 個のコードを新しく作ります。今までのコードはすべて使えなくなります。認証アプリの登録はそのままです。</div>
          <div><button className={BTN_S} disabled={busy} onClick={regen}>作り直す</button></div>
        </section>
      )}
      {codes.length > 0 && (
        <section aria-label="新しいリカバリーコード" className={`${EDIT_CARD} flex flex-col gap-3`}>
          <div className="text-[15px] font-semibold">新しいリカバリーコード</div>
          <div className="rounded-[10px] border border-[#6B5A19] bg-[#2A2410] px-3.5 py-2.5 text-[13px] leading-relaxed text-[#F5D98A]">このコードは今しか表示されません。各コードは 1 回だけ使えます。パスワードマネージャーか、印刷して鍵のかかる場所に保管してください。</div>
          <ul className="m-0 grid max-w-[460px] list-none grid-cols-2 gap-2 p-0 font-mono text-[15px] text-teal-200">{codes.map((c) => <li key={c} className="select-all rounded-lg bg-slate-900 px-3 py-1.5 text-center tracking-wider">{c}</li>)}</ul>
          <div className="flex flex-wrap items-center gap-3">
            <button className={BTN_S} onClick={copy}>コピー</button>
            <label className="flex items-center gap-2 text-[13px] text-slate-300"><input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />保存しました</label>
            <button className={BTN_P} disabled={!saved} onClick={() => setCodes([])}>閉じる</button>
          </div>
        </section>
      )}
    </div>
  );
}

/* EDR-121: ホストスキャンの定期実行と、外部 AI に送るユーザー名の扱い */
const SCHED_LABEL: Record<string, string> = { "1d": "毎日", "7d": "週 1", "30d": "月 1", off: "しない" };
function HostScanTab() {
  const { user } = useContext(UserCtx); const admin = user?.role === "admin";
  const [st, setSt] = useState<any>(null); const [sched, setSched] = useState<Record<string, string>>({}); const [pseudo, setPseudo] = useState(true); const [err, setErr] = useState(""); const [ok, setOk] = useState(false); const [busy, setBusy] = useState(false);
  useEffect(() => { api.get<any>("/settings/host-scan").then((r) => { setSt(r); setSched(r.schedule); setPseudo(r.pseudonymize_users); }).catch((e) => setErr(e.message)); }, []);
  const save = async () => {
    if (!pseudo && !confirm("ユーザー名を仮名にせず外部の AI に送りますか？（個人を特定できる情報が外部に出ます）")) return;
    setBusy(true); setErr(""); setOk(false);
    try { const r = await api.put<any>("/settings/host-scan", { schedule: sched, pseudonymize_users: pseudo }); setSched(r.schedule); setPseudo(r.pseudonymize_users); setOk(true); } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  if (!st) return <div className={NOTE}>{err || "読み込み中…"}</div>;
  return (
    <div className="flex flex-col gap-3.5">
      <div className={NOTE}>管理ホスト画面の「ホストを AI でスキャン」の設定です。スキャンは読み取りだけで、ホストを変更しません。Windows など Wazuh エージェントだけの端末は、Wazuh に集まっている情報から作ります。</div>
      {err && <div className={ERR}>{err}</div>}
      <section aria-label="定期スキャン" className={`${CARD} flex flex-col gap-3`}>
        <div className="text-[15px] font-semibold">定期スキャン（環境区分ごと）</div>
        <div className="flex flex-wrap gap-4">{(["production", "staging", "lab"] as const).map((env) => (
          <Field key={env} label={{ production: "本番", staging: "ステージング", lab: "検証" }[env]}><select className={`${INPUT} w-36`} disabled={!admin} value={sched[env] ?? "7d"} onChange={(e) => { setSched({ ...sched, [env]: e.target.value }); setOk(false); }}>{(st.choices as string[]).map((c) => <option key={c} value={c}>{SCHED_LABEL[c] ?? c}</option>)}</select></Field>
        ))}</div>
        <div className="text-xs text-slate-400">ホストごとに変えたいときは、管理ホスト › 編集 の「定期スキャン」で上書きできます。接続が切れているエージェントだけの端末は定期スキャンしません。</div>
      </section>
      <section aria-label="プライバシー" className={`${CARD} flex flex-col gap-2`}>
        <div className="text-[15px] font-semibold">外部の AI に送るユーザー名</div>
        <label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" disabled={!admin} checked={pseudo} onChange={(e) => { setPseudo(e.target.checked); setOk(false); }} />仮名（U01, U02 …）に置き換えて送る（推奨）</label>
        <div className="text-xs text-slate-400">画面には実名で表示します。AI に送るのは集計した事実だけで、生のログは送りません。</div>
      </section>
      <section aria-label="状態" className={`${CARD} flex flex-col gap-1 text-[13px] text-slate-300`}>
        <div>AI による解釈: {st.ai ? <span className="text-[#3CCB8C]">有効</span> : <span className="text-[#F5C542]">無効（LLM 未設定、または HOST_SCAN_AI=false。事実だけ表示します）</span>}</div>
        <div>Windows の遮断操作（Wazuh 自動対処）: {st.ar_configured ? <span className="text-[#3CCB8C]">API ユーザー設定済み</span> : <span className="text-[#F5C542]">未設定（docs/host-actions.md の手順で WAZUH_AR_USER を作成）</span>}・必要なアドオン v{st.ar_addon_min} 以上</div>
      </section>
      {admin && <div className="flex items-center gap-3"><button className={BTN_P} disabled={busy} onClick={save}>保存</button>{ok && <span className="text-[13px] text-[#3CCB8C]">保存しました</span>}</div>}
    </div>
  );
}

export default function Settings() {
  return (
    <div className="mx-auto flex max-w-[1600px] flex-col gap-[18px]">
      <h1 className="m-0 text-[26px] font-bold">{t("nav.settings")}</h1>
      <Tabs />
      <Routes>
        <Route path="wazuh" element={<WazuhTab />} />
        <Route path="hosts" element={<Navigate to="/hosts" replace />} />
        <Route path="keys" element={<KeysTab />} />
        <Route path="playbooks" element={<Navigate to="/playbooks" replace />} />
        <Route path="protected" element={<ProtectedTab />} />
        <Route path="sentinel" element={<SentinelTab />} />
        <Route path="users" element={<UsersTab />} />
        <Route path="account" element={<AccountTab />} />
        <Route path="hostscan" element={<HostScanTab />} />
        <Route path="agentpack" element={<AgentPackSettings />} />
        <Route path="*" element={<Navigate to="wazuh" replace />} />
      </Routes>
    </div>
  );
}
