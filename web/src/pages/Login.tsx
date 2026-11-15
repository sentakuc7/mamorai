import { useEffect, useState } from "react";
import { api, ApiError } from "../lib/api";
import { t } from "../lib/i18n";
import { LogoMark, Wordmark } from "../components/Logo";

const INPUT = "w-full min-h-[44px] rounded-[10px] border border-slate-600 bg-slate-900 px-3 text-[15px] text-slate-100 placeholder-slate-500 focus:border-teal-400 focus:outline-none";
const CODE = `${INPUT} text-center font-mono text-[22px] tracking-[0.4em]`;
const LABEL = "mb-1.5 block text-[13px] text-slate-400";
const BTN = "min-h-[48px] rounded-xl bg-teal-500 text-[15px] font-bold text-white transition hover:bg-teal-400 disabled:cursor-not-allowed disabled:opacity-50";
const LINK = "self-center text-[13px] text-teal-300 hover:underline";
const ERRBOX = "rounded-[10px] border border-[#6B2329] bg-[#2A1216] px-3.5 py-2.5 text-[13px] text-[#FF9A9D]";

/** 「MamorAI にログイン」の製品名部分だけワードマークで表示する */
function Title({ text }: { text: string }) {
  const parts = text.split("MamorAI");
  if (parts.length < 2) return <>{text}</>;
  return <>{parts[0]}<Wordmark className="text-[20px]" />{parts.slice(1).join("MamorAI")}</>;
}

type Stage = "password" | "verify" | "enroll" | "codes";

const errText = (e: unknown, fallback: string) => {
  if (e instanceof ApiError) {
    if (e.status === 429) return "試行回数が上限に達しました。15 分ほど待ってからやり直してください。";
    if (e.message === "invalid code") return "コードが違います。アプリに表示されている最新の 6 桁を入力してください。";
  }
  return fallback;
};

/**
 * EDR-90: sign-in = password → TOTP (6 digits from an authenticator app). Users without an authenticator
 * register one here (QR code generated on the server, no e-mail / SMS / external service).
 */
export default function Login({ onLogin, initialStage, initialEmail }: { onLogin: () => Promise<void>; initialStage?: "verify" | "enroll"; initialEmail?: string }) {
  const [stage, setStage] = useState<Stage>(initialStage ?? "password");
  const [email, setEmail] = useState(initialEmail ?? ""); const [password, setPassword] = useState("");
  const [code, setCode] = useState(""); const [useRecovery, setUseRecovery] = useState(false);
  const [enroll, setEnroll] = useState<{ secret: string; otpauth: string; qr_svg_data_url: string } | null>(null);
  const [codes, setCodes] = useState<string[]>([]); const [saved, setSaved] = useState(false);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (stage !== "enroll" || enroll) return;
    api.post<any>("/auth/mfa/enroll/start").then(setEnroll).catch(() => setErr("認証アプリの登録を開始できませんでした。もう一度ログインしてください。"));
  }, [stage, enroll]);

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try {
      const r = await api.post<{ mfa: "verify" | "enroll" | null }>("/auth/login", { email, password });
      setPassword("");
      if (r.mfa) { setCode(""); setStage(r.mfa); } else await onLogin();
    } catch (e) { setErr(errText(e, t("login.failed"))); } finally { setBusy(false); }
  };
  const submitVerify = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try {
      const r = await api.post<{ remaining_recovery_codes?: number }>("/auth/mfa/verify", useRecovery ? { recovery_code: code } : { code });
      if (useRecovery && r.remaining_recovery_codes !== undefined) alert(`リカバリーコードでログインしました。残りは ${r.remaining_recovery_codes} 個です。少なくなったら設定から作り直してください。`);
      await onLogin();
    } catch (e) { setErr(errText(e, useRecovery ? "リカバリーコードが違うか、使用済みです。" : "コードが違います。")); setCode(""); } finally { setBusy(false); }
  };
  const submitEnroll = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try { const r = await api.post<{ recovery_codes: string[] }>("/auth/mfa/enroll/confirm", { code }); setCodes(r.recovery_codes); setStage("codes"); }
    catch (e) { setErr(errText(e, "コードが違います。")); setCode(""); } finally { setBusy(false); }
  };
  const restart = async () => { try { await api.post("/auth/logout"); } catch { /* ignore */ } setStage("password"); setEnroll(null); setCode(""); setErr(""); };
  const copyCodes = async () => { try { await navigator.clipboard.writeText(codes.join("\n")); } catch { /* manual copy */ } };

  const head = (sub?: string) => (
    <div className="flex flex-col items-center gap-3.5 pb-1.5">
      <LogoMark size={64} />
      <h1 className="m-0 text-[20px] font-semibold"><Title text={t("login.title")} /></h1>
      {sub && <p className="m-0 text-center text-[13px] leading-relaxed text-slate-400">{sub}</p>}
    </div>
  );
  const codeInput = (id: string, label: string) => (
    <div><label className={LABEL} htmlFor={id}>{label}</label>
      <input id={id} className={useRecovery && stage === "verify" ? INPUT : CODE} inputMode={useRecovery && stage === "verify" ? "text" : "numeric"} autoComplete="one-time-code" maxLength={useRecovery && stage === "verify" ? 12 : 6} value={code} onChange={(e) => setCode(useRecovery && stage === "verify" ? e.target.value : e.target.value.replace(/\D/g, ""))} placeholder={useRecovery && stage === "verify" ? "xxxx-xxxx" : "000000"} autoFocus required />
    </div>
  );

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 p-4">
      {stage === "password" && (
        <form onSubmit={submitPassword} className="flex w-full max-w-[420px] flex-col gap-5 rounded-[20px] border border-slate-700 bg-slate-800 px-9 py-10">
          {head()}
          <div><label className={LABEL} htmlFor="login-email">{t("login.email")}</label><input id="login-email" className={INPUT} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required /></div>
          <div><label className={LABEL} htmlFor="login-pw">{t("login.password")}</label><input id="login-pw" className={INPUT} type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></div>
          {err && <div role="alert" className={ERRBOX}>{err}</div>}
          <button className={BTN} disabled={busy}>{t("login.submit")}</button>
          <div className="text-center text-xs text-slate-500">見張りは AI に。決断はあなたに。</div>
        </form>
      )}

      {stage === "verify" && (
        <form onSubmit={submitVerify} className="flex w-full max-w-[420px] flex-col gap-5 rounded-[20px] border border-slate-700 bg-slate-800 px-9 py-10">
          {head(useRecovery ? "保存しておいたリカバリーコードを 1 つ入力してください。使ったコードは無効になります。" : "認証アプリ（Google Authenticator など）に表示されている 6 桁を入力してください。")}
          {codeInput("login-code", useRecovery ? "リカバリーコード" : "確認コード（6 桁）")}
          {err && <div role="alert" className={ERRBOX}>{err}</div>}
          <button className={BTN} disabled={busy || (!useRecovery && code.length !== 6)}>確認</button>
          <button type="button" className={LINK} onClick={() => { setUseRecovery(!useRecovery); setCode(""); setErr(""); }}>{useRecovery ? "6 桁のコードを使う" : "スマホが手元にない（リカバリーコードを使う）"}</button>
          <button type="button" className={LINK} onClick={restart}>別のアカウントでログイン</button>
        </form>
      )}

      {stage === "enroll" && (
        <form onSubmit={submitEnroll} className="flex w-full max-w-[460px] flex-col gap-5 rounded-[20px] border border-teal-500 bg-slate-800 px-9 py-9">
          {head("ログインには認証アプリの登録が必要です。メールや外部サービスは使いません。")}
          <ol className="m-0 flex list-decimal flex-col gap-1.5 pl-5 text-[13px] leading-relaxed text-slate-300">
            <li>スマホに認証アプリ（Google Authenticator、Microsoft Authenticator など）を入れる</li>
            <li>アプリで「QR コードをスキャン」を選び、下の QR を読み取る</li>
            <li>アプリに出た 6 桁を入力して登録を完了する</li>
          </ol>
          <div className="flex flex-col items-center gap-2">
            {enroll ? <img src={enroll.qr_svg_data_url} alt="認証アプリ登録用の QR コード" className="h-52 w-52 rounded-xl bg-white p-2" /> : <div className="flex h-52 w-52 items-center justify-center rounded-xl border border-slate-700 text-xs text-slate-500">QR を作成中…</div>}
            {enroll && <details className="w-full text-[12px] text-slate-400"><summary className="cursor-pointer text-center">QR を読めないときは、このキーを手入力</summary><code className="mt-1.5 block select-all break-all rounded-lg bg-slate-900 px-3 py-2 text-center font-mono text-[13px] tracking-wider text-teal-200">{enroll.secret.replace(/(.{4})/g, "$1 ").trim()}</code></details>}
          </div>
          {codeInput("enroll-code", "アプリに表示された 6 桁")}
          {err && <div role="alert" className={ERRBOX}>{err}</div>}
          <button className={BTN} disabled={busy || !enroll || code.length !== 6}>登録する</button>
          <button type="button" className={LINK} onClick={restart}>中止してログイン画面に戻る</button>
        </form>
      )}

      {stage === "codes" && (
        <div className="flex w-full max-w-[460px] flex-col gap-5 rounded-[20px] border border-teal-500 bg-slate-800 px-9 py-9">
          {head("登録できました。スマホをなくしたときのために、リカバリーコードを保存してください。")}
          <div className="rounded-[10px] border border-[#6B5A19] bg-[#2A2410] px-3.5 py-2.5 text-[13px] leading-relaxed text-[#F5D98A]">このコードは今しか表示されません。各コードは 1 回だけ使えます。パスワードマネージャーか、印刷して鍵のかかる場所に保管してください。</div>
          <ul className="m-0 grid list-none grid-cols-2 gap-2 p-0 font-mono text-[15px] text-teal-200">{codes.map((c) => <li key={c} className="select-all rounded-lg bg-slate-900 px-3 py-1.5 text-center tracking-wider">{c}</li>)}</ul>
          <button type="button" className="self-center rounded-lg border border-slate-600 px-3 py-1.5 text-[13px] text-slate-200 hover:bg-slate-700" onClick={copyCodes}>コピー</button>
          <label className="flex items-center gap-2 text-[13px] text-slate-300"><input id="codes-saved" type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />保存しました</label>
          <button className={BTN} disabled={!saved} onClick={() => onLogin()}>MamorAI を使い始める</button>
        </div>
      )}
    </div>
  );
}
