import { useState } from "react";
import { api } from "../lib/api";
import { t } from "../lib/i18n";
import { Ico } from "../components/Icon";

const INPUT = "w-full min-h-[44px] rounded-[10px] border border-slate-600 bg-slate-900 px-3 text-[15px] text-slate-100 placeholder-slate-500 focus:border-teal-400 focus:outline-none";
const LABEL = "mb-1.5 block text-[13px] text-slate-400";
const LOCK = "M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4";

export default function ChangePassword({ onDone }: { onDone: () => Promise<void> }) {
  const [current, setCurrent] = useState(""); const [next, setNext] = useState(""); const [err, setErr] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr("");
    try { await api.post("/auth/change-password", { current, next }); alert("Password changed. Please sign in again."); await onDone(); }
    catch (e: any) { setErr(e.message); }
  };
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 p-4">
      <form onSubmit={submit} className="flex w-full max-w-[420px] flex-col gap-[18px] rounded-[20px] border border-teal-500 bg-slate-800 p-9">
        <div className="flex items-center gap-2.5"><Ico d={LOCK} size={22} /><h1 className="m-0 text-[17px] font-semibold">{t("pw.title")}</h1></div>
        <div><label className={LABEL} htmlFor="pw-cur">{t("pw.current")}</label><input id="pw-cur" className={INPUT} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required /></div>
        <div><label className={LABEL} htmlFor="pw-next">{t("pw.next")}</label><input id="pw-next" className={INPUT} type="password" minLength={12} value={next} onChange={(e) => setNext(e.target.value)} required /></div>
        {err && <div role="alert" className="rounded-[10px] border border-[#6B2329] bg-[#2A1216] px-3.5 py-2.5 text-[13px] text-[#FF9A9D]">{err}</div>}
        <button className="min-h-[48px] rounded-xl bg-teal-500 text-[15px] font-bold text-white transition hover:bg-teal-400">{t("pw.submit")}</button>
      </form>
    </div>
  );
}
