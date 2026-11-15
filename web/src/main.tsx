import React, { useEffect, useState } from "react";
import { onServerEvent } from "./lib/events";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route, NavLink, Navigate } from "react-router-dom";
import "./index.css";
import { api, type User } from "./lib/api";
import { t, setLocale } from "./lib/i18n";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Overview from "./pages/Overview";
import Alerts from "./pages/Alerts";
import Settings from "./pages/Settings";
import Audit from "./pages/Audit";
import Sidekick from "./pages/Sidekick";
import Playbooks from "./pages/Playbooks";
import Hosts from "./pages/Hosts";
import ContainHelp from "./pages/ContainHelp";
import Help from "./pages/Help";
import Cloud from "./pages/Cloud";
import Approvals from "./pages/Approvals";
import ProcessTree from "./pages/ProcessTree";
import NextActions from "./pages/NextActions";
import Schedules from "./pages/Schedules";
import { ScsDashboard, ScsVulns, ScsAssets } from "./pages/Scs";
import ChangePassword from "./pages/ChangePassword";
import ErrorBoundary from "./components/ErrorBoundary";
import { LogoMark, Wordmark } from "./components/Logo";
import { ModeCtx, loadMode, saveMode, type ViewMode } from "./lib/mode";

export const UserCtx = React.createContext<{ user: User | null; refresh: () => Promise<void> }>({ user: null, refresh: async () => {} });

function ModeToggle() {
  const { mode, setMode } = React.useContext(ModeCtx);
  return (
    <div role="group" aria-label="表示モード" className="flex overflow-hidden rounded-lg border border-slate-600 text-[13px]">
      {(["simple", "detail"] as ViewMode[]).map((m) => <button key={m} onClick={() => setMode(m)} className={`flex-1 py-1.5 transition ${mode === m ? "bg-teal-500 text-white" : "text-slate-400 hover:text-slate-200"}`}>{m === "simple" ? "かんたん" : "詳細"}</button>)}
    </div>
  );
}

/** Stroke icons for the side navigation (24x24 viewBox). */
const ICON: Record<string, string> = {
  dashboard: "M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 9h8V3h-8z",
  scs: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4",
  vulns: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM12 8v5M12 16h.01",
  assets: "M4 5h16v10H4zM8 19h8M12 15v4",
  overview: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
  alerts: "M12 3l10 18H2zM12 10v4M12 17h.01",
  sidekick: "M21 12a8 8 0 0 1-11.5 7.2L4 21l1.8-5.5A8 8 0 1 1 21 12z",
  approvals: "M9 12l2 2 4-4M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  actions: "M4 4h5v16H4zM10 4h5v10h-5zM16 4h4v7h-4z",
  schedules: "M12 8v4l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z",
  hosts: "M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01",
  cloud: "M7 18a5 5 0 1 1 1-9.9A6 6 0 0 1 19 10a4 4 0 0 1-1 8z",
  playbooks: "M4 4h11a3 3 0 0 1 3 3v13H7a3 3 0 0 1-3-3zM18 20V7",
  audit: "M6 2h9l5 5v15H6zM14 2v6h6M9 13h8M9 17h8",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM4 12h2M18 12h2M12 4v2M12 18v2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M6.3 17.7l1.4-1.4M16.3 7.7l1.4-1.4",
};
const NavIcon = ({ k }: { k: string }) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="shrink-0"><path d={ICON[k]} /></svg>;

type NavItem = { to: string; k: string; label: string; badge?: "approvals" | "actions" };
const NAV: { label: string; items: NavItem[]; scs?: boolean }[] = [
  { label: "監視", items: [{ to: "/", k: "dashboard", label: t("nav.dashboard") }, { to: "/overview", k: "overview", label: "攻撃可視化" }, { to: "/alerts", k: "alerts", label: t("nav.alerts") }] },
  { label: "対応", items: [{ to: "/sidekick", k: "sidekick", label: t("nav.sidekick") }, { to: "/approvals", k: "approvals", label: t("nav.approvals"), badge: "approvals" }, { to: "/next-actions", k: "actions", label: "Action ボード", badge: "actions" }, { to: "/schedules", k: "schedules", label: "スケジュール" }] },
  { label: "資産・ナレッジ", items: [{ to: "/hosts", k: "hosts", label: "管理ホスト" }, { to: "/cloud", k: "cloud", label: "クラウド管理" }, { to: "/playbooks", k: "playbooks", label: "プレイブック" }] },
  { label: "SCS 評価制度", scs: true, items: [{ to: "/scs", k: "scs", label: "SCS ダッシュボード" }, { to: "/scs/vulns", k: "vulns", label: "脆弱性台帳" }, { to: "/scs/assets", k: "assets", label: "資産台帳" }] }, // EDR-176（設定でオン / オフ）
  { label: "管理", items: [{ to: "/audit", k: "audit", label: t("nav.audit") }, { to: "/settings", k: "settings", label: t("nav.settings") }] },
];
/** EDR-176: SCS 機能（設定でオン / オフ）。オフならメニューに出さない */
function useScsEnabled() {
  const [on, setOn] = useState(false);
  useEffect(() => { api.get<{ enabled: boolean }>("/scs/settings").then((r) => setOn(!!r.enabled)).catch(() => setOn(false)); }, []);
  return on;
}

/** Pending approvals / open actions for the nav badges (refreshed on server events). */
function useNavCounts() {
  const [c, setC] = useState<{ approvals: number; actions: number }>({ approvals: 0, actions: 0 });
  useEffect(() => {
    const load = () => Promise.all([api.get<{ items: any[] }>("/approvals?decision=pending&limit=200"), api.get<{ items: any[] }>("/next-actions?limit=200")])
      .then(([ap, na]) => setC({ approvals: ap.items.length, actions: na.items.filter((a) => ["proposed", "blocked", "approved", "executing"].includes(a.status)).length }))
      .catch(() => {});
    load();
    const off = onServerEvent(["approval", "next_actions", "status"], load);
    // fallback: an event can be missed (reconnect, another tab) — re-count every 30 s and when the window gets focus
    const iv = setInterval(load, 30_000); window.addEventListener("focus", load);
    return () => { off(); clearInterval(iv); window.removeEventListener("focus", load); };
  }, []);
  return c;
}

/** EDR-90: kill switch for automatic approvals (stop / resume with one click, admins only) */
function SafetySwitch({ user }: { user: User }) {
  const [hold, setHold] = useState<{ on: boolean; reason: string | null } | null>(null);
  const [err, setErr] = useState("");
  const load = () => api.get<{ auto_approval_hold: { on: boolean; reason: string | null } }>("/safety").then((r) => setHold(r.auto_approval_hold)).catch(() => {});
  useEffect(() => { load(); return onServerEvent("status", load); }, []);
  if (!hold) return null;
  const admin = user.role === "admin";
  const put = async (on: boolean) => {
    setErr("");
    try { const r = await api.put<{ auto_approval_hold: any }>("/safety", { hold: on, reason: on ? "管理者が緊急停止" : "管理者が再開" }); setHold(r.auto_approval_hold); }
    catch (e: any) { setErr(e.message); }
  };
  return (
    <div className={`mx-1 mt-2 rounded-lg border px-3 py-2 text-xs ${hold.on ? "border-[#5A1E24] bg-[#2A0F14] text-[#FF9A9D]" : "border-slate-700 text-slate-400"}`}>
      <div className="flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${hold.on ? "bg-[#F2555A]" : "bg-[#3CCB8C]"}`} /><span className="flex-1 font-semibold">{hold.on ? "自動承認を停止中" : "自動承認: 有効"}</span>
        {admin && !hold.on && <button className="rounded-md border border-[#4A1E24] px-2 py-0.5 text-[11px] text-[#FF9A9D] hover:bg-[#2A1216]" onClick={() => put(true)} title="AI の変更を自動で承認する仕組み（再試行の自動承認・自律度 L2/L3）をすべて止め、全部人の承認に戻します">緊急停止</button>}
        {admin && hold.on && <button className="rounded-md border border-slate-600 px-2 py-0.5 text-[11px] text-slate-200 hover:bg-slate-700" onClick={() => put(false)}>再開</button>}
      </div>
      {hold.on && hold.reason && <div className="mt-1 leading-snug">{hold.reason}</div>}
      {err && <div className="mt-1">{err}</div>}
    </div>
  );
}

function Shell({ user, onLogout }: { user: User; onLogout: () => void }) {
  const counts = useNavCounts();
  const scsOn = useScsEnabled();
  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r border-slate-700 bg-slate-900 px-3.5 py-4">
        <div className="mb-2 flex items-center gap-2.5 px-2">
          <LogoMark size={30} />
          <div className="flex flex-col leading-tight"><Wordmark className="text-xl" /><span className="font-mono text-[11px] text-slate-500">v0.1 · lab</span></div>
        </div>
        <div className="mx-1 mb-2 mt-2"><ModeToggle /></div>
        <nav aria-label="メインメニュー" className="flex-1 space-y-2 overflow-y-auto">
          {NAV.filter((g) => !g.scs || scsOn).map((g) => (
            <div key={g.label}>
              <div className="px-3 pb-1 pt-2 text-[11px] font-semibold tracking-widest text-slate-500">{g.label}</div>
              <div className="space-y-0.5">
                {g.items.map((it) => {
                  const n = it.badge ? counts[it.badge] : 0;
                  return (
                    <NavLink key={it.to} to={it.to} end={it.to === "/" || it.to === "/scs"} className={({ isActive }) => `flex min-h-[36px] items-center gap-2.5 rounded-lg px-3 py-1.5 text-sm transition ${isActive ? "bg-teal-500/15 font-semibold text-white" : "text-slate-300 hover:bg-slate-700"}`}>
                      <NavIcon k={it.k} /><span className="flex-1">{it.label}</span>
                      {n > 0 && <span className={`rounded-full px-2 text-xs font-bold text-white ${it.badge === "approvals" ? "bg-rose-600" : "bg-teal-500"}`}>{n}</span>}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
        <SafetySwitch user={user} />
        {user.role === "admin" && <a href="/wazuh/app/wz-home" target="_blank" rel="noreferrer" className="mx-1 mt-2 flex min-h-[36px] items-center gap-2.5 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700" title="MamorAI のログイン（パスワード＋認証アプリ）で Wazuh ダッシュボードを開きます"><NavIcon k="overview" /><span className="flex-1">Wazuh ダッシュボード</span><span aria-hidden="true" className="text-xs text-slate-500">↗</span></a>}
        <div className="mt-4 border-t border-slate-700 px-2 pt-3 text-xs">
          <div className="truncate text-sm font-semibold text-slate-100">{user.name}</div>
          <div className="truncate text-slate-400">{user.email} · {user.role}</div>
          <button className="mt-2 rounded-md border border-slate-600 px-3 py-1 text-slate-300 hover:bg-slate-700" onClick={onLogout}>ログアウト</button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-6">
        <ErrorBoundary>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/sidekick" element={<Sidekick />} />
          <Route path="/sidekick/:id" element={<Sidekick />} />
          <Route path="/approvals" element={<Approvals />} />
          <Route path="/process-tree" element={<ProcessTree />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/cloud" element={<Cloud />} />
          <Route path="/next-actions" element={<NextActions />} />
          <Route path="/schedules" element={<Schedules />} />
          <Route path="/scs" element={<ScsDashboard />} />
          <Route path="/scs/vulns" element={<ScsVulns />} />
          <Route path="/scs/assets" element={<ScsAssets />} />
          <Route path="/playbooks" element={<Playbooks />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/hosts/:id/contain" element={<ContainHelp />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/settings/*" element={<Settings />} />
          <Route path="/help/:topic" element={<Help />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
        </ErrorBoundary>
      </main>
    </div>
  );
}

function App() {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [pending, setPending] = useState<{ stage: "verify" | "enroll"; email?: string } | null>(null);
  const [mode, setModeState] = useState<ViewMode>(loadMode());
  const setMode = (m: ViewMode) => { setModeState(m); saveMode(m); };
  const refresh = async () => {
    // EDR-90: a session can be waiting for the second factor (TOTP) — show that step of the sign-in
    try {
      const r = await api.get<{ user: User | null; mfa_pending?: "verify" | "enroll"; email?: string }>("/auth/me");
      if (r.user) { setLocale(r.user.locale); setPending(null); setUser(r.user); }
      else { setPending(r.mfa_pending ? { stage: r.mfa_pending, email: r.email } : null); setUser(null); }
    } catch { setPending(null); setUser(null); }
  };
  useEffect(() => { refresh(); }, []);
  if (user === undefined) return <div className="p-8 text-slate-400">{t("common.loading")}</div>;
  if (!user) return <Login key={pending?.stage ?? "password"} onLogin={refresh} initialStage={pending?.stage} initialEmail={pending?.email} />;
  if (user.must_change_password) return <ChangePassword onDone={refresh} />;
  return (
    <UserCtx.Provider value={{ user, refresh }}>
      <ModeCtx.Provider value={{ mode, setMode }}>
        <BrowserRouter>
          <Shell user={user} onLogout={async () => { await api.post("/auth/logout"); setUser(null); }} />
        </BrowserRouter>
      </ModeCtx.Provider>
    </UserCtx.Provider>
  );
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
