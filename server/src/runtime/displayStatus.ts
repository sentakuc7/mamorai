/**
 * EDR-172: what the session card on the left shows (14 states). The stored session.status only says what the AI loop is
 * doing (running / waiting_user / ...); while an approved change runs, a restart is pending or a Contain is in force the
 * card used to say 「承認待ち」 or 「完了」. This derives the state from approvals, host actions and schedules.
 */
import type { Knex } from "knex";
import { pj } from "../db/index.js";

export type DisplayKey = "investigating" | "waiting_user" | "waiting_approval" | "executing" | "scheduled" | "reboot_wait"
  | "unconfirmed" | "contained" | "monitoring" | "waiting_external" | "done" | "failed" | "rejected" | "cancelled";
export interface DisplayStatus { key: DisplayKey; note: string | null; extra: DisplayKey[] }

/** strongest first (the card shows the first one; the others as small chips) */
export const DISPLAY_ORDER: DisplayKey[] = ["contained", "executing", "waiting_approval", "reboot_wait", "scheduled", "unconfirmed", "investigating", "waiting_user", "rejected", "monitoring", "waiting_external", "failed", "done", "cancelled"];

const jst = (iso: string | null | undefined): string | null => {
  if (!iso) return null; const t = Date.parse(iso); if (!t) return null;
  const d = new Date(t + 9 * 3600_000); const now = new Date(Date.now() + 9 * 3600_000);
  const hm = `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
  return d.toISOString().slice(0, 10) === now.toISOString().slice(0, 10) ? hm : `${d.getUTCMonth() + 1}/${d.getUTCDate()} ${hm}`;
};

export interface DisplayInput { status: string; approvals: any[]; actions: any[]; schedules: any[] }

export function deriveDisplay(x: DisplayInput): DisplayStatus {
  const found = new Map<DisplayKey, string | null>();
  const add = (k: DisplayKey, note: string | null = null) => { if (!found.has(k)) found.set(k, note); };
  const aps = [...x.approvals].sort((a, b) => b.id - a.id);
  for (const a of aps) {
    const r = pj<any>(a.exec_result);
    if (a.decision === "pending") add("waiting_approval");
    else if (["approved", "edited"].includes(a.decision)) {
      if (r?.status === "scheduled") add("scheduled", a.run_after ? `${jst(a.run_after)} に実行` : null);
      else if (!r || r.status === "running") {
        const wu = r?.win_update; const items = wu?.items ?? [];
        const done = items.filter((i: any) => ["installed", "failed"].includes(i.state)).length;
        add("executing", items.length ? `${done}/${items.length}` : (r?.current_purpose ? String(r.current_purpose).slice(0, 40) : null));
      }
    }
  }
  for (const h of x.actions) {
    const res = pj<any>(h.result);
    if (h.op === "isolate" && ["active", "unconfirmed"].includes(h.status)) add("contained");
    else if (h.op === "reboot" && ["running", "active"].includes(h.status)) add("reboot_wait", res?.progress ? null : null);
    else if (["running"].includes(h.status)) add("executing");
    else if (h.status === "unconfirmed") add("unconfirmed");
  }
  for (const s of x.schedules) if (s.enabled && s.state === "active") add("monitoring", s.next_run_at ? `次回 ${jst(s.next_run_at)}` : null);
  // the AI loop itself
  const base: Record<string, DisplayKey> = { running: "investigating", waiting_approval: "waiting_approval", waiting_user: "waiting_user", waiting_external: "waiting_external", done: "done", failed: "failed", cancelled: "cancelled" };
  const b = base[x.status] ?? "waiting_user";
  // a stored "承認待ち" without a pending card means the approved plan is running (or just finished): do not say 承認待ち
  if (!(b === "waiting_approval" && !found.has("waiting_approval"))) add(b);
  // stopped because the last decided card was rejected
  const lastDecided = aps.find((a) => a.decision !== "pending");
  if (lastDecided?.decision === "rejected" && ["waiting_user", "done"].includes(x.status) && !found.has("executing")) add("rejected");
  // the last change failed
  const lastExec = aps.find((a) => ["approved", "edited"].includes(a.decision) && pj<any>(a.exec_result)?.status);
  const ls = pj<any>(lastExec?.exec_result)?.status;
  if (ls && !["executed", "running", "scheduled"].includes(ls) && ["waiting_user", "done", "failed"].includes(x.status)) add("failed");
  if (!found.size) add("waiting_user");
  const keys = DISPLAY_ORDER.filter((k) => found.has(k));
  // terminal states only as the main one when nothing else is going on
  return { key: keys[0], note: found.get(keys[0]) ?? null, extra: keys.slice(1).filter((k) => !["done", "cancelled", "investigating", "waiting_user"].includes(k)).slice(0, 3) };
}

/** batch: display status for many sessions (list view) */
export async function displayFor(db: Knex, sessions: { id: number; status: string }[]): Promise<Map<number, DisplayStatus>> {
  const ids = sessions.map((s) => s.id); const out = new Map<number, DisplayStatus>();
  if (!ids.length) return out;
  const aps = await db("approvals").whereIn("session_id", ids).select("id", "session_id", "decision", "exec_result", "run_after");
  const apIds = aps.map((a: any) => a.id);
  const acts = apIds.length ? await db("host_actions").whereIn("approval_id", apIds).whereIn("status", ["running", "active", "unconfirmed"]).select("id", "op", "status", "approval_id", "result") : [];
  const sch = await db("schedules").whereIn("session_id", ids).select("session_id", "enabled", "state", "next_run_at");
  const apSession = new Map<number, number>(aps.map((a: any) => [a.id, a.session_id]));
  for (const s of sessions) {
    out.set(s.id, deriveDisplay({ status: s.status, approvals: aps.filter((a: any) => a.session_id === s.id), actions: acts.filter((h: any) => apSession.get(h.approval_id) === s.id), schedules: sch.filter((x: any) => x.session_id === s.id) }));
  }
  return out;
}
