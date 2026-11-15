/**
 * スケジュール実行（EDR-77）: AI チャットから登録された定期タスクを、登録元セッションに「⏰ スケジュール実行」メッセージとして投入し、
 * AI に実行させる。結果（最後の assistant 発言）は schedule_runs と schedules.last_result に残り、チャット画面にもそのまま出る。
 */
import type { Ctx } from "../api/context.js";
import type { SessionEvent } from "../runtime/index.js";

const TZ_OFFSET_MIN = 9 * 60; // JST
const RUN_TIMEOUT_MS = 20 * 60_000;
const TERMINAL = new Set(["waiting_user", "waiting_external", "done", "failed", "cancelled"]);

export const EVERY: Record<string, number> = { "15m": 15, "30m": 30, "1h": 60, "2h": 120, "3h": 180, "6h": 360, "12h": 720, "1d": 1440, "2d": 2880, "3d": 4320, "7d": 10080, "14d": 20160, "30d": 43200 };
const UNIT_JA: Record<string, string> = { m: "分", h: "時間", d: "日" };
export function everyLabel(min: number): string { const k = Object.entries(EVERY).find(([, v]) => v === min)?.[0]; return k ? `${k.slice(0, -1)}${UNIT_JA[k.slice(-1)]}ごと` : `${min} 分ごと`; }

/** 次回実行時刻: 間隔を足し、at_time があり間隔が 1 日以上なら JST のその時刻に揃える */
/** EDR-168: the first run of a new schedule: the next "HH:MM" (JST) from now, today if it is still ahead (not "tomorrow at HH:MM") */
export function firstRun(from: Date, intervalMin: number, atTime?: string | null): Date {
  if (atTime && intervalMin >= 1440 && /^\d{1,2}:\d{2}$/.test(atTime)) {
    const [hh, mm] = atTime.split(":").map(Number);
    const jst = new Date(from.getTime() + TZ_OFFSET_MIN * 60_000);
    jst.setUTCHours(hh, mm, 0, 0);
    let t = new Date(jst.getTime() - TZ_OFFSET_MIN * 60_000);
    if (t.getTime() < from.getTime() + 60_000) t = new Date(t.getTime() + 86_400_000);
    return t;
  }
  return nextRun(from, intervalMin, atTime);
}

export function nextRun(from: Date, intervalMin: number, atTime?: string | null): Date {
  let t = new Date(from.getTime() + intervalMin * 60_000);
  if (atTime && intervalMin >= 1440 && /^\d{1,2}:\d{2}$/.test(atTime)) {
    const [hh, mm] = atTime.split(":").map(Number);
    const jst = new Date(t.getTime() + TZ_OFFSET_MIN * 60_000);
    jst.setUTCHours(hh, mm, 0, 0);
    t = new Date(jst.getTime() - TZ_OFFSET_MIN * 60_000);
    if (t.getTime() < from.getTime() + Math.max(intervalMin - 1440, 0) * 60_000 + 60_000) t = new Date(t.getTime() + 86_400_000);
  }
  return t;
}

export class Scheduler {
  private timer: NodeJS.Timeout | null = null;
  private inflight = new Map<number, { runId: number; sessionId: number; started: number; waiting?: boolean }>();
  constructor(private ctx: Ctx) {}

  start() {
    this.ctx.runtime!.events.on("event", (ev: SessionEvent) => { this.onEvent(ev).catch((e) => this.ctx.log.warn({ err: e.message }, "scheduler event failed")); });
    this.timer = setInterval(() => this.tick().catch((e) => this.ctx.log.warn({ err: e.message }, "scheduler tick failed")), 30_000);
    setTimeout(() => this.tick().catch(() => {}), 5_000);
  }
  stop() { if (this.timer) clearInterval(this.timer); }

  async tick() {
    const { db } = this.ctx; const now = new Date();
    for (const [sid, f] of this.inflight) if (!f.waiting && Date.now() - f.started > RUN_TIMEOUT_MS) await this.finish(sid, f.sessionId, "timeout", "（タイムアウト: 20 分以内に完了しませんでした）");
    const due = await db("schedules").where({ enabled: true, state: "active" }).where("next_run_at", "<=", now.toISOString()).orderBy("next_run_at");
    for (const s of due) { if (!this.inflight.has(s.id)) await this.run(s, "schedule"); }
    await this.ctx.runtime!.runDueApprovals(); // EDR-168: changes approved for a later time
  }

  /** 1 回実行（手動実行にも使う） */
  async run(s: any, trigger: "schedule" | "manual"): Promise<{ started: boolean; reason?: string }> {
    const { db, runtime } = this.ctx;
    const sess = await db("sessions").where({ id: s.session_id }).first();
    if (!sess) { await db("schedules").where({ id: s.id }).update({ enabled: false, state: "cancelled", last_status: "error", last_result: "登録元セッションが見つかりません", updated_at: db.fn.now() }); return { started: false, reason: "session missing" }; }
    if (["running", "waiting_approval"].includes(sess.status)) {
      if (trigger === "schedule") await db("schedules").where({ id: s.id }).update({ next_run_at: new Date(Date.now() + 5 * 60_000).toISOString(), last_status: "skipped", updated_at: db.fn.now() });
      return { started: false, reason: sess.status === "running" ? "セッションが実行中のため 5 分後に再試行します" : "承認待ちのため、承認 / 却下されるまで実行を保留します" };
    }
    const n = (s.run_count ?? 0) + 1;
    const [runId] = await db("schedule_runs").insert({ schedule_id: s.id, session_id: s.session_id, status: "running" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    this.inflight.set(s.id, { runId, sessionId: s.session_id, started: Date.now() });
    const text = `⏰ スケジュール実行 #${s.id}「${s.title}」（${n} 回目${s.max_runs ? ` / 最大 ${s.max_runs}` : ""}、${everyLabel(s.interval_min)}）\n${s.prompt}${s.goal ? `\n\n達成条件: ${s.goal}` : ""}\n\n[指示] これは自動実行です。人間は見ていない前提で、結果を 1〜3 文で報告してください。` +
      `\n- 達成条件を満たした / 対処できる状態になった場合: add_action(kind="change", commands 付き) でタスクを登録し、続けて apply_change（next_action_id を渡す）で承認待ちにしてから complete_schedule(schedule_id=${s.id}) を呼ぶ。` +
      `\n- まだの場合: 「未達」と理由を短く報告するだけ。新しいスケジュールは登録しない。` +
      `\n- これ以上続ける意味がない場合（対象が消えた等）: complete_schedule(schedule_id=${s.id}, result="...") で終了する。` +
      `\n- propose_next_actions と close_investigation は呼ばない（既存の提案が消えるため）。` +
      `\n- 確認は読み取り専用コマンドで行う（apt list --upgradable / apt-cache policy / rpm -q 等）。apt update のような書き込みは承認待ちで止まるので、必要なときだけ使う。`;
    await db("schedules").where({ id: s.id }).update({ last_run_at: db.fn.now(), run_count: n, next_run_at: nextRun(new Date(), s.interval_min, s.at_time).toISOString(), last_status: "running", updated_at: db.fn.now() });
    await this.ctx.audit.log("system", null, "schedule.run", { schedule_id: s.id, run_id: runId, trigger }, s.session_id);
    try { await runtime!.scheduledMessage(s.session_id, text); }
    catch (e: any) { await this.finish(s.id, s.session_id, "error", `起動に失敗: ${e.message}`); return { started: false, reason: e.message }; }
    return { started: true };
  }

  private async onEvent(ev: SessionEvent) {
    if (ev.type !== "status") return;
    const st0 = String((ev as any).status);
    if (st0 === "waiting_approval") {
      // 承認待ち: 実行は人間の承認後に続く。タイムアウト対象から外して待つ
      for (const [, f] of this.inflight) if (f.sessionId === ev.session_id && !f.waiting) { f.waiting = true; await this.ctx.db("schedule_runs").where({ id: f.runId }).update({ status: "waiting_approval", result: "承認待ち（承認キューで承認すると続きが実行されます）" }); await this.ctx.db("schedules").where({ session_id: ev.session_id, last_status: "running" }).update({ last_status: "waiting_approval", updated_at: this.ctx.db.fn.now() }); }
      return;
    }
    if (st0 === "running") { for (const [, f] of this.inflight) if (f.sessionId === ev.session_id && f.waiting) { f.waiting = false; f.started = Date.now(); } return; }
    if (!TERMINAL.has(st0)) return;
    for (const [sid, f] of [...this.inflight]) if (f.sessionId === ev.session_id) {
      const { db } = this.ctx;
      // 最後の assistant テキスト（messages.content は ChatMessage の JSON）
      const rows = await db("messages").where({ session_id: f.sessionId, role: "assistant" }).orderBy("id", "desc").limit(5);
      let txt = "";
      for (const r of rows) { try { const m = JSON.parse(r.content); if (typeof m?.content === "string" && m.content.trim()) { txt = m.content.trim(); break; } } catch { if (String(r.content).trim()) { txt = String(r.content).trim(); break; } } }
      const st = (ev as any).status === "failed" ? "error" : "ok";
      await this.finish(sid, f.sessionId, st, txt || (st === "ok" ? "（応答なし）" : "（失敗）"));
    }
  }

  async finish(scheduleId: number, sessionId: number, status: string, result: string) {
    const f = this.inflight.get(scheduleId); this.inflight.delete(scheduleId);
    const { db } = this.ctx;
    if (f) await db("schedule_runs").where({ id: f.runId }).update({ status, result: result.slice(0, 4000), finished_at: db.fn.now() });
    const s = await db("schedules").where({ id: scheduleId }).first();
    if (!s) return;
    const upd: any = { last_status: status, last_result: result.slice(0, 4000), updated_at: db.fn.now() };
    if (s.max_runs && s.run_count >= s.max_runs && s.state === "active") { upd.state = "done"; upd.enabled = false; }
    await db("schedules").where({ id: scheduleId }).update(upd);
    if (upd.state) await this.ctx.runtime!.refreshWaiting(sessionId).catch(() => {});
    this.ctx.runtime!.events.emit("event", { type: "schedule", session_id: sessionId, schedule_id: scheduleId, status } as any);
  }
}
