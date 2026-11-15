import { alertTitle } from "../runtime/title.js";
import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Ctx } from "./context.js";
import { requireRole } from "../auth/index.js";
import { pj } from "../db/index.js";
import type { SessionEvent } from "../runtime/index.js";

type H = (req: Request, res: Response) => Promise<unknown>;
const wrap = (fn: H) => (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);
function parse<S extends z.ZodTypeAny>(schema: S, data: unknown): z.infer<S> {
  const r = schema.safeParse(data);
  if (!r.success) throw Object.assign(new Error("validation: " + r.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join(", ")), { status: 400 });
  return r.data;
}

export function sessionsRouter(ctx: Ctx): Router {
  const r = Router();
  const rt = ctx.runtime!;
  const { db } = ctx;

  r.get("/llm/status", requireRole("viewer"), (_req, res) => res.json(rt.llmStatus));

  r.get("/sessions", requireRole("viewer"), wrap(async (req, res) => {
    const q = parse(z.object({ limit: z.coerce.number().min(1).max(500).default(50), status: z.string().optional(), kind: z.string().optional(), archived: z.coerce.number().optional(), q: z.string().max(200).optional() }), req.query);
    let qb = db("sessions").orderBy("id", "desc").limit(q.limit);
    if (q.status) qb = qb.where("status", q.status);
    if (q.kind) qb = qb.where("kind", q.kind);
    if (q.archived) qb = qb.whereNotNull("archived_at"); else qb = qb.whereNull("archived_at");
    if (q.q) { const like = `%${q.q}%`; qb = qb.where((w) => w.where("title", "like", like).orWhere("label", "like", like).orWhere("tags", "like", like)); }
    const rows = await qb;
    const disp = await (await import("../runtime/displayStatus.js")).displayFor(db, rows).catch(() => new Map()); // EDR-172
    const items = rows.map((s: any) => ({ ...s, summary: pj(s.summary), alert_ref: pj(s.alert_ref), tags: pj(s.tags) ?? [], display: disp.get(s.id) ?? null }));
    const archivedCount = Number((await db("sessions").whereNotNull("archived_at").count<{ c: number }[]>({ c: "*" }).first())?.c ?? 0);
    res.json({ items, archived_count: archivedCount });
  }));

  const attachmentSchema = z.object({ name: z.string().min(1).max(255), content: z.string().max(6_000_000), mime: z.string().max(128).optional(), encoding: z.enum(["utf8", "base64"]).optional() });
  const KICKOFF: Record<string, string> = {
    playbook_setup: "新しいプレイブックを作りたい。ヒアリングを始めてください。",
    host_setup: "新しいホストを登録したい。手順を案内しながらヒアリングを始めてください。",
    overview_setup: "攻撃可視化（Overview）を描けるようにしたい。まず現状を診断して、足りないものを教えてください。",
    cloud_setup: "クラウド管理について相談したい。まず cloud_list で現状を確認してから、何をしたいか聞いてください。",
    contain_consult: "この端末のインターネット通信遮断（Contain）について相談したい。まず host_profile で端末の状況を確認し、遮断すると何が起きるかをポンチ絵付きで短く説明してから、何が気になるか聞いてください。",
  };
  r.post("/sessions", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({
      kind: z.enum(["investigate", "playbook_setup", "host_setup", "overview_setup", "cloud_setup", "contain_consult"]).default("investigate"),
      title: z.string().min(1).max(255).optional(), message: z.string().min(1).optional(), wazuh_instance_id: z.number().int().optional(), host_ids: z.array(z.number().int()).optional(), alert: z.any().optional(),
      attachments: z.array(attachmentSchema).max(10).optional(),
      context: z.object({ playbook_id: z.number().int().nullable().optional(), host_id: z.number().int().nullable().optional() }).optional(),
    }), req.body);
    if (b.kind === "contain_consult" && !b.context?.host_id) return res.status(400).json({ error: "context.host_id required" });
    // EDR-147: every AI chat is open to operators; admin-only tools are refused inside the chat (runtime ADMIN_ONLY_TOOLS)
    const message = b.message ?? KICKOFF[b.kind];
    if (!message) return res.status(400).json({ error: "message required" });
    const title = b.title ?? (b.alert?.rule ? await alertTitle(db, b.alert) : b.kind === "playbook_setup" ? "プレイブック作成（AI ガイド）" : b.kind === "host_setup" ? "ホスト登録（AI ガイド）" : b.kind === "overview_setup" ? "攻撃可視化セットアップ（AI ガイド）" : b.kind === "cloud_setup" ? "クラウド管理（AI 相談）" : b.kind === "contain_consult" ? `通信遮断の相談: ${(await db("hosts").where({ id: b.context!.host_id! }).first())?.name ?? "host#" + b.context!.host_id}` : message.slice(0, 80));
    const id = await rt.createSession({ origin: "user", kind: b.kind, title, userId: req.user!.id, wazuhInstanceId: b.wazuh_instance_id ?? null, hostIds: b.host_ids ?? [], alertRef: b.alert, attachments: b.attachments, context: b.context,
      firstMessage: b.alert ? `${message}\n\nAlert context (JSON):\n${JSON.stringify(b.alert).slice(0, 6000)}` : message });
    res.status(201).json({ id });
  }));

  /** Attach text files to a session; the agent reads them with read_attachment. Optionally sends a message in the same call. */
  r.post("/sessions/:id/attachments", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = parse(z.object({ attachments: z.array(attachmentSchema).min(1).max(10), message: z.string().max(4000).optional() }), req.body);
    const s = await db("sessions").where({ id }).first();
    if (!s) return res.status(404).json({ error: "not found" });
    const saved: { id: number; name: string; size: number; image?: string }[] = [];
    for (const a of b.attachments) {
      const img = a.encoding === "base64";
      if (img && !/^image\/(png|jpeg|jpg|gif|webp)$/.test(a.mime ?? "")) return res.status(415).json({ error: "バイナリは画像（png/jpeg/gif/webp）のみ添付できます" });
      const r0 = await rt.addAttachment(id, req.user!.id, a, "in", undefined, img ? "base64" : "utf8", img ? Math.floor(a.content.length * 3 / 4) : undefined);
      saved.push({ ...r0, image: img ? a.mime : undefined });
    }
    const note = saved.map((a) => a.image ? `[画像] ${a.name}` : `[添付] ${a.name} (${a.size} bytes)`).join("\n");
    await rt.userMessage(id, req.user!.id, (b.message?.trim() ? b.message.trim() + "\n" : "") + note, saved.filter((a) => a.image).map((a) => ({ mime: a.image!, attachment_id: a.id })));
    res.status(201).json({ items: saved });
  }));
  r.get("/sessions/:id/attachments", requireRole("viewer"), wrap(async (req, res) => {
    res.json({ items: await db("attachments").where({ session_id: Number(req.params.id) }).select("id", "name", "size", "mime", "direction", "description", "created_at").orderBy("id") });
  }));
  /** Download / preview a session file (input attachment or agent output). SVG/HTML are served with a strict CSP for inline preview. */
  r.get("/sessions/:id/files/:fid", requireRole("viewer"), wrap(async (req, res) => {
    const f = await db("attachments").where({ session_id: Number(req.params.id), id: Number(req.params.fid) }).first();
    if (!f) return res.status(404).json({ error: "file not found" });
    const dl = req.query.download !== undefined;
    res.setHeader("Content-Type", f.mime ?? "application/octet-stream");
    res.removeHeader("X-Frame-Options"); // same-origin iframe preview; CSP below still forbids scripts
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Disposition", `${dl ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(f.name)}`);
    res.send(f.encoding === "base64" ? Buffer.from(f.content, "base64") : f.content);
  }));

  r.get("/sessions/:id", requireRole("viewer"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const s = await db("sessions").where({ id }).first();
    if (!s) return res.status(404).json({ error: "not found" });
    const messages = (await db("messages").where({ session_id: id }).orderBy("seq")).map((m: any) => ({ id: m.id, seq: m.seq, created_at: m.created_at, ...pj(m.content) })).filter((m: any) => m.role !== "system");
    const tool_calls = (await db("tool_calls").where({ session_id: id }).orderBy("id")).map((t: any) => ({ ...t, args: pj(t.args), result: pj(t.result) }));
    const hostsById = Object.fromEntries((await db("hosts")).map((h: any) => [h.id, h]));
    const approvals = (await db("approvals").where({ session_id: id }).orderBy("id")).map((a: any) => ({ ...a, host_name: hostsById[a.host_id]?.name, host_environment: hostsById[a.host_id]?.environment, steps: pj(a.steps), auto_checks: pj(a.auto_checks), exec_result: pj(a.exec_result) }));
    const next_actions = (await db("next_actions").where({ session_id: id }).orderBy("id")).map((n: any) => ({ ...n, commands: pj(n.commands), rollback: pj(n.rollback) }));
    const attachments = await db("attachments").where({ session_id: id }).select("id", "name", "size", "mime", "direction", "description", "created_at").orderBy("id");
    const schedules = await db("schedules").where({ session_id: id }).orderBy("id");
    const display = (await (await import("../runtime/displayStatus.js")).displayFor(db, [s]).catch(() => new Map())).get(s.id) ?? null; // EDR-172
    res.json({ session: { ...s, summary: pj(s.summary), alert_ref: pj(s.alert_ref), tags: pj(s.tags) ?? [], display }, messages, tool_calls, approvals, next_actions, attachments, schedules });
  }));

  r.post("/sessions/:id/message", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ message: z.string().min(1) }), req.body);
    await rt.userMessage(Number(req.params.id), req.user!.id, b.message);
    res.json({ ok: true });
  }));

  r.post("/sessions/:id/archive", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const r0 = await rt.archive(id, req.user!.id); res.json({ ok: true, ...r0 });
  }));
  r.post("/sessions/:id/unarchive", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    await db("sessions").where({ id }).update({ archived_at: null, updated_at: db.fn.now() });
    await ctx.audit.log("user", req.user!.id, "session.unarchived", {}, id); res.json({ ok: true });
  }));
  r.post("/sessions/:id/label", requireRole("operator"), wrap(async (req, res) => {
    const out = await rt.labelSession(Number(req.params.id), true); res.json(out ?? { ok: false });
  }));
  r.put("/sessions/:id/label", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ label: z.string().min(1).max(60), tags: z.array(z.string().max(24)).max(5).optional() }), req.body);
    const upd: any = { label: b.label, updated_at: db.fn.now() }; if (b.tags) upd.tags = JSON.stringify(b.tags);
    await db("sessions").where({ id: Number(req.params.id) }).update(upd); res.json({ ok: true });
  }));
  /** Permanently delete a session and everything attached to it (messages, tool calls, approvals, files). Admin, or the user who started it. */
  r.delete("/sessions/:id", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const s = await db("sessions").where({ id }).first();
    if (!s) return res.status(404).json({ error: "not found" });
    if (req.user!.role !== "admin" && s.started_by !== req.user!.id) return res.status(403).json({ error: "only admin or the owner can delete" });
    if (["running", "waiting_approval"].includes(s.status)) return res.status(409).json({ error: "cancel the session first" });
    await db("next_actions").where({ session_id: id }).delete();
    await db("approvals").where({ session_id: id }).delete();
    await db("sessions").where({ id }).delete(); // messages/tool_calls/attachments cascade
    await ctx.audit.log("user", req.user!.id, "session.deleted", { title: s.title, label: s.label }, id);
    res.json({ ok: true });
  }));
  r.post("/sessions/:id/cancel", requireRole("operator"), wrap(async (req, res) => { await rt.cancel(Number(req.params.id), req.user!.id); res.json({ ok: true }); }));
  r.post("/sessions/:id/done", requireRole("operator"), wrap(async (req, res) => { await rt.markDone(Number(req.params.id), req.user!.id); res.json({ ok: true }); }));
  r.post("/sessions/:id/reopen", requireRole("operator"), wrap(async (req, res) => { await rt.reopen(Number(req.params.id), req.user!.id); res.json({ ok: true }); }));
  r.post("/next-actions/:id/status", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ status: z.enum(["proposed", "approved", "executing", "done", "rejected", "rolled_back", "blocked"]) }), req.body);
    await db("next_actions").where({ id: Number(req.params.id) }).update({ status: b.status, updated_at: db.fn.now() });
    await ctx.audit.log("user", req.user!.id, "next_action.status", { id: Number(req.params.id), status: b.status });
    if (b.status === "done") rt.onActionDone(Number(req.params.id)).catch(() => {});
    else { const na = await db("next_actions").where({ id: Number(req.params.id) }).first(); if (na) rt.refreshWaiting(na.session_id).catch(() => {}); }
    res.json({ ok: true });
  }));

  // ---------- sentinel / triggers ----------
  r.get("/sentinel/status", requireRole("viewer"), (_req, res) => res.json(ctx.sentinel?.status ?? { enabled: false }));
  r.post("/sentinel/run", requireRole("admin"), wrap(async (req, res) => { await ctx.sentinel?.tick(true); await ctx.audit.log("user", req.user!.id, "sentinel.manual_run", ctx.sentinel?.lastRun); res.json(ctx.sentinel?.status ?? {}); }));
  r.get("/triggers", requireRole("viewer"), wrap(async (_req, res) => res.json({ items: (await db("triggers").orderBy("priority")).map((t: any) => ({ ...t, config: pj(t.config) })) })));
  r.put("/triggers/:id", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ name: z.string().min(1).optional(), enabled: z.boolean().optional(), config: z.record(z.any()).optional(), dedupe_window_sec: z.number().int().min(0).optional(), priority: z.number().int().optional() }), req.body);
    const upd: any = { ...b, updated_at: db.fn.now() }; if (b.config) upd.config = JSON.stringify(b.config);
    await db("triggers").where({ id: Number(req.params.id) }).update(upd);
    await ctx.audit.log("user", req.user!.id, "trigger.updated", { id: Number(req.params.id), fields: Object.keys(b) });
    res.json({ ...(await db("triggers").where({ id: Number(req.params.id) }).first()), config: b.config });
  }));
  r.get("/next-actions", requireRole("viewer"), wrap(async (req, res) => {
    const q = parse(z.object({ limit: z.coerce.number().min(1).max(200).default(100) }), req.query);
    const rows = await db("next_actions as n").leftJoin("sessions as s", "s.id", "n.session_id").leftJoin("hosts as h", "h.id", "n.host_id")
      .select("n.*", "s.title as session_title", "s.origin as session_origin", "s.status as session_status", "s.summary as session_summary", "s.created_at as session_created_at", "h.name as host_name").whereNull("s.archived_at").orderBy("n.id", "desc").limit(q.limit);
    res.json({ items: rows.map((x: any) => ({ ...x, commands: pj(x.commands), rollback: pj(x.rollback), session_summary: pj(x.session_summary) })) });
  }));

  // ---------- schedules (EDR-77) ----------
  r.get("/schedules", requireRole("viewer"), wrap(async (req, res) => {
    const q = parse(z.object({ session_id: z.coerce.number().optional(), all: z.coerce.boolean().optional() }), req.query);
    let qb = db("schedules as c").leftJoin("sessions as s", "s.id", "c.session_id").select("c.*", "s.title as session_title", "s.status as session_status", "s.kind as session_kind").orderBy("c.id", "desc");
    if (q.session_id) qb = qb.where("c.session_id", q.session_id);
    res.json({ items: await qb });
  }));
  r.get("/schedules/:id/runs", requireRole("viewer"), wrap(async (req, res) => { res.json({ items: await db("schedule_runs").where({ schedule_id: Number(req.params.id) }).orderBy("id", "desc").limit(50) }); }));
  const scheduleBody = z.object({ session_id: z.number().int().optional(), title: z.string().min(1).max(255), prompt: z.string().min(1), interval_min: z.number().int().min(15), at_time: z.string().regex(/^\d{1,2}:\d{2}$/).nullable().optional(), max_runs: z.number().int().nullable().optional(), goal: z.string().nullable().optional(), kind: z.enum(["investigate", "cloud_setup", "host_setup", "overview_setup", "playbook_setup"]).optional() });
  r.post("/schedules", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(scheduleBody, req.body); const { nextRun } = await import("../scheduler/index.js");
    let sessionId = b.session_id ?? null;
    if (!sessionId) {
      sessionId = await rt.createSession({ origin: "schedule", kind: b.kind ?? "investigate", title: `⏰ ${b.title}`, userId: req.user!.id, firstMessage: `このセッションはスケジュール「${b.title}」の実行用です。初回は何もせず、指示を待ってください。`, hostIds: [] });
    }
    const [id] = await db("schedules").insert({ session_id: sessionId, title: b.title, prompt: b.prompt, interval_min: b.interval_min, at_time: b.at_time ?? null, max_runs: b.max_runs ?? null, goal: b.goal ?? null, next_run_at: nextRun(new Date(), b.interval_min, b.at_time ?? null).toISOString(), created_by: "user" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await ctx.audit.log("user", req.user!.id, "schedule.created", { id, title: b.title }, sessionId);
    await rt.refreshWaiting(sessionId!).catch(() => {});
    res.json({ id, session_id: sessionId });
  }));
  r.put("/schedules/:id", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ title: z.string().min(1).max(255).optional(), prompt: z.string().min(1).optional(), interval_min: z.number().int().min(15).optional(), at_time: z.string().nullable().optional(), max_runs: z.number().int().nullable().optional(), goal: z.string().nullable().optional(), enabled: z.boolean().optional(), state: z.enum(["active", "done", "cancelled"]).optional() }), req.body);
    const id = Number(req.params.id); const row = await db("schedules").where({ id }).first(); if (!row) return res.status(404).json({ error: "not found" });
    const upd: any = { ...b, updated_at: db.fn.now() };
    if (b.enabled === true && row.state !== "active") upd.state = "active";
    if (b.state && b.state !== "active") upd.enabled = false;
    if ((b.interval_min && b.interval_min !== row.interval_min) || b.at_time !== undefined || (b.enabled && !row.enabled)) { const { nextRun } = await import("../scheduler/index.js"); upd.next_run_at = nextRun(new Date(), b.interval_min ?? row.interval_min, b.at_time === undefined ? row.at_time : b.at_time).toISOString(); }
    await db("schedules").where({ id }).update(upd);
    await ctx.audit.log("user", req.user!.id, "schedule.updated", { id, fields: Object.keys(b) }, row.session_id);
    await rt.refreshWaiting(row.session_id).catch(() => {});
    res.json(await db("schedules").where({ id }).first());
  }));
  r.post("/schedules/:id/run", requireRole("operator"), wrap(async (req, res) => {
    const row = await db("schedules").where({ id: Number(req.params.id) }).first(); if (!row) return res.status(404).json({ error: "not found" });
    const r0 = await ctx.scheduler!.run(row, "manual"); res.json(r0);
  }));
  r.delete("/schedules/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id); const row = await db("schedules").where({ id }).first(); if (!row) return res.status(404).json({ error: "not found" });
    await db("schedule_runs").where({ schedule_id: id }).delete(); await db("schedules").where({ id }).delete();
    await ctx.audit.log("user", req.user!.id, "schedule.deleted", { id, title: row.title }, row.session_id); await rt.refreshWaiting(row.session_id).catch(() => {}); res.json({ ok: true });
  }));

  /** Server-sent events: live updates for one session (or all when id = 0). */
  r.get("/sessions/:id/events", requireRole("viewer"), (req, res) => {
    const id = Number(req.params.id);
    res.setHeader("Content-Type", "text/event-stream"); res.setHeader("Cache-Control", "no-cache"); res.setHeader("Connection", "keep-alive"); res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();
    res.write(`event: hello\ndata: ${JSON.stringify({ session_id: id })}\n\n`);
    const onEvent = (ev: SessionEvent) => { if (id === 0 || ev.session_id === id) res.write(`event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`); };
    rt.events.on("event", onEvent);
    const ping = setInterval(() => res.write(": ping\n\n"), 25_000);
    req.on("close", () => { clearInterval(ping); rt.events.off("event", onEvent); });
  });

  // ---------- EDR-90: kill switch for automatic approvals ----------
  r.get("/safety", requireRole("viewer"), wrap(async (_req, res) => res.json({ auto_approval_hold: await rt.getHold() })));
  r.put("/safety", requireRole("admin"), wrap(async (req, res) => {
    // EDR-90 (revised 2026-10-24): the one-time code is used only at sign-in; admins stop and resume freely
    const b = parse(z.object({ hold: z.boolean(), reason: z.string().max(500).optional() }), req.body);
    await rt.setHold(b.hold, b.reason || (b.hold ? "管理者が停止" : "管理者が再開"), req.user!.id);
    res.json({ auto_approval_hold: await rt.getHold() });
  }));

  // ---------- approvals ----------
  r.get("/approvals", requireRole("viewer"), wrap(async (req, res) => {
    const q = parse(z.object({ decision: z.string().default("pending"), limit: z.coerce.number().min(1).max(200).default(50) }), req.query);
    const rows = await db("approvals as a").leftJoin("hosts as h", "h.id", "a.host_id").leftJoin("sessions as s", "s.id", "a.session_id")
      .select("a.*", "h.name as host_name", "h.environment as host_environment", "s.title as session_title")
      .where("a.decision", q.decision).whereNull("s.archived_at").orderBy("a.id", "desc").limit(q.limit);
    res.json({ items: rows.map((a: any) => ({ ...a, steps: pj(a.steps), auto_checks: pj(a.auto_checks), exec_result: pj(a.exec_result) })) });
  }));

  r.post("/approvals/:id/approve", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ command: z.string().optional(), note: z.string().optional(), self_drive: z.number().int().min(0).max(ctx.cfg.RETRY_GRANT_MAX).optional() }), req.body);
    const a = await db("approvals").where({ id: Number(req.params.id) }).first();
    if (!a) return res.status(404).json({ error: "not found" });
    const checks = pj<any>(a.auto_checks);
    if (checks?.checks?.some((c: any) => c.level === "block") && !b.command) return res.status(400).json({ error: "blocked by auto-check; edit the command to proceed" });
    // EDR-94: how many automatic fix-and-retry attempts the approver allows for this change
    if (b.self_drive !== undefined) await db("approvals").where({ id: a.id }).update({ self_drive_max: b.self_drive });
    await rt.decide(a.id, req.user!.id, b.command && b.command !== a.command ? "edited" : "approved", { command: b.command, note: b.note });
    res.json({ ok: true });
  }));

  r.post("/approvals/:id/cancel-scheduled", requireRole("operator"), wrap(async (req, res) => { // EDR-168
    await rt.cancelScheduled(Number(req.params.id), req.user!.id);
    res.json({ ok: true });
  }));

  r.post("/approvals/:id/reject", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ note: z.string().min(1) }), req.body);
    await rt.decide(Number(req.params.id), req.user!.id, "rejected", { note: b.note });
    res.json({ ok: true });
  }));

  return r;
}
