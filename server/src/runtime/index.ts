import { EventEmitter } from "node:events";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fetch as ufetch } from "undici";
import type { Ctx } from "../api/context.js";
import { indexer, managerApi } from "../api/context.js";
import { j, pj } from "../db/index.js";
import type { ChatMessage, LlmProvider, ToolCall } from "../llm/index.js";
import { createProvider } from "../llm/index.js";
import { ACTION_TOOL_DEF, SESSION_TOOL_DEFS, SCHEDULE_TOOL_DEFS, CLOSE_TOOL_DEF, TOOL_DEFS, SYSTEM_PROMPT_BASE, ATTACHMENT_TOOL_DEFS, PLAYBOOK_TOOL_DEFS, HOST_TOOL_DEFS, OVERVIEW_TOOL_DEFS, CLOUD_SETUP_TOOL_DEFS, SYSTEM_PROMPT_PLAYBOOK_SETUP, SYSTEM_PROMPT_HOST_SETUP, SYSTEM_PROMPT_OVERVIEW_SETUP, SYSTEM_PROMPT_CLOUD_SETUP, SYSTEM_PROMPT_CONTAIN_CONSULT } from "./tools.js";
import { classifyCommand, loadAllowlist, changeScope, scopeCovers, mustAskOps, forbiddenOps, isLongStep, type Allowlist } from "../gate/classify.js";
import { buildScript as pkgScript, parse as pkgParse } from "../vuln/pkgCandidates.js";
import { sshExec, generateEd25519, keyFingerprint } from "../ssh/index.js";
import { buildProcessTree, renderTreeText } from "../processtree/index.js";
import { JiraClient } from "../integrations/jira.js";
import { redactSecrets } from "../crypto/index.js";
import { coerceMeta, renderMarkdown, parseMarkdown, type PlaybookMeta } from "../playbooks/meta.js";
import { buildPptx } from "../reports/pptx.js";
import { versionCheck, isVulnQuestion, VULN_GUIDE, cmpVer, normalizeVersion } from "../vuln/versionCheck.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const MAX_TURNS = 40;
const TOOL_RESULT_MAX = 12_000; // chars kept in context; full result stored in DB

export type SessionEvent =
  | { type: "message"; session_id: number; message: any }
  | { type: "tool_call"; session_id: number; tool_call: any }
  | { type: "tool_result"; session_id: number; tool_call: any }
  | { type: "approval"; session_id: number; approval: any }
  | { type: "schedule"; session_id: number; schedule_id: number; status: string }
  | { type: "next_actions"; session_id: number; proposal: any }
  | { type: "status"; session_id: number; status: string; detail?: string }
  | { type: "error"; session_id: number; error: string };

export type SessionKind = "investigate" | "playbook_setup" | "host_setup" | "overview_setup" | "cloud_setup" | "contain_consult";

/** Tool set per session kind. */
export function toolsFor(kind: SessionKind, wrapUp = false): import("../llm/index.js").ToolDef[] {
  if (kind === "investigate") return wrapUp ? TOOL_DEFS.filter((t) => t.name === "propose_next_actions") : [...TOOL_DEFS, ...ATTACHMENT_TOOL_DEFS, CLOSE_TOOL_DEF, ACTION_TOOL_DEF, ...SESSION_TOOL_DEFS.filter((t) => t.name !== "set_next_action_status"), ...SCHEDULE_TOOL_DEFS];
  if (wrapUp) return [];
  if (kind === "contain_consult") return [...TOOL_DEFS.filter((t) => ["indexer_query", "wazuh_api", "host_profile", "host_scan", "host_action"].includes(t.name)), ...ATTACHMENT_TOOL_DEFS, ACTION_TOOL_DEF];
  const base = TOOL_DEFS.filter((t) => ["indexer_query", "wazuh_api", "ssh_exec", "host_profile", "host_scan"].includes(t.name));
  if (kind === "cloud_setup") return [...TOOL_DEFS.filter((t) => ["indexer_query", "wazuh_api", "ssh_exec", "apply_change", "cloud_list", "cloud_snapshot", "cloud_power", "cloud_isolate"].includes(t.name)), ...ATTACHMENT_TOOL_DEFS, ...CLOUD_SETUP_TOOL_DEFS, ACTION_TOOL_DEF, ...SESSION_TOOL_DEFS, ...SCHEDULE_TOOL_DEFS];
  if (kind === "overview_setup") return [...TOOL_DEFS.filter((t) => ["indexer_query", "wazuh_api", "ssh_exec", "apply_change"].includes(t.name)), ...ATTACHMENT_TOOL_DEFS, ...OVERVIEW_TOOL_DEFS, ACTION_TOOL_DEF, ...SESSION_TOOL_DEFS, ...SCHEDULE_TOOL_DEFS];
  // EDR-171: the host page's agent operates hosts like Sidekick (host_action / win_updates / apply_change), not only registers them
  const hostOps = TOOL_DEFS.filter((t) => ["host_action", "win_updates", "apply_change"].includes(t.name));
  return kind === "playbook_setup" ? [...base, ...ATTACHMENT_TOOL_DEFS, ...PLAYBOOK_TOOL_DEFS, ACTION_TOOL_DEF, ...SESSION_TOOL_DEFS, ...SCHEDULE_TOOL_DEFS] : [...base, ...hostOps, ...ATTACHMENT_TOOL_DEFS, ...HOST_TOOL_DEFS, ACTION_TOOL_DEF, ...SESSION_TOOL_DEFS, ...SCHEDULE_TOOL_DEFS];
}

/**
 * EDR-145: the human may write while a tool call waits for approval. LLM APIs require every tool call to be answered right after it,
 * so (only when sending, never in the DB):
 *  - an unanswered tool call gets a "pending approval" placeholder result right after the assistant message
 *  - a result that arrives later (after other messages) is passed on as a [system] note from the human side
 */
export const PENDING_TOOL_RESULT = JSON.stringify({ status: "pending_approval", note: "This step is waiting for the human's approval (approval card) and has NOT run yet. The card stays valid; it runs when approved and its result will arrive later as a [system] note. If the human writes meanwhile, answer their message directly; do not propose the same plan again unless they ask for a change. If their message makes the card unnecessary, say so and ask the human to press 却下 (reject) on that card — you cannot reject or withdraw it yourself, so never say you did." });
export function normalizeTranscript(msgs: ChatMessage[]): ChatMessage[] {
  const out: ChatMessage[] = [];
  const note = (m: ChatMessage): ChatMessage => ({ role: "user", content: `[system] 承認待ちだった操作（${m.name ?? "tool"}）の結果が届きました:\n${m.content ?? ""}` });
  for (let i = 0; i < msgs.length; i++) {
    const m = msgs[i];
    if (m.role === "assistant" && m.tool_calls?.length) {
      out.push(m);
      let j = i + 1; const seen = new Set<string>();
      while (j < msgs.length && msgs[j].role === "tool") {
        const t = msgs[j];
        if (m.tool_calls.some((c) => c.id === t.tool_call_id) && !seen.has(t.tool_call_id!)) { out.push(t); seen.add(t.tool_call_id!); } else out.push(note(t));
        j++;
      }
      for (const c of m.tool_calls) if (!seen.has(c.id)) out.push({ role: "tool", tool_call_id: c.id, name: c.name, content: PENDING_TOOL_RESULT });
      i = j - 1; continue;
    }
    out.push(m.role === "tool" ? note(m) : m);
  }
  return out;
}

/** EDR-147: tools that change MamorAI's configuration directly (no approval card) — only when an admin started the chat */
export const ADMIN_ONLY_TOOLS = new Set(["save_playbook", "generate_ssh_key", "register_host", "update_host", "add_protected_range", "register_cloud_provider", "update_cloud_provider", "link_cloud_instance", "set_site", "update_setup_state"]);

export class AgentRuntime {
  readonly events = new EventEmitter();
  private running = new Set<number>();
  private allow: Allowlist;
  private provider: LlmProvider | null = null;
  private providerError: string | null = null;

  constructor(private ctx: Ctx) {
    this.allow = loadAllowlist(path.resolve(here, "..", "..", "..", "config", "readonly-commands.yaml"));
    try { this.provider = createProvider(ctx.cfg, ctx.cfg.APP_BASE_URL); } catch (e: any) { this.providerError = e.message; ctx.log.warn({ err: e.message }, "LLM provider not configured"); }
  }

  /** EDR-121: the host scanner uses the same provider for its one-shot interpretation */
  get llmProvider(): LlmProvider | null { return this.provider; }

  get llmStatus() { return this.provider ? { ok: true, provider: this.provider.name, model: this.provider.model } : { ok: false, error: this.providerError }; }

  private emit(ev: SessionEvent) { this.events.emit("event", ev); }

  // ---------------- session lifecycle ----------------
  async createSession(opts: { origin: "alert" | "user" | "schedule"; kind?: SessionKind; title: string; userId?: number | null; wazuhInstanceId?: number | null; hostIds?: number[]; alertRef?: unknown; firstMessage: string; attachments?: { name: string; content: string; mime?: string }[]; context?: { playbook_id?: number | null; host_id?: number | null } }): Promise<number> {
    const { db } = this.ctx;
    const kind: SessionKind = opts.kind ?? "investigate";
    const [id] = await db("sessions").insert({
      origin: opts.origin, kind, title: opts.title.slice(0, 255), status: "running", started_by: opts.userId ?? null,
      alert_ref: j(opts.alertRef ?? null), llm_model: this.provider?.model ?? null,
      summary: j({ wazuh_instance_id: opts.wazuhInstanceId ?? null, host_ids: opts.hostIds ?? [], context: opts.context ?? null }),
    }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    let system = await this.buildSystemPrompt(kind, opts.wazuhInstanceId ?? null, opts.hostIds ?? []);
    if (opts.context?.playbook_id) { const p = await db("playbooks").where({ id: opts.context.playbook_id }).first(); if (p) system += `\n\n## Session context\nThe human opened this chat from the existing playbook #${p.id} "${p.name}" (v${p.version}). Work on THIS playbook (get_playbook → propose changes → save_playbook with playbook_id=${p.id}) unless they ask for a new one.`; }
    if (kind === "contain_consult" && opts.context?.host_id) system += await this.containContext(opts.context.host_id);
    else if (opts.context?.host_id) { const h = await db("hosts").where({ id: opts.context.host_id }).first(); if (h) system += `\n\n## Session context\nThe human opened this chat from the registered host "${h.name}" (${h.ssh_user}@${h.address}:${h.port}, env=${h.environment}, sudo=${h.sudo_mode}, autonomy L${h.autonomy_level}/max${h.autonomy_max}, hostkey ${h.host_key ? "pinned" : "not pinned"}). Review or fix THIS host's registration (test_host / update_host) unless they ask to add a new host.`; }
    await this.appendMessage(id, { role: "system", content: system });
    let first = opts.firstMessage;
    const firstImages: { mime: string; attachment_id: number }[] = [];
    for (const a of opts.attachments ?? []) {
      const img = (a as any).encoding === "base64";
      const saved = await this.addAttachment(id, opts.userId ?? null, a, "in", undefined, img ? "base64" : "utf8", img ? Math.floor(a.content.length * 3 / 4) : undefined);
      if (img && /^image\//.test(a.mime ?? "")) { firstImages.push({ mime: a.mime!, attachment_id: saved.id }); first += `\n[画像] ${a.name}`; } else first += `\n[添付] ${a.name} (${saved.size} bytes)`;
    }
    await this.appendMessage(id, { role: "user", content: first, images: firstImages.length ? firstImages : undefined });
    await this.ctx.audit.log(opts.userId ? "user" : "system", opts.userId ?? null, "session.created", { origin: opts.origin, title: opts.title }, id);
    this.kick(id);
    return id;
  }

  async userMessage(sessionId: number, userId: number, text: string, images?: { mime: string; attachment_id: number }[]): Promise<void> {
    const s = await this.ctx.db("sessions").where({ id: sessionId }).first();
    if (!s) throw Object.assign(new Error("session not found"), { status: 404 });
    if (["done", "failed", "cancelled"].includes(s.status)) await this.setStatus(sessionId, "running", "reopened by user");
    await this.appendMessage(sessionId, { role: "user", content: text, images: images?.length ? images : undefined });
    await this.ctx.audit.log("user", userId, "session.user_message", { len: text.length }, sessionId);
    // EDR-145: answer the human even while an approval card is pending (the card stays valid; the transcript gets a "pending" placeholder)
    await this.setStatus(sessionId, "running", s.status === "waiting_approval" ? "answering while an approval is pending" : "thinking");
    this.kick(sessionId);
  }

  /** 依存タスクの解放: id のタスクが完了したら、after_id=id で blocked のタスクを proposed に戻し、元セッションの AI に続きを促す */
  async onActionDone(actionId: number): Promise<void> {
    const { db } = this.ctx;
    const done = await db("next_actions").where({ id: actionId }).first(); if (!done) return;
    const deps = await db("next_actions").where({ after_id: actionId, status: "blocked" });
    if (!deps.length) await this.refreshWaiting(done.session_id).catch(() => {});
    for (const d of deps) {
      await db("next_actions").where({ id: d.id }).update({ status: "proposed", updated_at: db.fn.now() });
      await this.ctx.audit.log("system", null, "next_action.unblocked", { id: d.id, after: actionId }, d.session_id);
      this.emit({ type: "next_actions", session_id: d.session_id, proposal: null });
      const s = await db("sessions").where({ id: d.session_id }).first(); if (!s) continue;
      const text = `🔗 依存タスク #${actionId}「${done.title}」が完了したため、タスク #${d.id}「${d.title}」${d.relation === "revert" ? "（元に戻す作業）" : ""}が実行可能になりました。\n\n[指示] 内容を確認し、実行すべきなら apply_change（next_action_id=${d.id}）で変更計画を作って承認待ちにしてください。前提が変わっていて不要なら set_next_action_status(${d.id}, rejected) にして理由を一文で。propose_next_actions は呼ばないでください。`;
      if (["running", "waiting_approval"].includes(s.status)) { await this.appendMessage(d.session_id, { role: "user", content: text }); continue; }
      if (["done", "failed", "cancelled"].includes(s.status)) await this.setStatus(d.session_id, "running", "reopened by dependency");
      await this.appendMessage(d.session_id, { role: "user", content: text });
      await this.setStatus(d.session_id, "running", "dependency released");
      this.kick(d.session_id);
    }
  }

  /** スケジューラからの投入: 登録元セッションに指示を入れて AI を走らせる（完了済みなら再開） */
  async scheduledMessage(sessionId: number, text: string): Promise<void> {
    const s = await this.ctx.db("sessions").where({ id: sessionId }).first();
    if (!s) throw new Error("session not found");
    if (["done", "failed", "cancelled"].includes(s.status)) await this.setStatus(sessionId, "running", "reopened by schedule");
    await this.appendMessage(sessionId, { role: "user", content: text });
    await this.setStatus(sessionId, "running", "scheduled run");
    this.kick(sessionId);
  }

  /** Store a text attachment on a session (the agent reads it with read_attachment). */
  async addAttachment(sessionId: number, userId: number | null, a: { name: string; content: string; mime?: string }, direction: "in" | "out" = "in", description?: string, encoding: "utf8" | "base64" = "utf8", rawSize?: number): Promise<{ id: number; name: string; size: number }> {
    const name = a.name.replace(/[\\/]/g, "_").slice(0, 255);
    const size = rawSize ?? Buffer.byteLength(a.content, "utf8");
    if (size > 8_000_000 || (encoding === "utf8" && size > 2_000_000)) throw Object.assign(new Error("attachment too large (max 2MB text / 8MB binary)"), { status: 413 });
    if (encoding === "utf8" && /\u0000/.test(a.content)) throw Object.assign(new Error("binary attachments are not supported; attach text (config, log, markdown)"), { status: 415 });
    await this.ctx.db("attachments").where({ session_id: sessionId, name, direction }).delete();
    const [id] = await this.ctx.db("attachments").insert({ session_id: sessionId, name, size, mime: a.mime ?? mimeFor(name), content: a.content, uploaded_by: userId, direction, description: description ?? null, encoding }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await this.ctx.audit.log(direction === "out" ? "agent" : userId ? "user" : "system", direction === "out" ? null : userId, direction === "out" ? "session.file_written" : "session.attachment", { name, size }, sessionId);
    return { id, name, size };
  }

  async markDone(sessionId: number, userId: number): Promise<void> {
    await this.setStatus(sessionId, "done", "closed by user");
    await this.ctx.db("next_actions").where({ session_id: sessionId, status: "proposed" }).update({ status: "done" });
    await this.ctx.audit.log("user", userId, "session.done", {}, sessionId);
  }

  /** Human reopens a finished ticket without having to write a message. */
  async reopen(sessionId: number, userId: number): Promise<void> {
    const s = await this.ctx.db("sessions").where({ id: sessionId }).first();
    if (!s) throw Object.assign(new Error("session not found"), { status: 404 });
    if (!["done", "cancelled", "failed"].includes(s.status)) throw Object.assign(new Error("session is not closed"), { status: 409 });
    const meta = pj<any>(s.summary) ?? {};
    await this.ctx.db("sessions").where({ id: sessionId }).update({ finished_at: null, summary: j({ ...meta, reopened: { by: userId, at: new Date().toISOString() }, labeled_done: false }) });
    await this.appendMessage(sessionId, { role: "user", content: "[system] The human reopened this ticket. Wait for their instruction; do not act yet." });
    await this.ctx.audit.log("user", userId, "session.reopened", {}, sessionId);
    await this.setStatus(sessionId, "waiting_user", "reopened by user");
  }

  /** アーカイブ: 一覧から隠すと同時に、承認待ちを自動却下し、進行中なら閉じる（承認キュー / ダッシュボードに残らないように） */
  async archive(sessionId: number, userId: number | null): Promise<{ rejected: number }> {
    const { db } = this.ctx;
    const s = await db("sessions").where({ id: sessionId }).first();
    if (!s) throw Object.assign(new Error("session not found"), { status: 404 });
    const pend = await db("approvals").where({ session_id: sessionId, decision: "pending" });
    for (const a of pend) {
      await db("approvals").where({ id: a.id }).update({ decision: "rejected", decided_by: userId, decided_at: db.fn.now(), decision_note: "セッションがアーカイブされたため自動却下" });
      if (a.tool_call_id) {
        const tc = await db("tool_calls").where({ id: a.tool_call_id }).first();
        await db("tool_calls").where({ id: a.tool_call_id }).update({ status: "rejected", result: j({ status: "rejected", note: "archived" }), finished_at: db.fn.now() });
        if (tc) await this.appendMessage(sessionId, { role: "tool", tool_call_id: pj(tc.args)?._call_id, name: tc.tool, content: JSON.stringify({ status: "rejected", reason: "The session was archived; this plan was discarded. Do not retry unless the human asks." }) });
      }
      if (a.next_action_id) await db("next_actions").where({ id: a.next_action_id }).update({ status: "proposed", approval_id: null });
    }
    const upd: any = { archived_at: db.fn.now(), updated_at: db.fn.now() };
    if (!["done", "failed", "cancelled"].includes(s.status)) { upd.status = "done"; upd.finished_at = db.fn.now(); const meta = pj<any>(s.summary) ?? {}; upd.summary = j({ ...meta, closed: { outcome: "archived", note: "アーカイブ時に自動で閉じた", by: userId ? "user" : "agent", at: new Date().toISOString() } }); }
    await db("sessions").where({ id: sessionId }).update(upd);
    // 有効なスケジュールも止める（Action ボードの表示は一覧側でアーカイブ済みセッションを除外）
    await db("schedules").where({ session_id: sessionId, state: "active" }).update({ state: "cancelled", enabled: false, last_result: "セッションがアーカイブされたため停止", updated_at: db.fn.now() });
    await this.ctx.audit.log(userId ? "user" : "agent", userId, "session.archived", { rejected_approvals: pend.length }, sessionId);
    this.emit({ type: "status", session_id: sessionId, status: upd.status ?? s.status, detail: "archived" });
    for (const a of pend) this.emit({ type: "approval", session_id: sessionId, approval: { ...a, decision: "rejected" } });
    return { rejected: pend.length };
  }

  async cancel(sessionId: number, userId: number): Promise<void> {
    await this.setStatus(sessionId, "cancelled", "cancelled by user");
    await this.ctx.db("approvals").where({ session_id: sessionId, decision: "pending" }).update({ decision: "rejected", decided_by: userId, decided_at: this.ctx.db.fn.now(), decision_note: "session cancelled" });
    await this.ctx.audit.log("user", userId, "session.cancelled", {}, sessionId);
  }

  /** Human decision on a pending approval. */
  /** Number of approved plans currently executing over SSH (deploy scripts wait while > 0). */
  async runningCount(): Promise<number> { const r = await this.ctx.db("sessions").where({ status: "running" }).count<{ c: number }[]>({ c: "*" }).first(); return Number(r?.c ?? 0); }
  async executingCount(): Promise<number> {
    const rows = await this.ctx.db("approvals").whereIn("decision", ["approved", "edited"]).whereNotNull("decided_at").select("id", "exec_result");
    return rows.filter((r: any) => { const x = pj(r.exec_result); return !x || x.status === "running"; }).length;
  }

  /** Called once at startup: approvals that were executing when the previous process died are marked interrupted and the AI is asked to verify the host state. */
  async recoverInterrupted(): Promise<void> {
    for (const r of await this.ctx.db("sessions").whereIn("status", ["waiting_user", "waiting_external"]).select("id")) await this.refreshWaiting(r.id).catch(() => {});
    // アーカイブ済みセッションに残った承認待ちを掃除（旧バージョンで作られた滞留分）
    { const stale = await this.ctx.db("approvals as a").join("sessions as s", "s.id", "a.session_id").where("a.decision", "pending").whereNotNull("s.archived_at").distinct("s.id as id"); for (const r of stale) await this.archive(r.id, null).catch(() => {}); }
    const { db } = this.ctx;
    const rows = await db("approvals").whereIn("decision", ["approved", "edited"]).whereNotNull("decided_at");
    for (const a of rows) {
      const prev = pj(a.exec_result);
      if (prev && prev.status !== "running") continue;
      const done = prev?.steps_done ?? 0, total = prev?.steps_total ?? (pj(a.steps)?.length ?? 1), cur = prev?.current_step ?? (done + 1);
      const result = { ...(prev ?? {}), status: "interrupted", exit_code: null,
        error: `MamorAI が再起動されたため、実行が中断されました（ステップ ${cur}/${total} の実行中。${done} ステップまでは完了を記録済み）。ホスト側ではコマンドが完了している可能性があります。`,
        stdout: (prev?.steps ?? []).map((x: any) => `[${x.step}/${total}] ${x.purpose}\n$ ${x.command}\n${x.stdout}${x.stderr ? "\n[stderr] " + x.stderr : ""}`).join("\n\n"), stderr: "", interrupted_at: new Date().toISOString() };
      await db("approvals").where({ id: a.id }).update({ exec_result: j(result) });
      { const ha = pj<any>(a.host_action); if (ha?.action_id) await db("host_actions").where({ id: ha.action_id, status: "running" }).update({ status: "unconfirmed" }); } // EDR-168: the endpoint may still be working
      await db("tool_calls").where({ id: a.tool_call_id }).update({ status: "failed", result: j(result), finished_at: db.fn.now() });
      if (a.next_action_id) await db("next_actions").where({ id: a.next_action_id }).update({ status: "approved", updated_at: db.fn.now() });
      const tc = await db("tool_calls").where({ id: a.tool_call_id }).first();
      if (tc) await this.appendMessage(a.session_id, { role: "tool", tool_call_id: pj(tc.args)?._call_id, name: tc.tool, content: truncate(JSON.stringify({ ...result, approved_by_human: true, instruction: "The console restarted while this approved plan was executing. Do NOT re-run write steps blindly: first verify the current host state with read-only commands (ssh_exec) — which steps actually took effect — then report to the human in Japanese and propose only the missing steps." })) });
      await this.ctx.audit.log("system", null, "approval.interrupted", { approval_id: a.id, steps_done: done, steps_total: total }, a.session_id);
      this.ctx.log.warn({ approval_id: a.id, session_id: a.session_id, done, total }, "approval execution interrupted by restart; session resumed");
      await this.setStatus(a.session_id, "running", "resumed after restart");
      this.kick(a.session_id);
    }
    // sessions that were mid-turn (status running) when the process died: close dangling tool calls and resume the loop
    const running = await db("sessions").where({ status: "running" });
    for (const s of running) {
      const dangling = await db("tool_calls").where({ session_id: s.id, status: "executed" }).whereNull("result");
      for (const t of dangling) {
        const res = { status: "failed", error: "MamorAI が再起動されたため、このツール呼び出しは中断されました。必要なら呼び直してください。" };
        await db("tool_calls").where({ id: t.id }).update({ status: "failed", result: j(res), finished_at: db.fn.now() });
        await this.appendMessage(s.id, { role: "tool", tool_call_id: pj(t.args)?._call_id, name: t.tool, content: JSON.stringify(res) });
      }
      // if the last message is an assistant turn with tool calls that have no tool result, the API would reject the transcript → covered above; otherwise just resume
      this.ctx.log.warn({ session_id: s.id, dangling: dangling.length }, "session was running at restart; resuming");
      await this.ctx.audit.log("system", null, "session.resumed_after_restart", { dangling: dangling.length }, s.id);
      this.kick(s.id);
    }
    // sessions stuck in waiting_approval with nothing pending
    const stuck = await db("sessions").where({ status: "waiting_approval" });
    for (const s of stuck) {
      const pend = await db("approvals").where({ session_id: s.id, decision: "pending" }).first();
      if (!pend) { this.ctx.log.warn({ session_id: s.id }, "session waiting_approval without pending approval; resuming"); await this.setStatus(s.id, "running", "resumed after restart"); this.kick(s.id); continue; }
      // EDR-145: the human wrote while the card was pending (before this change nobody answered) → answer now
      const last = await db("messages").where({ session_id: s.id }).orderBy("seq", "desc").first();
      const lm = last ? pj<any>(last.content) : null;
      if (lm?.role === "user" && typeof lm.content === "string" && !lm.content.startsWith("[system]")) { await this.setStatus(s.id, "running", "answering a message left while an approval was pending"); this.kick(s.id); }
    }
    // EDR-87: approvals still pending that are read-only under the current gate (e.g. after an allowlist update) run now
    for (const p of await db("approvals").where({ decision: "pending" }).orderBy("id")) {
      if (p.cloud_action) continue;
      const host = await db("hosts").where({ id: p.host_id }).first();
      if (!host || Number(host.autonomy_level ?? 1) < 1) continue;
      const cmds: string[] = p.steps ? (pj<any[]>(p.steps) ?? []).map((x: any) => String(x.command)) : [String(p.command)];
      if (!cmds.length || !cmds.every((cmd) => classifyCommand(cmd, this.allow).classification === "read")) continue;
      this.ctx.log.info({ approval_id: p.id, session_id: p.session_id }, "pending approval is read-only under the current gate; running it");
      await this.ctx.audit.log("system", null, "approval.auto", { approval_id: p.id, why: "read-only under the updated gate" }, p.session_id ?? undefined);
      await this.decide(p.id, 0, "approved", { note: "自動実行: 判定ルールの更新で読み取り専用と判定" }).catch((e) => this.ctx.log.warn({ err: e.message, approval_id: p.id }, "auto-run of pending read failed"));
    }
  }

  async decide(approvalId: number, userId: number, decision: "approved" | "edited" | "rejected", opts: { command?: string; note?: string }): Promise<void> {
    const { db, box } = this.ctx;
    const a = await db("approvals").where({ id: approvalId }).first();
    if (!a) throw Object.assign(new Error("approval not found"), { status: 404 });
    if (a.decision !== "pending") throw Object.assign(new Error("already decided"), { status: 409 });
    const tc = await db("tool_calls").where({ id: a.tool_call_id }).first();
    if (decision === "rejected") {
      if (a.next_action_id) await db("next_actions").where({ id: a.next_action_id }).update({ status: "proposed", approval_id: null });
      await db("approvals").where({ id: approvalId }).update({ decision, decided_by: userId, decided_at: db.fn.now(), decision_note: opts.note ?? null });
      if (a.tool_call_id) await db("tool_calls").where({ id: a.tool_call_id }).update({ status: "rejected", result: j({ status: "rejected", note: opts.note ?? "" }), finished_at: db.fn.now() });
      await this.ctx.audit.log("user", userId, "approval.rejected", { approval_id: approvalId, command: a.command, note: opts.note }, a.session_id ?? undefined);
      { const ha = pj<any>(a.host_action); if (ha?.action_id && !ha.revert) await db("host_actions").where({ id: ha.action_id, status: "pending" }).update({ status: "rejected" }); } // EDR-121
      if (a.session_id && tc) {
        await this.appendMessage(a.session_id, { role: "tool", tool_call_id: pj(tc.args)?._call_id, name: tc.tool, content: JSON.stringify({ status: "rejected", reason: opts.note || "The human rejected this command. Propose an alternative or ask what they prefer." }) });
        this.emit({ type: "approval", session_id: a.session_id, approval: { ...a, decision } });
        if (await db("approvals").where({ session_id: a.session_id, decision: "pending" }).first()) return; // EDR-87
        await this.setStatus(a.session_id, "running", "approval rejected");
        this.kickSoon(a.session_id);
      }
      return;
    }
    const command = decision === "edited" && opts.command ? opts.command : a.command;
    await db("approvals").where({ id: approvalId }).update({ decision, decided_by: userId || null, decided_at: db.fn.now(), decision_note: opts.note ?? null, executed_command: command });
    await this.ctx.audit.log(userId ? "user" : "system", userId || null, "approval.approved", { approval_id: approvalId, command, edited: decision === "edited", auto: !userId, run_after: a.run_after ?? undefined }, a.session_id);
    // EDR-168: approved now, run later (e.g. "tonight at 22:00"). The tool call is answered now; the result comes as a [system] note.
    if (a.run_after && new Date(a.run_after).getTime() > Date.now() + 30_000) {
      const runAt = new Date(a.run_after).toISOString();
      const result = { status: "scheduled", run_after: runAt };
      await db("approvals").where({ id: approvalId }).update({ exec_result: j(result) });
      if (a.tool_call_id) await db("tool_calls").where({ id: a.tool_call_id }).update({ status: "approved", result: j(result) });
      if (a.next_action_id) await db("next_actions").where({ id: a.next_action_id }).update({ status: "approved", updated_at: db.fn.now() });
      await this.ctx.audit.log("system", null, "approval.scheduled", { approval_id: approvalId, run_after: runAt }, a.session_id ?? undefined);
      this.emit({ type: "approval", session_id: a.session_id ?? 0, approval: { ...a, decision, exec_result: result } });
      if (a.session_id && tc) {
        await this.appendMessage(a.session_id, { role: "tool", tool_call_id: pj(tc.args)?._call_id, name: tc.tool, content: JSON.stringify({ ...result, approved_by_human: true, note: `Approved. It runs automatically at ${runAt} (UTC); its result will arrive later as a [system] note. Do not request it again.` }) });
        if (await db("approvals").where({ session_id: a.session_id, decision: "pending" }).first()) return;
        await this.setStatus(a.session_id, "running", "approval scheduled");
        this.kickSoon(a.session_id);
      }
      return;
    }
    await this.executeApproval(a, approvalId, decision, command, userId, false);
  }

  /** EDR-168: run approvals whose time has come (called by the scheduler every 30 s). The emergency stop holds them. */
  async runDueApprovals(): Promise<void> {
    const { db } = this.ctx;
    const due = await db("approvals").whereIn("decision", ["approved", "edited"]).whereNotNull("run_after").where("run_after", "<=", new Date().toISOString()).where("exec_result", "like", '%"status":"scheduled"%');
    for (const a of due) {
      const hold = await this.getHold();
      if (hold.on) { // safety: the kill switch also stops changes that were approved for later
        const r = { status: "held", run_after: a.run_after, note: "緊急停止中のため実行しませんでした（解除後に承認し直してください）" };
        await db("approvals").where({ id: a.id }).update({ exec_result: j(r) });
        this.emit({ type: "approval", session_id: a.session_id ?? 0, approval: { ...a, exec_result: r } });
        if (a.session_id) { await this.appendMessage(a.session_id, { role: "user", content: `[system] 予約していた操作（承認 #${a.id}「${a.title ?? ""}」）は、緊急停止中のため実行しませんでした。` }); }
        continue;
      }
      const claimed = await db("approvals").where({ id: a.id }).where("exec_result", "like", '%"status":"scheduled"%').update({ exec_result: j({ status: "running", steps_done: 0, steps_total: 1, current_step: 1, current_purpose: "予約時刻になったので実行を開始", started_at: new Date().toISOString() }) });
      if (!claimed) continue;
      await this.ctx.audit.log("system", null, "approval.scheduled_run", { approval_id: a.id, run_after: a.run_after }, a.session_id ?? undefined);
      this.executeApproval(a, a.id, a.decision, a.executed_command ?? a.command, a.decided_by ?? 0, true).catch((e) => this.ctx.log.warn({ err: e.message, approval: a.id }, "scheduled approval failed"));
    }
  }

  /** EDR-168: cancel an approved-for-later change before it runs */
  async cancelScheduled(approvalId: number, userId: number): Promise<void> {
    const { db } = this.ctx;
    const a = await db("approvals").where({ id: approvalId }).first();
    if (!a) throw Object.assign(new Error("approval not found"), { status: 404 });
    if (!String(a.exec_result ?? "").includes('"status":"scheduled"')) throw Object.assign(new Error("予約中ではありません（すでに実行済み、または予約なし）"), { status: 409 });
    const r = { status: "cancelled", run_after: a.run_after };
    await db("approvals").where({ id: approvalId }).update({ exec_result: j(r) });
    { const ha = pj<any>(a.host_action); if (ha?.action_id && !ha.revert) await db("host_actions").where({ id: ha.action_id, status: "pending" }).update({ status: "rejected" }); }
    if (a.next_action_id) await db("next_actions").where({ id: a.next_action_id }).update({ status: "proposed", approval_id: null, updated_at: db.fn.now() });
    await this.ctx.audit.log("user", userId, "approval.scheduled_cancelled", { approval_id: approvalId }, a.session_id ?? undefined);
    this.emit({ type: "approval", session_id: a.session_id ?? 0, approval: { ...a, exec_result: r } });
    if (a.session_id) await this.appendMessage(a.session_id, { role: "user", content: `[system] 予約していた操作（承認 #${approvalId}「${a.title ?? ""}」）は、人が取り消しました。実行していません。` });
  }

  private async executeApproval(a: any, approvalId: number, decision: string, command: string, userId: number, deferred: boolean): Promise<void> {
    const { db, box } = this.ctx;
    const tc = a.tool_call_id ? await db("tool_calls").where({ id: a.tool_call_id }).first() : null;
    const host = await db("hosts").where({ id: a.host_id }).first();
    const key = host?.ssh_key_id ? await db("ssh_keys").where({ id: host.ssh_key_id }).first() : null;
    let result: any;
    const cloud = pj<any>(a.cloud_action);
    const hostAct = pj<any>(a.host_action);
    try {
      if (hostAct) {
        // EDR-121: stop a service / block / isolate — SSH on Linux, Wazuh active response on Windows
        const { executeAction } = await import("../hosts/actions.js");
        const startedAt = new Date().toISOString();
        const r = await executeAction(this.ctx, { ...a, id: approvalId }, async (purpose, extra) => {
          const pr = { status: "running", steps_done: 0, steps_total: 1, current_step: 1, current_purpose: purpose, started_at: startedAt, ...(extra ?? {}) };
          await db("approvals").where({ id: approvalId }).update({ exec_result: j(pr) });
          this.emit({ type: "approval", session_id: a.session_id ?? 0, approval: { ...a, decision, exec_result: pr } });
        });
        result = r;
      } else if (cloud) {
        // クラウド操作（EDR-76）: SSH ではなくプロバイダ API を叩く
        await db("approvals").where({ id: approvalId }).update({ exec_result: j({ status: "running", steps_done: 0, steps_total: 1, current_step: 1, current_purpose: "クラウド API を呼び出し中", started_at: new Date().toISOString() }) });
        const { executeCloudAction } = await import("../cloud/service.js");
        const r = await executeCloudAction(db, box, cloud);
        result = { status: r.ok ? "executed" : "failed", exit_code: r.ok ? 0 : 1, stdout: `${r.instance}\n${r.message}${r.ref ? "\nref: " + r.ref : ""}${r.detail ? "\n" + JSON.stringify(r.detail, null, 1).slice(0, 2000) : ""}`, stderr: "", cloud: { op: cloud.op, ref: r.ref ?? null, detail: r.detail ?? null } };
      } else {
      if (!host || !key) throw new Error("host or key missing");
      const target = { address: host.address, port: host.port, user: host.ssh_user, privateKey: box.decrypt(key.private_key_enc), sudoMode: host.sudo_mode, hostKey: host.host_key };
      const steps: { purpose: string; command: string }[] | null = a.steps ? pj(a.steps) : null;
      if (steps && steps.length && decision !== "edited") {
        // EDR-88: snapshot every file the plan may change, so a failure can be undone without a new approval
        const scope = changeScope(steps.map((x) => x.command), this.allow);
        const snap = this.ctx.cfg.AUTO_ROLLBACK_ON_FAILURE && scope.paths.length ? await this.snapshotFiles(target, approvalId, scope.paths).catch((e) => { this.ctx.log.warn({ err: e.message, approvalId }, "snapshot failed"); return [] as { i: number; path: string }[]; }) : [];
        // multi-step plan: run in order, stop at first failure
        const results: any[] = [];
        let failed = false;
        const startedAt = new Date().toISOString();
        for (let i = 0; i < steps.length; i++) {
          // persist progress BEFORE each step so a restart mid-plan leaves evidence of how far we got
          const progress = { status: "running", steps_done: results.length, steps_total: steps.length, current_step: i + 1, current_purpose: steps[i].purpose, steps: results, started_at: startedAt };
          await db("approvals").where({ id: approvalId }).update({ exec_result: j(progress) });
          this.emit({ type: "approval", session_id: a.session_id, approval: { ...a, decision, exec_result: progress } });
          // EDR-114: package transactions / long steps run detached on the host and are polled, so the SSH timeout never leaves an orphan running while the next plan starts
          const isLong = (steps[i] as any).long === true || isLongStep(steps[i].command);
          const r: any = isLong
            ? await this.runLong(target, approvalId, i, steps[i].command, async (tail, sec) => {
                const p2 = { ...progress, current_detail: `${Math.round(sec / 60)} 分経過`, current_tail: tail.slice(-1500) };
                await db("approvals").where({ id: approvalId }).update({ exec_result: j(p2) });
                this.emit({ type: "approval", session_id: a.session_id, approval: { ...a, decision, exec_result: p2 } });
              })
            : await sshExec(target, steps[i].command, 300_000);
          if (!host.host_key && r.hostKey) { await db("hosts").where({ id: host.id }).update({ host_key: r.hostKey }); target.hostKey = r.hostKey; }
          results.push({ step: i + 1, purpose: steps[i].purpose, command: steps[i].command, exit_code: r.code, stdout: r.stdout.slice(-20000), stderr: r.stderr.slice(0, 5000), duration_ms: r.durationMs, long: isLong || undefined });
          if (r.stillRunning) (steps[i] as any).no_rollback = true; // never roll back under a running package transaction
          if (r.code !== 0) { failed = true; break; }
        }
        // EDR-87: the human approved the rollback together with the plan → run it on failure without a new approval
        let rollbackRun: any = null;
        const failedStep: any = failed ? steps[results.length - 1] : null;
        const rbCmds: string[] = a.rollback ? String(a.rollback).split("\n").map((x: string) => x.trim()).filter(Boolean) : [];
        if (failed && snap.length && !failedStep?.no_rollback) {
          // EDR-88: restore the pre-execution snapshot and restart the services the plan touched (independent of the LLM's rollback text)
          const svcs = changeScope(results.map((x: any) => x.command), this.allow).services;
          const rr = await this.restoreSnapshot(target, approvalId, snap, svcs);
          rollbackRun = { executed: true, kind: "snapshot", ok: rr.code === 0, restored: snap.map((x) => x.path), services: svcs, steps: [{ command: `スナップショットから復元: ${snap.map((x) => x.path).join(", ")}${svcs.length ? ` → ${svcs.join(", ")} を再起動` : ""}`, exit_code: rr.code, stdout: rr.stdout.slice(0, 5000), stderr: rr.stderr.slice(0, 2000) }] };
          await this.ctx.audit.log("system", null, "approval.auto_rollback", { approval_id: approvalId, kind: "snapshot", ok: rollbackRun.ok, files: snap.length, services: svcs }, a.session_id ?? undefined);
        } else if (failed && rbCmds.length && !failedStep?.no_rollback && this.ctx.cfg.AUTO_ROLLBACK_ON_FAILURE) {
          const rres: any[] = [];
          for (const cmd of rbCmds) { const r = await sshExec(target, cmd, 300_000); rres.push({ command: cmd, exit_code: r.code, stdout: r.stdout.slice(0, 5000), stderr: r.stderr.slice(0, 2000) }); if (r.code !== 0) break; }
          rollbackRun = { executed: true, ok: rres.length === rbCmds.length && rres.every((x) => x.exit_code === 0), steps: rres };
          await this.ctx.audit.log("system", null, "approval.auto_rollback", { approval_id: approvalId, ok: rollbackRun.ok, steps: rres.length }, a.session_id ?? undefined);
        }
        const done = results.length, total = steps.length;
        result = { status: failed ? "failed" : "executed", exit_code: failed ? results[results.length - 1].exit_code : 0, steps_done: done, steps_total: total, steps: results,
          stdout: results.map((x) => `[${x.step}/${total}] ${x.purpose}\n$ ${x.command}\n${x.stdout}${x.stderr ? "\n[stderr] " + x.stderr : ""}`).join("\n\n"), stderr: "",
          duration_ms: results.reduce((acc, x) => acc + x.duration_ms, 0),
          note: failed ? (rollbackRun ? `step ${done}/${total} failed; remaining steps were skipped. The approved rollback was executed automatically (${rollbackRun.ok ? "succeeded" : "FAILED — check the host state"}). Fix the cause and submit ONE corrected plan.` : `step ${done}/${total} failed; remaining steps were skipped.${failedStep?.no_rollback ? " This step restores the file by itself; nothing needs to be rolled back." : " Consider the rollback."}`) : undefined,
          rollback: rollbackRun ?? undefined };
        if (rollbackRun) result.stdout += `\n\n[自動ロールバック ${rollbackRun.ok ? "成功" : "失敗"}]\n` + rollbackRun.steps.map((x: any) => `$ ${x.command}\n${x.stdout}${x.stderr ? "\n[stderr] " + x.stderr : ""}`).join("\n");
        // EDR-115: after anything that touched packages, check the package database, leftovers and services
        if (steps.some((x) => isLongStep(x.command))) {
          const pc = await this.postCheck(target, changeScope(steps.map((x) => x.command), this.allow).services).catch((e: any) => ({ ok: false, issues: [`点検を実行できず: ${String(e?.message ?? e).slice(0, 200)}`], info: [], raw: "" }));
          result.post_check = pc;
          if (!pc.ok) result.note = `${result.note ?? ""} POST-CHECK FOUND PROBLEMS: ${pc.issues.join(" / ")}. Fix them (see the playbook 'Linux のパッケージ更新・脆弱性修正') before you report the work as done; do not kill package managers.`.trim();
          else if (pc.info.length) result.note = `${result.note ?? ""} Post-check OK. Tell the human: ${pc.info.join(" / ")}`.trim();
          await this.ctx.audit.log("system", null, "approval.post_check", { approval_id: approvalId, ok: pc.ok, issues: pc.issues, info: pc.info }, a.session_id ?? undefined);
        }
        if (failed) { // EDR-94: is everything the plan touched still running? A broken service stops self-drive.
          const svcs = changeScope(steps.map((x) => x.command), this.allow).services;
          if (svcs.length) {
            const hc: any = await sshExec(target, svcs.map((s) => `printf '%s=' '${s.replace(/'/g, "")}'; systemctl is-active '${s.replace(/'/g, "")}' || true`).join("; "), 60_000).catch((e: any) => ({ code: 1, stdout: "", stderr: String(e?.message ?? e) }));
            const down = String(hc.stdout ?? "").split("\n").map((l: string) => l.trim()).filter((l: string) => l.includes("=") && !l.endsWith("=active"));
            result.health = { ok: down.length === 0 && !hc.stderr, detail: down.length ? `停止中: ${down.join(", ")}` : hc.stderr ? `確認できず: ${String(hc.stderr).slice(0, 200)}` : `稼働中: ${svcs.join(", ")}` };
            if (!result.health.ok) {
              result.note = `${result.note ?? ""} SERVICES ARE NOT HEALTHY (${result.health.detail}). Do not try further changes: verify with read-only commands and report to the human.`;
              await this.ctx.audit.log("system", null, "approval.health_degraded", { approval_id: approvalId, host: host?.name, detail: result.health.detail }, a.session_id ?? undefined);
              this.discord(`[MamorAI #${a.session_id}] ${host?.name}: 変更の失敗後にサービスが止まっています（${result.health.detail}）。自動の再試行を止めました。`);
            }
          }
        }
      } else {
        await db("approvals").where({ id: approvalId }).update({ exec_result: j({ status: "running", steps_done: 0, steps_total: 1, current_step: 1, started_at: new Date().toISOString() }) });
        const r: any = isLongStep(command) ? await this.runLong(target, approvalId, 0, command, async () => {}) : await sshExec(target, command, 300_000);
        if (!host.host_key && r.hostKey) await db("hosts").where({ id: host.id }).update({ host_key: r.hostKey });
        result = { status: "executed", exit_code: r.code, stdout: r.stdout, stderr: r.stderr, duration_ms: r.durationMs, truncated: r.truncated };
        if (isLongStep(command)) { const pc = await this.postCheck(target, changeScope([command], this.allow).services).catch(() => null); if (pc) { result.post_check = pc; if (!pc.ok) result.note = `POST-CHECK FOUND PROBLEMS: ${pc.issues.join(" / ")}. Fix them before reporting done.`; } }
      }
      }
    } catch (e: any) {
      result = { status: "failed", error: e.message };
    }
    if (a.next_action_id) {
      const ok = result.status === "executed" && (result.exit_code ?? 0) === 0;
      await db("next_actions").where({ id: a.next_action_id }).update({ status: ok ? "done" : "approved", updated_at: db.fn.now() });
      if (ok) this.onActionDone(a.next_action_id).catch((e) => this.ctx.log.warn({ err: e.message }, "unblock failed"));
    }
    await db("approvals").where({ id: approvalId }).update({ exec_result: j(result) });
    if (a.tool_call_id) await db("tool_calls").where({ id: a.tool_call_id }).update({ status: result.status === "executed" ? "approved" : "failed", result: j(result), finished_at: db.fn.now() });
    if (!hostAct) await this.ctx.audit.log("agent", null, cloud ? "cloud.action_executed" : "ssh.write_executed", { host: host?.name, command, exit_code: result.exit_code, status: result.status, cloud: cloud ?? undefined }, a.session_id ?? undefined);
    this.checkRunaway().catch((e) => this.ctx.log.warn({ err: e.message }, "runaway check failed"));
    if (a.session_id && tc && deferred) { // EDR-168: the tool call was answered when it was approved; report as a note
      await this.appendMessage(a.session_id, { role: "user", content: truncate(`[system] 予約していた操作（承認 #${approvalId}「${a.title ?? ""}」）を予約時刻に実行しました。結果:\n${JSON.stringify({ ...result, executed_command: command })}`) });
      this.emit({ type: "approval", session_id: a.session_id, approval: { ...a, decision, exec_result: result } });
      const sess = await db("sessions").where({ id: a.session_id }).first();
      if (sess && !["running", "waiting_approval"].includes(sess.status)) { await this.setStatus(a.session_id, "running", "scheduled approval executed"); this.kickSoon(a.session_id); }
    } else if (a.session_id && tc) {
      await this.appendMessage(a.session_id, { role: "tool", tool_call_id: pj(tc.args)?._call_id, name: tc.tool, content: truncate(JSON.stringify({ ...result, approved_by_human: true, executed_command: command })) });
      this.emit({ type: "approval", session_id: a.session_id, approval: { ...a, decision, exec_result: result } });
      if (await db("approvals").where({ session_id: a.session_id, decision: "pending" }).first()) return; // EDR-87: wait for the other approvals of this turn
      await this.setStatus(a.session_id, "running", "approval executed");
      this.kickSoon(a.session_id);
    } else {
      this.emit({ type: "approval", session_id: a.session_id ?? 0, approval: { ...a, decision, exec_result: result } });
    }
  }

  // ---------------- internals ----------------
  /** 「対応待ち」判定: 人間の返事ではなく外部要因（修正版の提供・依存タスクの完了・定期確認）を待っている状態か */
  private async externalWait(id: number): Promise<string | null> {
    const { db } = this.ctx;
    if (await db("approvals").where({ session_id: id, decision: "pending" }).first()) return null;
    const sc = await db("schedules").where({ session_id: id, state: "active", enabled: true }).orderBy("next_run_at").first();
    if (sc) return `schedule #${sc.id}`;
    const blk = await db("next_actions").where({ session_id: id, status: "blocked" }).first();
    if (blk) return `action #${blk.id} waits for #${blk.after_id}`;
    const s = await db("sessions").where({ id }).first();
    const w = pj<any>(s?.summary)?.waiting_external;
    return w ? `flag: ${w.reason ?? ""}` : null;
  }
  /** 待ち状態の再評価: 返答待ち ⇔ 対応待ち（スケジュール完了・取消、依存解放、フラグ変更のあとに呼ぶ） */
  async refreshWaiting(id: number): Promise<void> {
    const s = await this.ctx.db("sessions").where({ id }).first();
    if (!s || !["waiting_user", "waiting_external"].includes(s.status)) return;
    const why = await this.externalWait(id);
    const want = why ? "waiting_external" : "waiting_user";
    if (want !== s.status) await this.setStatus(id, want, why ?? "external wait ended");
  }

  private async setStatus(id: number, status: string, detail?: string) {
    if (status === "waiting_user") { const why = await this.externalWait(id); if (why) { status = "waiting_external"; detail = `${detail ?? ""} (waiting: ${why})`.trim(); } }
    const upd: any = { status, updated_at: this.ctx.db.fn.now() };
    if (["done", "failed", "cancelled"].includes(status)) upd.finished_at = this.ctx.db.fn.now();
    await this.ctx.db("sessions").where({ id }).update(upd);
    this.emit({ type: "status", session_id: id, status, detail });
    if (status === "waiting_user" || status === "waiting_external" || status === "done") this.labelSession(id).catch((e) => this.ctx.log.warn({ err: e.message, id }, "labeling failed"));
  }

  /** Plain-Japanese triage notes for unknown Wazuh rules (one LLM call for up to 20 rules). Returns the number stored. */
  async explainRules(rules: { id: string; description: string; level: number; groups?: string[]; sample?: string }[]): Promise<number> {
    if (!this.provider || !rules.length) return 0;
    const res = await this.provider.chat([
      { role: "system", content: `You write plain-Japanese triage notes for Wazuh/Sysmon security alerts, for readers who are NOT security experts. For each rule return: title_ja (<=40 chars, what happened in everyday words), meaning (1-2 sentences: what was observed), cause (likely causes incl. the normal/benign cases), impact (what happens if it is a real attack and is ignored), action (concrete first steps a responder should take), triage: "benign_likely" (usually normal noise / false positive), "check" (needs a look), "danger" (likely attack, act now). Be honest about uncertainty. IMPORTANT: a note is keyed by rule id and shown for EVERY alert of that rule on every host and OS, so describe the rule in general terms; the "sample" is only a hint about what the rule matches — never copy host names, CVE ids, package names, file paths, user names or IP addresses from it into the text. Reply with JSON only: {"notes":[{"rule_id":"...","title_ja":"...","meaning":"...","cause":"...","impact":"...","action":"...","triage":"..."}]}` },
      { role: "user", content: JSON.stringify(rules) },
    ], [], { maxTokens: 3500, temperature: 0 });
    const m = String(res.message.content ?? "").match(/\{[\s\S]*\}/);
    if (!m) return 0;
    let parsed: any; try { parsed = JSON.parse(m[0]); } catch { return 0; }
    let n = 0;
    for (const x of parsed.notes ?? []) {
      const id = String(x.rule_id ?? "").trim(); const src = rules.find((r) => r.id === id);
      if (!src || !x.title_ja) continue;
      const triage = ["benign_likely", "check", "danger"].includes(x.triage) ? x.triage : src.level >= 15 ? "danger" : "check";
      const row = { title_ja: String(x.title_ja).slice(0, 120), meaning: String(x.meaning ?? ""), cause: String(x.cause ?? ""), impact: String(x.impact ?? ""), action: String(x.action ?? ""), triage, source: "ai", description_en: src.description.slice(0, 255), updated_at: this.ctx.db.fn.now() };
      const ex = await this.ctx.db("rule_notes").where({ rule_id: id }).first();
      if (ex) { if (ex.source !== "user") await this.ctx.db("rule_notes").where({ rule_id: id }).update(row); } else await this.ctx.db("rule_notes").insert({ rule_id: id, ...row });
      n++;
    }
    await this.ctx.audit.log("agent", null, "rule_notes.generated", { count: n, ids: rules.map((r) => r.id) });
    return n;
  }

  /** Ask the model for a short label + tags once the conversation has substance (first waiting_user, refreshed on done). */
  async labelSession(id: number, force = false): Promise<{ label: string; tags: string[] } | null> {
    if (!this.provider) return null;
    const { db } = this.ctx;
    const s = await db("sessions").where({ id }).first();
    if (!s) return null;
    if (s.label && !force && s.status !== "done") return null;
    if (s.label && s.status === "done" && pj<any>(s.summary)?.labeled_done) return null;
    const rows = await db("messages").where({ session_id: id }).orderBy("seq");
    const text = rows.map((r: any) => pj<ChatMessage>(r.content)).filter((m) => m.role === "user" || (m.role === "assistant" && m.content)).map((m) => `${m.role === "user" ? "人間" : "AI"}: ${String(m.content).slice(0, 600)}`).join("\n").slice(0, 6000);
    if (text.length < 20) return null;
    const kindJa: Record<string, string> = { investigate: "調査", playbook_setup: "プレイブック作成", host_setup: "ホスト登録", overview_setup: "攻撃可視化セットアップ", cloud_setup: "クラウド管理", contain_consult: "通信遮断の相談" };
    const res = await this.provider.chat([
      { role: "system", content: "You label chat sessions of a security console. Reply with JSON only: {\"label\": string, \"tags\": string[]}. label: Japanese, max 24 characters, concrete (host/rule/topic + what was done or asked), no quotes. tags: 1-3 short Japanese or technical tokens (e.g. 誤検知, Shellshock, fail2ban, レポート, SMTP). No markdown." },
      { role: "user", content: `種別: ${kindJa[s.kind] ?? s.kind}\n会話:\n${text}` },
    ], [], { maxTokens: 200, temperature: 0 });
    const raw = String(res.message.content ?? "");
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) return null;
    let parsed: any; try { parsed = JSON.parse(m[0]); } catch { return null; }
    const label = String(parsed.label ?? "").replace(/\s+/g, " ").trim().slice(0, 60);
    const tags = Array.isArray(parsed.tags) ? parsed.tags.map((t: any) => String(t).trim().slice(0, 24)).filter(Boolean).slice(0, 3) : [];
    if (!label) return null;
    const meta = pj<any>(s.summary) ?? {};
    await db("sessions").where({ id }).update({ label, tags: j(tags), summary: j({ ...meta, labeled_done: s.status === "done" }), updated_at: db.fn.now() });
    this.emit({ type: "status", session_id: id, status: s.status, detail: "labeled" });
    return { label, tags };
  }

  private async appendMessage(sessionId: number, m: ChatMessage): Promise<number> {
    const { db } = this.ctx;
    const last = await db("messages").where({ session_id: sessionId }).max<{ m: number }[]>({ m: "seq" }).first();
    const seq = Number(last?.m ?? 0) + 1;
    const [id] = await db("messages").insert({ session_id: sessionId, seq, role: m.role, content: j(m), tool_call_id: m.tool_call_id ?? null }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    if (m.role !== "system") this.emit({ type: "message", session_id: sessionId, message: { id, seq, ...m } });
    return id;
  }

  private async loadMessages(sessionId: number): Promise<ChatMessage[]> {
    const rows = await this.ctx.db("messages").where({ session_id: sessionId }).orderBy("seq");
    const msgs = normalizeTranscript(rows.map((r: any) => pj<ChatMessage>(r.content)).filter(Boolean));
    // 画像添付: attachments（base64）から送信直前に解決。直近 6 枚だけ渡す（古い画像はテキスト注記のみ）
    let budget = 6;
    for (let i = msgs.length - 1; i >= 0; i--) {
      const m = msgs[i]; if (!m || m.role !== "user" || !m.images?.length) continue;
      for (const im of m.images) {
        if (budget <= 0 || !im.attachment_id) { im.data = undefined; continue; }
        const row = await this.ctx.db("attachments").where({ id: im.attachment_id }).first();
        if (row?.encoding === "base64") { im.data = row.content; budget--; }
      }
    }
    // Context compaction: keep the last KEEP_FULL tool results verbatim, shrink older ones (full text stays in DB / UI)
    const KEEP_FULL = 6, OLD_MAX = 1200;
    const toolIdx = msgs.map((m, i) => (m.role === "tool" ? i : -1)).filter((i) => i >= 0);
    const shrink = new Set(toolIdx.slice(0, Math.max(0, toolIdx.length - KEEP_FULL)));
    return msgs.map((m, i) => shrink.has(i) && (m.content?.length ?? 0) > OLD_MAX ? { ...m, content: m.content!.slice(0, OLD_MAX) + `\n...[older tool result compacted: ${m.content!.length} chars total; ask again if you need the details]` } : m);
  }

  private async buildSystemPrompt(kind: SessionKind, wazuhInstanceId: number | null, hostIds: number[]): Promise<string> {
    const { db } = this.ctx;
    if (kind !== "investigate") return this.buildSetupPrompt(kind);
    const parts = [SYSTEM_PROMPT_BASE];
    const playbooks = await db("playbooks").where({ enabled: true }).whereIn("scope", ["global"]).orderBy("id");
    for (const p of playbooks) parts.push(`## Playbook: ${p.name}\n${p.markdown}`);
    const wz = wazuhInstanceId ? await db("wazuh_instances").where({ id: wazuhInstanceId }).first() : await db("wazuh_instances").orderBy("id").first();
    if (wz) parts.push(`## Wazuh\nInstance: ${wz.name} (archives ${wz.archives_enabled ? "enabled" : "disabled"}). indexer_query / wazuh_api use this instance.`);
    const hosts = await db("hosts").orderBy("id");
    const hostLines = hosts.map((h: any) => `- ${h.name}: ${h.ssh_user}@${h.address} env=${h.environment} sudo=${h.sudo_mode} agent=${h.agent_id ?? "-"} autonomy=L${h.autonomy_level}${h.notes ? " — " + h.notes : ""}${hostIds.includes(h.id) ? " [in scope]" : ""}`);
    parts.push(`## Registered hosts (ssh_exec targets)\n${hostLines.join("\n") || "(none)"}`);
    parts.push(await this.hostSyncNote());
    const ranges = await db("protected_ranges").orderBy("id");
    if (ranges.length) parts.push(`## Protected addresses (never propose blocking these)\n${ranges.map((r: any) => `- ${r.cidr} ${r.label}`).join("\n")}`);
    const recent = await db("sessions").whereIn("status", ["done"]).whereNotNull("summary").orderBy("id", "desc").limit(5);
    const prior = recent.map((s: any) => { const sm = pj<any>(s.summary); return sm?.proposal ? `- [${s.created_at}] ${s.title}: ${sm.proposal.verdict ?? ""} — ${String(sm.proposal.summary ?? "").slice(0, 200)}` : null; }).filter(Boolean);
    if (prior.length) parts.push(`## Recent investigations\n${prior.join("\n")}`);
    parts.push(`## Now\n${new Date().toISOString()} (UTC). The lab is in Asia/Tokyo (UTC+9).`);
    return parts.join("\n\n");
  }

  /** EDR-153: how hosts get into the list, and which agents are deliberately NOT imported (so the agent can explain "why is my PC missing") */
  private async hostSyncNote(): Promise<string> {
    let ignored: string[] = [];
    try { ignored = JSON.parse((await this.ctx.db("app_flags").where({ key: "host_sync_ignore" }).first())?.value ?? "[]"); } catch { ignored = []; }
    const mins = this.ctx.cfg.HOST_AGENT_SYNC_MIN;
    return `## How hosts get into MamorAI's host list
- Every Wazuh agent (Windows / Linux / macOS, installed with the agent pack or by hand) is imported automatically as an "agent only" host ${mins > 0 ? `every ${mins} minutes` : "only when an admin presses 「Wazuh から取り込む」 (automatic import is off)"}. No SSH and no extra registration is needed for that. Windows hosts never need SSH.
- Exception: when an admin DELETES such a host in MamorAI, its agent goes on a "do not import again" list. It stays off the list until an admin presses 「元に戻す」 in 管理ホスト › 取り込み対象外. Agents on that list now: ${ignored.length ? ignored.map((k) => `agent ${k.split(":")[1]} (Wazuh #${k.split(":")[0]})`).join(", ") : "none"}.
- If a PC is missing: check that the agent exists and is Active in Wazuh (wazuh_api), whether it is on the list above, and how long ago it enrolled (up to ${mins || "?"} minutes delay). Do not tell the user that Windows needs SSH or a special registration.`;
  }

  /** EDR-142: host + latest Contain impact note for the consultation chat */
  private async containContext(hostId: number): Promise<string> {
    const { db } = this.ctx;
    const h = await db("hosts").where({ id: hostId }).first();
    if (!h) return "";
    const note = await db("host_ai_notes").where({ host_id: hostId, kind: "contain_impact" }).orderBy("id", "desc").first().catch(() => null);
    const c = note ? pj<any>(note.content) : null;
    const lines = [`\n\n## Session context\nThe human opened this chat from the Contain help page of host "${h.name}" (host_id=${h.id}, env=${h.environment}, kind=${h.kind ?? "-"}, os=${h.os_family ?? "-"}, agent=${h.agent_id ?? "-"}, contained=${h.isolation_state === "isolated" ? "yes" : "no"}). Use host_id=${h.id} for host_profile / host_scan / host_action.`];
    if (c) lines.push(`## Contain impact note (AI, from scan #${note.scan_id}; may be older than the latest scan)\n${JSON.stringify({ summary: c.summary, keeps: c.keeps, stops: c.stops, use_now_if: c.use_now_if, avoid_if: c.avoid_if, keeps_behaviour: c.keeps_behaviour }).slice(0, 6000)}`);
    else lines.push("## Contain impact note\n(not generated yet — use host_profile)");
    return lines.join("\n\n");
  }

  private async buildSetupPrompt(kind: SessionKind): Promise<string> {
    const { db } = this.ctx;
    if (kind === "contain_consult") return [SYSTEM_PROMPT_CONTAIN_CONSULT, `## Now\n${new Date().toISOString()} (UTC). The lab is in Asia/Tokyo (UTC+9).`].join("\n\n");
    const parts = [kind === "playbook_setup" ? SYSTEM_PROMPT_PLAYBOOK_SETUP : kind === "overview_setup" ? SYSTEM_PROMPT_OVERVIEW_SETUP : kind === "cloud_setup" ? SYSTEM_PROMPT_CLOUD_SETUP : SYSTEM_PROMPT_HOST_SETUP];
    if (kind === "cloud_setup") {
      const provs = await db("cloud_providers").orderBy("id");
      parts.push(`## Cloud providers\n${provs.map((p: any) => `- #${p.id} ${p.kind} "${p.name}" capability=${p.capability} status=${p.status} credentials=${p.secret_enc ? "stored" : "MISSING"}`).join("\n") || "(none)"}`);
    }
    if (kind === "overview_setup") {
      const st = await db("overview_setup").orderBy("wazuh_instance_id").first();
      if (st) parts.push(`## Wizard state (from the UI)\nassets=${st.assets ?? "[]"} vendors=${st.vendors ?? "{}"} manager_addr=${st.manager_addr ?? "(unknown)"} step=${st.step} completed=${!!st.completed}`);
      const sites = await db("sites").orderBy("id"); const members = await db("site_members");
      parts.push(`## Sites\n${sites.map((x: any) => `- #${x.id} ${x.name} (${x.lat},${x.lon}) ${x.kind}${x.is_default ? " [default]" : ""}: ${members.filter((m: any) => m.site_id === x.id).map((m: any) => m.agent_name).join(", ") || "(no hosts)"}`).join("\n") || "(none yet — hosts are drawn at Tokyo until a site is set)"}`);
    }
    const playbooks = await db("playbooks").orderBy("id");
    parts.push(`## Existing playbooks\n${playbooks.map((p: any) => `- #${p.id} ${p.name}${p.enabled ? "" : " (disabled)"}${p.builtin ? " (builtin)" : ""} — ${String(p.markdown).split("\n").slice(1).find((l: string) => l.trim())?.slice(0, 120) ?? ""}`).join("\n") || "(none)"}`);
    const hosts = await db("hosts").orderBy("id");
    parts.push(`## Registered hosts\n${hosts.map((h: any) => h.kind === "agent_only" ? `- ${h.name} (host_id=${h.id}): Wazuh-agent-only ${h.os_family ?? ""} endpoint, agent=${h.agent_id ?? "-"}, add-on=${h.ar_addon_version ?? "unknown"}, pack=r${h.pack_rev ?? "?"} env=${h.environment} — operate with host_profile / win_updates / host_action (no SSH)${h.notes ? " — " + h.notes : ""}` : `- ${h.name}: ${h.ssh_user}@${h.address}:${h.port} env=${h.environment} sudo=${h.sudo_mode} key#${h.ssh_key_id ?? "-"} agent=${h.agent_id ?? "-"} autonomy=L${h.autonomy_level}/max${h.autonomy_max} hostkey=${h.host_key ? "pinned" : "not yet"}${h.notes ? " — " + h.notes : ""}`).join("\n") || "(none)"}`);
    parts.push(await this.hostSyncNote());
    const keys = await db("ssh_keys").orderBy("id");
    parts.push(`## SSH keys (console-owned)\n${keys.map((k: any) => `- #${k.id} ${k.name} ${k.fingerprint}`).join("\n") || "(none)"}`);
    const wz = await db("wazuh_instances").orderBy("id");
    parts.push(`## Wazuh instances\n${wz.map((w: any) => `- #${w.id} ${w.name} (${w.api_url ? "API configured" : "no API"})`).join("\n") || "(none)"}`);
    const ranges = await db("protected_ranges").orderBy("id");
    if (ranges.length) parts.push(`## Protected addresses\n${ranges.map((r: any) => `- ${r.cidr} ${r.label}`).join("\n")}`);
    parts.push(`## Anything else\nThis chat is shown to the user as 「AIエージェントに相談」 and they may ask anything, not only this page's job (questions, explanations, patching, improvements). Answer plain questions directly. Do what your tools here allow; when the request needs tools this page does not have (e.g. investigating alerts or patching a server from a playbook page), say so in one sentence and suggest the main screen 「Sidekick」 (/sidekick) with a ready-to-paste request.`);
    parts.push(`## Now\n${new Date().toISOString()} (UTC). The lab is in Asia/Tokyo (UTC+9).`);
    return parts.join("\n\n");
  }

  private rekick = new Set<number>();
  /** Like kick(), but if the loop is still running (auto-approval raced the turn), run once more after it ends. */
  private kickSoon(sessionId: number) {
    if (this.running.has(sessionId)) { this.rekick.add(sessionId); return; }
    this.kick(sessionId);
  }

  private kick(sessionId: number) {
    if (this.running.has(sessionId)) return;
    this.running.add(sessionId);
    this.loop(sessionId).catch(async (e) => {
      this.ctx.log.error({ err: e, sessionId }, "session loop failed");
      this.emit({ type: "error", session_id: sessionId, error: e.message });
      await this.failWith(sessionId, e.message);
    }).finally(() => {
      this.running.delete(sessionId);
      if (this.rekick.delete(sessionId)) this.ctx.db("approvals").where({ session_id: sessionId, decision: "pending" }).first().then(async (p: any) => { if (!p) { await this.setStatus(sessionId, "running", "approval executed"); this.kick(sessionId); } }).catch(() => {});
    });
  }

  private async loop(sessionId: number): Promise<void> {
    const { db, cfg } = this.ctx;
    if (!this.provider) { await this.setStatus(sessionId, "failed", "LLM not configured: " + this.providerError); return; }
    const session = await db("sessions").where({ id: sessionId }).first();
    if (session.status !== "running") await this.setStatus(sessionId, "running", "thinking");
    const kind: SessionKind = session.kind ?? "investigate";
    const meta = pj<any>(session.summary) ?? {};
    const wazuhId: number | null = meta.wazuh_instance_id ?? (await db("wazuh_instances").orderBy("id").first())?.id ?? null;
    let tokenIn = session.token_in ?? 0, tokenOut = session.token_out ?? 0;
    // EDR-93: the budget applies to THIS run (one human message → reply), not to the session's lifetime.
    // A long-lived ticket (scheduled re-checks over days) used to exceed the cumulative budget and then failed on every new message.
    const startIn = tokenIn, startOut = tokenOut;

    let wrapUp = false, vulnLogged = false;
    for (let turn = 0; turn < MAX_TURNS + 1; turn++) {
      const cur = await db("sessions").where({ id: sessionId }).first();
      if (cur.status === "cancelled") return;
      const overBudget = (tokenIn - startIn) + (tokenOut - startOut) > cfg.LLM_MAX_TOKENS_PER_SESSION || turn >= MAX_TURNS;
      if (overBudget && wrapUp) {
        // EDR-93: do not fail the ticket — pause it and let the human continue with one reply
        await this.appendMessage(sessionId, { role: "assistant", content: "作業が長くなったため、ここで一度止めました。続ける場合は「続けて」と返信してください。" });
        await this.ctx.audit.log("system", null, "session.paused_budget", { tokenIn: tokenIn - startIn, tokenOut: tokenOut - startOut, turn }, sessionId);
        await this.releaseStuckActions(sessionId);
        await this.setStatus(sessionId, "waiting_user", "paused: run budget reached");
        return;
      }
      if (overBudget && !wrapUp) {
        wrapUp = true;
        await this.appendMessage(sessionId, { role: "user", content: kind === "investigate" ? "[system] Investigation budget reached. Do not call any more investigation tools. Call propose_next_actions NOW with what you know so far (mark open questions explicitly)." : "[system] Session budget reached. Summarise where the setup stands and what the human should do next, in one short message." });
        await this.ctx.audit.log("system", null, "session.wrap_up", { tokenIn, tokenOut, turn }, sessionId);
      }
      const messages = await this.loadMessages(sessionId);
      // EDR-81: 人間の最新の発言が脆弱性・版・パッチの話題なら、この質問の間だけ判断ルールを system prompt に足す（DB には保存しない）
      if (kind === "investigate" && !wrapUp && messages[0]?.role === "system") {
        // EDR-113: also when the ticket itself is about a vulnerability ("承認OK" / "もう一回やって" do not mention CVEs)
        const humans = messages.filter((m) => m.role === "user" && typeof m.content === "string" && !m.content.startsWith("[system]"));
        if (isVulnQuestion(session.title) || humans.slice(-5).some((m) => isVulnQuestion(m.content as string))) {
          messages[0] = { ...messages[0], content: `${messages[0].content}\n\n${VULN_GUIDE}` };
          if (!vulnLogged) { vulnLogged = true; await this.ctx.audit.log("system", null, "session.vuln_guide", { turn }, sessionId); }
        }
      }
      // EDR-115: the human's decisions for this ticket, on every turn (long tickets push the original message out of focus)
      if (messages[0]?.role === "system") {
        const ds = await db("session_decisions").where({ session_id: sessionId, active: true }).orderBy("id");
        if (ds.length) messages[0] = { ...messages[0], content: `${messages[0].content}\n\n## Decisions the human made in this ticket (binding — plans that break them are refused)\n${ds.map((d: any) => `- ${d.text}${d.forbid ? ` [forbids: ${d.forbid}]` : ""}`).join("\n")}` };
      }
      this.emit({ type: "status", session_id: sessionId, status: "running", detail: "thinking" });
      const res = await this.provider.chat(messages, toolsFor(kind, wrapUp));
      tokenIn += res.usage.input; tokenOut += res.usage.output;
      await db("sessions").where({ id: sessionId }).update({ token_in: tokenIn, token_out: tokenOut, llm_model: res.model });
      await this.appendMessage(sessionId, res.message);
      await this.ctx.audit.log("agent", null, "llm.turn", { model: res.model, usage: res.usage, finish: res.finish, tool_calls: res.message.tool_calls?.map((t) => t.name) }, sessionId);

      if (!res.message.tool_calls?.length) {
        await this.releaseStuckActions(sessionId);
        // EDR-145: a reply given while an approval card is still open → back to "waiting for approval"
        if (await db("approvals").where({ session_id: sessionId, decision: "pending" }).first()) { await this.setStatus(sessionId, "waiting_approval", "replied; approval still pending"); return; }
        await this.setStatus(sessionId, "waiting_user", "assistant replied without tools"); return;
      }

      let paused = false, finished = false, closed = false;
      for (const call of res.message.tool_calls) {
        // EDR-93: in the wrap-up turn only the offered tool may run; anything else is answered "skipped" (the transcript stays valid)
        if (wrapUp && kind === "investigate" && call.name !== "propose_next_actions") {
          await this.appendMessage(sessionId, { role: "tool", tool_call_id: call.id, name: call.name, content: JSON.stringify({ status: "skipped", reason: "wrap-up turn: only propose_next_actions is allowed now" }) });
          continue;
        }
        const out = await this.runTool(sessionId, wazuhId, call);
        if (out === "pending_approval") paused = true;
        if (out === "finished") finished = true;
        if (out === "closed") closed = true;
      }
      if (paused) { await this.setStatus(sessionId, "waiting_approval"); return; }
      if (closed) { await this.releaseStuckActions(sessionId); await this.ctx.db("next_actions").where({ session_id: sessionId, status: "proposed" }).update({ status: "done", updated_at: this.ctx.db.fn.now() }); await this.setStatus(sessionId, "done", "closed by agent"); return; }
      if (finished) { await this.releaseStuckActions(sessionId); const pend = await db("approvals").where({ session_id: sessionId, decision: "pending" }).first(); await this.setStatus(sessionId, pend ? "waiting_approval" : "waiting_user", pend ? "proposal presented; approval still pending" : "proposal presented"); return; }
    }
    await this.failWith(sessionId, `turn limit ${MAX_TURNS} reached`);
  }

  /** An action the human asked to run, but for which the agent produced no plan, goes back to "proposed" so the button returns. */
  private async releaseStuckActions(sessionId: number) {
    await this.ctx.db("next_actions").where({ session_id: sessionId, status: "approved" }).whereNull("approval_id").update({ status: "proposed", updated_at: this.ctx.db.fn.now() });
  }

  private async failWith(sessionId: number, reason: string) {
    const s = await this.ctx.db("sessions").where({ id: sessionId }).first();
    const meta = pj<any>(s?.summary) ?? {};
    await this.ctx.db("sessions").where({ id: sessionId }).update({ summary: j({ ...meta, error: reason }) });
    await this.ctx.audit.log("system", null, "session.failed", { reason }, sessionId);
    await this.setStatus(sessionId, "failed", reason);
  }

  /** Execute one tool call; returns "ok" | "pending_approval" | "finished". */
  private async runTool(sessionId: number, wazuhId: number | null, call: ToolCall): Promise<"ok" | "pending_approval" | "finished" | "closed"> {
    const { db } = this.ctx;
    const started = new Date();
    const [tcId] = await db("tool_calls").insert({ session_id: sessionId, tool: call.name, args: j({ ...call.args, _call_id: call.id }), status: "executed", started_at: started }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    this.emit({ type: "tool_call", session_id: sessionId, tool_call: { id: tcId, tool: call.name, args: call.args } });
    const reply = async (content: unknown, status = "executed", extra: Record<string, unknown> = {}) => {
      const text = typeof content === "string" ? content : JSON.stringify(content);
      await db("tool_calls").where({ id: tcId }).update({ status, result: j(content), finished_at: db.fn.now(), ...extra });
      await this.appendMessage(sessionId, { role: "tool", tool_call_id: call.id, name: call.name, content: truncate(redactSecrets(text)) });
      this.emit({ type: "tool_result", session_id: sessionId, tool_call: { id: tcId, tool: call.name, status, result_preview: text.slice(0, 500) } });
    };
    try {
      // EDR-147: operators may open every AI chat; tools that change MamorAI's own configuration directly (no approval card) stay admin-only
      if (ADMIN_ONLY_TOOLS.has(call.name)) {
        // the person who wrote last decides (an admin may pick up a chat an operator started)
        const sess = await db("sessions").where({ id: sessionId }).first();
        const lastHuman = await db("audit_log").where({ session_id: sessionId, actor: "user" }).whereIn("event", ["session.user_message", "session.created"]).orderBy("id", "desc").first().catch(() => null);
        const actorId = lastHuman?.actor_id ? Number(lastHuman.actor_id) : sess?.started_by ?? null;
        const owner = actorId ? await db("users").where({ id: actorId }).first() : null;
        if (actorId && owner?.role !== "admin") {
          await reply({ status: "forbidden", reason: "admin_only", note: `「${call.name}」は MamorAI の設定を直接変える操作なので、管理者（admin）だけが実行できます。この相談を始めた人は ${owner?.role ?? "不明"} です。実行はせず、内容（下書き・設定値・手順）をまとめて見せ、管理者に依頼するよう伝えてください（管理者がこの相談の内容を見て実行できます）。` }, "rejected");
          await this.ctx.audit.log("agent", null, "tool.forbidden_role", { tool: call.name, role: owner?.role ?? null }, sessionId);
          return "ok";
        }
      }
      switch (call.name) {
        case "indexer_query": {
          if (!wazuhId) return (await reply({ error: "no wazuh instance" }, "failed"), "ok");
          const ix = await indexer(this.ctx, wazuhId);
          const a = call.args as any;
          const r = await ix.search(String(a.index), a.query ?? {}, Number(a.size ?? 20));
          const compact = { took: r.took, total: r.hits?.total, hits: (r.hits?.hits ?? []).map((h: any) => ({ _id: h._id, ...h._source })), aggregations: r.aggregations };
          await reply(compact);
          return "ok";
        }
        case "wazuh_api": {
          if (!wazuhId) return (await reply({ error: "no wazuh instance" }, "failed"), "ok");
          const api = await managerApi(this.ctx, wazuhId);
          const r = await api.get(String((call.args as any).path));
          await reply(r);
          return "ok";
        }
        case "version_check": {
          const a = call.args as any;
          let ix: any = null;
          if (a.agent && wazuhId) { try { ix = await indexer(this.ctx, wazuhId); } catch { ix = null; } }
          await reply(await versionCheck({ product: String(a.product ?? ""), version: String(a.version ?? ""), agent: a.agent ? String(a.agent) : undefined }, ix));
          return "ok";
        }
        case "pkg_candidates": { // EDR-114
          const a = call.args as any;
          const host = await db("hosts").where({ name: String(a.host) }).first();
          if (!host) return (await reply({ error: `unknown host '${a.host}'` }, "failed"), "ok");
          if (!host.ssh_key_id) return (await reply({ error: host.kind === "agent_only" ? `host '${host.name}' is a Wazuh-agent-only endpoint (no SSH). Use host_profile / indexer_query to read it and host_action for containment.` : `host '${host.name}' has no SSH key configured` }, "failed"), "ok");
          let script: string;
          try { script = pkgScript(String(a.package ?? "")); } catch (e: any) { return (await reply({ error: e.message }, "failed"), "ok"); }
          const key = await db("ssh_keys").where({ id: host.ssh_key_id }).first();
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: `${host.name}: 入れられる版を確認中（数分かかることがあります）` });
          const r = await sshExec({ address: host.address, port: host.port, user: host.ssh_user, privateKey: this.ctx.box.decrypt(key.private_key_enc), sudoMode: host.sudo_mode, hostKey: host.host_key }, script, 280_000)
            .catch((e: any) => ({ code: null, stdout: "", stderr: String(e?.message ?? e), durationMs: 0, truncated: false, hostKey: "" } as any));
          let fixed: string | null = a.fixed_version ? String(a.fixed_version) : null;
          let res = pkgParse(host.name, String(a.package), r.stdout, fixed, r.stderr);
          let vc: any = null;
          const inst = res.packages.find((p) => p.installed)?.installed ?? null;
          if (!fixed && a.product && inst) {
            vc = await versionCheck({ product: String(a.product), version: normalizeVersion(inst.replace(/^\d+:/, "")) }).catch(() => null);
            if (vc?.latest_in_cycle) { fixed = String(vc.latest_in_cycle); res = pkgParse(host.name, String(a.package), r.stdout, fixed, r.stderr); }
          }
          await this.ctx.audit.log("agent", null, "pkg.candidates", { host: host.name, package: a.package, verdict: res.verdict, fixed: res.fixed_version, ms: r.durationMs }, sessionId);
          await reply({ ...res, fixed_version_source: a.fixed_version ? "given" : vc?.latest_in_cycle ? "version_check (latest of the installed line)" : null });
          return "ok";
        }
        case "record_decision": { // EDR-115
          const a = call.args as any;
          const text = String(a.text ?? "").trim().slice(0, 500);
          if (!text) return (await reply({ error: "text is required" }, "failed"), "ok");
          const forbid = ["source_build", "external_repo", "os_upgrade", "package_removal", "reboot"].includes(a.forbid) ? String(a.forbid) : null;
          const dup = await db("session_decisions").where({ session_id: sessionId, text, active: true }).first();
          if (!dup) await db("session_decisions").insert({ session_id: sessionId, text, forbid });
          await this.ctx.audit.log("agent", null, "session.decision", { text, forbid }, sessionId);
          await reply({ status: "recorded", text, forbid, note: "Shown to you on every turn; plans containing the forbidden operation are refused." });
          return "ok";
        }
        case "host_profile": case "host_scan": { // EDR-121
          const a = call.args as any;
          const host = await db("hosts").where({ name: String(a.host) }).first();
          if (!host) return (await reply({ error: `unknown host '${a.host}'. Agent-only hosts are imported from Wazuh automatically (管理ホスト).` }, "failed"), "ok");
          if (call.name === "host_scan") {
            if (!this.ctx.hostScanner) return (await reply({ error: "host scanner not running" }, "failed"), "ok");
            const id = await this.ctx.hostScanner.enqueue(host.id, "manual", null);
            await reply({ status: "queued", scan_id: id, note: "Takes 30-90 s. Call host_profile afterwards; if status is still running, wait and call again." });
            return "ok";
          }
          const scan = await db("host_scans").where({ host_id: host.id }).orderBy("id", "desc").first();
          const done = scan?.status === "done" ? scan : await db("host_scans").where({ host_id: host.id, status: "done" }).orderBy("id", "desc").first();
          if (!done) return (await reply({ host: host.name, status: scan?.status ?? "never_scanned", note: "No finished scan yet. Call host_scan (read-only) and then host_profile again." }), "ok");
          const f = pj<any>(done.facts) ?? {};
          await reply({ host: host.name, kind: host.kind, scanned_at: done.finished_at, latest_status: scan?.status, profile: pj(done.profile), diff: pj(done.diff),
            facts: { system: f.system, listening: (f.listening ?? []).slice(0, 40), users: (f.users ?? []).slice(0, 25), connections: (f.connections ?? []).slice(0, 15), vulns: f.vulns, sca: f.sca, software_total: f.software?.total, browser_extensions: (f.software?.browser_extensions ?? []).slice(0, 15), top_rules: f.activity?.top_rules, ssh: f.ssh ? { units: (f.ssh.units ?? []).slice(0, 40), containers: f.ssh.containers, cron: (f.ssh.cron ?? []).slice(0, 15) } : undefined } });
          return "ok";
        }
        case "win_updates": { // EDR-168: read-only
          const a = call.args as any;
          const host = await db("hosts").where({ name: String(a.host) }).first();
          if (!host) return (await reply({ error: `unknown host '${a.host}'` }, "failed"), "ok");
          const { scanWindowsUpdates } = await import("../hosts/actions.js");
          const fresh = host.win_updates_at && Date.now() - new Date(host.win_updates_at).getTime() < 6 * 3600_000;
          if (!a.refresh && fresh && host.win_updates) return (await reply({ host: host.name, cached: true, ...pj<any>(host.win_updates) }), "ok");
          await this.emit({ type: "status", session_id: sessionId, status: "running", detail: `${host.name} で Windows Update を確認中（1〜5 分）` });
          const r = await scanWindowsUpdates(this.ctx, host, a.apps !== false);
          if (!r.ok) return (await reply({ host: host.name, error: r.message }, "failed"), "ok");
          await reply({ host: host.name, cached: false, ...r.scan });
          return "ok";
        }
        case "host_action": { // EDR-121: always a human approval
          const a = call.args as any;
          const host = await db("hosts").where({ name: String(a.host) }).first();
          if (!host) return (await reply({ error: `unknown host '${a.host}'` }, "failed"), "ok");
          const { requestAction } = await import("../hosts/actions.js");
          const params: any = {};
          for (const k of ["service", "proto", "ip", "allow_dns", "allow_ad", "wu", "kbs", "apps"]) if (a[k] !== undefined && a[k] !== null && a[k] !== "") params[k] = a[k];
          for (const k of ["port", "minutes", "reboot_after"]) if (a[k] !== undefined && a[k] !== null && a[k] !== "") params[k] = Number(a[k]);
          let runAfter: Date | null = null; // EDR-168: "HH:MM" (JST, next occurrence) or an ISO time
          if (a.run_at) {
            const v = String(a.run_at).trim(); const m = v.match(/^(\d{1,2}):(\d{2})$/);
            if (m) { const jstNow = new Date(Date.now() + 9 * 3600_000); jstNow.setUTCHours(Number(m[1]), Number(m[2]), 0, 0); runAfter = new Date(jstNow.getTime() - 9 * 3600_000); if (runAfter.getTime() < Date.now() + 60_000) runAfter = new Date(runAfter.getTime() + 86_400_000); }
            else { const d = new Date(v); if (isNaN(d.getTime())) return (await reply({ error: "run_at must be HH:MM (Japan time) or an ISO date-time" }, "failed"), "ok"); runAfter = d; }
          }
          if (Array.isArray(params.kbs)) params.kbs = params.kbs.map((x: any) => String(x).toUpperCase().replace(/^(\d)/, "KB$1"));
          try {
            await db("tool_calls").where({ id: tcId }).update({ classification: "write", classification_reason: `host action ${a.op}` });
            let revertOf: number | undefined; let op = a.op;
            if (a.op === "update_cancel") { // EDR-168: stop the update that is running on this host (a revert of that action)
              const run = await db("host_actions").where({ host_id: host.id, op: "update_install", status: "running" }).orderBy("id", "desc").first();
              if (!run) return (await reply({ error: `no update is running on ${host.name}` }, "failed"), "ok");
              revertOf = run.id; op = "update_install";
            }
            if (a.op === "reboot_cancel") { // EDR-168 / 1.3.1: cancel the restart that is scheduled (or postponed by the user)
              const rb = await db("host_actions").where({ host_id: host.id, op: "reboot" }).whereIn("status", ["running", "active"]).orderBy("id", "desc").first();
              if (!rb) return (await reply({ error: `no restart is scheduled on ${host.name}` }, "failed"), "ok");
              revertOf = rb.id; op = "reboot";
            }
            const r = await requestAction(this.ctx, { host, op, params, userId: null, reason: String(a.reason ?? ""), sessionId, toolCallId: tcId, runAfter, revertOf });
            await db("tool_calls").where({ id: tcId }).update({ status: "pending_approval" });
            const ap = await db("approvals").where({ id: r.approval_id }).first();
            this.emit({ type: "approval", session_id: sessionId, approval: { ...ap, host: host.name, steps: pj(ap.steps), checks: pj<any>(ap.auto_checks)?.checks ?? [], classification: "write", decision: "pending" } });
            return "pending_approval";
          } catch (e: any) { return (await reply({ error: String(e.message ?? e) }, "failed"), "ok"); }
        }
        case "process_tree": {
          if (!wazuhId) return (await reply({ error: "no wazuh instance" }, "failed"), "ok");
          const a = call.args as any;
          const wz = await db("wazuh_instances").where({ id: wazuhId }).first();
          const ix = await indexer(this.ctx, wazuhId);
          const tree = await buildProcessTree(ix, { agentId: String(a.agent_id), guid: String(a.process_guid), from: String(a.from ?? "now-24h"), to: String(a.to ?? "now"), preferArchives: !!wz?.archives_enabled });
          await reply(renderTreeText(tree) + `\n\n(UI: /process-tree?wazuh=${wazuhId}&agent=${a.agent_id}&guid=${encodeURIComponent(tree.focusGuid)})`);
          return "ok";
        }
        case "cloud_list": {
          const a = call.args as any; const { syncProvider, pubInstance } = await import("../cloud/service.js");
          if (a.sync) for (const pr of await db("cloud_providers")) { try { await syncProvider(db, this.ctx.box, pr.id); } catch (e: any) { await this.ctx.log.warn({ err: e.message, provider: pr.id }, "cloud sync failed"); } }
          const provs = await db("cloud_providers"); const byId = Object.fromEntries(provs.map((p: any) => [p.id, p]));
          const hosts = await db("hosts").select("id", "name");
          let rows = (await db("cloud_instances").orderBy(["provider_id", "name"])).map((r: any) => { const x = pubInstance(r, byId[r.provider_id]); return { id: x.id, provider: x.provider_name, kind: x.provider_kind, service: x.service, name: x.name, external_id: x.external_id, state: x.state, public_ip: x.public_ip, private_ip: x.private_ip, region: x.region, zone: x.zone, machine_type: x.machine_type, os: x.os, host: hosts.find((h: any) => h.id === r.host_id)?.name ?? null, agent: r.agent_name, capability: byId[r.provider_id]?.capability }; });
          if (a.query) { const q = String(a.query).toLowerCase(); rows = rows.filter((r: any) => JSON.stringify(r).toLowerCase().includes(q)); }
          await reply({ providers: provs.map((p: any) => ({ id: p.id, kind: p.kind, name: p.name, capability: p.capability, status: p.status, last_sync_at: p.last_sync_at })), instances: rows, note: rows.length ? undefined : "No cloud instances known. The admin can register providers under 管理ホスト › クラウド管理." });
          return "ok";
        }
        case "cloud_snapshot": case "cloud_power": case "cloud_isolate": {
          const a = call.args as any; const { describeAction } = await import("../cloud/service.js");
          const q = String(a.instance ?? "").toLowerCase();
          const inst = (await db("cloud_instances")).find((r: any) => r.name.toLowerCase() === q || r.external_id.toLowerCase() === q || r.public_ip === a.instance || r.private_ip === a.instance);
          if (!inst) return (await reply({ error: `instance '${a.instance}' not found in the cloud inventory; call cloud_list first` }, "failed"), "ok");
          const prov = await db("cloud_providers").where({ id: inst.provider_id }).first();
          const op = call.name === "cloud_snapshot" ? "snapshot" : call.name === "cloud_power" ? "power" : "isolate";
          if (prov.capability === "inventory") return (await reply({ error: "this provider is registered as inventory-only; the admin must raise its capability" }, "failed"), "ok");
          if (op === "isolate" && prov.capability !== "isolate") return (await reply({ error: "isolation is not enabled for this provider (capability must be 'isolate')" }, "failed"), "ok");
          const action = { provider_id: prov.id, instance_id: inst.id, op, params: { name: a.name, power: a.power, allow_cidrs: a.allow_cidrs } };
          const title = describeAction(action as any, prov.name, inst.name);
          await db("tool_calls").where({ id: tcId }).update({ classification: "write", classification_reason: `cloud ${op}` });
          const [apId] = await db("approvals").insert({ tool_call_id: tcId, session_id: sessionId, host_id: inst.host_id ?? null, title, command: `cloud:${op} ${prov.kind}/${inst.service}/${inst.external_id}`, intent: String(a.reason ?? ""), rollback: op === "isolate" ? "隔離前のセキュリティグループ / タグは実行結果に記録されます" : op === "power" ? "逆の電源操作" : "スナップショットは削除せず残します",
            steps: j([{ purpose: title, command: `cloud API: ${op}` }]), auto_checks: j({ classification: "write", reason: "cloud API", checks: [] }), risk: op === "isolate" ? "high" : op === "power" && a.power !== "reboot" ? "medium" : "low", cloud_action: j(action) }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await db("tool_calls").where({ id: tcId }).update({ status: "pending_approval" });
          await this.ctx.audit.log("agent", null, "approval.requested", { approval_id: apId, cloud: action, title }, sessionId);
          this.emit({ type: "approval", session_id: sessionId, approval: { id: apId, host: inst.host_id ? (await db("hosts").where({ id: inst.host_id }).first())?.name : prov.name, title, command: `cloud:${op}`, steps: [{ purpose: title, command: `cloud API: ${op}` }], intent: a.reason, risk: op === "isolate" ? "high" : "low", classification: "write", checks: [], decision: "pending" } });
          return "pending_approval";
        }
        case "add_wazuh_rule": {
          // Server-built plan: the LLM only supplies the rule XML. Avoids sed/heredoc XML surgery and duplicate rule ids.
          const a0 = call.args as any;
          const host0 = await db("hosts").where({ name: String(a0.host) }).first();
          if (!host0) return (await reply({ error: `unknown host '${a0.host}'` }, "failed"), "ok");
          const ruleXml = String(a0.rule_xml ?? "").trim();
          if (!/<rule\b[^>]*id="\d+"/.test(ruleXml)) return (await reply({ error: "rule_xml must contain one or more <rule id=\"...\"> elements" }, "failed"), "ok");
          const group = String(a0.group ?? "local,syslog,sysmon,").replace(/"/g, "");
          const file = String(a0.file ?? "/var/ossec/etc/rules/local_rules.xml");
          if (!/^\/var\/ossec\/etc\/(rules|decoders)\/[\w.-]+\.xml$/.test(file)) return (await reply({ error: "file must be under /var/ossec/etc/rules/ or /var/ossec/etc/decoders/" }, "failed"), "ok");
          const py = `import re,sys,base64,os
path=${JSON.stringify(file)}; group=${JSON.stringify(group)}
new=base64.b64decode(${JSON.stringify(Buffer.from(ruleXml, "utf8").toString("base64"))}).decode()
txt=open(path,encoding="utf-8").read() if os.path.exists(path) else ""
used=set(int(x) for x in re.findall(r'<rule\\s+[^>]*id="(\\d+)"',txt))
def free(start):
    i=max(start,100200)
    while i in used: i+=1
    used.add(i); return i
changed=[]
def fix(m):
    rid=int(m.group(2))
    if rid in used:
        nid=free(rid); changed.append((rid,nid)); return m.group(1)+str(nid)+m.group(3)
    used.add(rid); return m.group(0)
new=re.sub(r'(<rule\\s+[^>]*id=")(\\d+)(")',fix,new)
# insert into the LAST group whose name matches, else append a new group
gm=None
for m in re.finditer(r'<group\\s+name="([^"]*)"\\s*>',txt):
    if group.rstrip(",")==m.group(1).rstrip(","): gm=m
if gm:
    end=txt.find("</group>",gm.end())
    if end<0: print("ERR: unterminated group"); sys.exit(2)
    txt=txt[:end]+"\\n"+new+"\\n"+txt[end:]
else:
    txt=txt.rstrip()+"\\n\\n<group name=\""+group+"\">\\n"+new+"\\n</group>\\n"
open(path,"w",encoding="utf-8").write(txt)
print("inserted into",path,"group",group,"ids:",re.findall(r'<rule\\s+[^>]*id="(\\d+)"',new),"renumbered:",changed)`;
          const b64 = Buffer.from(py, "utf8").toString("base64");
          const bak = `${file}.bak.$(date +%Y%m%d%H%M%S)`;
          const steps = [
            { purpose: `${file.split("/").pop()} をバックアップ`, no_rollback: true, command: `sudo cp ${file} ${bak} && echo "BACKUP=${bak}" && sudo cp ${file} /tmp/edr_rules_before.xml` },
            { purpose: "ルールを挿入（ID の重複は自動で採番し直す）", no_rollback: true, command: `echo ${b64} | base64 -d > /tmp/edr_addrule.py && sudo python3 /tmp/edr_addrule.py` },
            { purpose: "ルール構文を検証（失敗したら自動で元に戻す）", no_rollback: true, command: `sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -20; if ! sudo /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then sudo cp /tmp/edr_rules_before.xml ${file}; echo "VALIDATION FAILED: restored ${file}"; exit 1; fi; echo VALID` },
            { purpose: "Wazuh manager を再起動", command: "sudo systemctl restart wazuh-manager" },
            { purpose: "再起動完了とエージェント接続を確認", command: "sleep 25 && sudo systemctl is-active wazuh-manager && sudo /var/ossec/bin/agent_control -l | grep -c Active" },
          ];
          call = { ...call, name: "apply_change", args: { host: a0.host, title: a0.title ?? "Wazuh ルールを追加して manager を再起動", intent: a0.intent, plain: a0.plain, steps, rollback: [`sudo cp /tmp/edr_rules_before.xml ${file}`, "sudo systemctl restart wazuh-manager"], risk: a0.risk ?? "low", next_action_id: a0.next_action_id } };
          await db("tool_calls").where({ id: tcId }).update({ args: j({ ...call.args, _call_id: call.id, original_tool: "add_wazuh_rule", rule_xml: ruleXml }) });
        }
        // falls through
        case "apply_change": {
          const a = call.args as any;
          const host = await db("hosts").where({ name: String(a.host) }).first();
          if (!host) return (await reply({ error: `unknown host '${a.host}'` }, "failed"), "ok");
          if (!host.ssh_key_id) return (await reply({ error: host.kind === "agent_only" ? `host '${host.name}' is a Wazuh-agent-only endpoint (no SSH). Use host_profile / indexer_query to read it and host_action for containment.` : `host '${host.name}' has no SSH key configured` }, "failed"), "ok");
          // EDR-93: some models send steps / rollback as a JSON string instead of an array
          if (typeof a.steps === "string") { try { a.steps = JSON.parse(a.steps); } catch { /* reported below as missing steps */ } }
          if (typeof a.rollback === "string" && a.rollback.trim().startsWith("[")) { try { a.rollback = JSON.parse(a.rollback); } catch { /* keep as text */ } }
          const steps: { purpose: string; command: string }[] = Array.isArray(a.steps) ? a.steps.filter((x: any) => x && x.command) : [];
          if (!steps.length) return (await reply({ error: "steps[] is required" }, "failed"), "ok");
          { // EDR-94: premise check / retreat line before a change is even proposed
            const stop = await this.preChangeGuards(sessionId, host, [a.title, a.intent, a.plain].filter(Boolean).join("\n"), steps.map((x) => x.command));
            if (stop) return (await reply(stop, "failed"), "ok");
          }
          const script = steps.map((x) => x.command).join("\n");
          const rollbackArr: string[] = Array.isArray(a.rollback) ? a.rollback : (a.rollback ? [String(a.rollback)] : []);
          const checks = await this.autoChecks(host, script);
          const classes = steps.map((x) => classifyCommand(x.command, this.allow));
          const worst = classes.some((c) => c.classification === "unknown") ? "unknown" : classes.some((c) => c.classification === "write") ? "write" : "read";
          await db("tool_calls").where({ id: tcId }).update({ classification: worst, classification_reason: `plan of ${steps.length} step(s)` });
          const linkNa = a.next_action_id ? Number(a.next_action_id) : (await db("next_actions").where({ session_id: sessionId, status: "approved" }).whereNull("approval_id").orderBy("id").first())?.id ?? null;
          const [apId] = await db("approvals").insert({
            tool_call_id: tcId, session_id: sessionId, host_id: host.id, title: String(a.title ?? "").slice(0, 255), command: script, intent: [a.intent, a.plain].filter(Boolean).join("\n"),
            rollback: rollbackArr.join("\n"), steps: j(steps), next_action_id: linkNa,
            auto_checks: j({ classification: worst, reason: `plan: ${steps.map((x, i) => `${i + 1}. ${x.purpose}`).join(" / ")}`, checks }), risk: ["low", "medium", "high"].includes(a.risk) ? a.risk : "medium",
          }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await db("tool_calls").where({ id: tcId }).update({ status: "pending_approval" });
          if (linkNa) await db("next_actions").where({ id: linkNa, session_id: sessionId }).update({ status: "approved", approval_id: apId });
          await this.ctx.audit.log("agent", null, "approval.requested", { approval_id: apId, host: host.name, plan: a.title, steps: steps.length }, sessionId);
          this.emit({ type: "approval", session_id: sessionId, approval: { id: apId, host: host.name, title: a.title, command: script, steps, intent: a.intent, rollback: rollbackArr.join("\n"), risk: a.risk, classification: worst, checks, decision: "pending" } });
          // EDR-87: a plan whose every step is read-only runs at once; a retry of a failed approved change within its scope is approved automatically
          let autoNote: string | null = null;
          if (worst === "read" && Number(host.autonomy_level ?? 1) >= 1 && !checks.some((c) => c.level === "block")) autoNote = "自動実行: すべてのステップが読み取り専用";
          // EDR-90: no automatic approval of changes while the kill switch is on, or when the session started from an alert (attacker-controlled input)
          const noAuto = await this.noAutoApproval(sessionId);
          if (!autoNote && !noAuto) autoNote = await this.retryGrant(sessionId, host, steps.map((x) => x.command), checks);
          if (!autoNote && !noAuto) { const auto = await this.autoApprovable(host, script, worst, a.risk, checks, rollbackArr.length > 0); if (auto) autoNote = `auto-approved (L${host.autonomy_level}): ${auto}`; }
          if (autoNote) {
            const note = autoNote;
            await this.ctx.audit.log("system", null, "approval.auto", { approval_id: apId, host: host.name, why: note }, sessionId);
            await db("approvals").where({ id: apId }).update({ decision_note: note });
            setImmediate(() => this.decide(apId, 0, "approved", { note }).catch((e) => this.ctx.log.error({ err: e }, "auto-approve failed")));
          }
          return "pending_approval";
        }
        case "ssh_exec": {
          const a = call.args as any;
          const host = await db("hosts").where({ name: String(a.host) }).first();
          if (!host) return (await reply({ error: `unknown host '${a.host}'. Use one of the registered host names.` }, "failed"), "ok");
          if (!host.ssh_key_id) return (await reply({ error: host.kind === "agent_only" ? `host '${host.name}' is a Wazuh-agent-only endpoint (no SSH). Use host_profile / indexer_query to read it and host_action for containment.` : `host '${host.name}' has no SSH key configured` }, "failed"), "ok");
          const cls = classifyCommand(String(a.command), this.allow);
          await db("tool_calls").where({ id: tcId }).update({ classification: cls.classification, classification_reason: cls.reason });
          if (cls.classification === "read" && Number(host.autonomy_level ?? 1) >= 1) {
            const key = await db("ssh_keys").where({ id: host.ssh_key_id }).first();
            const r = await sshExec({ address: host.address, port: host.port, user: host.ssh_user, privateKey: this.ctx.box.decrypt(key.private_key_enc), sudoMode: host.sudo_mode, hostKey: host.host_key }, String(a.command), 60_000);
            if (!host.host_key && r.hostKey) await db("hosts").where({ id: host.id }).update({ host_key: r.hostKey });
            await this.ctx.audit.log("agent", null, "ssh.read_executed", { host: host.name, command: a.command, exit_code: r.code, ms: r.durationMs }, sessionId);
            await reply({ status: "executed", classification: "read", exit_code: r.code, stdout: r.stdout, stderr: r.stderr, truncated: r.truncated });
            return "ok";
          }
          // write / unknown (or autonomy 0): queue for approval
          if (cls.classification !== "read") { // EDR-94
            const stop = await this.preChangeGuards(sessionId, host, String(a.intent ?? ""), [String(a.command)]);
            if (stop) return (await reply(stop, "failed"), "ok");
          }
          const checks = await this.autoChecks(host, String(a.command));
          const pendingNa = await db("next_actions").where({ session_id: sessionId, status: "approved" }).whereNull("approval_id").orderBy("id").first();
          const [apId] = await db("approvals").insert({
            tool_call_id: tcId, session_id: sessionId, host_id: host.id, command: String(a.command), intent: a.intent ?? null, rollback: a.rollback ?? null, next_action_id: pendingNa?.id ?? null,
            auto_checks: j({ classification: cls.classification, reason: cls.reason, checks }), risk: ["low", "medium", "high"].includes(a.risk) ? a.risk : "medium",
          }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await db("tool_calls").where({ id: tcId }).update({ status: "pending_approval" });
          if (pendingNa) await db("next_actions").where({ id: pendingNa.id }).update({ approval_id: apId });
          await this.ctx.audit.log("agent", null, "approval.requested", { approval_id: apId, host: host.name, command: a.command, classification: cls.classification, reason: cls.reason }, sessionId);
          this.emit({ type: "approval", session_id: sessionId, approval: { id: apId, host: host.name, command: a.command, intent: a.intent, rollback: a.rollback, risk: a.risk, classification: cls.classification, reason: cls.reason, checks, decision: "pending" } });
          // Autonomy L2/L3: auto-approve under strict conditions (see autoApprovable)
          const noAuto = await this.noAutoApproval(sessionId);
          const grant = cls.classification === "read" || noAuto ? null : await this.retryGrant(sessionId, host, [String(a.command)], checks);
          const auto0 = grant || noAuto ? null : await this.autoApprovable(host, String(a.command), cls.classification, a.risk, checks, !!a.rollback);
          const auto = grant ?? (auto0 ? `auto-approved (L${host.autonomy_level}): ${auto0}` : null);
          if (auto) {
            await this.ctx.audit.log("system", null, "approval.auto", { approval_id: apId, host: host.name, level: host.autonomy_level, why: auto }, sessionId);
            await db("approvals").where({ id: apId }).update({ decision_note: auto });
            // decide() appends the tool result and resumes the loop; we stop this loop here to avoid double-running
            setImmediate(() => this.decide(apId, 0, "approved", { note: auto }).catch((e) => this.ctx.log.error({ err: e }, "auto-approve failed")));
          }
          // note: the tool result message is appended when the human (or auto-approval) decides
          return "pending_approval";
        }
        case "propose_next_actions": {
          const p = call.args as any;
          const toArr = (v: any) => (Array.isArray(v) ? v : v == null || v === "" ? [] : [v]);
          p.findings = toArr(p.findings); p.questions = toArr(p.questions); p.actions = toArr(p.actions).filter((x: any) => x && typeof x === "object");
          const hosts = await db("hosts");
          await db("next_actions").where({ session_id: sessionId }).whereIn("status", ["proposed", "blocked"]).update({ status: "rejected", updated_at: db.fn.now() });
          const insertedIds: number[] = [];
          for (const act of p.actions ?? []) {
            const h = hosts.find((x: any) => x.name === act.host);
            const kind = act.kind === "followup" || (act.kind !== "change" && !(toArr(act.commands).length) && !act.host) ? "followup" : "change";
            let afterId: number | null = null;
            if (act.after != null) { const idx = Number(act.after); if (Number.isInteger(idx) && idx >= 1 && idx <= insertedIds.length) afterId = insertedIds[idx - 1]; }
            if (!afterId && act.after_action_id) { const dep = await db("next_actions").where({ id: Number(act.after_action_id) }).first(); if (dep && !["done", "rejected", "rolled_back"].includes(dep.status)) afterId = dep.id; }
            const [nid] = await db("next_actions").insert({ session_id: sessionId, title: String(act.title ?? "").slice(0, 255), host_id: h?.id ?? null, commands: j(toArr(act.commands)), rollback: j(toArr(act.rollback)), risk: ["low", "medium", "high"].includes(act.risk) ? act.risk : "medium", why: act.why ?? null, plain: act.plain ?? null, impact: act.impact ?? null, kind, due: act.due ? String(act.due).slice(0, 64) : null, after_id: afterId, relation: act.relation ?? (afterId ? "next" : null), status: afterId ? "blocked" : "proposed" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
            insertedIds.push(nid);
          }
          // 改善案が無いのに判定が「問題なし」ではない → 残タスク（経過観察）を自動で積み、Action ボードから消えないようにする
          if (!(p.actions ?? []).length && !["benign", "false_positive"].includes(p.verdict)) {
            const s0 = await db("sessions").where({ id: sessionId }).first();
            await db("next_actions").insert({ session_id: sessionId, title: `経過観察: ${String(s0?.title ?? "").slice(0, 200)}`, host_id: null, commands: j([]), rollback: j([]), risk: "low", why: String(p.summary ?? "").slice(0, 1000), plain: "今すぐ実行できる改善策はありませんが、状況が変わるまで残タスクとして追跡します。", impact: "なし（追跡のみ）", kind: "followup", due: "状況が変わったら再確認" });
            p.actions = [{ title: "経過観察（自動）", kind: "followup", risk: "low", why: p.summary, plain: "残タスクとして追跡します", impact: "なし" }];
          }
          const s = await db("sessions").where({ id: sessionId }).first();
          const meta = pj<any>(s.summary) ?? {};
          await db("sessions").where({ id: sessionId }).update({ summary: j({ ...meta, proposal: p }) });
          await this.ctx.audit.log("agent", null, "proposal.presented", { severity: p.severity, verdict: p.verdict, actions: (p.actions ?? []).length }, sessionId);
          this.emit({ type: "next_actions", session_id: sessionId, proposal: p });
          if (s.origin === "alert" && this.ctx.cfg.DISCORD_WEBHOOK_URL) {
            const txt = `🛡️ Sentinel #${sessionId} ${s.title}\n判定: ${p.verdict} / ${p.severity}\n${String(p.summary).slice(0, 600)}\n提案 ${(p.actions ?? []).length} 件 → ${this.ctx.cfg.APP_BASE_URL}/sidekick/${sessionId}`;
            ufetch(this.ctx.cfg.DISCORD_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: txt }) }).catch(() => {});
          }
          // benign / false positive with nothing to do → the ticket is finished; close it instead of leaving it "返答待ち" with nothing to answer
          const pendingHere = await db("approvals").where({ session_id: sessionId, decision: "pending" }).first();
          if (!(p.actions ?? []).length && ["benign", "false_positive"].includes(p.verdict) && !pendingHere) {
            await db("sessions").where({ id: sessionId }).update({ summary: j({ ...meta, proposal: p, closed: { outcome: "no_action_needed", note: p.summary_simple ?? p.summary, by: "agent", at: new Date().toISOString() } }) });
            await this.appendMessage(sessionId, { role: "assistant", content: `✅ ${p.verdict === "false_positive" ? "誤検知" : "正常な動作"}で対処は不要と判断したため、このチケットを完了にしました。${p.summary_simple ?? ""} 必要なら「↩ 再開する」か返信で続きを指示できます。` });
            await this.ctx.audit.log("agent", null, "session.closed", { outcome: "no_action_needed", auto: true }, sessionId);
            await reply({ status: "presented_and_closed", note: "No actions and a benign verdict: the ticket was closed automatically." });
            return "closed";
          }
          await reply({ status: "presented", note: "The human now sees your summary and proposed actions. Wait for their reply." });
          return "finished";
        }
        case "add_action": {
          const a = call.args as any; const toArr = (v: any) => (Array.isArray(v) ? v : v == null || v === "" ? [] : [v]);
          const h = a.host ? await db("hosts").where({ name: a.host }).first() : null;
          const kind = a.kind === "followup" || (a.kind !== "change" && !toArr(a.commands).length) ? "followup" : "change";
          let afterId: number | null = a.after_action_id ? Number(a.after_action_id) : null;
          if (afterId) { const dep = await db("next_actions").where({ id: afterId }).first(); if (!dep) return (await reply({ error: `after_action_id ${afterId} not found` }, "failed"), "ok"); if (["done", "rejected", "rolled_back"].includes(dep.status)) afterId = null; }
          const [naId] = await db("next_actions").insert({ session_id: sessionId, title: String(a.title ?? "").slice(0, 255), host_id: h?.id ?? null, commands: j(toArr(a.commands)), rollback: j(toArr(a.rollback)), risk: ["low", "medium", "high"].includes(a.risk) ? a.risk : "low", why: a.why ?? null, plain: a.plain ?? null, impact: a.impact ?? null, kind, due: a.due ? String(a.due).slice(0, 64) : null, after_id: afterId, relation: a.relation ?? (afterId ? "next" : null), status: afterId ? "blocked" : "proposed" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await this.ctx.audit.log("agent", null, "action.registered", { id: naId, title: a.title, kind }, sessionId);
          this.emit({ type: "next_actions", session_id: sessionId, proposal: null });
          await reply({ ok: true, id: naId, kind, status: afterId ? "blocked" : "proposed", after_action_id: afterId, note: afterId ? `Registered as #${naId}, blocked until action #${afterId} is done; it will be released automatically and you will be asked to plan it.` : `Registered on the Action board as #${naId}.` });
          return "ok";
        }
        case "mark_alerts_handled": {
          const a = call.args as any;
          const ruleId = String(a.rule_id ?? "").trim(); const who = String(a.agent ?? "").trim();
          if (!ruleId || !who) return (await reply({ error: "rule_id and agent are required" }, "failed"), "ok");
          let agentId: string | null = /^\d{3,}$/.test(who) ? who : null;
          if (!agentId) { const h = await db("hosts").where("name", who).first(); if (h?.agent_id) agentId = String(h.agent_id); }
          if (!agentId) { try { const wz = await db("wazuh_instances").orderBy("id").first(); if (wz?.api_url) { const api = await managerApi(this.ctx, wz.id); const r: any = await api.get(`/agents?name=${encodeURIComponent(who)}&select=id,name`); agentId = r?.data?.affected_items?.[0]?.id ?? null; } } catch { /* ignore */ } }
          if (!agentId) return (await reply({ error: `agent '${who}' not found (use the Wazuh agent name or id)` }, "failed"), "ok");
          const scope = ["agent", "program", "rule"].includes(a.scope) ? a.scope : "agent";
          if (scope === "program" && !a.program) return (await reply({ error: "program is required for scope=program" }, "failed"), "ok");
          const days = Math.max(0, Math.min(3650, Number(a.quiet_days ?? 0) || 0));
          const [mid] = await db("alert_marks").insert({ rule_id: ruleId, agent_id: agentId, scope, program: scope === "program" ? String(a.program).toLowerCase() : null, alert_id: null, until: new Date(Date.now() + days * 86_400_000), note: String(a.note ?? "").slice(0, 500), user_id: null, session_id: sessionId, alert_json: null }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await this.ctx.audit.log("agent", null, "alert.marked_handled", { mark_id: mid, rule_id: ruleId, agent_id: agentId, scope, quiet_days: days, note: a.note }, sessionId);
          await reply({ ok: true, mark_id: mid, agent_id: agentId, scope, quiet_until: new Date(Date.now() + days * 86_400_000).toISOString(), note: "Alerts of this kind are now shown as 対応済み; newer ones stay quiet until quiet_until." });
          return "ok";
        }
        case "session_control": {
          const a = call.args as any; const op = String(a.op);
          const s0 = await db("sessions").where({ id: sessionId }).first();
          if (op === "done") {
            const pending = await db("approvals").where({ session_id: sessionId, decision: "pending" }).first();
            if (pending) return (await reply({ error: "an approval is still pending; wait for the human to decide before closing" }, "failed"), "ok");
            const meta = pj<any>(s0.summary) ?? {};
            await db("sessions").where({ id: sessionId }).update({ summary: j({ ...meta, closed: { outcome: a.outcome ?? "resolved", note: a.note ?? null, by: "agent", at: new Date().toISOString() } }) });
            await this.ctx.audit.log("agent", null, "session.closed", { outcome: a.outcome ?? "resolved", note: a.note ?? null }, sessionId);
            await reply({ ok: true, note: "The ticket is now marked done." });
            await this.appendMessage(sessionId, { role: "assistant", content: `✅ このチケットを完了にしました${a.note ? `（${String(a.note).slice(0, 200)}）` : ""}。必要なら「↩ 再開する」か返信で続きを指示できます。` });
            return "closed";
          }
          if (op === "archive") {
            await reply({ ok: true, note: "Archiving after this reply: pending approvals are discarded and the ticket is closed. The human can unarchive from the list." });
            setTimeout(() => this.archive(sessionId, null).catch((e) => this.ctx.log.warn({ err: e.message }, "archive failed")), 1500);
            return "closed";
          }
          if (op === "reopen") {
            const meta = pj<any>(s0.summary) ?? {}; delete meta.closed;
            await db("sessions").where({ id: sessionId }).update({ summary: j(meta), archived_at: null, finished_at: null, updated_at: db.fn.now() });
            await this.ctx.audit.log("agent", null, "session.reopened", { by: "agent" }, sessionId);
            await reply({ ok: true, note: "Reopened; continue the conversation." });
            return "ok";
          }
          if (op === "wait_external" || op === "clear_wait") {
            const meta = pj<any>(s0.summary) ?? {};
            if (op === "wait_external") meta.waiting_external = { reason: String(a.note ?? "").slice(0, 300), at: new Date().toISOString() }; else delete meta.waiting_external;
            await db("sessions").where({ id: sessionId }).update({ summary: j(meta) });
            await this.ctx.audit.log("agent", null, `session.${op}`, { note: a.note ?? null }, sessionId);
            await reply({ ok: true, note: op === "wait_external" ? "When this turn ends the ticket shows 対応待ち (waiting on something outside the human's reply)." : "Flag cleared." });
            return "ok";
          }
          return (await reply({ error: "op must be done | archive | reopen | wait_external | clear_wait" }, "failed"), "ok");
        }
        case "schedule_task": {
          const a = call.args as any; const { EVERY, firstRun, everyLabel } = await import("../scheduler/index.js");
          const interval = EVERY[String(a.every)] ?? Number(a.every_minutes);
          if (!interval || !Number.isFinite(interval) || interval < 15) return (await reply({ error: `invalid 'every' (use one of ${Object.keys(EVERY).join(", ")})` }, "failed"), "ok");
          const at = a.at && /^\d{1,2}:\d{2}$/.test(String(a.at)) ? String(a.at).padStart(5, "0") : null;
          const first = a.first_run === "now" ? new Date(Date.now() + 60_000) : firstRun(new Date(), interval, at);
          const [scId] = await db("schedules").insert({ session_id: sessionId, title: String(a.title ?? "").slice(0, 255), prompt: String(a.prompt ?? ""), interval_min: interval, at_time: at, max_runs: a.max_runs ? Number(a.max_runs) : null, goal: a.goal ? String(a.goal) : null, next_run_at: first.toISOString(), created_by: "agent" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await this.ctx.audit.log("agent", null, "schedule.created", { id: scId, title: a.title, interval, at, max_runs: a.max_runs ?? null }, sessionId);
          this.emit({ type: "schedule", session_id: sessionId, schedule_id: scId, status: "created" });
          await reply({ ok: true, schedule_id: scId, every: everyLabel(interval), at, next_run_at: first.toISOString(), note: "Registered. Each run posts into THIS session; results appear here and on the スケジュール page. Tell the human in one sentence." });
          return "ok";
        }
        case "list_schedules": {
          const rows = await db("schedules").where({ session_id: sessionId }).orderBy("id");
          await reply({ schedules: rows.map((r: any) => ({ id: r.id, title: r.title, every_minutes: r.interval_min, at: r.at_time, state: r.state, enabled: !!r.enabled, run_count: r.run_count, max_runs: r.max_runs, next_run_at: r.next_run_at, last_run_at: r.last_run_at, last_status: r.last_status, last_result: r.last_result })) });
          return "ok";
        }
        case "complete_schedule": case "cancel_schedule": {
          const a = call.args as any; const id = Number(a.schedule_id);
          const row = await db("schedules").where({ id, session_id: sessionId }).first();
          if (!row) return (await reply({ error: "schedule not found in this session" }, "failed"), "ok");
          const state = call.name === "complete_schedule" ? "done" : "cancelled";
          await db("schedules").where({ id }).update({ state, enabled: false, last_result: a.result ? String(a.result).slice(0, 4000) : row.last_result, updated_at: db.fn.now() });
          await this.ctx.audit.log("agent", null, `schedule.${state}`, { id, result: a.result ?? null }, sessionId);
          this.emit({ type: "schedule", session_id: sessionId, schedule_id: id, status: state });
          await reply({ ok: true, state });
          return "ok";
        }
        case "close_investigation": {
          const p = call.args as any;
          const s = await db("sessions").where({ id: sessionId }).first();
          const pendingApproval = await db("approvals").where({ session_id: sessionId, decision: "pending" }).first();
          const executing = (await db("approvals").where({ session_id: sessionId }).whereIn("decision", ["approved", "edited"])).find((a: any) => { const x = pj<any>(a.exec_result); return !x || x.status === "running"; });
          if (pendingApproval || executing) { await reply({ status: "refused", reason: "An approval is still pending or executing. Wait for its result, verify, then close." }); return "ok"; }
          const meta = pj<any>(s.summary) ?? {};
          await db("sessions").where({ id: sessionId }).update({ summary: j({ ...meta, closed: { outcome: p.outcome, note: p.closing_note, by: "agent", at: new Date().toISOString() } }) });
          await this.appendMessage(sessionId, { role: "assistant", content: `✅ ${p.closing_note}` });
          await this.ctx.audit.log("agent", null, "session.closed", { outcome: p.outcome }, sessionId);
          await reply({ status: "closed" });
          return "closed";
        }
        case "jira_record": {
          const jira = new JiraClient(this.ctx.cfg);
          if (!jira.enabled) return (await reply({ status: "skipped", reason: "Jira not configured (JIRA_BASE_URL / JIRA_EMAIL / JIRA_API_TOKEN)" }), "ok");
          const a = call.args as any;
          const footer = `\n\n— MamorAI session #${sessionId} (${this.ctx.cfg.APP_BASE_URL}/sidekick/${sessionId})`;
          const out = a.issue_key ? await jira.comment(String(a.issue_key), String(a.body) + footer) : await jira.create(String(a.title ?? `MamorAI: session #${sessionId}`), String(a.body) + footer);
          await this.ctx.audit.log("agent", null, "jira.recorded", { issue_key: a.issue_key ?? (out as any).key }, sessionId);
          await reply({ status: "recorded", ...out });
          return "ok";
        }
        case "set_next_action_status": {
          const a = call.args as any;
          // 自分のセッションの提案は常に可。他セッションのタスクは人間が明示的に番号を指定したとき用（any_session=true）
          const na = a.any_session ? await db("next_actions").where({ id: Number(a.next_action_id) }).first() : await db("next_actions").where({ id: Number(a.next_action_id), session_id: sessionId }).first();
          if (!na) return (await reply({ error: "next action not found" + (a.any_session ? "" : " in this session (pass any_session=true for a task from another session)") }, "failed"), "ok");
          if (!["proposed", "approved", "done", "rejected", "rolled_back", "blocked"].includes(a.status)) return (await reply({ error: "invalid status" }, "failed"), "ok");
          const upd: any = { status: a.status, updated_at: db.fn.now() };
          if (a.status === "done") setTimeout(() => this.onActionDone(na.id).catch(() => {}), 50);
          if (a.note) upd.impact = String(a.note).slice(0, 500);
          await db("next_actions").where({ id: na.id }).update(upd);
          await this.ctx.audit.log("agent", null, "next_action.status", { id: na.id, status: a.status, note: a.note }, sessionId);
          this.emit({ type: "next_actions", session_id: sessionId, proposal: null });
          await reply({ status: "updated" });
          return "ok";
        }
        case "notify": {
          const url = this.ctx.cfg.DISCORD_WEBHOOK_URL;
          if (!url) return (await reply({ status: "skipped", reason: "no webhook configured" }), "ok");
          await ufetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: `[MamorAI #${sessionId}] ${String((call.args as any).text).slice(0, 1800)}` }) });
          await reply({ status: "sent" });
          return "ok";
        }
        // ---------- attachments ----------
        case "read_attachment": {
          const a = call.args as any;
          const row = await db("attachments").where({ session_id: sessionId, name: String(a.name) }).first();
          if (!row) { const names = (await db("attachments").where({ session_id: sessionId })).map((x: any) => x.name); return (await reply({ error: `no attachment '${a.name}'`, available: names }, "failed"), "ok"); }
          if (row.encoding === "base64") return (await reply({ name: row.name, size: row.size, mime: row.mime, note: /^image\//.test(row.mime ?? "") ? "This is an image; it was shown to you inline in the user message that attached it. Describe what you saw there." : "Binary attachment; cannot be read as text." }), "ok");
          const off = Math.max(0, Number(a.offset ?? 0)), len = Math.min(60000, Math.max(100, Number(a.length ?? 20000)));
          const text: string = row.content;
          await reply({ name: row.name, size: row.size, offset: off, returned: Math.min(len, Math.max(0, text.length - off)), has_more: off + len < text.length, content: text.slice(off, off + len) });
          return "ok";
        }
        case "write_file": {
          const a = call.args as any;
          const rawName = String(a.name ?? "").trim();
          if (!/^[\w\-. ぁ-んァ-ヶ一-龠々ー（）()]+\.(csv|md|html|svg|txt|json|tsv)$/i.test(rawName)) return (await reply({ error: "name must be a plain file name ending in .csv .md .html .svg .txt .json .tsv" }, "failed"), "ok");
          let content = String(a.content ?? "");
          if (/<script|javascript:|on\w+\s*=/i.test(content) && /\.(svg|html)$/i.test(rawName)) return (await reply({ error: "scripts/event handlers are not allowed in svg/html files" }, "failed"), "ok");
          if (/\.(csv|tsv)$/i.test(rawName) && !content.startsWith("\uFEFF")) content = "\uFEFF" + content;
          if (/(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/i.test(content)) return (await reply({ error: "the file seems to contain a secret; remove it" }, "failed"), "ok");
          const s = await db("sessions").where({ id: sessionId }).first();
          const saved = await this.addAttachment(sessionId, s?.started_by ?? null, { name: rawName, content, mime: mimeFor(rawName) }, "out", a.description ? String(a.description).slice(0, 500) : undefined);
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "file written" });
          await reply({ status: "written", id: saved.id, name: saved.name, size: saved.size, url: `/api/sessions/${sessionId}/files/${saved.id}`, note: "The human sees a file card with preview and download. Mention the file in one short sentence; do not repeat its content." });
          return "ok";
        }
        case "write_pptx": {
          const a = call.args as any;
          const rawName = String(a.name ?? "report.pptx").trim().replace(/[\\/]/g, "_");
          if (!/\.pptx$/i.test(rawName)) return (await reply({ error: "name must end in .pptx" }, "failed"), "ok");
          const deck = a.deck ?? {};
          if (!deck.title || !Array.isArray(deck.slides) || !deck.slides.length) return (await reply({ error: "deck.title and deck.slides[] are required" }, "failed"), "ok");
          const txt = JSON.stringify(deck);
          if (/(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/i.test(txt)) return (await reply({ error: "the deck seems to contain a secret; remove it" }, "failed"), "ok");
          let buf: Buffer;
          try { buf = await buildPptx(deck); } catch (e: any) { return (await reply({ error: "pptx build failed: " + e.message }, "failed"), "ok"); }
          const s = await db("sessions").where({ id: sessionId }).first();
          const saved = await this.addAttachment(sessionId, s?.started_by ?? null, { name: rawName, content: buf.toString("base64"), mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation" }, "out", a.description ? String(a.description).slice(0, 500) : undefined, "base64", buf.length);
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "file written" });
          await reply({ status: "written", id: saved.id, name: saved.name, size: saved.size, slides: deck.slides.length + 1, url: `/api/sessions/${sessionId}/files/${saved.id}`, note: "The human sees a download card. Mention the deck in one short sentence (what is on which slide); do not repeat its content." });
          return "ok";
        }
        // ---------- playbook setup ----------
        case "get_playbook": {
          const p = await db("playbooks").where({ name: String((call.args as any).name) }).first();
          if (!p) return (await reply({ error: "playbook not found" }, "failed"), "ok");
          await reply({ id: p.id, name: p.name, enabled: !!p.enabled, builtin: !!p.builtin, version: p.version, meta: pj(p.meta) ?? parseMarkdown(p.markdown), structured: !!p.meta });
          return "ok";
        }
        case "save_playbook": {
          const a = call.args as any;
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const name = String(a.name ?? "").trim().slice(0, 128);
          let meta: PlaybookMeta;
          try { meta = coerceMeta(a.meta ?? {}); } catch (e: any) { return (await reply({ error: e.message }, "failed"), "ok"); }
          if (!name || !meta.purpose.trim()) return (await reply({ error: "name and meta.purpose are required" }, "failed"), "ok");
          const md = renderMarkdown(name, meta);
          if (/(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}/i.test(md) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(md)) return (await reply({ error: "the markdown seems to contain a secret (password/key/token). Remove it and retry." }, "failed"), "ok");
          const enabled = a.enabled !== false;
          let id: number;
          if (a.playbook_id) {
            const ex = await db("playbooks").where({ id: Number(a.playbook_id) }).first();
            if (!ex) return (await reply({ error: "playbook_id not found" }, "failed"), "ok");
            await db("playbooks").where({ id: ex.id }).update({ name, markdown: md, meta: j(meta), enabled, updated_at: db.fn.now() }).increment("version", 1);
            id = ex.id;
          } else {
            if (await db("playbooks").where({ name }).first()) return (await reply({ error: `a playbook named '${name}' already exists; pass its playbook_id to update it or choose another name` }, "failed"), "ok");
            [id] = await db("playbooks").insert({ name, scope: "global", markdown: md, meta: j(meta), enabled, builtin: false }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          }
          await this.ctx.audit.log("agent", null, a.playbook_id ? "playbook.updated" : "playbook.created", { id, name, via: "setup_session" }, sessionId);
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "playbook saved" });
          await reply({ status: "saved", id, name, enabled, where: "プレイブック画面" });
          return "ok";
        }
        // ---------- host setup ----------
        case "list_ssh_keys": {
          await reply({ keys: (await db("ssh_keys").orderBy("id")).map((k: any) => ({ id: k.id, name: k.name, fingerprint: k.fingerprint, public_key: k.public_key })) });
          return "ok";
        }
        case "generate_ssh_key": {
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const name = String((call.args as any).name ?? "").trim().slice(0, 128) || `edr-console-${Date.now()}`;
          const k = generateEd25519(`edr-console:${name}`);
          const [id] = await db("ssh_keys").insert({ name, public_key: k.publicKey, private_key_enc: this.ctx.box.encrypt(k.privateKey), fingerprint: keyFingerprint(k.publicKey) }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await this.ctx.audit.log("agent", null, "sshkey.generated", { id, name, via: "setup_session" }, sessionId);
          await reply({ id, name, fingerprint: keyFingerprint(k.publicKey), public_key: k.publicKey, install: `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${k.publicKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys` });
          return "ok";
        }
        case "register_host":
        case "update_host": {
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const a = call.args as any;
          const fields: any = call.name === "register_host" ? a : (a.fields ?? {});
          const upd: any = {};
          for (const k of ["name", "address", "ssh_user", "sudo_mode", "environment", "agent_id", "notes", "maintenance_window"]) if (fields[k] !== undefined && fields[k] !== null) upd[k] = String(fields[k]).trim();
          for (const k of ["port", "ssh_key_id", "autonomy_level", "autonomy_max", "wazuh_instance_id"]) if (fields[k] !== undefined && fields[k] !== null) upd[k] = Number(fields[k]);
          if (Array.isArray(fields.tags)) upd.tags = j(fields.tags.map(String));
          if (upd.sudo_mode && !["none", "nopasswd"].includes(upd.sudo_mode)) return (await reply({ error: "sudo_mode must be none|nopasswd" }, "failed"), "ok");
          if (upd.environment && !["lab", "staging", "production"].includes(upd.environment)) return (await reply({ error: "environment must be lab|staging|production" }, "failed"), "ok");
          if (upd.ssh_key_id !== undefined && !(await db("ssh_keys").where({ id: upd.ssh_key_id }).first())) return (await reply({ error: `ssh_key_id ${upd.ssh_key_id} does not exist (use list_ssh_keys)` }, "failed"), "ok");
          const maxL = this.ctx.cfg.AUTONOMY_MAX;
          if (upd.autonomy_level !== undefined) upd.autonomy_level = Math.max(0, Math.min(3, upd.autonomy_level, maxL));
          if (upd.autonomy_max !== undefined) upd.autonomy_max = Math.max(0, Math.min(3, upd.autonomy_max, maxL));
          if (call.name === "register_host") {
            for (const k of ["name", "address", "ssh_user", "ssh_key_id", "sudo_mode", "environment"]) if (upd[k] === undefined || upd[k] === "") return (await reply({ error: `${k} is required` }, "failed"), "ok");
            if (await db("hosts").where({ name: upd.name }).first()) return (await reply({ error: `host '${upd.name}' already exists; use update_host` }, "failed"), "ok");
            upd.port ??= 22; upd.autonomy_level ??= 1; upd.autonomy_max ??= 1; upd.tags ??= j([]);
            const [id] = await db("hosts").insert(upd).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
            await this.ctx.audit.log("agent", null, "host.created", { id, name: upd.name, via: "setup_session" }, sessionId);
            const h = await db("hosts").where({ id }).first();
            await reply({ status: "registered", host: { ...h, tags: pj(h.tags), host_key: h.host_key ? "pinned" : null }, next: "call test_host" });
          } else {
            const h = await db("hosts").where({ name: String(a.host) }).first();
            if (!h) return (await reply({ error: `unknown host '${a.host}'` }, "failed"), "ok");
            if (!Object.keys(upd).length) return (await reply({ error: "no valid fields" }, "failed"), "ok");
            if (upd.address && upd.address !== h.address) upd.host_key = null; // new endpoint → re-pin
            await db("hosts").where({ id: h.id }).update({ ...upd, updated_at: db.fn.now() });
            await this.ctx.audit.log("agent", null, "host.updated", { id: h.id, name: h.name, fields: Object.keys(upd), via: "setup_session" }, sessionId);
            const h2 = await db("hosts").where({ id: h.id }).first();
            await reply({ status: "updated", host: { ...h2, tags: pj(h2.tags), host_key: h2.host_key ? "pinned" : null } });
          }
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "host changed" });
          return "ok";
        }
        case "list_cloud_providers": {
          const { pubProvider } = await import("../cloud/service.js");
          const rows = await db("cloud_providers").orderBy("id"); const inst = await db("cloud_instances");
          await reply({ providers: rows.map((r: any) => ({ ...pubProvider(r), instances: inst.filter((i: any) => i.provider_id === r.id).length, credentials: r.secret_enc ? "stored" : "missing" })), instances_total: inst.length, unlinked: inst.filter((i: any) => !i.host_id && !i.agent_name).map((i: any) => i.name) });
          return "ok";
        }
        case "get_cloud_policy": {
          const { POLICIES, KIND_JA } = await import("../cloud/index.js"); const k = String((call.args as any).kind);
          if (k === "aws") await reply({ kind: k, label: KIND_JA.aws, iam_policy: POLICIES.aws_iam_policy, console_steps: ["IAM › ユーザー › ユーザーを作成: 名前 edr-console（コンソールアクセスは付けない）", "許可のオプション: ポリシーを直接アタッチ › ポリシーの作成 › JSON に下のポリシーを貼る（隔離を使わないなら Isolate の Statement を削る）› 名前 EDRConsolePolicy", "ユーザー作成後 › セキュリティ認証情報 › アクセスキーを作成 › 『AWS の外で実行されるアプリケーション』› キーをダウンロード", "MamorAI のクラウド管理画面の『🔑 資格情報を入力』にアクセスキー ID とシークレットを貼る"], cli: ["aws iam create-user --user-name edr-console", "aws iam put-user-policy --user-name edr-console --policy-name EDRConsolePolicy --policy-document file://edr-console-policy.json", "aws iam create-access-key --user-name edr-console"], note: "Lightsail は EC2 と同じキーで動きます。リージョンは Lightsail インスタンスのあるリージョン（東京なら ap-northeast-1）。" });
          else if (k === "gce") await reply({ kind: k, label: KIND_JA.gce, roles: POLICIES.gcp_roles, console_steps: ["IAM と管理 › サービスアカウント › 作成: 名前 edr-console", "ロール: Compute 閲覧者（台帳）＋ Compute インスタンス管理者（v1）（スナップショット・電源・タグ）。隔離を使う場合は Compute セキュリティ管理者 も", "作成したサービスアカウント › キー › 鍵を追加 › JSON › ダウンロード", "MamorAI のクラウド管理画面の『🔑 資格情報を入力』に JSON の中身を貼る"], cli: ["gcloud iam service-accounts create edr-console --display-name 'MamorAI'", "gcloud projects add-iam-policy-binding <PROJECT_ID> --member serviceAccount:edr-console@<PROJECT_ID>.iam.gserviceaccount.com --role roles/compute.viewer", "gcloud projects add-iam-policy-binding <PROJECT_ID> --member serviceAccount:edr-console@<PROJECT_ID>.iam.gserviceaccount.com --role roles/compute.instanceAdmin.v1", "gcloud iam service-accounts keys create edr-console.json --iam-account edr-console@<PROJECT_ID>.iam.gserviceaccount.com"] });
          else await reply({ kind: k, label: (KIND_JA as any)[k] ?? k, status: "not implemented yet (phase 2)" });
          return "ok";
        }
        case "register_cloud_provider": {
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const a = call.args as any;
          if (!["aws", "gce"].includes(String(a.kind))) return (await reply({ error: `kind '${a.kind}' is not implemented yet; only aws and gce in this phase` }, "failed"), "ok");
          const cfg = a.kind === "aws" ? { regions: a.config?.regions?.length ? a.config.regions : ["ap-northeast-1"], use_ec2: a.config?.use_ec2 !== false, use_lightsail: a.config?.use_lightsail !== false } : { project_id: a.config?.project_id ?? "", zones: a.config?.zones ?? [] };
          const id = await db("cloud_providers").insert({ kind: a.kind, name: String(a.name).slice(0, 120), config: j(cfg), secret_enc: null, capability: ["inventory", "ops", "isolate"].includes(a.capability) ? a.capability : "ops", status: "needs_secret" }).returning("id").then((x: any) => (typeof x[0] === "object" ? x[0].id : x[0]));
          await this.ctx.audit.log("agent", null, "cloud.provider_created", { id, kind: a.kind, name: a.name, via: "setup_session" }, sessionId);
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "cloud provider changed" });
          await reply({ status: "created", provider_id: id, next: "The human must now enter the credentials in the 🔑 form on the クラウド管理 page (it appears automatically for providers without credentials). Then call test_cloud_provider." });
          return "ok";
        }
        case "update_cloud_provider": {
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const a = call.args as any; const upd: any = { updated_at: db.fn.now() };
          if (a.name) upd.name = String(a.name).slice(0, 120); if (a.config) upd.config = j(a.config); if (["inventory", "ops", "isolate"].includes(a.capability)) upd.capability = a.capability;
          const n = await db("cloud_providers").where({ id: Number(a.provider_id) }).update(upd);
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "cloud provider changed" });
          await reply(n ? { status: "updated" } : { error: "provider not found" }, n ? "executed" : "failed"); return "ok";
        }
        case "test_cloud_provider": {
          const { providerFor } = await import("../cloud/service.js"); const row = await db("cloud_providers").where({ id: Number((call.args as any).provider_id) }).first();
          if (!row) return (await reply({ error: "provider not found" }, "failed"), "ok");
          if (!row.secret_enc) return (await reply({ ok: false, message: "credentials not entered yet — the human must fill the 🔑 form on the クラウド管理 page first" }), "ok");
          let out: any; try { out = await providerFor(this.ctx.box, row).test(); } catch (e: any) { out = { ok: false, message: e.message }; }
          await db("cloud_providers").where({ id: row.id }).update({ status: out.ok ? "ok" : "error", last_error: out.ok ? null : out.message, updated_at: db.fn.now() });
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "cloud provider changed" });
          await reply(out); return "ok";
        }
        case "sync_cloud_inventory": {
          const { syncProvider } = await import("../cloud/service.js"); const pid = Number((call.args as any).provider_id);
          let agents: { name: string; ip: string | null }[] = [];
          try { const wz = await db("wazuh_instances").orderBy("id").first(); if (wz?.api_url) { const api = await managerApi(this.ctx, wz.id); const r: any = await api.get("/agents?select=name,ip&limit=500"); agents = (r?.data?.affected_items ?? []).map((x: any) => ({ name: x.name, ip: x.ip ?? null })); } } catch { /* optional */ }
          try {
            const r = await syncProvider(db, this.ctx.box, pid, agents);
            const inst = await db("cloud_instances").where({ provider_id: pid }); const hosts = await db("hosts").select("id", "name");
            this.emit({ type: "status", session_id: sessionId, status: "running", detail: "cloud provider changed" });
            await reply({ ...r, instances: inst.map((i: any) => ({ name: i.name, service: i.service, state: i.state, public_ip: i.public_ip, private_ip: i.private_ip, region: i.region, host: hosts.find((h: any) => h.id === i.host_id)?.name ?? null, agent: i.agent_name })) });
          } catch (e: any) { await reply({ error: e.message }, "failed"); }
          return "ok";
        }
        case "link_cloud_instance": {
          const a = call.args as any; const q = String(a.instance).toLowerCase();
          const inst = (await db("cloud_instances")).find((r: any) => r.name.toLowerCase() === q || r.external_id.toLowerCase() === q);
          if (!inst) return (await reply({ error: "instance not found in inventory" }, "failed"), "ok");
          const upd: any = {};
          if (a.host) { const h = await db("hosts").where({ name: String(a.host) }).first(); if (!h) return (await reply({ error: `unknown host '${a.host}'` }, "failed"), "ok"); upd.host_id = h.id; }
          if (a.agent_name) upd.agent_name = String(a.agent_name);
          await db("cloud_instances").where({ id: inst.id }).update(upd);
          this.emit({ type: "status", session_id: sessionId, status: "running", detail: "cloud provider changed" });
          await reply({ status: "linked", instance: inst.name, ...upd }); return "ok";
        }
        case "probe_attack_data": {
          const { readiness } = await import("../attackmap/setup.js");
          const wid = wazuhId ?? (await db("wazuh_instances").orderBy("id").first())?.id;
          const ix = await indexer(this.ctx, wid); const wz = await db("wazuh_instances").where({ id: wid }).first();
          const r = await readiness(ix, wz?.api_url ? () => managerApi(this.ctx, wid) : null, String((call.args as any).window ?? "now-24h"));
          await reply(r); return "ok";
        }
        case "get_ingest_recipe": {
          const { loadRecipes, render } = await import("../attackmap/setup.js");
          const a = call.args as any; const rec = loadRecipes(); const asset = rec.assets.find((x: any) => x.id === a.asset);
          if (!asset) return (await reply({ error: `unknown asset; one of ${rec.assets.map((x: any) => x.id).join(", ")}` }, "failed"), "ok");
          const st = await db("overview_setup").orderBy("wazuh_instance_id").first(); const vars = { MANAGER: st?.manager_addr ?? "<MANAGER_ADDRESS>", DEVICE_IP: "<DEVICE_IP>" };
          const steps = asset.steps.map((x: any) => ({ ...x, detail: x.detail ? render(x.detail, vars) : undefined, snippet: x.snippet ? render(x.snippet, vars) : undefined }));
          const vendor = a.vendor ? rec.vendors[a.vendor] : null;
          await reply({ asset: asset.id, label: asset.label, profiles: asset.profiles, steps, vendor: vendor ? { id: a.vendor, ...vendor, howto: render(vendor.howto, vars) } : null, agent_install: { linux_deb: `curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb && sudo WAZUH_MANAGER='${vars.MANAGER}' WAZUH_AGENT_NAME='<HOSTNAME>' dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb && sudo systemctl enable --now wazuh-agent`, linux_rpm: `curl -sO https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.2-1.x86_64.rpm && sudo WAZUH_MANAGER='${vars.MANAGER}' WAZUH_AGENT_NAME='<HOSTNAME>' rpm -ihv wazuh-agent-4.9.2-1.x86_64.rpm && sudo systemctl enable --now wazuh-agent`, note: "Match the agent version to the manager version (wazuh_api /manager/info)." } });
          return "ok";
        }
        case "get_decoder_pack": { const { decoderPack } = await import("../attackmap/setup.js"); await reply(decoderPack()); return "ok"; }
        case "set_site": {
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const a = call.args as any;
          if (a.is_default) await db("sites").update({ is_default: false });
          const ex = await db("sites").where({ name: String(a.name) }).first();
          let id: number;
          if (ex) { await db("sites").where({ id: ex.id }).update({ lat: a.lat, lon: a.lon, kind: a.kind ?? ex.kind, is_default: a.is_default ?? ex.is_default }); id = ex.id; }
          else id = await db("sites").insert({ name: String(a.name).slice(0, 120), lat: a.lat, lon: a.lon, kind: ["home", "cloud", "office"].includes(a.kind) ? a.kind : "home", is_default: !!a.is_default }).returning("id").then((x: any) => (typeof x[0] === "object" ? x[0].id : x[0]));
          for (const m of a.members ?? []) { await db("site_members").where({ agent_name: String(m) }).delete(); await db("site_members").insert({ site_id: id, agent_name: String(m) }); }
          await this.ctx.audit.log("agent", null, "site.set", { id, name: a.name, members: a.members ?? [] }, sessionId);
          await reply({ status: "saved", site_id: id }); return "ok";
        }
        case "update_setup_state": {
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const a = call.args as any; const wid = wazuhId ?? (await db("wazuh_instances").orderBy("id").first())?.id;
          const upd: any = { updated_at: db.fn.now() }; if (a.assets) upd.assets = j(a.assets); if (a.vendors) upd.vendors = j(a.vendors); if (a.manager_addr) upd.manager_addr = String(a.manager_addr); if (a.step != null) upd.step = Number(a.step); if (a.completed != null) upd.completed = !!a.completed;
          const ex = await db("overview_setup").where({ wazuh_instance_id: wid }).first();
          if (ex) await db("overview_setup").where({ wazuh_instance_id: wid }).update(upd); else await db("overview_setup").insert({ wazuh_instance_id: wid, ...upd });
          await reply({ status: "saved" }); return "ok";
        }
        case "test_host": {
          const h = await db("hosts").where({ name: String((call.args as any).host) }).first();
          if (!h) return (await reply({ error: `unknown host` }, "failed"), "ok");
          if (!h.ssh_key_id) return (await reply({ error: "host has no ssh key" }, "failed"), "ok");
          const k = await db("ssh_keys").where({ id: h.ssh_key_id }).first();
          try {
            const r = await sshExec({ address: h.address, port: h.port, user: h.ssh_user, privateKey: this.ctx.box.decrypt(k.private_key_enc), sudoMode: h.sudo_mode, hostKey: h.host_key },
              "hostname; id -un; uname -sr; (. /etc/os-release 2>/dev/null && echo os=$PRETTY_NAME); uptime -p 2>/dev/null || uptime; (command -v fail2ban-client >/dev/null && echo fail2ban=yes || echo fail2ban=no); (sudo -n true 2>/dev/null && echo sudo=ok || echo sudo=no)", 20000);
            if (!h.host_key && r.hostKey) await db("hosts").where({ id: h.id }).update({ host_key: r.hostKey, updated_at: db.fn.now() });
            await this.ctx.audit.log("agent", null, "host.tested", { id: h.id, name: h.name, code: r.code, ms: r.durationMs, via: "setup_session" }, sessionId);
            await reply({ ok: r.code === 0, exit_code: r.code, stdout: r.stdout, stderr: r.stderr, host_key_pinned: true, duration_ms: r.durationMs });
          } catch (e: any) {
            await this.ctx.audit.log("agent", null, "host.test_failed", { id: h.id, name: h.name, error: e.message, via: "setup_session" }, sessionId);
            await reply({ ok: false, error: e.message, hint: /authentication/i.test(e.message) ? "public key not installed for this user, or wrong ssh_user" : /ECONNREFUSED|timed out|EHOSTUNREACH|ENOTFOUND|ETIMEDOUT/i.test(e.message) ? "address/port unreachable from the console (firewall, wrong address, tailnet not joined?)" : /host key/i.test(e.message) ? "host key changed; use update_host with the same address to re-pin only if the human confirms the host was reinstalled" : undefined });
          }
          return "ok";
        }
        case "add_protected_range": {
          const denied = await this.requireAdmin(sessionId); if (denied) return (await reply({ error: denied }, "failed"), "ok");
          const a = call.args as any;
          if (!/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(String(a.cidr))) return (await reply({ error: "cidr must be IPv4 or IPv4/prefix" }, "failed"), "ok");
          const [id] = await db("protected_ranges").insert({ cidr: String(a.cidr), label: String(a.label).slice(0, 128), reason: a.reason ? String(a.reason) : null }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          await this.ctx.audit.log("agent", null, "protected_range.created", { id, cidr: a.cidr, label: a.label, via: "setup_session" }, sessionId);
          await reply({ status: "added", id });
          return "ok";
        }
        default:
          await reply({ error: `unknown tool ${call.name}` }, "failed");
          return "ok";
      }
    } catch (e: any) {
      await reply({ error: e.message }, "failed");
      return "ok";
    }
  }

  /** Setup tools change console configuration: only sessions started by an admin may use them. Returns an error string or null. */
  private async requireAdmin(sessionId: number): Promise<string | null> {
    const s = await this.ctx.db("sessions").where({ id: sessionId }).first();
    const u = s?.started_by ? await this.ctx.db("users").where({ id: s.started_by, disabled: false }).first() : null;
    return u?.role === "admin" ? null : "this action requires the session to be started by an admin user";
  }

  /**
   * Autonomy levels (host.autonomy_level, capped by host.autonomy_max and AUTONOMY_MAX):
   *  L0 proposal only (even read commands are queued) · L1 reads run, writes need a human (default)
   *  L2 low-risk writes with a rollback run automatically when an identical command on the same host was approved by a human before
   *  L3 writes run automatically unless an auto-check blocks or warns (still logged + notified)
   */
  private async autoApprovable(host: any, command: string, cls: string, risk: string | undefined, checks: { level: string }[], hasRollback: boolean): Promise<string | null> {
    const level = Math.min(Number(host.autonomy_level ?? 1), Number(host.autonomy_max ?? 2), this.ctx.cfg.AUTONOMY_MAX);
    if (level < 2 || cls !== "write") return null;
    if (checks.some((c) => c.level === "block")) return null;
    if (level === 3) return checks.some((c) => c.level === "warn") ? null : "L3: no blocking/warning checks";
    if (risk !== "low" || !hasRollback || checks.some((c) => c.level === "warn")) return null;
    const prior = await this.ctx.db("approvals").where({ host_id: host.id, command }).whereIn("decision", ["approved", "edited"]).whereNotNull("decided_by").where("decided_by", ">", 0).first();
    return prior ? `L2: identical command approved by a human before (approval #${prior.id})` : null;
  }

  /**
   * EDR-87: after a human-approved change FAILED, a corrected plan from the same session/host is approved
   * automatically when it stays inside the approved scope (same files, same services, file-edit commands only),
   * within RETRY_GRANT_MINUTES of the human decision and at most RETRY_GRANT_MAX times. Returns the note or null.
   */
  private async retryGrant(sessionId: number, host: any, steps: string[], checks: { name?: string; level: string }[]): Promise<string | null> {
    const minutes = Number(this.ctx.cfg.RETRY_GRANT_MINUTES ?? 30), cap = Number(this.ctx.cfg.RETRY_GRANT_MAX ?? 5);
    if (!minutes || !cap || !steps.length) return null;
    const ops = mustAskOps(steps);
    if (ops.length) { this.ctx.log.info({ session_id: sessionId, ops }, "retry contains operations that always need a human"); return null; }
    if (checks.some((c) => c.level === "block")) return null;
    const { db } = this.ctx;
    const toMs = (v: any) => v instanceof Date ? v.getTime() : Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(String(v)) ? String(v) : String(v).replace(" ", "T") + "Z");
    const last = await db("approvals").where({ session_id: sessionId, host_id: host.id }).whereIn("decision", ["approved", "edited"]).whereNotNull("decided_at").whereNot("id", -1).orderBy("id", "desc").first();
    if (!last) return null;
    const lr = pj<any>(last.exec_result);
    if (!lr || lr.status === "running" || (lr.status === "executed" && (lr.exit_code ?? 0) === 0)) return null; // only after a failure
    if (lr.health && lr.health.ok === false) return null; // EDR-94: a service is down — a human decides
    const m = String(last.decision_note ?? "").match(/^retry-of #(\d+) /);
    const base = m ? await db("approvals").where({ id: Number(m[1]) }).first() : last;
    if (!base || !(Number(base.decided_by) > 0)) return null; // the scope must come from a human decision
    if (Date.now() - toMs(base.decided_at) > minutes * 60_000) return null;
    const used = (await db("approvals").where({ session_id: sessionId }).where("decision_note", "like", `retry-of #${base.id} %`)).length;
    // EDR-94: the approver's allowance (self_drive_max) or the environment default, never above RETRY_GRANT_MAX
    const max = Math.min(cap, base.self_drive_max != null ? Number(base.self_drive_max) : this.selfDriveDefault(host));
    if (used >= max) return null;
    const baseSteps: string[] = base.steps ? (pj<any[]>(base.steps) ?? []).map((x: any) => String(x.command)) : [String(base.executed_command ?? base.command)];
    const why = scopeCovers(changeScope(baseSteps, this.allow), changeScope(steps, this.allow));
    if (why) { this.ctx.log.info({ session_id: sessionId, base: base.id, why }, "retry is outside the approved scope; asking the human"); return null; }
    const baseChecks: any[] = pj<any>(base.auto_checks)?.checks ?? [];
    if (checks.some((c) => c.level === "warn" && !baseChecks.some((b: any) => b.name === c.name && b.level === "warn"))) return null; // a new warning needs a human
    return `retry-of #${base.id} (${used + 1}/${max}) 承認 #${base.id} の範囲で自動で修正・再実行（あと ${max - used - 1} 回）`;
  }

  // ---------------- EDR-94: self-drive guards ----------------
  selfDriveDefault(host: any): number {
    return host?.environment === "production" ? Number(this.ctx.cfg.SELF_DRIVE_MAX_PRODUCTION ?? 3) : Number(this.ctx.cfg.SELF_DRIVE_MAX_LAB ?? 5);
  }
  private discord(text: string) {
    const url = this.ctx.cfg.DISCORD_WEBHOOK_URL;
    if (url) ufetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: text.slice(0, 1900) }) }).catch(() => {});
  }
  /**
   * Checks before a change is proposed (returns the tool result that stops it, or null):
   *  - vulnerability fixes must be based on version_check (official EOL / release data), not on the model's memory
   *  - production retreat line: after N different human-approved approaches failed since the human last wrote, stop and report
   *  - a service left down after a failed change: stop and report
   */
  private async preChangeGuards(sessionId: number, host: any, text: string, cmds: string[]): Promise<Record<string, unknown> | null> {
    const { db, cfg } = this.ctx;
    const since24h = new Date(Date.now() - 24 * 3600_000).toISOString().replace("T", " ").slice(0, 19);
    // EDR-113: operations the AI never runs, approval or not
    const never = forbiddenOps(cmds, host.environment);
    if (never.length) {
      await this.ctx.audit.log("system", null, "change.blocked_forbidden", { host: host.name, ops: never }, sessionId);
      return { status: "blocked", reason: "forbidden_operation", operations: never, instruction: `This plan contains operations MamorAI never runs on ${host.name} (env=${host.environment}): ${never.join(", ")}. Do not try to work around it. Package transactions must be allowed to finish (they run as long steps and can take 30+ minutes); a stuck one is for the human to handle. Instead of building from source, use the distribution package (pkg_candidates tells you how). Remove these steps and submit the plan again, or explain to the human why you are stuck.` };
    }
    // EDR-115: decisions the human recorded for this ticket
    const decisions = await db("session_decisions").where({ session_id: sessionId, active: true }).whereNotNull("forbid");
    if (decisions.length) {
      const ask = mustAskOps(cmds), prodNever = forbiddenOps(cmds, "production");
      const hitOf: Record<string, boolean> = {
        source_build: ask.includes("ソースからのビルド・システムのプログラム差し替え") || prodNever.includes("本番ホストでのソースビルド"),
        external_repo: ask.includes("外部リポジトリの追加"), os_upgrade: ask.includes("OS 全体のアップグレード"),
        package_removal: ask.includes("パッケージの削除"), reboot: ask.includes("再起動・停止"),
      };
      const broken = decisions.filter((d: any) => hitOf[d.forbid]);
      if (broken.length) {
        await this.ctx.audit.log("system", null, "change.blocked_decision", { host: host.name, decisions: broken.map((d: any) => d.text) }, sessionId);
        return { status: "blocked", reason: "against_human_decision", decisions: broken.map((d: any) => d.text), instruction: `The human decided in this ticket: ${broken.map((d: any) => `「${d.text}」`).join(" ")}. This plan breaks it. Do not submit it. Either find a way that respects the decision, or ask the human whether they want to change the decision (they must say so explicitly).` };
      }
    }
    // EDR-114: never install an older version than the one on the host
    {
      const known: { name: string; ver: string }[] = [];
      for (const t of await db("tool_calls").where({ session_id: sessionId }).whereIn("tool", ["version_check", "pkg_candidates"]).orderBy("id", "desc").limit(30)) {
        const ar = pj<any>(t.args) ?? {}, rs = pj<any>(t.result) ?? {};
        if (t.tool === "version_check" && ar.product && ar.version) known.push({ name: String(ar.product), ver: normalizeVersion(String(ar.version)) });
        if (t.tool === "pkg_candidates" && rs.host === host.name) for (const p of rs.packages ?? []) if (p.installed) known.push({ name: String(p.name), ver: normalizeVersion(String(p.installed).replace(/^\d+:/, "")) });
      }
      const plan = cmds.join("\n");
      const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      for (const k of known) {
        if (!k.ver || !/^[\w.+-]{2,40}$/.test(k.name)) continue;
        const base = k.name.replace(/[0-9.]+$/, "") || k.name; // php8.3 → php
        const re = new RegExp(`\\b${esc(base)}[\\w.]*?[-_ /]v?(\\d+\\.\\d+\\.\\d+)`, "gi");
        for (const m of plan.matchAll(re)) {
          const v = m[1];
          if (k.ver.split(".")[0] === v.split(".")[0] && cmpVer(v, k.ver) < 0) {
            await this.ctx.audit.log("system", null, "change.blocked_downgrade", { host: host.name, package: k.name, installed: k.ver, planned: v }, sessionId);
            return { status: "blocked", reason: "downgrade", installed: `${k.name} ${k.ver}`, planned: v, instruction: `The plan installs or builds ${base} ${v}, which is OLDER than the installed ${k.ver}. Versions compare numerically (${v} < ${k.ver}); a distribution never renumbers upstream versions. An older version cannot be the fix. Re-check the fixed version (advisory / version_check) and use pkg_candidates to see how this host can get it.` };
          }
        }
      }
      if (/\b(dnf|yum)\s+(-\S+\s+)*downgrade\b|\bapt(-get)?\s+[^;&|\n]*install\s+[^;&|\n]*=\S*/i.test(plan) && /CVE-\d|脆弱性|vulnerab|セキュリティ/i.test(text)) {
        return { status: "blocked", reason: "downgrade", instruction: "A vulnerability fix never downgrades or pins an older package version. Use pkg_candidates and install the fixed (newer) version." };
      }
    }
    if (/CVE-\d|脆弱性|vulnerab|php2shell|セキュリティ(修正|パッチ|アップデート)|security (fix|patch|update)/i.test(text + "\n" + cmds.join("\n")) && cmds.some((c) => isLongStep(c))) {
      const pc = await db("tool_calls").where({ session_id: sessionId, tool: "pkg_candidates" }).where("created_at", ">=", since24h).first();
      if (!pc) return { status: "blocked", reason: "premise_unverified", instruction: `This package change is a vulnerability fix, but pkg_candidates has not been run for ${host.name} in this ticket. Call pkg_candidates(host, package, fixed_version) first and follow its verdict (on Amazon Linux 2023 the fix may only exist in a newer OS release). Then submit the plan again.` };
    }
    if (/CVE-\d|脆弱性|vulnerab|php2shell|セキュリティ(修正|パッチ|アップデート)|security (fix|patch|update)/i.test(text + "\n" + cmds.join("\n"))) {
      const vc = await db("tool_calls").where({ session_id: sessionId, tool: "version_check" }).where("created_at", ">=", since24h).first();
      if (!vc) {
        await this.ctx.audit.log("system", null, "change.blocked_premise", { host: host.name }, sessionId);
        return { status: "blocked", reason: "premise_unverified", instruction: "This change is about a vulnerability, but version_check has not been run in this ticket. First get the installed version on the host (read-only) and call version_check for that product/version. Base the plan only on its result (which versions contain the fix, what the repository actually offers). Never assume a version number is the fixed one. Then submit the plan again and quote the version_check verdict in intent." };
      }
    }
    // the last thing the human WROTE (clicking "この提案を進める" or a schedule run does not reset the retreat line)
    const userMsgs = await db("messages").where({ session_id: sessionId, role: "user" }).orderBy("id", "desc").limit(100).select("content", "created_at");
    const human = userMsgs.find((r: any) => { const c = pj<any>(r.content)?.content; const t = typeof c === "string" ? c.trim() : "x"; return t && !/^(\[system\]|⏰|提案「)/.test(t); });
    const sinceHuman = human?.created_at ?? "1970-01-01 00:00:00";
    const recent = await db("approvals").where({ session_id: sessionId, host_id: host.id }).whereIn("decision", ["approved", "edited"]).where("decided_at", ">", sinceHuman).orderBy("id");
    const down = recent.find((r: any) => pj<any>(r.exec_result)?.health?.ok === false);
    const stopMsg = (why: string) => ({ status: "stopped", reason: why, instruction: "STOP changing this host. Do NOT propose another approach or another change. Verify the current state with read-only commands (services running, site responding, versions). Then report to the human in Japanese, briefly: what was tried, why each attempt failed, the current state, and the decision you need from them. Use propose_next_actions with kind=followup actions only. The human can tell you to continue." });
    if (down) {
      await this.ctx.audit.log("system", null, "session.retreat", { host: host.name, reason: "service_down", approval_id: down.id }, sessionId);
      return stopMsg("a service was left down after a failed change");
    }
    const limit = host.environment === "production" ? Number(cfg.RETREAT_FAILED_APPROACHES_PRODUCTION ?? 2) : Number(cfg.RETREAT_FAILED_APPROACHES_LAB ?? 0);
    if (limit > 0) {
      let failedApproaches = 0;
      for (const b of recent.filter((r: any) => Number(r.decided_by) > 0)) {
        const chain = recent.filter((r: any) => r.id === b.id || String(r.decision_note ?? "").startsWith(`retry-of #${b.id} `));
        const lastOf = chain[chain.length - 1];
        const st = pj<any>(lastOf?.exec_result)?.status;
        if (st === "failed" || st === "interrupted") failedApproaches++;
      }
      if (failedApproaches >= limit) {
        await this.ctx.audit.log("system", null, "session.retreat", { host: host.name, reason: "failed_approaches", failed_approaches: failedApproaches, limit }, sessionId);
        this.discord(`[MamorAI #${sessionId}] ${host.name}: 別々のやり方で ${failedApproaches} 回失敗したため、変更を止めて報告に切り替えました。`);
        return { ...stopMsg(`${failedApproaches} different approved approaches failed on this production host since the human last wrote (limit ${limit})`), failed_approaches: failedApproaches };
      }
    }
    return null;
  }

  // ---------------- EDR-90: kill switch ----------------
  async getHold(): Promise<{ on: boolean; reason: string | null; updated_at: string | null; updated_by: number | null }> {
    const r = await this.ctx.db("app_flags").where({ key: "auto_approval_hold" }).first();
    const v = r?.value ? JSON.parse(r.value) : null;
    return { on: !!v?.on, reason: v?.reason ?? null, updated_at: r?.updated_at ?? null, updated_by: r?.updated_by ?? null };
  }
  async setHold(on: boolean, reason: string, userId: number | null): Promise<void> {
    const { db } = this.ctx;
    const value = JSON.stringify({ on, reason });
    const ex = await db("app_flags").where({ key: "auto_approval_hold" }).first();
    if (ex) await db("app_flags").where({ key: "auto_approval_hold" }).update({ value, updated_by: userId, updated_at: db.fn.now() });
    else await db("app_flags").insert({ key: "auto_approval_hold", value, updated_by: userId });
    await this.ctx.audit.log(userId ? "user" : "system", userId, on ? "safety.hold_on" : "safety.hold_off", { reason });
    this.emit({ type: "status", session_id: 0, status: "safety", detail: on ? "hold_on" : "hold_off" });
    const url = this.ctx.cfg.DISCORD_WEBHOOK_URL;
    if (url) ufetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: `[MamorAI] 自動承認を${on ? "停止しました" : "再開しました"}: ${reason}` }) }).catch(() => {});
  }
  /** true when changes must not be approved automatically in this session */
  private async noAutoApproval(sessionId: number): Promise<boolean> {
    if ((await this.getHold()).on) return true;
    const s = await this.ctx.db("sessions").where({ id: sessionId }).first();
    return s?.origin === "alert";
  }
  /** trip the kill switch when too many changes ran in 10 minutes (runaway agent or hijacked console) */
  private async checkRunaway(): Promise<void> {
    const max = Number(this.ctx.cfg.AUTO_HOLD_MAX_CHANGES_10MIN ?? 15);
    if (!max) return;
    const { db } = this.ctx;
    const since = new Date(Date.now() - 10 * 60_000).toISOString().replace("T", " ").slice(0, 19);
    const n = Number((await db("approvals").whereIn("decision", ["approved", "edited"]).where("decided_at", ">=", since).count<{ c: number }[]>({ c: "*" }).first())?.c ?? 0);
    if (n > max && !(await this.getHold()).on) await this.setHold(true, `10 分間に ${n} 件の変更が実行されたため自動で停止（上限 ${max}）`, null);
  }

  /**
   * EDR-114: run one step detached on the host (setsid nohup, output in /var/tmp/mamorai-job/<approval>-<step>/) and poll
   * until it writes its exit code. Waits first if another package transaction is running (never runs two, never kills one).
   * After LONG_STEP_MAX_MINUTES the job is left running and the step is reported with stillRunning=true.
   */
  private async runLong(target: any, approvalId: number, idx: number, command: string, onTick: (tail: string, sec: number) => Promise<void>): Promise<{ code: number | null; stdout: string; stderr: string; durationMs: number; truncated: boolean; hostKey?: string; stillRunning?: boolean }> {
    const maxMs = Number(this.ctx.cfg.LONG_STEP_MAX_MINUTES ?? 60) * 60_000, pollMs = Number(this.ctx.cfg.LONG_STEP_POLL_SECONDS ?? 15) * 1000;
    const started = Date.now();
    const D = `/var/tmp/mamorai-job/${approvalId}-${idx}`;
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const out = (code: number | null, stdout: string, stderr: string, extra: Record<string, unknown> = {}) => ({ code, stdout, stderr, durationMs: Date.now() - started, truncated: false, ...extra });
    // 1) another package transaction (or dnf-makecache) running → wait for it
    for (;;) {
      const b = await sshExec(target, "pgrep -a -x 'dnf|yum|rpm|apt|apt-get|dpkg|unattended-upgr' | grep -v unattended-upgrade-shutdown || true", 30_000).catch(() => ({ stdout: "" } as any));
      const busy = String(b.stdout ?? "").trim();
      if (!busy) break;
      if (Date.now() - started > maxMs) return out(125, "", `[edr-console] another package transaction kept running for ${Math.round(maxMs / 60000)} min: ${busy.slice(0, 300)}. Nothing was started. Do not kill it; try again later.`);
      await onTick(`別のパッケージ処理の終了を待っています:\n${busy}`, (Date.now() - started) / 1000);
      await sleep(pollMs);
    }
    // 2) start detached
    const b64 = Buffer.from(command, "utf8").toString("base64");
    const start = `mkdir -p ${D} && chmod 700 /var/tmp/mamorai-job ${D} && echo ${b64} | base64 -d > ${D}/cmd.sh && rm -f ${D}/rc ${D}/out && setsid nohup bash -c 'bash "$1/cmd.sh" > "$1/out" 2>&1; echo $? > "$1/rc"' _ ${D} </dev/null >/dev/null 2>&1 & echo STARTED`;
    const s0 = await sshExec(target, start, 60_000);
    if (!/STARTED/.test(s0.stdout)) return out(s0.code ?? 1, s0.stdout, `[edr-console] could not start the step on the host: ${s0.stderr}`, { hostKey: s0.hostKey });
    // 3) poll
    let tail = "";
    for (;;) {
      await sleep(pollMs);
      const p = await sshExec(target, `cat ${D}/rc 2>/dev/null; echo '--MAMORAI-TAIL--'; tail -c 4000 ${D}/out 2>/dev/null`, 45_000).catch(() => null);
      if (p) {
        const [rcPart, t = ""] = p.stdout.split("--MAMORAI-TAIL--");
        tail = t.replace(/^\n/, "");
        const rc = rcPart.trim();
        if (/^\d+$/.test(rc)) {
          const full = await sshExec(target, `tail -c 20000 ${D}/out`, 45_000).catch(() => null);
          return out(Number(rc), full?.stdout ?? tail, "", { hostKey: s0.hostKey });
        }
      }
      const sec = (Date.now() - started) / 1000;
      if (Date.now() - started > maxMs) return out(124, tail, `[edr-console] still running on the host after ${Math.round(maxMs / 60000)} min (job ${D}). It was NOT stopped. Do not start another package transaction and do not kill it; check later with: cat ${D}/rc; tail ${D}/out`, { stillRunning: true, hostKey: s0.hostKey });
      await onTick(tail, sec);
    }
  }

  /** EDR-115: deterministic check after a plan that touched packages. */
  private async postCheck(target: any, services: string[]): Promise<{ ok: boolean; issues: string[]; info: string[]; raw: string }> {
    const svc = [...new Set(services)].filter((x) => /^[\w@.-]+$/.test(x));
    const script = [
      "if command -v dnf >/dev/null 2>&1; then timeout 150 dnf -q check 2>&1 | head -40 | sed 's/^/DNFCHECK=/'; fi",
      "if command -v dpkg >/dev/null 2>&1; then dpkg --audit 2>&1 | head -10 | sed 's/^/DPKGAUDIT=/'; fi",
      "pgrep -a -x 'dnf|yum|rpm|apt|apt-get|dpkg' 2>/dev/null | head -5 | sed 's/^/BUSY=/'",
      "pgrep -af '[c]c1 |[c]c1plus |[m]ake -j|[m]ake install|[.]/configure' 2>/dev/null | head -5 | cut -c1-160 | sed 's/^/BUILD=/'",
      "if command -v php >/dev/null 2>&1; then php -m 2>&1 | grep -iE 'warning|undefined symbol|unable to load' | head -5 | cut -c1-200 | sed 's/^/PHPERR=/'; echo \"PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null)\"; fi",
      "if command -v gcc >/dev/null 2>&1; then echo GCC=1; fi",
      "K=$(rpm -q --last kernel 2>/dev/null | head -1 | awk '{print $1}' | sed 's/^kernel-//'); [ -n \"$K\" ] && [ \"$K\" != \"$(uname -r)\" ] && echo \"KERNEL=$K|$(uname -r)\"",
      '[ -f /var/run/reboot-required ] && echo "KERNEL=deb|reboot-required"',
      ...svc.map((x) => `echo "SVC=${x}|$(systemctl is-active ${x} 2>&1)"`),
      "true",
    ].join("\n");
    const r = await sshExec(target, script, 200_000);
    const lines = r.stdout.split("\n").map((l) => l.trim()).filter(Boolean);
    const get = (k: string) => lines.filter((l) => l.startsWith(k + "=")).map((l) => l.slice(k.length + 1));
    const issues: string[] = [], info: string[] = [];
    const dnf = get("DNFCHECK").filter((l) => l && !/^Error: Check discovered/.test(l));
    if (dnf.length) issues.push(`dnf check: ${dnf.length} 件（例: ${dnf[0].slice(0, 160)}）${dnf.some((l) => /duplicate/.test(l)) ? " → 二重登録。プレイブックの『途中で止まった dnf の後始末』" : ""}`);
    if (get("DPKGAUDIT").length) issues.push(`dpkg --audit: ${get("DPKGAUDIT")[0].slice(0, 160)} → dpkg --configure -a`);
    if (get("BUSY").length) issues.push(`パッケージ管理がまだ動いている: ${get("BUSY").join(", ").slice(0, 200)}（kill しない）`);
    if (get("BUILD").length) issues.push(`ビルドのプロセスが残っている: ${get("BUILD")[0]}`);
    if (get("PHPERR").length) issues.push(`php の拡張モジュールの読み込みエラー: ${get("PHPERR")[0]}`);
    for (const s of get("SVC")) { const [n, st] = s.split("|"); if (st !== "active") issues.push(`${n} が ${st}`); }
    if (get("GCC").length) info.push("gcc が入っている（ビルド用に入れたものなら片付ける）");
    const k = get("KERNEL")[0]; if (k) info.push(k.startsWith("deb|") ? "再起動待ちの更新がある（/var/run/reboot-required）" : `新しいカーネル ${k.split("|")[0]} が入った（稼働中 ${k.split("|")[1]}）。反映には再起動が必要 — メンテ枠で人と相談`);
    const pv = get("PHPVER")[0]; if (pv) info.push(`PHP ${pv}`);
    return { ok: issues.length === 0 && r.code === 0, issues, info, raw: r.stdout.slice(0, 4000) };
  }

  /** EDR-88: copy the files a plan may change to /var/tmp/mamorai-snap/<approval>/ on the host. Returns what was saved. */
  private async snapshotFiles(target: any, approvalId: number, paths: string[]): Promise<{ i: number; path: string }[]> {
    const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
    const dir = `/var/tmp/mamorai-snap/${approvalId}`;
    const script = [`mkdir -p ${dir}`, `chmod 700 /var/tmp/mamorai-snap ${dir}`, ...paths.map((p, i) => `if [ -f ${q(p)} ]; then cp -p ${q(p)} ${dir}/${i} && echo SAVED:${i}; fi`)].join("; ");
    const r = await sshExec(target, script, 60_000);
    const saved = [...r.stdout.matchAll(/SAVED:(\d+)/g)].map((m) => Number(m[1]));
    return saved.map((i) => ({ i, path: paths[i] }));
  }
  /** EDR-88: put the snapshot back and restart the given services. */
  private async restoreSnapshot(target: any, approvalId: number, saved: { i: number; path: string }[], services: string[]) {
    const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
    const dir = `/var/tmp/mamorai-snap/${approvalId}`;
    const parts = saved.map((x) => `cp -p ${dir}/${x.i} ${q(x.path)} && echo "restored ${x.path}"`);
    for (const s of services) parts.push(`systemctl restart ${q(s)}; sleep 3; echo "${s}: $(systemctl is-active ${q(s)})"; systemctl is-active --quiet ${q(s)}`);
    return sshExec(target, parts.join(" && "), 300_000);
  }

  /** Deterministic checks shown on the approval card. */
  private async autoChecks(host: any, command: string): Promise<{ name: string; level: "block" | "warn" | "info" | "ok"; detail: string }[]> {
    const out: { name: string; level: "block" | "warn" | "info" | "ok"; detail: string }[] = [];
    const ranges = await this.ctx.db("protected_ranges").where((q) => q.whereNull("host_id").orWhere("host_id", host.id));
    const ips = command.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g) ?? [];
    const hit = ips.filter((ip) => ranges.some((r: any) => cidrContains(r.cidr, ip)));
    if (hit.length) out.push({ name: "protected_ranges", level: "block", detail: `command touches protected address(es): ${hit.join(", ")}` });
    else out.push({ name: "protected_ranges", level: "ok", detail: ips.length ? `${ips.length} address(es) checked` : "no addresses in command" });
    if (host.environment === "production" && /systemctl\s+(restart|stop)|reboot|shutdown/.test(command)) out.push({ name: "production", level: "warn", detail: "service restart/stop on a production host" });
    { const ops = mustAskOps([command]); if (ops.length) out.push({ name: "always_ask", level: "warn", detail: `毎回人が確認する操作: ${ops.join("・")}` }); }
    if (/\brm\s+-rf?\b|\bmkfs\b|\bdd\s+if=/.test(command)) out.push({ name: "destructive", level: "warn", detail: "destructive command pattern" });
    return out;
  }
}

export function mimeFor(name: string): string {
  const ext = name.toLowerCase().split(".").pop();
  return ({ csv: "text/csv; charset=utf-8", tsv: "text/tab-separated-values; charset=utf-8", md: "text/markdown; charset=utf-8", html: "text/html; charset=utf-8", svg: "image/svg+xml", txt: "text/plain; charset=utf-8", json: "application/json" } as Record<string, string>)[ext ?? ""] ?? "application/octet-stream";
}

function truncate(s: string): string {
  if (s.length <= TOOL_RESULT_MAX) return s;
  return s.slice(0, TOOL_RESULT_MAX - 200) + `\n...[truncated ${s.length - TOOL_RESULT_MAX + 200} chars; full output stored in the console]`;
}

export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsStr] = cidr.split("/");
  const bits = bitsStr ? Number(bitsStr) : 32;
  const ipOnly = ip.split("/")[0];
  const toInt = (s: string) => s.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(base) || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ipOnly)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (toInt(base) & mask) === (toInt(ipOnly) & mask);
}
