/**
 * EDR-121 S3/S8: "ホストを AI でスキャン" job runner.
 *  queue (HOST_SCAN_CONCURRENCY at a time) → collect facts → AI interpretation (optional, budgeted) → save version → diff
 *  + periodic work: import Wazuh agents (S1), scheduled scans (S8), "still isolated" reminders (S7)
 */
import type { Ctx } from "../api/context.js";
import { j, pj } from "../db/index.js";
import { collectFacts, type Facts } from "./collect.js";
import { interpret } from "./interpret.js";
import { syncAgents } from "./sync.js";
import { remindIsolation } from "./actions.js";

export const SCHEDULE_CHOICES = ["1d", "7d", "30d", "off"] as const;
export const SCHEDULE_DEFAULT: Record<string, string> = { production: "1d", staging: "1d", lab: "7d" };
const MIN: Record<string, number> = { "1d": 1440, "7d": 10080, "30d": 43200 };
const REMOTE_TOOLS = /anydesk|teamviewer|rustdesk|\bvnc\b|tightvnc|ultravnc|realvnc|splashtop|screenconnect|connectwise|logmein|parsec|chrome remote|ammyy|supremo|radmin|atera|meshagent|ngrok|cloudflared|\bfrpc?\b|remote utilities|dameware|netsupport/i;
const KEEP = 10;

export async function getSchedule(ctx: Ctx): Promise<Record<string, string>> {
  const r = await ctx.db("app_flags").where({ key: "host_scan_schedule" }).first();
  let v: any = null; try { v = r?.value ? JSON.parse(r.value) : null; } catch { v = null; }
  return { ...SCHEDULE_DEFAULT, ...(v ?? {}) };
}
export async function setSchedule(ctx: Ctx, v: Record<string, string>, userId: number | null) {
  const clean = Object.fromEntries(Object.entries(v).filter(([k, x]) => ["production", "staging", "lab"].includes(k) && (SCHEDULE_CHOICES as readonly string[]).includes(x)));
  const value = JSON.stringify({ ...(await getSchedule(ctx)), ...clean });
  const ex = await ctx.db("app_flags").where({ key: "host_scan_schedule" }).first();
  if (ex) await ctx.db("app_flags").where({ key: "host_scan_schedule" }).update({ value, updated_by: userId, updated_at: ctx.db.fn.now() });
  else await ctx.db("app_flags").insert({ key: "host_scan_schedule", value, updated_by: userId });
}
export async function getPseudonymize(ctx: Ctx): Promise<boolean> {
  const r = await ctx.db("app_flags").where({ key: "host_scan_pseudonymize_users" }).first();
  return r ? r.value !== "false" : true;
}

/** what changed since the previous scan (dynamic RPC/ephemeral ports are ignored) */
export function diffFacts(prev: Facts | null, cur: Facts) {
  if (!prev) return { first: true, new_ports: [], gone_ports: [], new_exposed_ports: [], new_admins: [], new_users: [], new_remote_tools: [], new_software: [], removed_software: [], new_services: [], important: false };
  const stable = (l: Facts["listening"][number]) => l.port < 49152 || !!l.known;
  const pk = (l: Facts["listening"][number]) => `${l.proto}/${l.port}`;
  const prevPorts = new Set(prev.listening.filter(stable).map(pk));
  const curPorts = new Set(cur.listening.filter(stable).map(pk));
  const new_ports = cur.listening.filter((l) => stable(l) && !prevPorts.has(pk(l))).map((l) => ({ port: pk(l), exposure: l.exposure, process: l.process, known: l.known }));
  const gone_ports = [...prevPorts].filter((x) => !curPorts.has(x));
  const new_exposed_ports = new_ports.filter((x) => x.exposure !== "local");
  const prevAdmins = new Set(prev.users.filter((u) => u.admin).map((u) => u.name.toLowerCase()));
  const new_admins = cur.users.filter((u) => u.admin && !prevAdmins.has(u.name.toLowerCase())).map((u) => u.name);
  const prevUsers = new Set(prev.users.filter((u) => u.type !== "seen_in_logs").map((u) => u.name.toLowerCase()));
  const new_users = cur.users.filter((u) => u.type !== "seen_in_logs" && !prevUsers.has(u.name.toLowerCase())).map((u) => u.name);
  const prevSw = new Set(prev.software.items.map((p) => p.name)); const curSw = new Set(cur.software.items.map((p) => p.name));
  const new_software = cur.software.items.filter((p) => !prevSw.has(p.name)).map((p) => `${p.name}${p.version ? " " + p.version : ""}`).slice(0, 30);
  const removed_software = [...prevSw].filter((x) => !curSw.has(x)).slice(0, 30);
  const new_remote_tools = [...cur.software.items.map((p) => p.name), ...cur.processes.map((p) => p.name)].filter((n) => REMOTE_TOOLS.test(n) && ![...prev.software.items.map((p) => p.name), ...prev.processes.map((p) => p.name)].includes(n));
  const prevSvc = new Set([...prev.services.map((s) => s.name), ...(prev.ssh?.units ?? []).map((u) => u.name)]);
  const new_services = [...cur.services.map((s) => s.name), ...(cur.ssh?.units ?? []).map((u) => u.name)].filter((n) => !prevSvc.has(n)).slice(0, 30);
  return { first: false, new_ports, gone_ports, new_exposed_ports, new_admins, new_users, new_remote_tools: [...new Set(new_remote_tools)], new_software, removed_software, new_services, important: new_exposed_ports.length > 0 || new_admins.length > 0 || new_remote_tools.length > 0 };
}

export class HostScanner {
  private running = new Set<number>();
  private timers: NodeJS.Timeout[] = [];
  private lastSync = 0; private lastSchedule = 0;
  constructor(private ctx: Ctx) {}

  async start() {
    const { db } = this.ctx;
    await db("host_scans").where({ status: "running" }).update({ status: "failed", error: "MamorAI の再起動で中断されました", finished_at: db.fn.now() });
    this.timers.push(setInterval(() => this.tick().catch((e) => this.ctx.log.warn({ err: e.message }, "host scanner tick failed")), 30_000));
    setTimeout(() => this.tick().catch(() => {}), 15_000);
  }
  stop() { for (const t of this.timers) clearInterval(t); }

  async tick() {
    const now = Date.now();
    const syncMin = this.ctx.cfg.HOST_AGENT_SYNC_MIN;
    if (syncMin > 0 && now - this.lastSync > syncMin * 60_000) {
      this.lastSync = now;
      const r = await syncAgents(this.ctx).catch((e) => { this.ctx.log.warn({ err: e.message }, "agent sync failed"); return null; });
      if (r?.created.length) for (const name of r.created) { const h = await this.ctx.db("hosts").where({ name }).first(); if (h && h.agent_status === "active") await this.enqueue(h.id, "enroll", null); }
    }
    if (now - this.lastSchedule > 10 * 60_000) {
      this.lastSchedule = now;
      await this.scheduleDue().catch((e) => this.ctx.log.warn({ err: e.message }, "scan schedule failed"));
      await remindIsolation(this.ctx).catch((e) => this.ctx.log.warn({ err: e.message }, "isolation reminder failed"));
    }
    await (await import("../agentpack/index.js")).tick(this.ctx); // EDR-130: new pack revision when the add-on / Wazuh / installer changed
    (await import("../scs/sync.js")).tick(this.ctx).catch((e: any) => this.ctx.log.warn({ err: e?.message }, "scs tick failed")); // EDR-176: SCS 台帳（毎時・フィードは日次）。待たない
    await this.pump();
  }

  /** S8: queue hosts whose last scan is older than their schedule */
  async scheduleDue() {
    const { db } = this.ctx;
    const sched = await getSchedule(this.ctx);
    for (const h of await db("hosts").orderBy("id")) {
      const every = h.scan_schedule_override ?? sched[h.environment] ?? "7d";
      if (every === "off" || !MIN[every]) continue;
      if (h.kind === "agent_only" && h.agent_status !== "active") continue; // nothing new to read from a disconnected agent
      if (!h.agent_id && !(h.kind === "managed" && h.ssh_key_id)) continue;
      const last = h.last_scan_at ? new Date(h.last_scan_at).getTime() : 0;
      if (Date.now() - last < MIN[every] * 60_000) continue;
      await this.enqueue(h.id, "schedule", null);
    }
  }

  async enqueue(hostId: number, trigger: "manual" | "schedule" | "enroll", userId: number | null): Promise<number> {
    const { db } = this.ctx;
    const busy = await db("host_scans").where({ host_id: hostId }).whereIn("status", ["queued", "running"]).first();
    if (busy) return busy.id;
    const [id] = await db("host_scans").insert({ host_id: hostId, status: "queued", trigger, requested_by: userId }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    if (trigger !== "schedule") await this.ctx.audit.log(userId ? "user" : "system", userId, "host.scan_requested", { scan_id: id, host_id: hostId, trigger });
    setImmediate(() => this.pump().catch(() => {}));
    return id;
  }

  private async pump() {
    const { db } = this.ctx;
    const free = this.ctx.cfg.HOST_SCAN_CONCURRENCY - this.running.size;
    if (free <= 0) return;
    const next = await db("host_scans").where({ status: "queued" }).orderByRaw("CASE \"trigger\" WHEN 'manual' THEN 0 WHEN 'enroll' THEN 1 ELSE 2 END").orderBy("id").limit(free);
    for (const s of next) {
      if (this.running.has(s.id)) continue;
      this.running.add(s.id);
      this.run(s.id).catch((e) => this.ctx.log.error({ err: e.message, scan: s.id }, "host scan crashed")).finally(() => { this.running.delete(s.id); setImmediate(() => this.pump().catch(() => {})); });
    }
  }

  private async run(scanId: number) {
    const { db, cfg } = this.ctx;
    const stage = (st: string) => db("host_scans").where({ id: scanId }).update({ stage: st });
    const scan = await db("host_scans").where({ id: scanId }).first();
    const host = await db("hosts").where({ id: scan.host_id }).first();
    if (!host) { await db("host_scans").where({ id: scanId }).update({ status: "failed", error: "host not found", finished_at: db.fn.now() }); return; }
    await db("host_scans").where({ id: scanId }).update({ status: "running", stage: "collect", started_at: db.fn.now() });
    try {
      const facts = await collectFacts(this.ctx, host);
      await stage("normalize");
      let profile: any = null, model: string | null = null, tin = 0, tout = 0, aiNote: string | null = null;
      const provider = this.ctx.runtime?.llmProvider ?? null;
      // scheduled scans: reuse the previous AI interpretation when nothing meaningful changed (saves LLM cost)
      const prev0 = await db("host_scans").where({ host_id: host.id, status: "done" }).orderBy("id", "desc").first();
      const d0 = diffFacts(prev0 ? pj<Facts>(prev0.facts) : null, facts);
      const changed = d0.first || d0.important || d0.new_ports.length || d0.gone_ports.length || d0.new_services.length || d0.new_users.length || d0.new_software.length || d0.removed_software.length;
      const prevProfile = prev0 ? pj<any>(prev0.profile) : null;
      const fresh = prev0?.finished_at && Date.now() - new Date(prev0.finished_at).getTime() < 7 * 86400_000;
      if (scan.trigger === "schedule" && !changed && prevProfile?.summary && fresh) { profile = { ...prevProfile, note: undefined }; model = prev0.model; aiNote = "変化が無いため、前回の AI 解釈をそのまま表示しています"; }
      else if (!cfg.HOST_SCAN_AI) aiNote = "AI による解釈はオフです（HOST_SCAN_AI=false）";
      else if (!provider) aiNote = "AI（LLM）が未設定のため、集めた事実だけを表示しています";
      else {
        await stage("ai");
        try {
          const r = await interpret(provider, facts, { pseudonymize: await getPseudonymize(this.ctx), maxTokens: cfg.HOST_SCAN_MAX_TOKENS });
          profile = r.profile; model = r.model; tin = r.usage.input; tout = r.usage.output;
        } catch (e: any) { aiNote = e.code === "budget" ? `AI の予算を超えるため解釈を省きました（${e.message}）` : `AI の解釈に失敗しました: ${String(e.message ?? e).slice(0, 300)}`; }
      }
      await stage("save");
      const prev = await db("host_scans").where({ host_id: host.id, status: "done" }).orderBy("id", "desc").first();
      const diff = diffFacts(prev ? pj<Facts>(prev.facts) : null, facts);
      let factsJson = JSON.stringify(facts);
      if (factsJson.length > 256_000) { facts.software.items = facts.software.items.slice(0, 150); facts.processes = facts.processes.slice(0, 40); facts.limits.trimmed = "保存サイズの上限で一部を省略"; factsJson = JSON.stringify(facts); }
      await db("host_scans").where({ id: scanId }).update({ status: "done", stage: null, facts: factsJson, profile: profile ? j({ ...profile, note: aiNote }) : j({ note: aiNote }), diff: j(diff), model, tokens_in: tin, tokens_out: tout, finished_at: db.fn.now() });
      await db("hosts").where({ id: host.id }).update({ last_scan_at: db.fn.now(), ...(facts.ssh?.pack_rev ? { pack_rev: facts.ssh.pack_rev, pack_checked_at: db.fn.now() } : {}), ...(facts.host.os_family && !host.os_family ? { os_family: facts.host.os_family } : {}) });
      await this.ctx.audit.log("system", null, "host.scan_done", { scan_id: scanId, host: host.name, ai: !!profile, tokens: tin + tout });
      if (!diff.first && (diff.important || diff.new_ports.length || diff.new_services.length || diff.new_users.length)) {
        await this.ctx.audit.log("system", null, diff.important ? "host.scan_diff_important" : "host.scan_diff", { host: host.name, new_exposed_ports: diff.new_exposed_ports.map((x) => x.port), new_admins: diff.new_admins, new_remote_tools: diff.new_remote_tools, new_users: diff.new_users, new_services: diff.new_services.slice(0, 10) });
      }
      const old = await db("host_scans").where({ host_id: host.id }).whereIn("status", ["done", "failed"]).orderBy("id", "desc").offset(KEEP).select("id");
      if (old.length) await db("host_scans").whereIn("id", old.map((x: any) => x.id)).delete();
    } catch (e: any) {
      await db("host_scans").where({ id: scanId }).update({ status: "failed", error: String(e.message ?? e).slice(0, 1000), finished_at: db.fn.now() });
      await this.ctx.audit.log("system", null, "host.scan_failed", { scan_id: scanId, host: host.name, error: String(e.message ?? e).slice(0, 300) });
    }
  }
}
