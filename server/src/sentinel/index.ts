/**
 * Sentinel: alert-driven trigger engine.
 * Polls the indexer for new alerts matching enabled triggers, de-duplicates, rate-limits,
 * and starts an investigation session (origin = alert) for each new incident.
 */
import { fetch as ufetch } from "undici";
import type { Ctx } from "../api/context.js";
import { indexer } from "../api/context.js";
import { j, pj } from "../db/index.js";
import { alertTitle } from "../runtime/title.js";

export interface TriggerConfig {
  min_level?: number;              // kind=level
  rule_ids?: string[];             // kind=rule
  rule_groups?: string[];          // kind=rule (any of)
  exclude_rule_ids?: string[];
  agents?: string[];               // restrict to agent names (empty = all)
  dedupe_fields?: string[];        // default: agent.name, rule.id, data.srcip
  prompt?: string;                 // extra instruction for the agent
}

const DEFAULT_TRIGGERS = [
  { name: "High / Critical alerts", kind: "level", config: { min_level: 12, exclude_rule_ids: [] }, enabled: false, dedupe_window_sec: 1800, priority: 3 },
  { name: "fail2ban ban (custom 1003xx)", kind: "rule", config: { rule_groups: ["fail2ban"], min_level: 5 }, enabled: false, dedupe_window_sec: 3600, priority: 5 },
  { name: "LOLBin / intrusion indicators (1001xx, 1005xx)", kind: "rule", config: { rule_ids: ["100100", "100101", "100102", "100103", "100104", "100105"], rule_groups: ["edr48_intrusion"] }, enabled: false, dedupe_window_sec: 600, priority: 1 },
  { name: "Cross-host attacker (EDR-53)", kind: "rule", config: { rule_ids: ["100460"] }, enabled: false, dedupe_window_sec: 3600, priority: 2 },
];

export class Sentinel {
  private timer: NodeJS.Timeout | null = null;
  private busy = false;
  private startedThisHour: { hour: number; n: number } = { hour: -1, n: 0 };
  lastRun: { at: string; checked: number; started: number; error?: string } | null = null;

  constructor(private ctx: Ctx) {}

  async seedDefaults(): Promise<void> {
    const n = await this.ctx.db("triggers").count<{ c: number }[]>({ c: "*" }).first();
    if (Number(n?.c ?? 0) > 0) return;
    for (const t of DEFAULT_TRIGGERS) await this.ctx.db("triggers").insert({ ...t, config: j(t.config) });
    this.ctx.log.info("default triggers seeded (disabled)");
  }

  start(): void {
    const sec = Math.max(10, this.ctx.cfg.SENTINEL_POLL_SEC);
    this.timer = setInterval(() => this.tick().catch((e) => this.ctx.log.error({ err: e }, "sentinel tick failed")), sec * 1000);
    this.ctx.log.info({ everySec: sec, enabled: this.ctx.cfg.SENTINEL_ENABLED }, "sentinel scheduler started");
  }
  stop(): void { if (this.timer) clearInterval(this.timer); }

  get status() { return { enabled: this.ctx.cfg.SENTINEL_ENABLED, pollSec: this.ctx.cfg.SENTINEL_POLL_SEC, lastRun: this.lastRun, sessionsThisHour: this.startedThisHour.n }; }

  async tick(force = false): Promise<void> {
    if (this.busy) return; if (!force && !this.ctx.cfg.SENTINEL_ENABLED) return;
    this.busy = true;
    const { db, cfg } = this.ctx;
    let checked = 0, started = 0;
    try {
      const triggers = (await db("triggers").where({ enabled: true }).orderBy("priority")).map((t: any) => ({ ...t, config: pj<TriggerConfig>(t.config) ?? {} }));
      if (!triggers.length) { this.lastRun = { at: new Date().toISOString(), checked, started }; return; }
      const instances = await db("wazuh_instances").orderBy("id");
      for (const wz of instances) {
        const ix = await indexer(this.ctx, wz.id);
        for (const trg of triggers) {
          const filter: any[] = [{ range: { timestamp: { gte: `now-${Math.max(cfg.SENTINEL_POLL_SEC * 4, 120)}s` } } }];
          const c = trg.config;
          if (trg.kind === "level") filter.push({ range: { "rule.level": { gte: c.min_level ?? cfg.SENTINEL_MIN_LEVEL } } });
          if (trg.kind === "rule") {
            const should: any[] = [];
            if (c.rule_ids?.length) should.push({ terms: { "rule.id": c.rule_ids } });
            if (c.rule_groups?.length) should.push({ terms: { "rule.groups": c.rule_groups } });
            if (!should.length) continue;
            filter.push({ bool: { should, minimum_should_match: 1 } });
            if (c.min_level) filter.push({ range: { "rule.level": { gte: c.min_level } } });
          }
          if (c.agents?.length) filter.push({ terms: { "agent.name": c.agents } });
          const mustNot: any[] = c.exclude_rule_ids?.length ? [{ terms: { "rule.id": c.exclude_rule_ids } }] : [];
          const r = await ix.search("wazuh-alerts-*", { query: { bool: { filter, must_not: mustNot } }, sort: [{ timestamp: { order: "asc" } }], _source: ["timestamp", "rule.id", "rule.level", "rule.description", "rule.groups", "rule.mitre", "agent.id", "agent.name", "agent.ip", "data.srcip", "data.srcuser", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.parentImage", "data.win.eventdata.processGuid", "data.win.eventdata.user", "data.win.system.eventID", "data.vulnerability", "full_log"] }, 100);
          for (const h of r.hits?.hits ?? []) {
            checked++;
            const a = { _id: h._id, ...h._source };
            // already seen?
            const seen = await db("seen_alerts").where({ wazuh_instance_id: wz.id, alert_id: a._id }).first();
            if (seen) continue;
            await db("seen_alerts").insert({ wazuh_instance_id: wz.id, alert_id: a._id, rule_id: String(a.rule?.id ?? ""), agent_id: String(a.agent?.id ?? ""), ts: new Date(a.timestamp) });
            // dedupe: same (agent, rule, srcip) within window → attach to existing session instead of starting a new one
            const key = (c.dedupe_fields ?? ["agent.name", "rule.id", "data.srcip"]).map((f: string) => f.split(".").reduce((o: any, k: string) => o?.[k], a) ?? "").join("|");
            const since = new Date(Date.now() - (trg.dedupe_window_sec ?? 600) * 1000);
            const dup = await db("sessions").where({ origin: "alert" }).where("created_at", ">=", since).whereRaw("alert_ref like ?", [`%${JSON.stringify(key).slice(1, -1)}%`]).first();
            if (dup) { await db("seen_alerts").where({ wazuh_instance_id: wz.id, alert_id: a._id }).update({ session_id: dup.id }); continue; }
            // rate limit
            const hour = Math.floor(Date.now() / 3600e3);
            if (this.startedThisHour.hour !== hour) this.startedThisHour = { hour, n: 0 };
            if (this.startedThisHour.n >= cfg.LLM_MAX_SESSIONS_PER_HOUR) { await this.ctx.audit.log("system", null, "sentinel.rate_limited", { trigger: trg.name, alert_id: a._id }); continue; }
            this.startedThisHour.n++;
            const title = await alertTitle(db, a);
            const sid = await this.ctx.runtime!.createSession({
              origin: "alert", title, userId: null, wazuhInstanceId: wz.id, hostIds: [],
              alertRef: { dedupe_key: key, trigger_id: trg.id, trigger: trg.name, alert_id: a._id, rule_id: a.rule?.id, level: a.rule?.level, agent: a.agent?.name, srcip: a.data?.srcip },
              firstMessage: `Sentinel trigger "${trg.name}" fired. Investigate this alert, decide whether it is benign / false positive / suspicious / malicious / misconfiguration, and propose next actions. ${c.prompt ?? ""}\n\nAlert (JSON):\n${JSON.stringify(a).slice(0, 8000)}`,
            });
            await db("seen_alerts").where({ wazuh_instance_id: wz.id, alert_id: a._id }).update({ session_id: sid });
            await this.ctx.audit.log("system", null, "sentinel.session_started", { trigger: trg.name, alert_id: a._id, rule_id: a.rule?.id, agent: a.agent?.name }, sid);
            started++;
            if (cfg.DISCORD_WEBHOOK_URL) ufetch(cfg.DISCORD_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: `🛡️ Sentinel #${sid}: ${title}\n${cfg.APP_BASE_URL}/sidekick/${sid}` }) }).catch(() => {});
          }
        }
      }
      this.lastRun = { at: new Date().toISOString(), checked, started };
    } catch (e: any) {
      this.lastRun = { at: new Date().toISOString(), checked, started, error: e.message };
      throw e;
    } finally { this.busy = false; }
  }
}
