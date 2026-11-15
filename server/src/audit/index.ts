import type { DB } from "../db/index.js";
import { j } from "../db/index.js";
import { redactSecrets } from "../crypto/index.js";

export type Actor = "user" | "agent" | "system";

export class Audit {
  constructor(private db: DB) {}
  async log(actor: Actor, actorId: string | number | null, event: string, payload?: unknown, sessionId?: number | null): Promise<void> {
    const safe = payload === undefined ? null : JSON.parse(redactSecrets(JSON.stringify(payload)));
    await this.db("audit_log").insert({
      actor,
      actor_id: actorId == null ? null : String(actorId),
      event,
      session_id: sessionId ?? null,
      payload: j(safe),
    });
    // EDR-89: also emit every audit event as one JSON line on stdout → Docker journald → Wazuh (decoder "mamorai").
    // Lets Wazuh watch MamorAI itself (failed logins, new tokens/keys/hosts, approvals, changes) independently of this app's DB.
    try {
      let pl: unknown = safe;
      const txt = JSON.stringify(safe ?? null);
      if (txt.length > 4000) pl = { truncated: true, preview: txt.slice(0, 2000) };
      process.stdout.write(JSON.stringify({ level: 30, time: Date.now(), msg: "audit", mamorai_audit: { actor, actor_id: actorId == null ? null : String(actorId), event, session_id: sessionId ?? null, payload: pl } }) + "\n");
    } catch { /* never break the request because of logging */ }
  }

  /**
   * EDR-119: the CLI (`docker compose exec ... cli.js`) runs as a separate process whose stdout is not the container log,
   * so its audit events never reached journald/Wazuh. The server relays CLI-written audit rows to its own stdout.
   * Progress is kept in app_flags (audit_relay_cli_last) so events written while the server was down are relayed on start.
   */
  startCliRelay(intervalMs = 5000): () => void {
    let busy = false;
    const tick = async () => {
      if (busy) return; busy = true;
      try {
        const f = await this.db("app_flags").where({ key: "audit_relay_cli_last" }).first();
        let last = f ? Number(f.value) : NaN;
        if (!Number.isFinite(last)) last = Number((await this.db("audit_log").max<{ m: number }[]>({ m: "id" }).first())?.m ?? 0);
        const rows = await this.db("audit_log").where("id", ">", last).andWhere({ actor_id: "cli" }).orderBy("id").limit(200);
        for (const r of rows) {
          let pl: unknown = null; try { pl = typeof r.payload === "string" ? JSON.parse(r.payload) : r.payload; } catch { pl = r.payload; }
          const txt = JSON.stringify(pl ?? null);
          if (txt.length > 4000) pl = { truncated: true, preview: txt.slice(0, 2000) };
          process.stdout.write(JSON.stringify({ level: 30, time: Date.now(), msg: "audit", mamorai_audit: { actor: r.actor, actor_id: r.actor_id, event: r.event, session_id: r.session_id ?? null, payload: pl, relayed: true } }) + "\n");
        }
        const newLast = rows.length ? Number(rows[rows.length - 1].id) : Math.max(last, Number((await this.db("audit_log").max<{ m: number }[]>({ m: "id" }).first())?.m ?? 0));
        if (!f) await this.db("app_flags").insert({ key: "audit_relay_cli_last", value: String(newLast) });
        else if (String(newLast) !== f.value) await this.db("app_flags").where({ key: "audit_relay_cli_last" }).update({ value: String(newLast), updated_at: this.db.fn.now() });
      } catch { /* best effort */ } finally { busy = false; }
    };
    const h = setInterval(tick, intervalMs); h.unref?.(); void tick();
    return () => clearInterval(h);
  }
}
