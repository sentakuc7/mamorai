import type { Knex } from "knex";
/**
 * EDR-121: hosts that only have a Wazuh agent (no SSH), AI host scans ("host card") and host actions
 * (stop a service / block a port / block an IP / isolate) executed through the approval queue.
 */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => {
    t.string("kind", 16).notNullable().defaultTo("managed"); // managed (SSH) | agent_only (Wazuh agent only)
    t.string("os_family", 16);                               // linux | windows | darwin | other
    t.string("agent_status", 24);                            // copied from Wazuh on every sync
    t.timestamp("agent_last_seen", { useTz: true });
    t.string("agent_os", 128);
    t.string("agent_version", 32);
    t.timestamp("last_scan_at", { useTz: true });
    t.string("scan_schedule_override", 8);                   // null = follow the global schedule; 1d | 7d | 30d | off
    t.boolean("action_locked").notNullable().defaultTo(false); // never the target of block/isolate actions
    t.string("isolation_state", 16);                         // null | isolated
    t.string("ar_addon_version", 16);                        // Windows active-response add-on reported by the endpoint
    t.timestamp("ar_addon_checked_at", { useTz: true });
  });
  await db.schema.createTable("host_scans", (t) => {
    t.increments("id").primary();
    t.integer("host_id").notNullable().references("id").inTable("hosts").onDelete("CASCADE");
    t.string("status", 16).notNullable().defaultTo("queued"); // queued | running | done | failed
    t.string("stage", 32);                                    // collect | normalize | ai | save
    t.string("trigger", 16).notNullable().defaultTo("manual"); // manual | schedule | enroll
    t.integer("requested_by");
    t.timestamp("started_at", { useTz: true });
    t.timestamp("finished_at", { useTz: true });
    t.text("facts");   // JSON (normalized facts, ≤256KB)
    t.text("profile"); // JSON (AI interpretation, evidence-checked)
    t.text("diff");    // JSON (changes since the previous done scan)
    t.string("model", 96);
    t.integer("tokens_in");
    t.integer("tokens_out");
    t.text("error");
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.index(["host_id", "id"]);
  });
  await db.schema.createTable("host_actions", (t) => {
    t.increments("id").primary();
    t.integer("host_id").notNullable().references("id").inTable("hosts").onDelete("CASCADE");
    t.string("op", 24).notNullable();      // stop_service | block_port | block_ip | isolate (revert = reverse op)
    t.text("params");                       // JSON
    t.string("status", 16).notNullable().defaultTo("pending"); // pending | active | reverted | failed | rejected
    t.integer("approval_id");
    t.integer("revert_approval_id");
    t.integer("requested_by");
    t.string("via", 16);                    // ssh | wazuh_ar
    t.text("result");                       // JSON
    t.timestamp("applied_at", { useTz: true });
    t.timestamp("reverted_at", { useTz: true });
    t.timestamp("last_reminded_at", { useTz: true });
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.index(["host_id", "status"]);
  });
  await db.schema.alterTable("approvals", (t) => { t.text("host_action"); }); // JSON: { action_id, revert? }
  // the Wazuh manager agent (000) is never a target
  await db("hosts").where({ agent_id: "000" }).update({ action_locked: true });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("approvals", (t) => { t.dropColumn("host_action"); });
  await db.schema.dropTableIfExists("host_actions");
  await db.schema.dropTableIfExists("host_scans");
  await db.schema.alterTable("hosts", (t) => {
    for (const c of ["kind", "os_family", "agent_status", "agent_last_seen", "agent_os", "agent_version", "last_scan_at", "scan_schedule_override", "action_locked", "isolation_state", "ar_addon_version", "ar_addon_checked_at"]) t.dropColumn(c);
  });
}
