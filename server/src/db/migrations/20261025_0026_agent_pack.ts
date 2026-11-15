import type { Knex } from "knex";
/**
 * EDR-130: agent packs (Windows / Linux) downloaded from the host screen.
 * A new revision is recorded whenever what goes into a pack changes (settings, installer, add-on, Wazuh version).
 */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("agent_pack_revs", (t) => {
    t.increments("id").primary();          // = the revision number shown as rN (shared by both OS, always increasing)
    t.string("os", 16).notNullable();      // windows | linux
    t.string("hash", 64).notNullable();    // sha256 over the pack contents without secrets / build stamps
    t.text("components").notNullable();    // JSON: what went in (file hashes, settings, versions) — for the change list
    t.text("changes");                     // JSON string[]: what changed from the previous revision of the same OS
    t.string("reason", 64);                // settings | startup | addon | wazuh | installer
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.index(["os", "id"]);
  });
  await db.schema.alterTable("hosts", (t) => {
    t.integer("pack_rev");                               // agent pack revision installed on the host (reported by the add-on or read over SSH)
    t.timestamp("pack_checked_at", { useTz: true });
  });
}

export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => { t.dropColumn("pack_rev"); t.dropColumn("pack_checked_at"); });
  await db.schema.dropTableIfExists("agent_pack_revs");
}
