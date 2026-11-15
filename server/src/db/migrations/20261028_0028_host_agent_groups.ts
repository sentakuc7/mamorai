import type { Knex } from "knex";
/** EDR-154: Wazuh agent groups copied by the agent sync (laptop / desktop / linux-cloud … → server or client PC) */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => { t.text("agent_groups"); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => { t.dropColumn("agent_groups"); });
}
