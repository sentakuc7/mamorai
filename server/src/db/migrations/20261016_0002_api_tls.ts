import type { Knex } from "knex";
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("wazuh_instances", (t) => { t.boolean("api_tls_verify").notNullable().defaultTo(false); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("wazuh_instances", (t) => { t.dropColumn("api_tls_verify"); });
}
