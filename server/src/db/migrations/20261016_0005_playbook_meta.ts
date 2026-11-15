import type { Knex } from "knex";

/** Structured playbooks (meta JSON; markdown is generated from it) and last SSH test result per host. */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("playbooks", (t) => { t.text("meta"); });
  await db.schema.alterTable("hosts", (t) => { t.text("last_test"); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("playbooks", (t) => { t.dropColumn("meta"); });
  await db.schema.alterTable("hosts", (t) => { t.dropColumn("last_test"); });
}
