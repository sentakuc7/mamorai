import type { Knex } from "knex";
/** EDR-168: last Windows Update / winget scan reported by the add-on (JSON) */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => { t.text("win_updates"); t.timestamp("win_updates_at"); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => { t.dropColumn("win_updates"); t.dropColumn("win_updates_at"); });
}
