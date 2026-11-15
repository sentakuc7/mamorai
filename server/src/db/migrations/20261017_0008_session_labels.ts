import type { Knex } from "knex";
/** AI-generated session labels/tags, archive flag. */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("sessions", (t) => { t.string("label", 120); t.text("tags"); t.timestamp("archived_at", { useTz: true }); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("sessions", (t) => { t.dropColumn("label"); t.dropColumn("tags"); t.dropColumn("archived_at"); });
}
