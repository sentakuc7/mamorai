import type { Knex } from "knex";
/** EDR-155: what the admin decided about the AI's suggestions for the host settings (per field: applied / dismissed / manual + the purpose it was decided for) */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => { t.text("ai_decisions"); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("hosts", (t) => { t.dropColumn("ai_decisions"); });
}
