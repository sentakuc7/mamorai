import type { Knex } from "knex";
/** EDR-168: approve now, run later (e.g. tonight at 22:00) */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("approvals", (t) => { t.timestamp("run_after"); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("approvals", (t) => { t.dropColumn("run_after"); });
}
