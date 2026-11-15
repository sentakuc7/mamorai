import type { Knex } from "knex";
/** Keep a snapshot of the alert that was marked handled, so the history view can show it after it leaves the indexer window. */
export async function up(db: Knex): Promise<void> { await db.schema.alterTable("alert_marks", (t) => { t.text("alert_json"); }); }
export async function down(db: Knex): Promise<void> { await db.schema.alterTable("alert_marks", (t) => { t.dropColumn("alert_json"); }); }
