import type { Knex } from "knex";
/** Scope of a handled-mark: agent (this host only), program (same rule + same program on any host), rule (same rule on any host). */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("alert_marks", (t) => { t.string("scope", 16).notNullable().defaultTo("agent"); t.string("program", 255); });
}
export async function down(db: Knex): Promise<void> { await db.schema.alterTable("alert_marks", (t) => { t.dropColumn("scope"); t.dropColumn("program"); }); }
