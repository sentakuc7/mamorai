import type { Knex } from "knex";
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("approvals", (t) => { t.text("steps"); t.string("title", 255); t.integer("next_action_id"); });
  await db.schema.alterTable("next_actions", (t) => { t.text("plain"); t.text("impact"); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("approvals", (t) => { t.dropColumn("steps"); t.dropColumn("title"); t.dropColumn("next_action_id"); });
  await db.schema.alterTable("next_actions", (t) => { t.dropColumn("plain"); t.dropColumn("impact"); });
}
