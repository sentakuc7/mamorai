import type { Knex } from "knex";
/** Session files produced by the agent (CSV, Markdown reports, SVG diagrams, HTML): attachments gain a direction. */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("attachments", (t) => { t.string("direction", 4).notNullable().defaultTo("in"); t.string("description", 500); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("attachments", (t) => { t.dropColumn("direction"); t.dropColumn("description"); });
}
