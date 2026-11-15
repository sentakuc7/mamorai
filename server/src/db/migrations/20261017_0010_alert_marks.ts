import type { Knex } from "knex";
/** Manual "handled" marks on alerts (by rule+agent, optionally a single alert id) so the alert list can hide what was already dealt with. */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("alert_marks", (t) => {
    t.increments("id");
    t.string("tenant_id", 64).notNullable().defaultTo("default");
    t.string("rule_id", 16).notNullable();
    t.string("agent_id", 16).notNullable();
    t.string("alert_id", 128);            // null = every alert of this rule+agent up to `until`
    t.timestamp("until", { useTz: true }).notNullable(); // alerts at or before this time count as handled
    t.string("note", 500);
    t.integer("session_id");
    t.integer("user_id");
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.index(["rule_id", "agent_id"]);
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("alert_marks"); }
