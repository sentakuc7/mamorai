import type { Knex } from "knex";
/** EDR-115: what the human decided in a ticket ("ソースからビルドしない" …). Checked before every change plan. */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("session_decisions", (t) => {
    t.increments("id").primary();
    t.integer("session_id").notNullable().references("id").inTable("sessions").onDelete("CASCADE");
    t.text("text").notNullable();
    t.string("forbid", 32); // source_build | external_repo | os_upgrade | package_removal | reboot | service_restart | null
    t.integer("message_id");
    t.boolean("active").notNullable().defaultTo(true);
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.index(["session_id"]);
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("session_decisions"); }
