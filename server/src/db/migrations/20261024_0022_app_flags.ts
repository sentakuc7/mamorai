import type { Knex } from "knex";
/** EDR-90: global safety switches (e.g. "auto approval hold" = kill switch for automatic approvals). */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("app_flags", (t) => {
    t.string("key", 64).primary();
    t.text("value");
    t.integer("updated_by");
    t.datetime("updated_at").notNullable().defaultTo(db.fn.now());
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("app_flags"); }
