import type { Knex } from "knex";
/** EDR-142: AI explanations about a host that are cached per scan (first use: impact of Contain / isolation). */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("host_ai_notes", (t) => {
    t.increments("id").primary();
    t.integer("host_id").notNullable().references("id").inTable("hosts").onDelete("CASCADE");
    t.string("kind", 32).notNullable();   // contain_impact
    t.integer("scan_id");                 // the scan the explanation was made from
    t.text("content").notNullable();      // JSON
    t.string("model", 96);
    t.integer("tokens");
    t.integer("requested_by");
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.index(["host_id", "kind", "id"]);
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("host_ai_notes"); }
