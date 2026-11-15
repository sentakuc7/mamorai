import type { Knex } from "knex";
/** Plain-language (Japanese) triage notes per Wazuh rule id: builtin dictionary, AI-generated, or user-edited. */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("rule_notes", (t) => {
    t.string("rule_id", 16).primary();
    t.string("tenant_id", 64).notNullable().defaultTo("default");
    t.string("title_ja", 120).notNullable();
    t.text("meaning").notNullable();      // 何が起きたか
    t.text("cause").notNullable();        // 考えられる原因（正常なケース含む）
    t.text("impact").notNullable();       // 放置した場合の影響
    t.text("action").notNullable();       // 推奨対応
    t.string("triage", 16).notNullable(); // benign_likely | check | danger
    t.string("source", 16).notNullable(); // builtin | ai | user
    t.string("description_en", 255);
    t.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("rule_notes"); }
