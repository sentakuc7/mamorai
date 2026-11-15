import type { Knex } from "knex";
/** ダッシュボードのノード分類（サーバー / クライアント）の手動上書き。既定は OS から判定。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("node_roles", (t) => { t.string("agent_name", 128).primary(); t.string("role", 16).notNullable(); t.timestamp("updated_at").defaultTo(db.fn.now()); });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("node_roles"); }
