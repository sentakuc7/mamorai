import type { Knex } from "knex";
/** UI から直接積むクラウド操作（EDR-76）はセッション / tool_call を持たないため、approvals の両列を nullable にする。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("approvals", (t) => {
    t.integer("tool_call_id").nullable().alter();
    t.integer("session_id").nullable().alter();
  });
}
export async function down(_db: Knex): Promise<void> { /* 戻さない */ }
