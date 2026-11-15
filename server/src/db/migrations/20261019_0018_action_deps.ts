import type { Knex } from "knex";
/** タスク間の依存: after_id のタスクが完了するまで status=blocked（依存待ち）。完了したら proposed に戻し、元セッションの AI に続きを促す。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("next_actions", (t) => { t.integer("after_id").nullable(); t.string("relation", 16).nullable(); /* revert | followup | next */ });
}
export async function down(db: Knex): Promise<void> { await db.schema.alterTable("next_actions", (t) => { t.dropColumn("after_id"); t.dropColumn("relation"); }); }
