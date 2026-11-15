import type { Knex } from "knex";
/** 残タスク（経過観察 / ベンダー修正待ち等、今すぐ実行するコマンドが無いタスク）を Action ボードで管理するための列。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("next_actions", (t) => { t.string("kind", 16).notNullable().defaultTo("change"); t.string("due", 64).nullable(); });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("next_actions", (t) => { t.dropColumn("kind"); t.dropColumn("due"); });
}
