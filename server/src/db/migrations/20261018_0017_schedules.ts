import type { Knex } from "knex";
/** スケジュール実行: AI チャットから登録した定期タスク。実行結果は登録元セッションのチャットに出力する。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("schedules", (t) => {
    t.increments("id");
    t.integer("session_id").notNullable();           // 登録元（実行先）セッション
    t.string("title", 255).notNullable();
    t.text("prompt").notNullable();                  // 毎回 AI に渡す指示
    t.integer("interval_min").notNullable();         // 実行間隔（分）
    t.string("at_time", 5).nullable();               // "HH:MM"（JST）。1 日以上の間隔のとき、この時刻に揃える
    t.integer("max_runs").nullable();
    t.integer("run_count").notNullable().defaultTo(0);
    t.boolean("enabled").notNullable().defaultTo(true);
    t.string("state", 16).notNullable().defaultTo("active"); // active | done | cancelled
    t.timestamp("next_run_at").nullable();
    t.timestamp("last_run_at").nullable();
    t.text("last_result").nullable();
    t.string("last_status", 16).nullable();          // ok | error | skipped
    t.string("created_by", 16).notNullable().defaultTo("agent"); // agent | user
    t.text("goal").nullable();                       // 達成条件（任意）
    t.timestamp("created_at").defaultTo(db.fn.now());
    t.timestamp("updated_at").defaultTo(db.fn.now());
  });
  await db.schema.createTable("schedule_runs", (t) => {
    t.increments("id");
    t.integer("schedule_id").notNullable().index();
    t.integer("session_id").notNullable();
    t.timestamp("started_at").defaultTo(db.fn.now());
    t.timestamp("finished_at").nullable();
    t.string("status", 16).notNullable().defaultTo("running"); // running | ok | error | skipped | timeout
    t.text("result").nullable();
    t.integer("message_id").nullable();
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("schedule_runs"); await db.schema.dropTableIfExists("schedules"); }
