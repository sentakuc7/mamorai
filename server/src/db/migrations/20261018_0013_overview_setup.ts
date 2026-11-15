import type { Knex } from "knex";
/** 攻撃可視化（EDR-70）: セットアップ・ウィザードの状態と拠点（site）定義。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("overview_setup", (t) => {
    t.integer("wazuh_instance_id").primary();
    t.text("assets");          // JSON: ["web","ssh",...]
    t.text("vendors");         // JSON: {"vpn_fw":"sophos_xg", ...}
    t.text("manager_addr");    // エージェント/機器から見た manager のアドレス
    t.integer("step").notNullable().defaultTo(0);
    t.boolean("completed").notNullable().defaultTo(false);
    t.boolean("skipped").notNullable().defaultTo(false);
    t.boolean("demo").notNullable().defaultTo(false);
    t.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
  });
  await db.schema.createTable("sites", (t) => {
    t.increments("id");
    t.string("name", 120).notNullable();
    t.float("lat").notNullable(); t.float("lon").notNullable();
    t.string("kind", 16).notNullable().defaultTo("home"); // home | cloud | office
    t.boolean("is_default").notNullable().defaultTo(false);
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
  });
  await db.schema.createTable("site_members", (t) => {
    t.integer("site_id").notNullable().references("id").inTable("sites").onDelete("CASCADE");
    t.string("agent_name", 128).notNullable().unique();
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("site_members"); await db.schema.dropTableIfExists("sites"); await db.schema.dropTableIfExists("overview_setup"); }
