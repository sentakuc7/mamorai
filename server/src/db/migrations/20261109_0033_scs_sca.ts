import type { Knex } from "knex";
/**
 * EDR-178（SCS P1-6）: Wazuh SCA の結果のスナップショット。
 * 端末×ポリシー×スキャン終了時刻で 1 行（同じスキャンは重ねて保存しない）。3-1-1-6（設定情報の把握）の履歴にもなる。
 */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("scs_sca_results", (t) => {
    t.increments("id").primary();
    t.integer("asset_id").notNullable().references("id").inTable("scs_assets").onDelete("CASCADE");
    t.string("policy_id", 64).notNullable();          // cis_win11_enterprise など
    t.string("policy_name", 255);
    t.timestamp("scan_end", { useTz: true }).notNullable(); // Wazuh 側のスキャン終了時刻
    t.integer("pass").notNullable().defaultTo(0);
    t.integer("fail").notNullable().defaultTo(0);
    t.integer("invalid").notNullable().defaultTo(0);
    t.integer("score");
    t.text("checks_json").notNullable();              // SCS に関係するチェックだけ [{key,id,title,result}]
    t.timestamp("fetched_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.unique(["asset_id", "policy_id", "scan_end"]);
    t.index(["asset_id", "fetched_at"]);
  });
}
export async function down(db: Knex): Promise<void> { await db.schema.dropTableIfExists("scs_sca_results"); }
