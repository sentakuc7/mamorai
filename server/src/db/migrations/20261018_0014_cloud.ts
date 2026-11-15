import type { Knex } from "knex";
/** クラウド管理（EDR-76）: IaaS プロバイダ接続とインスタンス台帳、承認キュー経由のクラウド操作。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.createTable("cloud_providers", (t) => {
    t.increments("id");
    t.string("tenant_id", 64).notNullable().defaultTo("default");
    t.string("kind", 16).notNullable();            // aws | gce | hyperv | esxi | azure | proxmox
    t.string("name", 120).notNullable();
    t.text("config");                              // JSON（秘密でない設定: region / project / zones など）
    t.text("secret_enc");                          // 暗号化 JSON（アクセスキー / サービスアカウント）
    t.string("capability", 16).notNullable().defaultTo("ops"); // inventory | ops | isolate
    t.string("status", 16).notNullable().defaultTo("new");     // new | ok | error
    t.text("last_error");
    t.timestamp("last_sync_at", { useTz: true });
    t.integer("created_by");
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
  });
  await db.schema.createTable("cloud_instances", (t) => {
    t.increments("id");
    t.integer("provider_id").notNullable().references("id").inTable("cloud_providers").onDelete("CASCADE");
    t.string("service", 24).notNullable();         // ec2 | lightsail | gce
    t.string("external_id", 255).notNullable();    // i-xxx / lightsail name / gce name
    t.string("name", 255).notNullable();
    t.string("state", 32);
    t.string("public_ip", 64); t.string("private_ip", 64);
    t.string("region", 64); t.string("zone", 64);
    t.string("machine_type", 64); t.string("os", 128);
    t.text("tags");                                // JSON
    t.integer("host_id").references("id").inTable("hosts").onDelete("SET NULL");
    t.string("agent_name", 128);
    t.text("raw");                                 // JSON（抜粋）
    t.timestamp("seen_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.unique(["provider_id", "service", "external_id"]);
  });
  await db.schema.alterTable("approvals", (t) => { t.text("cloud_action"); }); // JSON: { provider_id, instance_id, op, params }
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("approvals", (t) => { t.dropColumn("cloud_action"); });
  await db.schema.dropTableIfExists("cloud_instances"); await db.schema.dropTableIfExists("cloud_providers");
}
