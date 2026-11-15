import type { Knex } from "knex";
/** EDR-90: TOTP MFA, recovery codes, login throttling, API token IP restriction. */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("users", (t) => {
    t.text("totp_secret_enc");
    t.text("totp_pending_enc");
    t.boolean("totp_enabled").notNullable().defaultTo(false);
    t.bigInteger("totp_last_step");
    t.integer("totp_failed").notNullable().defaultTo(0);
    t.bigInteger("totp_locked_until_ms");
    t.datetime("mfa_enrolled_at");
  });
  await db.schema.createTable("user_recovery_codes", (t) => {
    t.increments("id");
    t.integer("user_id").notNullable().references("id").inTable("users").onDelete("CASCADE");
    t.string("code_hash", 64).notNullable();
    t.datetime("used_at");
    t.datetime("created_at").notNullable().defaultTo(db.fn.now());
    t.index(["user_id"]);
  });
  await db.schema.createTable("login_throttle", (t) => {
    t.string("key", 255).primary();
    t.integer("fails").notNullable().defaultTo(0);
    t.bigInteger("window_start_ms").notNullable();
    t.bigInteger("locked_until_ms");
  });
  await db.schema.alterTable("auth_sessions", (t) => { t.string("mfa_state", 16); });
  await db.schema.alterTable("api_tokens", (t) => { t.text("allowed_ips"); });
  // every existing browser session must sign in again (and enroll TOTP)
  await db("auth_sessions").delete();
}
export async function down(db: Knex): Promise<void> {
  await db.schema.alterTable("api_tokens", (t) => { t.dropColumn("allowed_ips"); });
  await db.schema.alterTable("auth_sessions", (t) => { t.dropColumn("mfa_state"); });
  await db.schema.dropTableIfExists("login_throttle");
  await db.schema.dropTableIfExists("user_recovery_codes");
  await db.schema.alterTable("users", (t) => { for (const c of ["totp_secret_enc", "totp_pending_enc", "totp_enabled", "totp_last_step", "totp_failed", "totp_locked_until_ms", "mfa_enrolled_at"]) t.dropColumn(c); });
}
