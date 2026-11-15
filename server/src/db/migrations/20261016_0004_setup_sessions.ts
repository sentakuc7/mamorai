import type { Knex } from "knex";

/** C8: AI-guided setup sessions (playbook / host onboarding), session attachments, API tokens for service accounts. */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("sessions", (t) => { t.string("kind", 24).notNullable().defaultTo("investigate"); }); // investigate|playbook_setup|host_setup
  await db.schema.createTable("attachments", (t) => {
    t.increments("id").primary();
    t.string("tenant_id", 64).notNullable().defaultTo("default");
    t.integer("session_id").notNullable().references("id").inTable("sessions").onDelete("CASCADE");
    t.string("name", 255).notNullable();
    t.integer("size").notNullable();
    t.string("mime", 128);
    t.text("content").notNullable(); // text (utf-8); binary files are rejected on upload
    t.integer("uploaded_by").references("id").inTable("users").onDelete("SET NULL");
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.index(["session_id"]);
  });
  await db.schema.createTable("api_tokens", (t) => {
    t.increments("id").primary();
    t.string("tenant_id", 64).notNullable().defaultTo("default");
    t.integer("user_id").notNullable().references("id").inTable("users").onDelete("CASCADE");
    t.string("name", 128).notNullable();
    t.string("token_hash", 128).notNullable().unique();
    t.string("prefix", 12).notNullable(); // first chars, for display
    t.timestamp("expires_at", { useTz: true });
    t.timestamp("last_used_at", { useTz: true });
    t.integer("created_by").references("id").inTable("users").onDelete("SET NULL");
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
  });
}
export async function down(db: Knex): Promise<void> {
  await db.schema.dropTableIfExists("api_tokens");
  await db.schema.dropTableIfExists("attachments");
  await db.schema.alterTable("sessions", (t) => { t.dropColumn("kind"); });
}
