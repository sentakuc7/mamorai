import type { Knex } from "knex";

/**
 * Initial schema (design doc §6). Every table carries tenant_id (default 1).
 */
export async function up(db: Knex): Promise<void> {
  const base = (t: Knex.CreateTableBuilder) => {
    t.increments("id").primary();
    t.integer("tenant_id").notNullable().defaultTo(1);
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
  };

  await db.schema.createTable("users", (t) => {
    base(t);
    t.string("email", 255).notNullable();
    t.string("name", 255).notNullable();
    t.string("password_hash", 512).notNullable();
    t.string("role", 16).notNullable().defaultTo("viewer"); // admin|operator|viewer
    t.string("locale", 8).notNullable().defaultTo("ja");
    t.boolean("disabled").notNullable().defaultTo(false);
    t.boolean("must_change_password").notNullable().defaultTo(false);
    t.unique(["tenant_id", "email"]);
  });

  await db.schema.createTable("auth_sessions", (t) => {
    t.string("id", 128).primary();
    t.integer("user_id").notNullable().references("id").inTable("users").onDelete("CASCADE");
    t.timestamp("expires_at", { useTz: true }).notNullable();
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.string("ip", 64);
    t.string("user_agent", 512);
  });

  await db.schema.createTable("wazuh_instances", (t) => {
    base(t);
    t.string("name", 128).notNullable();
    t.string("indexer_url", 512).notNullable();
    t.string("indexer_user", 128).notNullable();
    t.text("indexer_secret_enc").notNullable();
    t.string("api_url", 512);
    t.string("api_user", 128);
    t.text("api_secret_enc");
    t.text("ca_pem");
    t.boolean("tls_verify").notNullable().defaultTo(true);
    t.boolean("archives_enabled").notNullable().defaultTo(false);
    t.text("notes");
    t.unique(["tenant_id", "name"]);
  });

  await db.schema.createTable("ssh_keys", (t) => {
    base(t);
    t.string("name", 128).notNullable();
    t.text("public_key").notNullable();
    t.text("private_key_enc").notNullable();
    t.string("fingerprint", 128).notNullable();
    t.unique(["tenant_id", "name"]);
  });

  await db.schema.createTable("hosts", (t) => {
    base(t);
    t.string("name", 128).notNullable();
    t.integer("wazuh_instance_id").references("id").inTable("wazuh_instances").onDelete("SET NULL");
    t.string("agent_id", 8);
    t.string("address", 255).notNullable();
    t.integer("port").notNullable().defaultTo(22);
    t.string("ssh_user", 64).notNullable();
    t.integer("ssh_key_id").references("id").inTable("ssh_keys").onDelete("SET NULL");
    t.string("sudo_mode", 16).notNullable().defaultTo("none"); // none|nopasswd
    t.string("environment", 16).notNullable().defaultTo("lab"); // lab|staging|production
    t.integer("autonomy_level").notNullable().defaultTo(1);
    t.integer("autonomy_max").notNullable().defaultTo(2);
    t.string("maintenance_window", 64);
    t.text("tags"); // JSON array
    t.text("notes");
    t.text("host_key"); // known_hosts line, learned on first connect (TOFU)
    t.unique(["tenant_id", "name"]);
  });

  await db.schema.createTable("playbooks", (t) => {
    base(t);
    t.string("name", 128).notNullable();
    t.string("scope", 16).notNullable().defaultTo("global"); // global|wazuh|hostgroup|host
    t.string("scope_ref", 128);
    t.text("markdown").notNullable();
    t.integer("version").notNullable().defaultTo(1);
    t.boolean("builtin").notNullable().defaultTo(false);
    t.boolean("enabled").notNullable().defaultTo(true);
  });

  await db.schema.createTable("protected_ranges", (t) => {
    base(t);
    t.string("cidr", 64).notNullable();
    t.string("label", 128).notNullable();
    t.text("reason");
    t.integer("host_id").references("id").inTable("hosts").onDelete("CASCADE");
  });

  await db.schema.createTable("triggers", (t) => {
    base(t);
    t.string("name", 128).notNullable();
    t.string("kind", 32).notNullable(); // level|rule|fail2ban|web_spike|cross_host|custom_query
    t.text("config").notNullable(); // JSON
    t.boolean("enabled").notNullable().defaultTo(false);
    t.integer("dedupe_window_sec").notNullable().defaultTo(600);
    t.integer("priority").notNullable().defaultTo(5);
  });

  await db.schema.createTable("integrations", (t) => {
    base(t);
    t.string("kind", 32).notNullable(); // jira|discord|webhook
    t.text("config").notNullable(); // JSON
    t.text("secret_enc");
    t.boolean("enabled").notNullable().defaultTo(true);
  });

  await db.schema.createTable("sessions", (t) => {
    base(t);
    t.string("origin", 16).notNullable(); // alert|user|schedule
    t.integer("trigger_id").references("id").inTable("triggers").onDelete("SET NULL");
    t.text("alert_ref"); // JSON
    t.string("title", 255).notNullable();
    t.string("status", 24).notNullable().defaultTo("running");
    t.string("llm_model", 128);
    t.integer("token_in").notNullable().defaultTo(0);
    t.integer("token_out").notNullable().defaultTo(0);
    t.decimal("cost_estimate", 12, 6).notNullable().defaultTo(0);
    t.integer("started_by").references("id").inTable("users").onDelete("SET NULL");
    t.timestamp("finished_at", { useTz: true });
    t.text("summary"); // JSON
  });

  await db.schema.createTable("messages", (t) => {
    base(t);
    t.integer("session_id").notNullable().references("id").inTable("sessions").onDelete("CASCADE");
    t.integer("seq").notNullable();
    t.string("role", 16).notNullable(); // system|user|assistant|tool
    t.text("content").notNullable(); // JSON
    t.string("tool_call_id", 128);
    t.index(["session_id", "seq"]);
  });

  await db.schema.createTable("tool_calls", (t) => {
    base(t);
    t.integer("session_id").notNullable().references("id").inTable("sessions").onDelete("CASCADE");
    t.integer("message_id").references("id").inTable("messages").onDelete("SET NULL");
    t.string("tool", 64).notNullable();
    t.text("args").notNullable(); // JSON
    t.string("classification", 16); // read|write|unknown
    t.text("classification_reason");
    t.string("status", 24).notNullable().defaultTo("executed");
    t.text("result"); // JSON
    t.timestamp("started_at", { useTz: true });
    t.timestamp("finished_at", { useTz: true });
    t.index(["session_id"]);
  });

  await db.schema.createTable("approvals", (t) => {
    base(t);
    t.integer("tool_call_id").notNullable().references("id").inTable("tool_calls").onDelete("CASCADE");
    t.integer("session_id").notNullable().references("id").inTable("sessions").onDelete("CASCADE");
    t.integer("host_id").references("id").inTable("hosts").onDelete("SET NULL");
    t.text("command").notNullable();
    t.text("intent");
    t.text("rollback");
    t.text("before_snapshot");
    t.text("auto_checks"); // JSON
    t.string("risk", 16).notNullable().defaultTo("medium");
    t.string("decision", 16).notNullable().defaultTo("pending"); // pending|approved|edited|rejected
    t.integer("decided_by").references("id").inTable("users").onDelete("SET NULL");
    t.timestamp("decided_at", { useTz: true });
    t.text("decision_note");
    t.text("executed_command");
    t.text("exec_result"); // JSON
    t.index(["decision"]);
  });

  await db.schema.createTable("next_actions", (t) => {
    base(t);
    t.integer("session_id").notNullable().references("id").inTable("sessions").onDelete("CASCADE");
    t.string("title", 255).notNullable();
    t.integer("host_id").references("id").inTable("hosts").onDelete("SET NULL");
    t.text("commands"); // JSON
    t.text("rollback"); // JSON
    t.string("risk", 16).notNullable().defaultTo("medium");
    t.text("why");
    t.string("status", 24).notNullable().defaultTo("proposed");
    t.integer("approval_id").references("id").inTable("approvals").onDelete("SET NULL");
  });

  await db.schema.createTable("audit_log", (t) => {
    t.increments("id").primary();
    t.integer("tenant_id").notNullable().defaultTo(1);
    t.timestamp("ts", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.string("actor", 16).notNullable(); // user|agent|system
    t.string("actor_id", 64);
    t.string("event", 64).notNullable();
    t.integer("session_id");
    t.text("payload"); // JSON
    t.index(["ts"]);
    t.index(["event"]);
  });

  await db.schema.createTable("seen_alerts", (t) => {
    t.increments("id").primary();
    t.integer("tenant_id").notNullable().defaultTo(1);
    t.integer("wazuh_instance_id").notNullable();
    t.string("alert_id", 128).notNullable();
    t.string("rule_id", 16);
    t.string("agent_id", 8);
    t.timestamp("ts", { useTz: true }).notNullable();
    t.integer("session_id");
    t.unique(["wazuh_instance_id", "alert_id"]);
  });
}

export async function down(db: Knex): Promise<void> {
  for (const t of [
    "seen_alerts", "audit_log", "next_actions", "approvals", "tool_calls", "messages", "sessions",
    "integrations", "triggers", "protected_ranges", "playbooks", "hosts", "ssh_keys", "wazuh_instances",
    "auth_sessions", "users",
  ]) await db.schema.dropTableIfExists(t);
}
