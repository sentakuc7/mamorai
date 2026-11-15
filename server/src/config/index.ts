import fs from "node:fs";
import { z } from "zod";

function readSecretFile(name: string): string | undefined {
  const file = process.env[`${name}_FILE`];
  if (file && fs.existsSync(file)) return fs.readFileSync(file, "utf8").trim();
  return undefined;
}

const bool = z
  .union([z.boolean(), z.string()])
  .transform((v) => (typeof v === "boolean" ? v : ["1", "true", "yes", "on"].includes(v.toLowerCase())));

const schema = z.object({
  APP_PORT: z.coerce.number().int().default(8444),
  APP_SECRET: z.string().min(32, "APP_SECRET must be at least 32 characters (openssl rand -hex 32)"),
  APP_BASE_URL: z.string().default("https://localhost:8444"),
  APP_LOCALE: z.enum(["ja", "en"]).default("ja"),
  APP_ADMIN_EMAIL: z.string().default("admin@example.com"),
  APP_ADMIN_PASSWORD: z.string().optional(),
  /** EDR-149: false when the administrator chose the password in the installer (no forced change at first login) */
  APP_ADMIN_MUST_CHANGE: z.preprocess((v) => (v === undefined || v === "" ? true : !["false", "0", "no"].includes(String(v).toLowerCase())), z.boolean()).default(true),
  APP_DATA_DIR: z.string().default("/app/data"),
  TLS_CERT_FILE: z.string().optional(),
  TLS_KEY_FILE: z.string().optional(),
  TLS_DISABLED: bool.default(false),
  TRUST_PROXY: bool.default(false),

  DB_DRIVER: z.enum(["sqlite", "postgres"]).default("sqlite"),
  DB_PATH: z.string().optional(),
  DATABASE_URL: z.string().optional(),

  WAZUH_NAME: z.string().optional(),
  WAZUH_INDEXER_URL: z.string().optional(),
  WAZUH_INDEXER_USER: z.string().optional(),
  WAZUH_INDEXER_PASSWORD: z.string().optional(),
  WAZUH_API_URL: z.string().optional(),
  WAZUH_API_USER: z.string().optional(),
  WAZUH_API_PASSWORD: z.string().optional(),
  WAZUH_CA_FILE: z.string().optional(),
  WAZUH_TLS_VERIFY: bool.default(true),
  WAZUH_API_TLS_VERIFY: bool.default(false),

  LLM_PROVIDER: z.enum(["openrouter", "ollama", "anthropic"]).default("openrouter"),
  OPENROUTER_API_KEY: z.string().optional(),
  OPENROUTER_MODEL: z.string().default("anthropic/claude-sonnet-4.5"),
  OPENROUTER_FALLBACK_MODEL: z.string().optional(),
  OLLAMA_URL: z.string().default("http://127.0.0.1:11434"),
  OLLAMA_MODEL: z.string().default("qwen2.5:14b"),
  ANTHROPIC_API_KEY: z.string().optional(),
  ANTHROPIC_MODEL: z.string().default("claude-sonnet-4-5"),
  LLM_MAX_TOKENS_PER_SESSION: z.coerce.number().int().default(1500000),
  LLM_MAX_SESSIONS_PER_HOUR: z.coerce.number().int().default(20),
  LLM_REDACT_INTERNAL_IPS: bool.default(false),

  JIRA_BASE_URL: z.string().optional(),
  JIRA_EMAIL: z.string().optional(),
  JIRA_API_TOKEN: z.string().optional(),
  JIRA_PROJECT_KEY: z.string().default("EDR"),
  DISCORD_WEBHOOK_URL: z.string().optional(),

  SENTINEL_ENABLED: bool.default(false),
  SENTINEL_POLL_SEC: z.coerce.number().int().default(30),
  SENTINEL_MIN_LEVEL: z.coerce.number().int().default(12),

  AUTONOMY_DEFAULT: z.coerce.number().int().min(0).max(3).default(1),
  AUTONOMY_MAX: z.coerce.number().int().min(0).max(3).default(2),
  // EDR-87: a failed, human-approved change can be retried within the same files/services without asking again
  RETRY_GRANT_MINUTES: z.coerce.number().int().min(0).default(60),
  RETRY_GRANT_MAX: z.coerce.number().int().min(0).default(5),
  // EDR-94: self-drive — after a human-approved change fails, MamorAI may fix and retry up to N times without asking
  //   (the approver can change N on the card). Some operations always ask (mustAskOps). On production hosts the agent
  //   stops after this many different human-approved approaches failed since the human last wrote (0 = never).
  SELF_DRIVE_MAX_PRODUCTION: z.coerce.number().int().min(0).default(3),
  SELF_DRIVE_MAX_LAB: z.coerce.number().int().min(0).default(5),
  RETREAT_FAILED_APPROACHES_PRODUCTION: z.coerce.number().int().min(0).default(2),
  RETREAT_FAILED_APPROACHES_LAB: z.coerce.number().int().min(0).default(0),
  // EDR-114: package transactions / long steps run detached on the host and are polled
  LONG_STEP_MAX_MINUTES: z.coerce.number().int().min(5).max(240).default(60),
  LONG_STEP_POLL_SECONDS: z.coerce.number().int().min(5).max(120).default(15),
  // EDR-87: when an approved multi-step plan fails, run its approved rollback automatically
  AUTO_ROLLBACK_ON_FAILURE: bool.default(true),

  // EDR-90: sign-in protection (TOTP MFA without external services, throttling, step-up, API token limits)
  MFA_REQUIRED: bool.default(true),
  MFA_MAX_FAILS: z.coerce.number().int().min(1).default(5),
  LOGIN_MAX_FAILS_PER_ACCOUNT: z.coerce.number().int().min(1).default(5),
  LOGIN_MAX_FAILS_PER_IP: z.coerce.number().int().min(1).default(20),
  LOGIN_FAIL_WINDOW_MIN: z.coerce.number().int().min(1).default(15),
  LOGIN_LOCK_MIN: z.coerce.number().int().min(1).default(15),
  API_TOKEN_MAX_DAYS: z.coerce.number().int().min(1).default(365),
  API_TOKEN_REQUIRE_IP: bool.default(true),
  // EDR-90: Wazuh dashboard behind MamorAI (installer module 30 switches the dashboard to loopback + proxy auth)
  // EDR-90: kill switch trips automatically when this many changes are executed within 10 minutes (0 = never)
  AUTO_HOLD_MAX_CHANGES_10MIN: z.coerce.number().int().min(0).default(15),
  WAZUH_DASHBOARD_PROXY: bool.default(true),
  WAZUH_DASHBOARD_URL: z.string().default("https://127.0.0.1:8443"),
  WAZUH_DASHBOARD_BASEPATH: z.string().default("/wazuh"),

  // EDR-121: host AI scan / host actions
  HOST_AGENT_SYNC_MIN: z.coerce.number().int().min(0).default(10),     // import Wazuh agents as "agent only" hosts every N minutes (0 = off)
  HOST_SCAN_CONCURRENCY: z.coerce.number().int().min(1).max(8).default(2),
  HOST_SCAN_AI: bool.default(true),                                    // false = facts only, no LLM interpretation
  HOST_SCAN_MAX_TOKENS: z.coerce.number().int().min(2000).default(60000), // per scan (input+output); over budget → facts only
  HOST_ACTION_LINUX_AUTOREVERT_SEC: z.coerce.number().int().min(60).max(900).default(180),
  WIN_UPDATE_WAIT_MIN: z.coerce.number().int().min(10).max(360).default(180), // EDR-168: how long to wait for Windows Update / winget to finish on the endpoint
  HOST_ACTION_ISOLATION_REMIND_HOURS: z.coerce.number().int().min(0).default(24),
  // Windows endpoints: actions run through Wazuh active response with a dedicated API user (only active-response:command)
  WAZUH_AR_USER: z.string().optional(),
  WAZUH_AR_PASSWORD: z.string().optional(),
  AR_ADDON_MIN_VERSION: z.string().default("1.0.0"),
  // EDR-130: agent packs downloaded from the host screen
  AGENT_PACK_TEMPLATE_DIR: z.string().default("/app/installer/agent-pack"), // installer templates (repo: installer/agent-pack)
  AGENT_PACK_ADDON_DIR: z.string().default("/app/addon"),
  HOST_BRIDGE_DIR: z.string().default("/app/host-bridge"),                  // EDR-149: requests to the root helper on the host (installer/modules/62-host-bridge.sh)                   // signed Windows add-on (build-addon.sh --out), mounted read-only
  AGENT_PACK_CHECK_MIN: z.coerce.number().int().min(1).default(10),         // how often to look for changes (new add-on, Wazuh upgrade)

  LOG_LEVEL: z.string().default("info"),
});

export type AppConfig = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const merged: Record<string, string | undefined> = { ...env };
  for (const k of ["APP_SECRET", "APP_ADMIN_PASSWORD", "WAZUH_INDEXER_PASSWORD", "WAZUH_API_PASSWORD", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "JIRA_API_TOKEN", "WAZUH_AR_PASSWORD"]) {
    const v = readSecretFile(k);
    if (v) merged[k] = v;
  }
  const parsed = schema.safeParse(merged);
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new Error(`Invalid configuration: ${msg}`);
  }
  const cfg = parsed.data;
  if (!cfg.DB_PATH) cfg.DB_PATH = `${cfg.APP_DATA_DIR}/edr-console.db`;
  if (cfg.DB_DRIVER === "postgres" && !cfg.DATABASE_URL) throw new Error("DATABASE_URL is required when DB_DRIVER=postgres");
  return cfg;
}
