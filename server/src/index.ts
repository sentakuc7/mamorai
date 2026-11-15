import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import express from "express";
import cookieParser from "cookie-parser";
import pino from "pino";
import { loadConfig } from "./config/index.js";
import { createDb, migrate } from "./db/index.js";
import { SecretBox } from "./crypto/index.js";
import { Audit } from "./audit/index.js";
import { AuthService, csrfGuard } from "./auth/index.js";
import { buildRouter } from "./api/routes.js";
import { sessionsRouter } from "./api/sessions.js";
import { agentPackRouter } from "./api/agentpack.js";
import { scsRouter } from "./api/scs.js";
import { AgentRuntime } from "./runtime/index.js";
import { Sentinel } from "./sentinel/index.js";
import type { Ctx } from "./api/context.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const VERSION = (() => { try { return JSON.parse(fs.readFileSync(path.join(here, "..", "package.json"), "utf8")).version; } catch { return "0.0.0"; } })();

async function main() {
  const cfg = loadConfig();
  const log = pino({ level: cfg.LOG_LEVEL });
  fs.mkdirSync(cfg.APP_DATA_DIR, { recursive: true });

  const db = createDb(cfg);
  await migrate(db);
  const box = new SecretBox(cfg.APP_SECRET);
  const audit = new Audit(db);
  audit.startCliRelay(); // EDR-119: CLI audit events -> journald -> Wazuh
  const auth = new AuthService(db, !cfg.TLS_DISABLED);
  auth.box = box;
  auth.mfa = { required: cfg.MFA_REQUIRED, maxFails: cfg.MFA_MAX_FAILS, lockMin: cfg.LOGIN_LOCK_MIN };
  const ctx: Ctx = { cfg, db, box, audit, auth, log, version: VERSION };
  ctx.runtime = new AgentRuntime(ctx);
  log.info(ctx.runtime.llmStatus, "llm provider");
  ctx.runtime.recoverInterrupted().catch((e) => log.error({ err: e.message }, "recovery of interrupted approvals failed"));
  ctx.sentinel = new Sentinel(ctx);
  await ctx.sentinel.seedDefaults();
  ctx.sentinel.start();
  const { Scheduler } = await import("./scheduler/index.js");
  ctx.scheduler = new Scheduler(ctx);
  ctx.scheduler.start();
  { // EDR-121: agent import, AI host scans, isolation reminders
    const { HostScanner } = await import("./hosts/scan.js");
    ctx.hostScanner = new HostScanner(ctx);
    await ctx.hostScanner.start();
  }
  // EDR-130: record a new agent pack revision if this MamorAI version ships a changed installer
  setTimeout(() => import("./agentpack/index.js").then((a) => a.refresh(ctx, "startup")).catch((e) => log.warn({ err: String(e) }, "agent pack refresh failed")), 20_000);

  // --- bootstrap admin + first Wazuh instance from env (only when tables are empty)
  const adminState = await auth.ensureAdmin(cfg.APP_ADMIN_EMAIL, cfg.APP_ADMIN_PASSWORD, cfg.APP_ADMIN_MUST_CHANGE);
  if (adminState === "created") { log.info({ email: cfg.APP_ADMIN_EMAIL, must_change: cfg.APP_ADMIN_MUST_CHANGE }, "admin user created from env"); await audit.log("system", null, "bootstrap.admin_created", { email: cfg.APP_ADMIN_EMAIL }); }
  if (adminState === "skipped") log.warn("no users exist and APP_ADMIN_PASSWORD is not set: nobody can log in");
  const nWazuh = await db("wazuh_instances").count<{ c: number }[]>({ c: "*" }).first();
  // EDR-149: the CA file must be readable by the container user; say so instead of silently starting without it
  let ca: string | null = null;
  if (cfg.WAZUH_CA_FILE) {
    try { ca = fs.readFileSync(cfg.WAZUH_CA_FILE, "utf8"); } catch (e: any) { log.error({ file: cfg.WAZUH_CA_FILE, err: e.code ?? e.message }, "WAZUH_CA_FILE cannot be read: TLS to the Wazuh indexer will fail (check the permissions of ./secrets)"); }
  }
  if (ca) {
    // bootstrapped instance that was created while the CA was unreadable → fill it in once
    const n = await db("wazuh_instances").whereNull("ca_pem").where({ indexer_url: cfg.WAZUH_INDEXER_URL ?? "" }).update({ ca_pem: ca });
    if (n) { log.warn({ instances: n }, "filled in the missing Wazuh CA certificate from WAZUH_CA_FILE"); await audit.log("system", null, "bootstrap.wazuh_ca_filled", { instances: n }); }
  }
  if (Number(nWazuh?.c ?? 0) === 0 && cfg.WAZUH_INDEXER_URL && cfg.WAZUH_INDEXER_USER && cfg.WAZUH_INDEXER_PASSWORD) {
    await db("wazuh_instances").insert({
      name: cfg.WAZUH_NAME ?? "wazuh", indexer_url: cfg.WAZUH_INDEXER_URL, indexer_user: cfg.WAZUH_INDEXER_USER, indexer_secret_enc: box.encrypt(cfg.WAZUH_INDEXER_PASSWORD),
      api_url: cfg.WAZUH_API_URL ?? null, api_user: cfg.WAZUH_API_USER ?? null, api_secret_enc: cfg.WAZUH_API_PASSWORD ? box.encrypt(cfg.WAZUH_API_PASSWORD) : null,
      ca_pem: ca, tls_verify: cfg.WAZUH_TLS_VERIFY, api_tls_verify: cfg.WAZUH_API_TLS_VERIFY,
    });
    await audit.log("system", null, "bootstrap.wazuh_created", { name: cfg.WAZUH_NAME, indexer_url: cfg.WAZUH_INDEXER_URL });
    log.info("wazuh instance created from env");
  }

  // --- built-in playbooks (config/playbooks/*.json: {name, replaces[], meta}): insert new ones; refresh unedited builtins (version 1); rename old names
  {
    const { coerceMeta, renderMarkdown } = await import("./playbooks/meta.js");
    const dir = path.resolve(here, "..", "..", "config", "playbooks");
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json")).sort()) {
      let spec: any; try { spec = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); } catch (e: any) { log.error({ f, err: e.message }, "bad playbook seed"); continue; }
      const name = String(spec.name ?? "").trim(); if (!name) continue;
      const meta = coerceMeta(spec.meta); const md = renderMarkdown(name, meta); const builtin = !/lab/.test(f);
      let existing = await db("playbooks").where({ name }).first();
      if (!existing) for (const old of spec.replaces ?? []) { existing = await db("playbooks").where({ name: old }).first(); if (existing) { await db("playbooks").where({ id: existing.id }).update({ name, updated_at: db.fn.now() }); log.info({ old, name }, "playbook renamed"); break; } }
      if (!existing) { await db("playbooks").insert({ name, scope: "global", markdown: md, meta: JSON.stringify(meta), builtin, enabled: spec.enabled !== false }); log.info({ name }, "playbook seeded"); continue; }
      if (existing.version === 1 && existing.markdown !== md) { await db("playbooks").where({ id: existing.id }).update({ markdown: md, meta: JSON.stringify(meta), updated_at: db.fn.now() }); log.info({ name }, "builtin playbook refreshed"); }
    }
  }

  // --- builtin rule notes (Japanese triage dictionary); user-edited rows are never overwritten
  try {
    const notes = JSON.parse(fs.readFileSync(path.resolve(here, "..", "..", "config", "rule-notes.json"), "utf8"));
    for (const n of notes) {
      const ex = await db("rule_notes").where({ rule_id: String(n.rule_id) }).first();
      const row = { title_ja: n.title_ja, meaning: n.meaning, cause: n.cause, impact: n.impact, action: n.action, triage: n.triage, source: "builtin" };
      if (!ex) await db("rule_notes").insert({ rule_id: String(n.rule_id), ...row });
      else if (ex.source !== "user") await db("rule_notes").where({ rule_id: String(n.rule_id) }).update({ ...row, updated_at: db.fn.now() });
    }
  } catch (e: any) { log.warn({ err: e.message }, "rule-notes seed failed"); }

  // --- app
  const app = express();
  app.disable("x-powered-by");
  if (cfg.TRUST_PROXY) app.set("trust proxy", 1);
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'");
    next();
  });
  // EDR-90: /wazuh → Wazuh dashboard (front door). Mounted before the JSON parser so request bodies stream through untouched.
  if (cfg.WAZUH_DASHBOARD_PROXY) {
    const { wazuhDashboardProxy } = await import("./api/wazuhProxy.js");
    app.use(cfg.WAZUH_DASHBOARD_BASEPATH, cookieParser(), auth.middleware(), wazuhDashboardProxy(ctx));
  }
  app.use(express.json({ limit: "8mb" }));
  app.use(cookieParser());
  app.use(auth.middleware());
  app.use("/api", csrfGuard(cfg.APP_BASE_URL), sessionsRouter(ctx), agentPackRouter(ctx), scsRouter(ctx), buildRouter(ctx));

  // static SPA
  const webDist = path.resolve(here, "..", "..", "web", "dist");
  if (fs.existsSync(webDist)) {
    app.use(express.static(webDist, { index: false, maxAge: "1h" }));
    app.get(/^(?!\/api\/).*/, (_req, res) => res.sendFile(path.join(webDist, "index.html")));
  } else {
    log.warn({ webDist }, "web/dist not found; API only");
  }

  // errors
  app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = err.status ?? 500;
    if (status >= 500) log.error({ err, path: req.path }, "request failed");
    // publicMessage: a 5xx whose message is safe and useful to show (e.g. the indexer is busy — EDR-157)
    res.status(status).json({ error: status >= 500 ? (err.publicMessage ?? "internal error") : err.message });
  });

  // --- TLS
  let server: http.Server | https.Server;
  if (cfg.TLS_DISABLED) {
    server = http.createServer(app);
  } else {
    let cert = cfg.TLS_CERT_FILE, key = cfg.TLS_KEY_FILE;
    if (!cert || !key || !fs.existsSync(cert) || !fs.existsSync(key)) {
      const dir = path.join(cfg.APP_DATA_DIR, "tls");
      fs.mkdirSync(dir, { recursive: true });
      cert = path.join(dir, "cert.pem"); key = path.join(dir, "key.pem");
      if (!fs.existsSync(cert) || !fs.existsSync(key)) {
        const host = (() => { try { return new URL(cfg.APP_BASE_URL).hostname; } catch { return "localhost"; } })();
        const san = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? `IP:${host}` : `DNS:${host}`;
        execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", cert, "-days", "825", "-subj", `/CN=${host}`, "-addext", `subjectAltName=${san},DNS:localhost,IP:127.0.0.1`]);
        log.info({ cert }, "self-signed TLS certificate generated");
      }
    }
    server = https.createServer({ cert: fs.readFileSync(cert), key: fs.readFileSync(key) }, app);
  }
  server.listen(cfg.APP_PORT, () => log.info({ port: cfg.APP_PORT, tls: !cfg.TLS_DISABLED, version: VERSION }, "edr-console listening"));

  const shutdown = async () => { log.info("shutting down"); server.close(); await db.destroy(); process.exit(0); };
  process.on("SIGTERM", shutdown); process.on("SIGINT", shutdown);
}

main().catch((e) => { console.error(e); process.exit(1); });
