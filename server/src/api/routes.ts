import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Ctx } from "./context.js";
import { indexer, managerApi, publicWazuh, wazuhConn } from "./context.js";
import { requireRole, SESSION_TIMEOUTS } from "../auth/index.js";
import { Throttle, normIp } from "../auth/throttle.js";
import { IndexerClient, ManagerApiClient } from "../wazuh/index.js";
import { sshExec, generateEd25519, keyFingerprint, publicFromPrivate } from "../ssh/index.js";
import { pj, j } from "../db/index.js";
import { buildProcessTree } from "../processtree/index.js";
import { decorateAlert } from "../alerts/keys.js";
import { isVulnAlert, vulnIdentity } from "../alerts/vulnText.js";
import { coerceMeta, parseMarkdown, renderMarkdown, playbookMetaSchema } from "../playbooks/meta.js";

type H = (req: Request, res: Response) => Promise<unknown>;
const wrap = (fn: H) => (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);

function parse<S extends z.ZodTypeAny>(schema: S, data: unknown): z.infer<S> {
  const r = schema.safeParse(data);
  if (!r.success) throw Object.assign(new Error("validation: " + r.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join(", ")), { status: 400 });
  return r.data;
}

export function buildRouter(ctx: Ctx): Router {
  const r = Router();
  const { db, box, audit, auth } = ctx;

  // ---------- public ----------
  r.get("/health", wrap(async (_req, res) => {
    const users = await db("users").count<{ c: number }[]>({ c: "*" }).first();
    const executing = ctx.runtime ? await ctx.runtime.executingCount().catch(() => 0) : 0;
    const running = ctx.runtime ? await ctx.runtime.runningCount().catch(() => 0) : 0;
    res.json({ ok: true, version: ctx.version, setup: Number(users?.c ?? 0) > 0, locale: ctx.cfg.APP_LOCALE, executing_approvals: executing, running_sessions: running, busy: executing + running });
  }));

  // ---------- auth ----------
  // EDR-90: throttling per account and per source IP; lockouts are audited (→ Wazuh rule 100705 / 1007xx)
  const throttle = new Throttle(db, { windowMin: ctx.cfg.LOGIN_FAIL_WINDOW_MIN, lockMin: ctx.cfg.LOGIN_LOCK_MIN });
  const meta = (req: Request) => ({ ip: req.ip, ua: req.headers["user-agent"] as string | undefined });
  r.post("/auth/login", wrap(async (req, res) => {
    const b = parse(z.object({ email: z.string().email(), password: z.string().min(1) }), req.body);
    const ip = normIp(req.ip); const kAcct = `acct:${b.email.toLowerCase()}`, kIp = `ip:${ip}`;
    const until = await throttle.lockedUntil([kAcct, kIp]);
    if (until) {
      await audit.log("system", null, "auth.login_blocked", { email: b.email, ip: req.ip, until: new Date(until).toISOString() });
      return res.status(429).json({ error: "too many attempts", retry_after_sec: Math.ceil((until - Date.now()) / 1000) });
    }
    const out = await auth.login(b.email, b.password, meta(req));
    if (!out) {
      await audit.log("system", null, "auth.login_failed", { email: b.email, ip: req.ip });
      const lockedAcct = await throttle.fail(kAcct, ctx.cfg.LOGIN_MAX_FAILS_PER_ACCOUNT);
      const lockedIp = await throttle.fail(kIp, ctx.cfg.LOGIN_MAX_FAILS_PER_IP);
      if (lockedAcct || lockedIp) await audit.log("system", null, "auth.locked", { email: b.email, ip: req.ip, scope: lockedAcct ? "account" : "ip", minutes: ctx.cfg.LOGIN_LOCK_MIN });
      return res.status(401).json({ error: "invalid credentials" });
    }
    await throttle.reset(kAcct);
    auth.setCookie(res, out.sid, !!out.stage);
    await audit.log("user", out.user.id, "auth.login", { ip: req.ip, mfa: out.stage ?? "none" });
    res.json({ user: out.stage ? null : out.user, mfa: out.stage });
  }));
  r.post("/auth/logout", wrap(async (req, res) => { await auth.logout(req.sid); auth.clearCookie(res); res.json({ ok: true }); }));
  r.get("/auth/me", (req, res) => {
    if (req.user) return res.json({ user: req.user });
    if (req.mfaPending) return res.json({ user: null, mfa_pending: req.mfaPending.stage, email: req.mfaPending.email });
    res.status(401).json({ error: "unauthenticated" });
  });

  // ---------- EDR-90: TOTP MFA ----------
  const enrollUid = (req: Request): number | null => req.mfaPending?.stage === "enroll" ? req.mfaPending.userId : (req.user && !req.user.mfa_enabled && req.authVia === "cookie" ? req.user.id : null);
  r.post("/auth/mfa/verify", wrap(async (req, res) => {
    const p = req.mfaPending;
    if (!p || p.stage !== "verify") return res.status(400).json({ error: "no sign-in is waiting for a code" });
    const b = parse(z.object({ code: z.string().optional(), recovery_code: z.string().optional() }), req.body);
    const r0 = await auth.mfaCheck(p.userId, b);
    if (r0.result === "ok" || r0.result === "recovery") {
      auth.setCookie(res, await auth.upgradeSession(req.sid, p.userId, meta(req)));
      await audit.log("user", p.userId, r0.result === "recovery" ? "auth.recovery_code_used" : "auth.mfa_verified", { ip: req.ip, remaining_recovery_codes: r0.remaining_recovery });
      return res.json({ ok: true, remaining_recovery_codes: r0.remaining_recovery });
    }
    if (r0.result === "locked") {
      if (r0.justLocked) await audit.log("system", null, "auth.mfa_locked", { user_id: p.userId, email: p.email, ip: req.ip, minutes: ctx.cfg.LOGIN_LOCK_MIN });
      return res.status(429).json({ error: "locked", retry_after_sec: Math.ceil(((r0.locked_until ?? Date.now()) - Date.now()) / 1000) });
    }
    await audit.log("system", null, "auth.mfa_failed", { user_id: p.userId, email: p.email, ip: req.ip });
    res.status(401).json({ error: "invalid code" });
  }));
  r.post("/auth/mfa/enroll/start", wrap(async (req, res) => {
    const uid = enrollUid(req);
    if (!uid) return res.status(400).json({ error: "enrollment is not available for this session" });
    const s = await auth.mfaEnrollStart(uid);
    const QR = await import("qrcode");
    const svg = await QR.toString(s.otpauth, { type: "svg", margin: 1, errorCorrectionLevel: "M" });
    res.json({ secret: s.secret, otpauth: s.otpauth, qr_svg_data_url: "data:image/svg+xml;base64," + Buffer.from(svg).toString("base64") });
  }));
  r.post("/auth/mfa/enroll/confirm", wrap(async (req, res) => {
    const uid = enrollUid(req);
    if (!uid) return res.status(400).json({ error: "enrollment is not available for this session" });
    const b = parse(z.object({ code: z.string() }), req.body);
    const codes = await auth.mfaEnrollConfirm(uid, b.code);
    if (!codes) { await audit.log("system", null, "auth.mfa_failed", { user_id: uid, ip: req.ip, stage: "enroll" }); return res.status(401).json({ error: "invalid code" }); }
    auth.setCookie(res, await auth.upgradeSession(req.sid, uid, meta(req)));
    await audit.log("user", uid, "auth.mfa_enrolled", { ip: req.ip });
    res.json({ recovery_codes: codes });
  }));
  r.post("/auth/mfa/recovery-codes", requireRole("viewer"), wrap(async (req, res) => {
    const codes = await auth.regenerateRecoveryCodes(req.user!.id);
    await audit.log("user", req.user!.id, "auth.recovery_codes_regenerated");
    res.json({ recovery_codes: codes });
  }));
  // EDR-117: own MFA status (remaining recovery codes) for the Settings > account tab
  r.get("/auth/mfa/status", requireRole("viewer"), wrap(async (req, res) => {
    const left = Number((await db("user_recovery_codes").where({ user_id: req.user!.id }).whereNull("used_at").count<{ c: number }[]>({ c: "*" }).first())?.c ?? 0);
    res.json({ mfa_enabled: !!req.user!.mfa_enabled, recovery_codes_remaining: left });
  }));
  r.post("/auth/change-password", requireRole("viewer"), wrap(async (req, res) => {
    const b = parse(z.object({ current: z.string(), next: z.string().min(12) }), req.body);
    const ok = await auth.changePassword(req.user!.id, b.current, b.next);
    if (!ok) return res.status(400).json({ error: "current password incorrect" });
    await audit.log("user", req.user!.id, "auth.password_changed");
    auth.clearCookie(res);
    res.json({ ok: true });
  }));

  // everything below requires login
  r.use(requireRole("viewer"));

  // ---------- wazuh instances ----------
  const wazuhSchema = z.object({
    name: z.string().min(1).max(128),
    indexer_url: z.string().url(), indexer_user: z.string().min(1), indexer_password: z.string().optional(),
    api_url: z.string().url().optional().nullable(), api_user: z.string().optional().nullable(), api_password: z.string().optional().nullable(),
    ca_pem: z.string().optional().nullable(), tls_verify: z.boolean().default(true), api_tls_verify: z.boolean().default(false), notes: z.string().optional().nullable(),
  });

  r.get("/wazuh", wrap(async (_req, res) => res.json({ items: (await db("wazuh_instances").orderBy("id")).map(publicWazuh) })));

  r.post("/wazuh", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(wazuhSchema, req.body);
    if (!b.indexer_password) throw Object.assign(new Error("indexer_password required"), { status: 400 });
    const [id] = await db("wazuh_instances").insert({
      name: b.name, indexer_url: b.indexer_url, indexer_user: b.indexer_user, indexer_secret_enc: box.encrypt(b.indexer_password),
      api_url: b.api_url ?? null, api_user: b.api_user ?? null, api_secret_enc: b.api_password ? box.encrypt(b.api_password) : null,
      ca_pem: b.ca_pem ?? null, tls_verify: b.tls_verify, api_tls_verify: b.api_tls_verify, notes: b.notes ?? null,
    }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "wazuh.created", { id, name: b.name });
    res.status(201).json(publicWazuh(await db("wazuh_instances").where({ id }).first()));
  }));

  r.put("/wazuh/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = parse(wazuhSchema.partial(), req.body);
    const upd: any = { updated_at: db.fn.now() };
    for (const k of ["name", "indexer_url", "indexer_user", "api_url", "api_user", "ca_pem", "tls_verify", "api_tls_verify", "notes"] as const) if (b[k] !== undefined) upd[k] = b[k];
    if (b.indexer_password) upd.indexer_secret_enc = box.encrypt(b.indexer_password);
    if (b.api_password) upd.api_secret_enc = box.encrypt(b.api_password);
    await db("wazuh_instances").where({ id }).update(upd);
    await audit.log("user", req.user!.id, "wazuh.updated", { id, fields: Object.keys(upd) });
    res.json(publicWazuh(await db("wazuh_instances").where({ id }).first()));
  }));

  r.delete("/wazuh/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    await db("wazuh_instances").where({ id }).delete();
    await audit.log("user", req.user!.id, "wazuh.deleted", { id });
    res.json({ ok: true });
  }));

  r.post("/wazuh/:id/test", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const { row, conn } = await wazuhConn(ctx, id);
    const out: any = { indexer: null, api: null };
    try { out.indexer = await new IndexerClient(conn).health(); } catch (e: any) { out.indexer = { error: e.message }; }
    if (conn.apiUrl) { try { out.api = await new ManagerApiClient(conn).info(); } catch (e: any) { out.api = { error: e.message }; } }
    if (out.indexer && !out.indexer.error) await db("wazuh_instances").where({ id }).update({ archives_enabled: !!out.indexer.archivesEnabled, updated_at: db.fn.now() });
    await audit.log("user", req.user!.id, "wazuh.tested", { id, name: row.name, ok: !out.indexer?.error });
    res.json(out);
  }));

  /** ダッシュボードのノード俯瞰: manager のエージェント一覧（OS / 状態）+ レベル帯別件数 + サーバー / クライアント分類 */
  r.get("/wazuh/:id/nodes", wrap(async (req, res) => {
    const wid = Number(req.params.id); const ix = await indexer(ctx, wid);
    const counts = await ix.perAgent(String(req.query.window ?? "now-24h"));
    let agents: any[] = [];
    try { const { conn } = await wazuhConn(ctx, wid); if (conn.apiUrl) { const api = await managerApi(ctx, wid); const r: any = await api.get("/agents?select=id,name,status,ip,os.name,os.platform,os.version,version,lastKeepAlive,group&limit=500"); agents = r?.data?.affected_items ?? []; } } catch { agents = []; }
    const overrides = Object.fromEntries((await db("node_roles")).map((x: any) => [x.agent_name, x.role]));
    const hosts = await db("hosts").select("id", "name", "agent_id", "address", "kind");
    const cloud = await db("cloud_instances").select("agent_name", "host_id", "name", "service", "region");
    const { guessRole: guess } = await import("../hosts/role.js");
    const guessRole = (os: any, name: string, groups?: string[], kind?: string | null): "server" | "client" => guess({ osName: os?.name, platform: os?.platform, groups, cloud: cloud.some((c: any) => c.agent_name === name), name, kind });
    const byName = new Map<string, any>();
    for (const a of agents) if (a.id !== "000") byName.set(a.name, { id: a.id, name: a.name, status: a.status, ip: a.ip ?? null, os: a.os?.name ?? null, platform: a.os?.platform ?? null, version: a.version ?? null, last_keepalive: a.lastKeepAlive ?? null, groups: a.group ?? [] });
    for (const c of counts) { if (c.name === (agents.find((a: any) => a.id === "000")?.name ?? "__manager__")) continue; const e = byName.get(c.name) ?? { id: c.id, name: c.name, status: "unknown", ip: null, os: null, platform: null, version: null, last_keepalive: null, groups: [] }; byName.set(c.name, { ...e, counts: { total: c.total, critical: c.critical, high: c.high, medium: c.medium, low: c.low }, last_alert: c.last }); }
    const items = [...byName.values()].map((n) => {
      const host = hosts.find((h: any) => h.agent_id === n.id || h.name.toLowerCase() === n.name.toLowerCase());
      const ci = cloud.find((c: any) => c.agent_name === n.name || (host && c.host_id === host.id));
      return { ...n, counts: n.counts ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0 }, last_alert: n.last_alert ?? null, role: overrides[n.name] ?? guessRole({ name: n.os, platform: n.platform }, n.name, n.groups, host?.kind), role_source: overrides[n.name] ? "manual" : "auto", host_id: host?.id ?? null, cloud: ci ? { name: ci.name, service: ci.service, region: ci.region } : null };
    });
    res.json({ items, manager_api: agents.length > 0 });
  }));
  r.put("/nodes/:name/role", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ role: z.enum(["server", "client", "auto"]) }), req.body); const name = String(req.params.name).slice(0, 128);
    if (b.role === "auto") await db("node_roles").where({ agent_name: name }).delete();
    else { await db("node_roles").where({ agent_name: name }).delete(); await db("node_roles").insert({ agent_name: name, role: b.role }); }
    await audit.log("user", req.user!.id, "node.role", { name, role: b.role }); res.json({ ok: true });
  }));
  r.get("/wazuh/:id/summary", wrap(async (req, res) => {
    const ix = await indexer(ctx, Number(req.params.id));
    res.json(await ix.summary(String(req.query.window ?? "now-24h")));
  }));
  // ---------- 攻撃可視化（EDR-70/71）: 攻撃ソース定義に基づく国別集計 ----------
  r.get("/wazuh/:id/attack-map", wrap(async (req, res) => {
    const q = parse(z.object({ window: z.enum(["now-24h", "now-7d", "now-30d", "24h", "7d", "30d"]).default("now-24h") }), req.query);
    const window = q.window.startsWith("now-") ? q.window : `now-${q.window}`;
    const ix = await indexer(ctx, Number(req.params.id));
    const { attackMap } = await import("../attackmap/index.js");
    const titles = Object.fromEntries((await db("rule_notes").select("rule_id", "title_ja")).map((n: any) => [n.rule_id, n.title_ja]));
    const { siteOfAgent } = await import("../attackmap/setup.js");
    const sites = await siteOfAgent(db);
    const out = await attackMap(ix, String(req.params.id), window, titles);
    // 拠点（EDR-73）: agent → site。未設定は既定拠点（無ければ東京）
    const def = sites.def ?? { id: 0, name: "自拠点（東京）", lat: 35.7, lon: 139.7, kind: "home" };
    const bySite = new Map<number, any>();
    for (const t of out.targets) { const s = sites.byAgent.get(t.host) ?? def; const row = bySite.get(s.id) ?? { site_id: s.id, name: s.name, lat: s.lat, lon: s.lon, kind: s.kind, total: 0, hosts: [] as string[] }; row.total += t.total; row.hosts.push(t.host); bySite.set(s.id, row); }
    if (!bySite.size) bySite.set(def.id, { site_id: def.id, name: def.name, lat: def.lat, lon: def.lon, kind: def.kind, total: 0, hosts: [] });
    const agentSite = Object.fromEntries([...sites.byAgent.entries()].map(([a, s]) => [a, s.id]));
    res.json({ ...out, sites: [...bySite.values()], agent_site: agentSite, default_site_id: def.id });
  }));
  r.get("/wazuh/:id/attack-map/replay", wrap(async (req, res) => {
    const q = parse(z.object({ window: z.enum(["now-24h", "now-7d", "now-30d", "24h", "7d", "30d"]).default("now-7d") }), req.query);
    const window = q.window.startsWith("now-") ? q.window : `now-${q.window}`;
    const ix = await indexer(ctx, Number(req.params.id));
    const { replay } = await import("../attackmap/index.js");
    res.json(await replay(ix, String(req.params.id), window));
  }));
  r.get("/wazuh/:id/attack-map/probe", wrap(async (req, res) => {
    const ix = await indexer(ctx, Number(req.params.id));
    const { probe } = await import("../attackmap/index.js");
    res.json(await probe(ix, String(req.query.window ?? "now-24h")));
  }));
  // ---------- 攻撃可視化 セットアップ・ウィザード（EDR-74）/ 拠点（EDR-73）----------
  r.get("/overview/setup", wrap(async (req, res) => {
    const wid = Number(req.query.wazuh ?? (await db("wazuh_instances").orderBy("id").first())?.id);
    const { readiness, loadRecipes, listSites } = await import("../attackmap/setup.js");
    const row = await db("overview_setup").where({ wazuh_instance_id: wid }).first();
    let ready: any; let managerAddr = row?.manager_addr ?? null;
    try {
      const ix = await indexer(ctx, wid);
      const { conn } = await wazuhConn(ctx, wid);
      const mgr = conn.apiUrl ? () => managerApi(ctx, wid) : null;
      ready = await readiness(ix, mgr, String(req.query.window ?? "now-24h"));
      if (!managerAddr) { try { const u = new URL(conn.apiUrl ?? conn.indexerUrl); managerAddr = ["127.0.0.1", "localhost"].includes(u.hostname) ? null : u.hostname; } catch { /* ignore */ } }
    } catch (e: any) {
      ready = { ok: false, level: "error", window: "now-24h", indexer: { ok: false, error: `Wazuh 接続が未設定または到達できません: ${e.message}` }, geo_rate: null, total_src: 0, profiles: [], agents: [], manager_remote: null, hints: ["設定 › Wazuh 接続で indexer（と可能なら manager API）を登録してください。"] };
    }
    res.json({ wazuh_instance_id: wid, state: row ? { ...row, assets: pj(row.assets) ?? [], vendors: pj(row.vendors) ?? {}, completed: !!row.completed, skipped: !!row.skipped, demo: !!row.demo } : { assets: [], vendors: {}, step: 0, completed: false, skipped: false, demo: false, manager_addr: null },
      manager_addr: managerAddr, readiness: ready, recipes: loadRecipes(), sites: await listSites(db), hosts: (await db("hosts").select("id", "name", "address", "agent_id", "environment")) });
  }));
  r.put("/overview/setup", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ wazuh_instance_id: z.number().int(), assets: z.array(z.string()).optional(), vendors: z.record(z.string(), z.string()).optional(), manager_addr: z.string().max(255).nullable().optional(), step: z.number().int().min(0).max(9).optional(), completed: z.boolean().optional(), skipped: z.boolean().optional(), demo: z.boolean().optional() }), req.body);
    const upd: any = { updated_at: db.fn.now() };
    if (b.assets) upd.assets = j(b.assets); if (b.vendors) upd.vendors = j(b.vendors); if (b.manager_addr !== undefined) upd.manager_addr = b.manager_addr; if (b.step != null) upd.step = b.step;
    if (b.completed != null) upd.completed = b.completed; if (b.skipped != null) upd.skipped = b.skipped; if (b.demo != null) upd.demo = b.demo;
    const ex = await db("overview_setup").where({ wazuh_instance_id: b.wazuh_instance_id }).first();
    if (ex) await db("overview_setup").where({ wazuh_instance_id: b.wazuh_instance_id }).update(upd); else await db("overview_setup").insert({ wazuh_instance_id: b.wazuh_instance_id, ...upd });
    await audit.log("user", req.user!.id, "overview.setup_updated", { ...b });
    res.json({ ok: true });
  }));
  r.get("/overview/decoder-pack", wrap(async (_req, res) => { const { decoderPack } = await import("../attackmap/setup.js"); res.json(decoderPack()); }));
  r.get("/wazuh/:id/attack-map/demo", wrap(async (req, res) => { const { demoData } = await import("../attackmap/setup.js"); res.json(demoData(String(req.query.window ?? "now-24h"))); }));
  r.get("/sites", wrap(async (_req, res) => { const { listSites } = await import("../attackmap/setup.js"); res.json({ items: await listSites(db) }); }));
  r.post("/sites", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ name: z.string().min(1).max(120), lat: z.number().min(-90).max(90), lon: z.number().min(-180).max(180), kind: z.enum(["home", "cloud", "office"]).default("home"), is_default: z.boolean().default(false), members: z.array(z.string().max(128)).default([]) }), req.body);
    if (b.is_default) await db("sites").update({ is_default: false });
    const [id] = await db("sites").insert({ name: b.name, lat: b.lat, lon: b.lon, kind: b.kind, is_default: b.is_default }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    for (const a of b.members) { await db("site_members").where({ agent_name: a }).delete(); await db("site_members").insert({ site_id: id, agent_name: a }); }
    await audit.log("user", req.user!.id, "site.created", { id, name: b.name, members: b.members });
    res.json({ id });
  }));
  r.put("/sites/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = parse(z.object({ name: z.string().min(1).max(120).optional(), lat: z.number().optional(), lon: z.number().optional(), kind: z.enum(["home", "cloud", "office"]).optional(), is_default: z.boolean().optional(), members: z.array(z.string().max(128)).optional() }), req.body);
    if (b.is_default) await db("sites").update({ is_default: false });
    const upd: any = {}; for (const k of ["name", "lat", "lon", "kind", "is_default"] as const) if (b[k] !== undefined) upd[k] = b[k];
    if (Object.keys(upd).length) await db("sites").where({ id }).update(upd);
    if (b.members) { await db("site_members").where({ site_id: id }).delete(); for (const a of b.members) { await db("site_members").where({ agent_name: a }).delete(); await db("site_members").insert({ site_id: id, agent_name: a }); } }
    await audit.log("user", req.user!.id, "site.updated", { id, ...b });
    res.json({ ok: true });
  }));
  r.delete("/sites/:id", requireRole("admin"), wrap(async (req, res) => { await db("sites").where({ id: Number(req.params.id) }).delete(); await audit.log("user", req.user!.id, "site.deleted", { id: Number(req.params.id) }); res.json({ ok: true }); }));
  // ---------- クラウド管理（EDR-76）----------
  const cloudSvc = () => import("../cloud/service.js");
  const cloudMod = () => import("../cloud/index.js");
  const agentsForMatch = async (): Promise<{ name: string; ip: string | null }[]> => {
    try { const wz = await db("wazuh_instances").orderBy("id").first(); if (!wz?.api_url) return []; const api = await managerApi(ctx, wz.id); const r: any = await api.get("/agents?select=name,ip&limit=500"); return (r?.data?.affected_items ?? []).map((a: any) => ({ name: a.name, ip: a.ip ?? null })); } catch { return []; }
  };
  r.get("/cloud/providers", wrap(async (_req, res) => {
    const { pubProvider } = await cloudSvc(); const { KIND_JA, POLICIES } = await cloudMod();
    const rows = await db("cloud_providers").orderBy("id");
    const counts: Record<number, number> = {}; for (const c of await db("cloud_instances").select("provider_id").count<{ provider_id: number; c: number }[]>({ c: "*" }).groupBy("provider_id")) counts[(c as any).provider_id] = Number((c as any).c);
    res.json({ items: rows.map((r: any) => pubProvider(r, counts)), kinds: KIND_JA, policies: POLICIES });
  }));
  const providerBody = z.object({ kind: z.enum(["aws", "gce", "hyperv", "esxi", "azure", "proxmox"]), name: z.string().min(1).max(120), config: z.record(z.string(), z.any()).default({}), secret: z.record(z.string(), z.any()).optional(), capability: z.enum(["inventory", "ops", "isolate"]).default("ops") });
  r.post("/cloud/providers", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(providerBody, req.body);
    const hasSecret = !!b.secret && Object.values(b.secret).some((v) => v);
    const [id] = await db("cloud_providers").insert({ kind: b.kind, name: b.name, config: j(b.config), secret_enc: hasSecret ? box.encrypt(JSON.stringify(b.secret)) : null, status: hasSecret ? "new" : "needs_secret", capability: b.capability, created_by: req.user!.id }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "cloud.provider_created", { id, kind: b.kind, name: b.name, capability: b.capability });
    res.json({ id });
  }));
  r.put("/cloud/providers/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id); const b = parse(providerBody.partial(), req.body);
    const upd: any = { updated_at: db.fn.now() };
    if (b.name) upd.name = b.name; if (b.config) upd.config = j(b.config); if (b.capability) upd.capability = b.capability; if (b.secret && Object.values(b.secret).some((v) => v)) { upd.secret_enc = box.encrypt(JSON.stringify(b.secret)); upd.status = "new"; upd.last_error = null; }
    await db("cloud_providers").where({ id }).update(upd);
    await audit.log("user", req.user!.id, "cloud.provider_updated", { id, fields: Object.keys(upd) });
    res.json({ ok: true });
  }));
  r.delete("/cloud/providers/:id", requireRole("admin"), wrap(async (req, res) => { await db("cloud_providers").where({ id: Number(req.params.id) }).delete(); await audit.log("user", req.user!.id, "cloud.provider_deleted", { id: Number(req.params.id) }); res.json({ ok: true }); }));
  r.post("/cloud/providers/:id/test", requireRole("admin"), wrap(async (req, res) => {
    const { providerFor } = await cloudSvc(); const row = await db("cloud_providers").where({ id: Number(req.params.id) }).first();
    if (!row) return res.status(404).json({ error: "not found" });
    let out: any; try { out = await providerFor(box, row).test(); } catch (e: any) { out = { ok: false, message: e.message }; }
    await db("cloud_providers").where({ id: row.id }).update({ status: out.ok ? "ok" : "error", last_error: out.ok ? null : out.message, updated_at: db.fn.now() });
    await audit.log("user", req.user!.id, "cloud.provider_tested", { id: row.id, ok: out.ok });
    res.json(out);
  }));
  r.post("/cloud/providers/:id/sync", requireRole("operator"), wrap(async (req, res) => {
    const { syncProvider } = await cloudSvc();
    try { const r = await syncProvider(db, box, Number(req.params.id), await agentsForMatch()); await audit.log("user", req.user!.id, "cloud.synced", { id: Number(req.params.id), ...r }); res.json(r); }
    catch (e: any) { res.status(502).json({ error: e.message }); }
  }));
  r.get("/cloud/instances", wrap(async (req, res) => {
    const { pubInstance } = await cloudSvc();
    const provs = await db("cloud_providers"); const byId = Object.fromEntries(provs.map((p: any) => [p.id, p]));
    let qb = db("cloud_instances").orderBy(["provider_id", "name"]); if (req.query.provider) qb = qb.where("provider_id", Number(req.query.provider));
    const hosts = await db("hosts").select("id", "name");
    res.json({ items: (await qb).map((r: any) => ({ ...pubInstance(r, byId[r.provider_id]), host_name: hosts.find((h: any) => h.id === r.host_id)?.name ?? null })) });
  }));
  r.put("/cloud/instances/:id/link", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ host_id: z.number().int().nullable().optional(), agent_name: z.string().max(128).nullable().optional() }), req.body);
    const upd: any = {}; if (b.host_id !== undefined) upd.host_id = b.host_id; if (b.agent_name !== undefined) upd.agent_name = b.agent_name;
    await db("cloud_instances").where({ id: Number(req.params.id) }).update(upd); res.json({ ok: true });
  }));
  /** 承認キューにクラウド操作を積む（人間が UI から依頼）。実行は承認後に decide() が行う。 */
  r.post("/cloud/instances/:id/request", requireRole("operator"), wrap(async (req, res) => {
    const b = parse(z.object({ op: z.enum(["snapshot", "power", "isolate"]), name: z.string().max(120).optional(), power: z.enum(["start", "stop", "reboot"]).optional(), allow_cidrs: z.array(z.string()).optional(), reason: z.string().max(500).optional() }), req.body);
    const inst = await db("cloud_instances").where({ id: Number(req.params.id) }).first(); if (!inst) return res.status(404).json({ error: "not found" });
    const prov = await db("cloud_providers").where({ id: inst.provider_id }).first();
    if (b.op === "isolate" && req.user!.role !== "admin") return res.status(403).json({ error: "隔離の依頼は admin のみ" });
    const { describeAction } = await cloudSvc();
    const action = { provider_id: prov.id, instance_id: inst.id, op: b.op, params: { name: b.name, power: b.power, allow_cidrs: b.allow_cidrs } };
    const title = describeAction(action as any, prov.name, inst.name);
    const [apId] = await db("approvals").insert({ tool_call_id: null, session_id: null, host_id: inst.host_id ?? null, title, command: `cloud:${b.op} ${prov.kind}/${inst.service}/${inst.external_id}`, intent: b.reason ?? "（UI から依頼）", rollback: b.op === "isolate" ? "隔離前のセキュリティグループ / タグは exec_result.detail に記録されます" : b.op === "power" ? "逆の電源操作" : "スナップショットは削除せず残します",
      steps: j([{ purpose: title, command: `cloud API: ${b.op}` }]), auto_checks: j({ classification: "write", reason: "cloud API", checks: [] }), risk: b.op === "isolate" ? "high" : b.op === "power" && b.power !== "reboot" ? "medium" : "low", cloud_action: j(action) }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "cloud.action_requested", { approval_id: apId, ...action });
    res.json({ approval_id: apId });
  }));
  r.get("/attack-profiles", wrap(async (_req, res) => { const { loadConfig } = await import("../attackmap/index.js"); const c = loadConfig(); res.json({ profiles: c.profiles, cdn: Object.keys(c.cdn_ranges).filter((k) => k !== "_doc") }); }));
  r.get("/wazuh/:id/alerts", wrap(async (req, res) => {
    const q = parse(z.object({ minLevel: z.coerce.number().default(12), size: z.coerce.number().default(50), window: z.string().default("now-24h") }), req.query);
    const ix = await indexer(ctx, Number(req.params.id));
    res.json({ items: (await ix.recentAlerts(q.minLevel, q.size, q.window)).map(decorateAlert) });
  }));
  r.get("/wazuh/:id/alert/:alertId", wrap(async (req, res) => {
    const ix = await indexer(ctx, Number(req.params.id));
    const r2 = await ix.search("wazuh-alerts-*", { query: { ids: { values: [String(req.params.alertId)] } } }, 1);
    const h = r2.hits?.hits?.[0];
    if (!h) return res.status(404).json({ error: "alert not found" });
    res.json({ _id: h._id, _index: h._index, ...h._source });
  }));
  r.get("/wazuh/:id/process-tree", wrap(async (req, res) => {
    const q = parse(z.object({ agentId: z.string().min(1), guid: z.string().min(8), from: z.string().default("now-24h"), to: z.string().default("now") }), req.query);
    const { row } = await wazuhConn(ctx, Number(req.params.id));
    const ix = await indexer(ctx, Number(req.params.id));
    const tree = await buildProcessTree(ix, { agentId: q.agentId, guid: q.guid, from: q.from, to: q.to, preferArchives: !!row.archives_enabled });
    res.json(tree);
  }));
  r.get("/wazuh/:id/agents", wrap(async (req, res) => {
    const api = await managerApi(ctx, Number(req.params.id));
    res.json({ items: await api.agents() });
  }));

  // ---------- alert handling status (derived from Sidekick sessions + manual marks) ----------
  const isoTs = (v: any): string => { if (v == null) return new Date().toISOString(); if (typeof v === "number") return new Date(v).toISOString(); const str = String(v); return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(str) ? str : str.replace(" ", "T") + "Z").toISOString(); };
  const programOf = (a: any): string | null => { const img = a?.data?.win?.eventdata?.image ?? a?.data?.win?.eventdata?.parentImage; return img ? String(img).split(/[\\/]/).pop()!.toLowerCase() : null; };
  r.get("/alerts/handling", wrap(async (_req, res) => {
    const sess = await db("sessions").whereNotNull("alert_ref").whereNot("kind", "playbook_setup").select("id", "status", "label", "title", "alert_ref", "updated_at", "finished_at", "created_at");
    const fromSessions = sess.map((s: any) => { const a = pj(s.alert_ref); if (!a?.rule?.id) return null; const program = programOf(a);
      // a finished Sidekick investigation covers the same rule+program on every host (that is what an exclusion rule does); without a program, this host only
      // 完了後の猶予: 同種のアラートは一定期間「対応済み」のまま扱う（脆弱性検知は再スキャンまで同じアラートが続くので長め）
      const groups: string[] = Array.isArray(a.rule?.groups) ? a.rule.groups : [];
      const graceMs = (groups.includes("vulnerability-detector") || /^235\d\d$/.test(String(a.rule.id))) ? 7 * 86_400_000 : 24 * 3_600_000;
      const base = new Date(isoTs(s.finished_at ?? s.updated_at ?? s.created_at)).getTime();
      const vi = vulnIdentity(a);
      return { kind: "session", session_id: s.id, status: s.status, label: s.label || s.title, rule_id: String(a.rule.id), agent_id: String(a.agent?.id ?? ""), scope: program ? "program" : "agent", program, alert_id: a._id ?? null, alert_ts: a.timestamp ?? null, until: new Date(base + graceMs).toISOString(), vuln_cve: vi?.cve ?? null, vuln_package: vi?.package ?? null, alert: a }; }).filter(Boolean);
    const marks = (await db("alert_marks").orderBy("id", "desc")).map((m: any) => ({ kind: "manual", mark_id: m.id, session_id: m.session_id, status: "done", label: m.note || "手動で対応済みにした", rule_id: m.rule_id, agent_id: m.agent_id, scope: m.scope ?? "agent", program: m.program ?? null, alert_id: m.alert_id, alert_ts: pj(m.alert_json)?.timestamp ?? null, until: isoTs(m.until), vuln_cve: m.vuln_cve ?? null, vuln_package: m.vuln_package ?? null, alert: pj(m.alert_json) ?? null, created_at: isoTs(m.created_at) }));
    res.json({ items: [...fromSessions, ...marks] });
  }));
  r.post("/alerts/handling", wrap(async (req, res) => {
    const b = parse(z.object({ rule_id: z.string().min(1).max(16), agent_id: z.string().min(1).max(16), scope: z.enum(["agent", "program", "rule"]).default("agent"), program: z.string().max(255).optional().nullable(), alert_id: z.string().max(128).optional().nullable(), until: z.string().datetime({ offset: true }).optional(), note: z.string().max(500).optional(), alert: z.any().optional(), vuln_cve: z.string().max(64).optional().nullable(), vuln_package: z.string().max(255).optional().nullable() }), req.body);
    if (b.scope === "program" && !b.program) throw Object.assign(new Error("program is required for scope=program"), { status: 400 });
    // EDR-80: 脆弱性は agent + CVE + パッケージで一致させる（rule.id だけだと別 CVE まで対応済みになる）
    const vi = b.alert ? vulnIdentity(b.alert) : null;
    const vulnCve = (b.vuln_cve ?? vi?.cve ?? "").toUpperCase() || null, vulnPkg = (b.vuln_package ?? vi?.package ?? "").toLowerCase() || null;
    if (/^235\d\d$/.test(b.rule_id) && !vulnCve) throw Object.assign(new Error("vuln_cve is required for vulnerability alerts"), { status: 400 });
    const [id] = await db("alert_marks").insert({ rule_id: b.rule_id, agent_id: b.agent_id, scope: b.scope, program: b.scope === "program" ? String(b.program).toLowerCase() : null, alert_id: b.alert_id ?? null, until: b.until ? new Date(b.until) : new Date(), note: b.note ?? null, vuln_cve: vulnCve, vuln_package: vulnPkg, user_id: req.user!.id, alert_json: b.alert ? JSON.stringify(b.alert).slice(0, 200_000) : null }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "alert.marked_handled", { rule_id: b.rule_id, agent_id: b.agent_id, scope: b.scope, program: b.program ?? null, vuln_cve: vulnCve, vuln_package: vulnPkg, note: b.note });
    res.json({ id });
  }));
  r.delete("/alerts/handling/:id", wrap(async (req, res) => {
    const n = await db("alert_marks").where({ id: Number(req.params.id) }).delete();
    await audit.log("user", req.user!.id, "alert.unmarked", { mark_id: Number(req.params.id) });
    res.json({ ok: n > 0 });
  }));

  // ---------- rule notes (plain-language triage per rule id) ----------
  const pubNote = (n: any) => ({ rule_id: n.rule_id, title_ja: n.title_ja, meaning: n.meaning, cause: n.cause, impact: n.impact, action: n.action, triage: n.triage, source: n.source, updated_at: n.updated_at });
  r.get("/rule-notes", wrap(async (req, res) => {
    const ids = String(req.query.ids ?? "").split(",").map((x) => x.trim()).filter(Boolean).slice(0, 300);
    const rows = ids.length ? await db("rule_notes").whereIn("rule_id", ids) : await db("rule_notes").orderBy("rule_id");
    res.json({ items: Object.fromEntries(rows.map((n: any) => [n.rule_id, pubNote(n)])) });
  }));
  /** Generate notes for unknown rule ids with the LLM (one call, JSON array), store as source=ai. */
  r.post("/rule-notes/explain", requireRole("viewer"), wrap(async (req, res) => {
    const b = parse(z.object({ rules: z.array(z.object({ id: z.string().min(1).max(16), description: z.string().max(300), level: z.number().int(), groups: z.array(z.string().max(64)).max(12).optional(), sample: z.string().max(600).optional() })).min(1).max(20) }), req.body);
    const have = new Set((await db("rule_notes").whereIn("rule_id", b.rules.map((x) => x.id))).map((n: any) => n.rule_id));
    // EDR-80: 脆弱性ルールは CVE ごとに文言が変わるので rule.id 単位の AI メモを作らない（一覧 API の simple を使う）
    const todo = b.rules.filter((x) => !have.has(x.id) && !isVulnAlert({ rule: { groups: x.groups ?? [] } }) && !/^235\d\d$/.test(x.id));
    if (!todo.length) return res.json({ generated: 0 });
    const out = await ctx.runtime!.explainRules(todo);
    res.json({ generated: out });
  }));
  r.put("/rule-notes/:rule_id", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ title_ja: z.string().min(1).max(120), meaning: z.string().min(1), cause: z.string().min(1), impact: z.string().min(1), action: z.string().min(1), triage: z.enum(["benign_likely", "check", "danger"]) }), req.body);
    const id = String(req.params.rule_id);
    const ex = await db("rule_notes").where({ rule_id: id }).first();
    if (ex) await db("rule_notes").where({ rule_id: id }).update({ ...b, source: "user", updated_at: db.fn.now() }); else await db("rule_notes").insert({ rule_id: id, ...b, source: "user" });
    await audit.log("user", req.user!.id, "rule_note.updated", { rule_id: id });
    res.json(pubNote(await db("rule_notes").where({ rule_id: id }).first()));
  }));

  // ---------- ssh keys ----------
  const pubKey = (row: any) => ({ id: row.id, name: row.name, public_key: row.public_key, fingerprint: row.fingerprint, created_at: row.created_at });
  r.get("/ssh-keys", wrap(async (_req, res) => res.json({ items: (await db("ssh_keys").orderBy("id")).map(pubKey) })));
  r.post("/ssh-keys/generate", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ name: z.string().min(1).max(128) }), req.body);
    const k = generateEd25519(`edr-console:${b.name}`);
    const [id] = await db("ssh_keys").insert({ name: b.name, public_key: k.publicKey, private_key_enc: box.encrypt(k.privateKey), fingerprint: keyFingerprint(k.publicKey) }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "sshkey.generated", { id, name: b.name });
    res.status(201).json(pubKey(await db("ssh_keys").where({ id }).first()));
  }));
  r.post("/ssh-keys/import", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ name: z.string().min(1).max(128), private_key: z.string().min(50) }), req.body);
    const pub = publicFromPrivate(b.private_key);
    const [id] = await db("ssh_keys").insert({ name: b.name, public_key: pub, private_key_enc: box.encrypt(b.private_key), fingerprint: keyFingerprint(pub) }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "sshkey.imported", { id, name: b.name });
    res.status(201).json(pubKey(await db("ssh_keys").where({ id }).first()));
  }));
  r.delete("/ssh-keys/:id", requireRole("admin"), wrap(async (req, res) => {
    await db("ssh_keys").where({ id: Number(req.params.id) }).delete();
    await audit.log("user", req.user!.id, "sshkey.deleted", { id: Number(req.params.id) });
    res.json({ ok: true });
  }));

  // ---------- hosts ----------
  const hostSchema = z.object({
    name: z.string().min(1).max(128), wazuh_instance_id: z.number().int().nullable().optional(), agent_id: z.string().max(8).nullable().optional(),
    address: z.string().min(1), port: z.number().int().min(1).max(65535).default(22), ssh_user: z.string().min(1), ssh_key_id: z.number().int().nullable().optional(),
    sudo_mode: z.enum(["none", "nopasswd"]).default("none"), environment: z.enum(["lab", "staging", "production"]).default("lab"),
    autonomy_level: z.number().int().min(0).max(3).default(1), autonomy_max: z.number().int().min(0).max(3).default(2),
    maintenance_window: z.string().nullable().optional(), tags: z.array(z.string()).default([]), notes: z.string().nullable().optional(),
    scan_schedule_override: z.enum(["1d", "7d", "30d", "off"]).nullable().optional(), action_locked: z.boolean().optional(), // EDR-121
    role: z.enum(["auto", "server", "client"]).optional(), // EDR-154: stored in node_roles (shared with the dashboard), not in hosts
  });
  /** EDR-154: server / client PC for hosts (a manual choice in node_roles — shared with the dashboard — wins) */
  const hostRoles = async () => {
    const { guessRole } = await import("../hosts/role.js");
    const roles = Object.fromEntries((await db("node_roles")).map((x: any) => [String(x.agent_name).toLowerCase(), x.role]));
    const cloudNames = new Set((await db("cloud_instances").select("agent_name", "host_id")).flatMap((c: any) => [String(c.agent_name ?? "").toLowerCase(), `#${c.host_id}`]));
    return (h: any) => {
      const manual = roles[String(h.name).toLowerCase()];
      const auto = guessRole({ osName: h.agent_os, platform: h.os_family, groups: pj<string[]>(h.agent_groups) ?? null, cloud: cloudNames.has(String(h.name).toLowerCase()) || cloudNames.has(`#${h.id}`), kind: h.kind, agentId: h.agent_id });
      return { role: manual ?? auto, role_auto: auto, role_source: manual ? "manual" : "auto" };
    };
  };
  const pubHost = (row: any) => ({ ...row, tags: pj(row.tags) ?? [], last_test: pj(row.last_test), host_key: row.host_key ? row.host_key.split(" ")[0] + " (pinned)" : null });

  r.get("/hosts", wrap(async (req, res) => {
    const kind = typeof req.query.kind === "string" ? req.query.kind : null;
    let qb = db("hosts").orderBy("id"); if (kind === "managed" || kind === "agent_only") qb = qb.where({ kind });
    // EDR-144: Contain state for the host cards (applied / waiting for approval)
    const acts = await db("host_actions").where({ op: "isolate" }).whereIn("status", ["pending", "active", "unconfirmed"]).select("host_id", "status", "applied_at", "created_at");
    const by = new Map<number, any>(); for (const a of acts) { const cur = by.get(a.host_id); if (!cur || (cur.status === "pending" && a.status !== "pending")) by.set(a.host_id, a); }
    const roleOf = await hostRoles();
    // EDR-155: number of open AI suggestions per host (✦ in the list)
    const sgm = await import("../hosts/suggest.js");
    const latest = new Map<number, any>();
    for (const sc of await db("host_scans").where({ status: "done" }).whereIn("id", db("host_scans").where({ status: "done" }).max("id").groupBy("host_id")).select("host_id", "profile")) { const p = pj<any>(sc.profile); if (p?.suggest) latest.set(sc.host_id, p); }
    res.json({ items: (await qb).map((h: any) => {
      const a = by.get(h.id);
      return { ...pubHost(h), ...roleOf(h), ai_suggestions: latest.has(h.id) ? sgm.suggestionsFor(h, latest.get(h.id)).length : 0, contain: a ? { status: a.status === "pending" ? "pending" : "isolated", since: a.status === "pending" ? a.created_at : a.applied_at } : null };
    }) });
  }));
  r.post("/hosts", requireRole("admin"), wrap(async (req, res) => {
    const { role, ...b } = parse(hostSchema, req.body);
    if (role && role !== "auto") { await db("node_roles").whereRaw("lower(agent_name) = ?", [b.name.toLowerCase()]).delete(); await db("node_roles").insert({ agent_name: b.name, role }); }
    const [id] = await db("hosts").insert({ ...b, tags: j(b.tags) }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "host.created", { id, name: b.name });
    res.status(201).json(pubHost(await db("hosts").where({ id }).first()));
  }));
  r.put("/hosts/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = parse(hostSchema.partial(), req.body);
    const cur = await db("hosts").where({ id }).first();
    if (!cur) return res.status(404).json({ error: "host not found" });
    const { role, ...rest } = b;
    const upd: any = { ...rest, updated_at: db.fn.now() };
    if (role) {
      const nm = String(b.name ?? cur.name);
      await db("node_roles").whereRaw("lower(agent_name) = ?", [nm.toLowerCase()]).delete();
      if (role !== "auto") await db("node_roles").insert({ agent_name: nm, role });
    }
    if (b.action_locked === false && String(cur.agent_id) === "000") throw Object.assign(new Error("Wazuh manager のエージェント（000）は常に遮断の対象外です"), { status: 400 });
    // EDR-121: an agent-only host becomes a managed (SSH) host once SSH is configured
    if (cur.kind === "agent_only" && (b.ssh_key_id ?? cur.ssh_key_id) && (b.ssh_user ?? cur.ssh_user)) upd.kind = "managed";
    if (b.tags) upd.tags = j(b.tags);
    if (b.autonomy_level !== undefined && b.autonomy_level > ctx.cfg.AUTONOMY_MAX) throw Object.assign(new Error(`autonomy_level exceeds AUTONOMY_MAX=${ctx.cfg.AUTONOMY_MAX}`), { status: 400 });
    // EDR-155: a person set these fields → the AI does not suggest them again (unless the purpose changes)
    {
      const sgm = await import("../hosts/suggest.js");
      const dec = sgm.decisionsOf(cur); const lp = await sgm.latestProfile(ctx, id); const pk = lp?.profile?.suggest?.purpose_key ?? null;
      const changedNow: Array<"notes" | "tags" | "environment"> = [];
      if (b.notes !== undefined && (b.notes ?? "") !== (cur.notes ?? "")) changedNow.push("notes");
      if (b.tags !== undefined && JSON.stringify(b.tags) !== JSON.stringify(pj(cur.tags) ?? [])) changedNow.push("tags");
      if (b.environment !== undefined && b.environment !== cur.environment) changedNow.push("environment");
      for (const f of changedNow) dec[f] = { state: "manual", purpose_key: pk, at: new Date().toISOString() };
      if (changedNow.length) upd.ai_decisions = JSON.stringify(dec);
    }
    await db("hosts").where({ id }).update(upd);
    await audit.log("user", req.user!.id, "host.updated", { id, fields: Object.keys(b) });
    res.json(pubHost(await db("hosts").where({ id }).first()));
  }));
  r.delete("/hosts/:id", requireRole("admin"), wrap(async (req, res) => {
    const h0 = await db("hosts").where({ id: Number(req.params.id) }).first();
    if (h0?.agent_id && h0.wazuh_instance_id) { // EDR-121: do not import this agent again
      const row = await db("app_flags").where({ key: "host_sync_ignore" }).first();
      let list: string[] = []; try { list = JSON.parse(row?.value ?? "[]"); } catch { list = []; }
      const k = `${h0.wazuh_instance_id}:${h0.agent_id}`;
      if (!list.includes(k)) { list.push(k); if (row) await db("app_flags").where({ key: "host_sync_ignore" }).update({ value: JSON.stringify(list), updated_at: db.fn.now() }); else await db("app_flags").insert({ key: "host_sync_ignore", value: JSON.stringify(list) }); }
    }
    await db("hosts").where({ id: Number(req.params.id) }).delete();
    await audit.log("user", req.user!.id, "host.deleted", { id: Number(req.params.id), name: h0?.name, agent_id: h0?.agent_id ?? null, sync_ignored: !!(h0?.agent_id && h0.wazuh_instance_id) });
    res.json({ ok: true });
  }));
  // EDR-155: AI suggestions for the host settings (from the latest AI scan)
  r.get("/hosts/:id/suggestions", requireRole("viewer"), wrap(async (req, res) => {
    const h = await db("hosts").where({ id: Number(req.params.id) }).first(); if (!h) return res.status(404).json({ error: "host not found" });
    const sgm = await import("../hosts/suggest.js"); const lp = await sgm.latestProfile(ctx, h.id);
    res.json({ scan_id: lp?.scan_id ?? null, items: lp ? sgm.suggestionsFor(h, lp.profile) : [] });
  }));
  r.post("/hosts/:id/suggestions/:field", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ action: z.enum(["apply", "dismiss"]) }), req.body);
    const field = z.enum(["notes", "tags", "environment"]).parse(req.params.field);
    const h = await db("hosts").where({ id: Number(req.params.id) }).first(); if (!h) return res.status(404).json({ error: "host not found" });
    const sgm = await import("../hosts/suggest.js"); const lp = await sgm.latestProfile(ctx, h.id);
    const it = lp ? sgm.suggestionsFor(h, lp.profile).find((x) => x.field === field) : null;
    if (!it) return res.status(409).json({ error: "この提案はもうありません（画面を更新してください）" });
    if (b.action === "apply") {
      const upd: any = { updated_at: db.fn.now() };
      if (field === "notes") upd.notes = String(it.value);
      if (field === "tags") upd.tags = j(it.value);
      if (field === "environment") upd.environment = it.value;
      await db("hosts").where({ id: h.id }).update(upd);
    }
    await sgm.decide(ctx, { ...h }, field, b.action === "apply" ? "applied" : "dismissed", it.purpose_key);
    await audit.log("user", req.user!.id, "host.ai_suggestion", { id: h.id, field, action: b.action, value: b.action === "apply" ? it.value : undefined, changed: it.changed });
    const h2 = await db("hosts").where({ id: h.id }).first();
    res.json({ items: lp ? sgm.suggestionsFor(h2, lp.profile) : [] });
  }));

  // EDR-153: agents that are NOT imported again because an admin deleted their host — list and undo
  r.get("/hosts/sync-ignore", requireRole("viewer"), wrap(async (_req, res) => {
    const { listSyncIgnore } = await import("../hosts/sync.js");
    res.json({ items: await listSyncIgnore(ctx) });
  }));
  r.delete("/hosts/sync-ignore/:key", requireRole("admin"), wrap(async (req, res) => {
    const { unignoreAgent, syncAgents } = await import("../hosts/sync.js");
    const removed = await unignoreAgent(ctx, String(req.params.key));
    if (!removed) return res.status(404).json({ error: "not in the list" });
    await audit.log("user", req.user!.id, "host.sync_unignored", { key: req.params.key });
    res.json(await syncAgents(ctx));
  }));
  r.post("/hosts/:id/reset-hostkey", requireRole("admin"), wrap(async (req, res) => {
    await db("hosts").where({ id: Number(req.params.id) }).update({ host_key: null, updated_at: db.fn.now() });
    await audit.log("user", req.user!.id, "host.hostkey_reset", { id: Number(req.params.id) });
    res.json({ ok: true });
  }));
  r.post("/hosts/:id/test", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const h = await db("hosts").where({ id }).first();
    if (!h) return res.status(404).json({ error: "host not found" });
    if (!h.ssh_key_id) return res.status(400).json({ error: "host has no ssh key" });
    const k = await db("ssh_keys").where({ id: h.ssh_key_id }).first();
    const started = Date.now();
    try {
      const r1 = await sshExec({ address: h.address, port: h.port, user: h.ssh_user, privateKey: box.decrypt(k.private_key_enc), sudoMode: h.sudo_mode, hostKey: h.host_key },
        "hostname; id -un; uptime -p 2>/dev/null || uptime; (command -v fail2ban-client >/dev/null && echo fail2ban=yes || echo fail2ban=no); (sudo -n true 2>/dev/null && echo sudo=ok || echo sudo=no)", 20000);
      const upd: any = { last_test: j({ ok: r1.code === 0, at: new Date().toISOString(), code: r1.code, ms: r1.durationMs, stdout: r1.stdout.slice(0, 2000), stderr: r1.stderr.slice(0, 1000) }), updated_at: db.fn.now() };
      if (!h.host_key && r1.hostKey) upd.host_key = r1.hostKey;
      await db("hosts").where({ id }).update(upd);
      await audit.log("user", req.user!.id, "host.tested", { id, name: h.name, code: r1.code, ms: r1.durationMs });
      res.json({ ok: r1.code === 0, ...r1, hostKey: r1.hostKey.split(" ")[0] });
    } catch (e: any) {
      await db("hosts").where({ id }).update({ last_test: j({ ok: false, at: new Date().toISOString(), error: e.message }), updated_at: db.fn.now() });
      await audit.log("user", req.user!.id, "host.test_failed", { id, name: h.name, error: e.message, ms: Date.now() - started });
      res.status(502).json({ ok: false, error: e.message });
    }
  }));

  /** Everything the host detail page shows: Wazuh agent state, related playbooks, recent approvals and sessions. */
  r.get("/hosts/:id/detail", wrap(async (req, res) => {
    const id = Number(req.params.id);
    const h = await db("hosts").where({ id }).first();
    if (!h) return res.status(404).json({ error: "host not found" });
    let agent: any = null;
    if (h.agent_id) { try { const api = await managerApi(ctx, h.wazuh_instance_id ?? (await db("wazuh_instances").orderBy("id").first())?.id); const r2: any = await api.get(`/agents?agents_list=${encodeURIComponent(h.agent_id)}&select=id,name,status,ip,os.name,os.version,version,lastKeepAlive,dateAdd,group`); agent = r2?.data?.affected_items?.[0] ?? null; } catch (e: any) { agent = { error: e.message }; } }
    const playbooks = (await db("playbooks").orderBy("id")).map(pubPlaybook).filter((p: any) => (p.meta?.targets ?? []).some((t: string) => t.toLowerCase() === h.name.toLowerCase()) || String(p.markdown).includes(h.name)).map((p: any) => ({ id: p.id, name: p.name, purpose: p.meta?.purpose ?? "", enabled: p.enabled }));
    const approvals = (await db("approvals").where({ host_id: id }).orderBy("id", "desc").limit(10)).map((a: any) => ({ id: a.id, session_id: a.session_id, title: a.title, command: a.command, decision: a.decision, decided_at: a.decided_at, risk: a.risk, exec: pj(a.exec_result)?.status ?? null, exit_code: pj(a.exec_result)?.exit_code ?? null }));
    const apSessions = new Set(approvals.map((a: any) => a.session_id));
    const sessions = (await db("sessions").orderBy("id", "desc").limit(200)).filter((s: any) => apSessions.has(s.id) || (pj<any>(s.summary)?.host_ids ?? []).includes(id)).slice(0, 10).map((s: any) => ({ id: s.id, title: s.title, status: s.status, kind: s.kind, origin: s.origin, created_at: s.created_at }));
    const key = h.ssh_key_id ? await db("ssh_keys").where({ id: h.ssh_key_id }).first() : null;
    res.json({ host: { ...pubHost(h), ...(await hostRoles())(h) }, key: key ? { id: key.id, name: key.name, fingerprint: key.fingerprint, public_key: key.public_key } : null, agent, playbooks, approvals, sessions });
  }));

  // ---------- EDR-121: host card (AI scan) and host actions ----------
  const hostOr404 = async (req: Request, res: Response) => { const h = await db("hosts").where({ id: Number(req.params.id) }).first(); if (!h) { res.status(404).json({ error: "host not found" }); return null; } return h; };
  r.post("/hosts/sync", requireRole("admin"), wrap(async (req, res) => {
    const { syncAgents } = await import("../hosts/sync.js");
    const r1 = await syncAgents(ctx);
    await audit.log("user", req.user!.id, "host.agents_synced", { created: r1.created.length, updated: r1.updated });
    res.json(r1);
  }));
  // EDR-142: what Contain would do to this host, explained by the AI from the latest scan (cached per scan)
  r.get("/hosts/:id/contain-impact", requireRole("viewer"), wrap(async (req, res) => {
    const h = await hostOr404(req, res); if (!h) return;
    const { getImpact } = await import("../hosts/containImpact.js");
    res.json(await getImpact(ctx, h));
  }));
  r.post("/hosts/:id/contain-impact", requireRole("operator"), wrap(async (req, res) => {
    const h = await hostOr404(req, res); if (!h) return;
    const { generateImpact, getImpact } = await import("../hosts/containImpact.js");
    await generateImpact(ctx, h, req.user!.id);
    res.json(await getImpact(ctx, h));
  }));
  r.get("/hosts/:id/profile", wrap(async (req, res) => {
    const h = await hostOr404(req, res); if (!h) return;
    const { capability, OP_JA } = await import("../hosts/actions.js");
    const latest = await db("host_scans").where({ host_id: h.id }).orderBy("id", "desc").first();
    const done = latest?.status === "done" ? latest : await db("host_scans").where({ host_id: h.id, status: "done" }).orderBy("id", "desc").first();
    const actions = (await db("host_actions").where({ host_id: h.id }).orderBy("id", "desc").limit(30)).map((a: any) => ({ ...a, params: pj(a.params), result: pj(a.result), label: a.op === "pack_update" ? `エージェントパックを r${pj<any>(a.params)?.rev ?? "?"} に更新` : (OP_JA[a.op as keyof typeof OP_JA] ?? a.op) }));
    const approvalIds = actions.flatMap((a: any) => [a.approval_id, a.revert_approval_id]).filter(Boolean);
    const aps = approvalIds.length ? await db("approvals").whereIn("id", approvalIds).select("id", "decision", "exec_result") : [];
    const apMap = Object.fromEntries(aps.map((a: any) => [a.id, { decision: a.decision, exec: pj<any>(a.exec_result)?.status ?? null }]));
    res.json({
      host: pubHost(h), capability: await capability(ctx, h),
      latest: latest ? { id: latest.id, status: latest.status, stage: latest.stage, trigger: latest.trigger, error: latest.error, created_at: latest.created_at, started_at: latest.started_at, finished_at: latest.finished_at } : null,
      scan: done ? { id: done.id, finished_at: done.finished_at, model: done.model, tokens: (done.tokens_in ?? 0) + (done.tokens_out ?? 0), facts: pj(done.facts), profile: pj(done.profile), diff: pj(done.diff) } : null,
      actions: actions.map((a: any) => ({ ...a, approval: apMap[a.approval_id] ?? null, revert_approval: apMap[a.revert_approval_id] ?? null })),
      win_updates: h.win_updates ? await (async () => { const { PROTECTED_APPS } = await import("../hosts/actions.js"); const w = pj<any>(h.win_updates) ?? {}; const apps = (w.apps ?? []).filter((a: any) => !PROTECTED_APPS.includes(String(a.id))); return { ...w, apps, app_count: apps.length, checked_at: h.win_updates_at }; })() : null, // EDR-168 (scans stored before the Wazuh agent was hidden)
      addon_published: (await import("../hosts/actions.js")).publishedAddon(ctx), // EDR-169
      pack_windows: h.os_family === "windows" ? await (async () => { const ap = await import("../agentpack/index.js"); const lr = await ap.latestRev(ctx, "windows"); const ov = lr ? await ap.overview(ctx) : null; return { latest: lr?.id ?? null, addon_only: (ov?.packs as any)?.windows?.addon_only ?? [], same_as: (ov?.packs as any)?.windows?.same_as ?? [], addon_version: (ov?.packs as any)?.windows?.addon_version ?? null }; })() : null, // EDR-171
    });
  }));
  r.get("/hosts/:id/scans", wrap(async (req, res) => {
    const rows = await db("host_scans").where({ host_id: Number(req.params.id) }).orderBy("id", "desc").limit(20).select("id", "status", "stage", "trigger", "error", "model", "tokens_in", "tokens_out", "created_at", "finished_at", "diff");
    res.json({ items: rows.map((x: any) => ({ ...x, diff: pj(x.diff) })) });
  }));
  r.post("/hosts/:id/scan", requireRole("operator"), wrap(async (req, res) => {
    const h = await hostOr404(req, res); if (!h) return;
    if (!ctx.hostScanner) return res.status(503).json({ error: "host scanner not running" });
    res.json({ scan_id: await ctx.hostScanner.enqueue(h.id, "manual", req.user!.id) });
  }));
  r.post("/hosts/:id/actions", requireRole("operator"), wrap(async (req, res) => {
    const h = await hostOr404(req, res); if (!h) return;
    const { requestAction, paramsSchema, OPS } = await import("../hosts/actions.js");
    const b = parse(z.object({ op: z.enum(OPS), params: paramsSchema.default({}), reason: z.string().max(1000).optional() }), req.body);
    if (b.op === "isolate" && req.user!.role !== "admin") return res.status(403).json({ error: "隔離の依頼は admin のみ" });
    res.json(await requestAction(ctx, { host: h, op: b.op, params: b.params, userId: req.user!.id, reason: b.reason }));
  }));
  r.post("/hosts/:id/actions/:aid/revert", requireRole("operator"), wrap(async (req, res) => {
    const h = await hostOr404(req, res); if (!h) return;
    const { requestAction } = await import("../hosts/actions.js");
    const b = parse(z.object({ reason: z.string().max(1000).optional() }), req.body ?? {});
    res.json(await requestAction(ctx, { host: h, op: "isolate", params: {}, userId: req.user!.id, reason: b.reason ?? "（ホスト画面から解除を依頼）", revertOf: Number(req.params.aid) }));
  }));
  r.post("/hosts/:id/win-updates", requireRole("operator"), wrap(async (req, res) => { // EDR-168: read-only scan on the endpoint
    const h = await hostOr404(req, res); if (!h) return;
    const { scanWindowsUpdates } = await import("../hosts/actions.js");
    const r1 = await scanWindowsUpdates(ctx, h, req.body?.apps !== false);
    await audit.log("user", req.user!.id, "host.win_updates_scanned", { host: h.name, ok: r1.ok, wu: r1.scan?.wu_count, apps: r1.scan?.app_count });
    res.status(r1.ok ? 200 : 502).json(r1.ok ? r1 : { error: r1.message });
  }));
  r.post("/hosts/:id/addon-update", requireRole("operator"), wrap(async (req, res) => { // EDR-169: no approval card (signed + self-test + rollback on the endpoint)
    const h = await hostOr404(req, res); if (!h) return;
    const { startAddonUpdate } = await import("../hosts/actions.js");
    try { res.json(await startAddonUpdate(ctx, h, req.user!.id)); }
    catch (e: any) { res.status(e?.status ?? 400).json({ error: String(e?.message ?? e) }); }
  }));
  r.post("/hosts/:id/pack-update", requireRole("operator"), wrap(async (req, res) => { // EDR-171: no approval card
    const h = await hostOr404(req, res); if (!h) return;
    const { startPackUpdate } = await import("../hosts/actions.js");
    try { res.json(await startPackUpdate(ctx, h, req.user!.id)); }
    catch (e: any) { res.status(e?.status ?? 400).json({ error: String(e?.message ?? e) }); }
  }));
  r.post("/hosts/:id/addon-check", requireRole("operator"), wrap(async (req, res) => {
    const h = await hostOr404(req, res); if (!h) return;
    const { checkAddon } = await import("../hosts/actions.js");
    const r1 = await checkAddon(ctx, h);
    await audit.log("user", req.user!.id, "host.addon_checked", { host: h.name, version: r1.version });
    res.json(r1);
  }));
  r.get("/settings/host-scan", requireRole("viewer"), wrap(async (_req, res) => {
    const { getSchedule, getPseudonymize, SCHEDULE_CHOICES } = await import("../hosts/scan.js");
    res.json({ schedule: await getSchedule(ctx), pseudonymize_users: await getPseudonymize(ctx), choices: SCHEDULE_CHOICES, ai: ctx.cfg.HOST_SCAN_AI && !!ctx.runtime?.llmProvider, ar_configured: !!(ctx.cfg.WAZUH_AR_USER && ctx.cfg.WAZUH_AR_PASSWORD), ar_addon_min: ctx.cfg.AR_ADDON_MIN_VERSION });
  }));
  r.put("/settings/host-scan", requireRole("admin"), wrap(async (req, res) => {
    if (req.authVia !== "cookie") return res.status(403).json({ error: "sign in to the console to change this" });
    const { setSchedule, getSchedule, getPseudonymize, SCHEDULE_CHOICES } = await import("../hosts/scan.js");
    const b = parse(z.object({ schedule: z.record(z.enum(SCHEDULE_CHOICES)).optional(), pseudonymize_users: z.boolean().optional() }), req.body);
    if (b.schedule) await setSchedule(ctx, b.schedule, req.user!.id);
    if (b.pseudonymize_users !== undefined) {
      const ex = await db("app_flags").where({ key: "host_scan_pseudonymize_users" }).first();
      if (ex) await db("app_flags").where({ key: "host_scan_pseudonymize_users" }).update({ value: String(b.pseudonymize_users), updated_by: req.user!.id, updated_at: db.fn.now() });
      else await db("app_flags").insert({ key: "host_scan_pseudonymize_users", value: String(b.pseudonymize_users), updated_by: req.user!.id });
    }
    await audit.log("user", req.user!.id, b.pseudonymize_users === false ? "host.scan_settings_privacy_off" : "host.scan_settings_changed", { schedule: b.schedule, pseudonymize_users: b.pseudonymize_users });
    res.json({ schedule: await getSchedule(ctx), pseudonymize_users: await getPseudonymize(ctx) });
  }));

  // ---------- playbooks (structured; markdown generated for the agent) ----------
  const pubPlaybook = (p: any) => { const meta = pj(p.meta) ?? parseMarkdown(p.markdown); return { ...p, meta, structured: !!p.meta, enabled: !!p.enabled, builtin: !!p.builtin }; };
  const pbSchema = z.object({ name: z.string().min(1).max(128), scope: z.enum(["global", "wazuh", "hostgroup", "host"]).default("global"), scope_ref: z.string().nullable().optional(), markdown: z.string().min(1).optional(), meta: playbookMetaSchema.optional(), enabled: z.boolean().default(true) });
  const SECRET_RE = /(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/i;
  r.get("/playbooks", wrap(async (_req, res) => res.json({ items: (await db("playbooks").orderBy("id")).map(pubPlaybook) })));
  r.get("/playbooks/:id", wrap(async (req, res) => { const p = await db("playbooks").where({ id: Number(req.params.id) }).first(); if (!p) return res.status(404).json({ error: "not found" }); res.json(pubPlaybook(p)); }));
  r.post("/playbooks", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(pbSchema, req.body);
    if (await db("playbooks").where({ name: b.name }).first()) throw Object.assign(new Error("a playbook with this name already exists"), { status: 409 });
    const meta = b.meta ? coerceMeta(b.meta) : null;
    const markdown = meta ? renderMarkdown(b.name, meta) : b.markdown;
    if (!markdown) throw Object.assign(new Error("meta or markdown required"), { status: 400 });
    if (SECRET_RE.test(markdown)) throw Object.assign(new Error("the content seems to contain a secret (password/key/token)"), { status: 400 });
    const [id] = await db("playbooks").insert({ name: b.name, scope: b.scope, scope_ref: b.scope_ref ?? null, markdown, meta: meta ? j(meta) : null, enabled: b.enabled, builtin: false }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "playbook.created", { id, name: b.name, structured: !!meta });
    res.status(201).json(pubPlaybook(await db("playbooks").where({ id }).first()));
  }));
  r.put("/playbooks/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const ex = await db("playbooks").where({ id }).first();
    if (!ex) return res.status(404).json({ error: "not found" });
    const b = parse(pbSchema.partial(), req.body);
    const upd: any = { updated_at: db.fn.now() };
    if (b.name !== undefined) upd.name = b.name;
    if (b.scope !== undefined) upd.scope = b.scope;
    if (b.scope_ref !== undefined) upd.scope_ref = b.scope_ref;
    if (b.enabled !== undefined) upd.enabled = b.enabled;
    if (b.meta) { const meta = coerceMeta(b.meta); upd.meta = j(meta); upd.markdown = renderMarkdown(b.name ?? ex.name, meta); }
    else if (b.markdown) { upd.markdown = b.markdown; upd.meta = null; }
    else if (b.name && ex.meta) upd.markdown = renderMarkdown(b.name, coerceMeta(pj(ex.meta)));
    if (upd.markdown && SECRET_RE.test(upd.markdown)) throw Object.assign(new Error("the content seems to contain a secret (password/key/token)"), { status: 400 });
    const contentChanged = upd.markdown !== undefined;
    const q = db("playbooks").where({ id }).update(upd);
    if (contentChanged) await q.increment("version", 1); else await q;
    await audit.log("user", req.user!.id, "playbook.updated", { id, fields: Object.keys(b) });
    res.json(pubPlaybook(await db("playbooks").where({ id }).first()));
  }));
  /** Convert a legacy markdown playbook into the structured model (heuristic; the AI can refine it afterwards). */
  r.post("/playbooks/:id/structure", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const ex = await db("playbooks").where({ id }).first();
    if (!ex) return res.status(404).json({ error: "not found" });
    const meta = parseMarkdown(ex.markdown);
    await db("playbooks").where({ id }).update({ meta: j(meta), markdown: renderMarkdown(ex.name, meta), updated_at: db.fn.now() }).increment("version", 1);
    await audit.log("user", req.user!.id, "playbook.structured", { id });
    res.json(pubPlaybook(await db("playbooks").where({ id }).first()));
  }));
  r.delete("/playbooks/:id", requireRole("admin"), wrap(async (req, res) => {
    const ex = await db("playbooks").where({ id: Number(req.params.id) }).first();
    if (ex?.builtin) { await db("playbooks").where({ id: ex.id }).update({ enabled: false, updated_at: db.fn.now() }); await audit.log("user", req.user!.id, "playbook.disabled", { id: ex.id, note: "builtin: disabled instead of deleted" }); return res.json({ ok: true, disabled: true }); }
    await db("playbooks").where({ id: Number(req.params.id) }).delete();
    await audit.log("user", req.user!.id, "playbook.deleted", { id: Number(req.params.id) });
    res.json({ ok: true });
  }));

  // ---------- protected ranges ----------
  r.get("/protected-ranges", wrap(async (_req, res) => res.json({ items: await db("protected_ranges").orderBy("id") })));
  r.post("/protected-ranges", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ cidr: z.string().regex(/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/), label: z.string().min(1), reason: z.string().nullable().optional(), host_id: z.number().int().nullable().optional() }), req.body);
    const [id] = await db("protected_ranges").insert(b).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "protected_range.created", { id, cidr: b.cidr, label: b.label });
    res.status(201).json(await db("protected_ranges").where({ id }).first());
  }));
  r.delete("/protected-ranges/:id", requireRole("admin"), wrap(async (req, res) => {
    await db("protected_ranges").where({ id: Number(req.params.id) }).delete();
    await audit.log("user", req.user!.id, "protected_range.deleted", { id: Number(req.params.id) });
    res.json({ ok: true });
  }));

  // ---------- audit ----------
  r.get("/audit", wrap(async (req, res) => {
    const q = parse(z.object({ limit: z.coerce.number().min(1).max(500).default(100), before: z.coerce.number().optional(), event: z.string().optional() }), req.query);
    let qb = db("audit_log").orderBy("id", "desc").limit(q.limit);
    if (q.before !== undefined) qb = qb.where("id", "<", q.before);
    if (q.event) qb = qb.where("event", "like", `${q.event}%`);
    res.json({ items: (await qb).map((x: any) => ({ ...x, payload: pj(x.payload) })) });
  }));

  // ---------- users (admin) ----------
  const roleEnum = z.enum(["admin", "operator", "viewer"]);
  const pubUser = (u: any) => ({ id: u.id, email: u.email, name: u.name, role: u.role, locale: u.locale, disabled: !!u.disabled, must_change_password: !!u.must_change_password, mfa_enabled: !!u.totp_enabled, mfa_enrolled_at: u.mfa_enrolled_at ?? null, created_at: u.created_at, updated_at: u.updated_at });
  const adminCount = async () => Number((await db("users").where({ role: "admin", disabled: false }).count<{ c: number }[]>({ c: "*" }).first())?.c ?? 0);

  r.get("/users", requireRole("admin"), wrap(async (_req, res) => {
    const users = (await db("users").orderBy("id")).map(pubUser);
    const tokens = await db("api_tokens").select("id", "user_id", "name", "prefix", "expires_at", "last_used_at", "created_at", "allowed_ips");
    res.json({ items: users.map((u) => ({ ...u, tokens: tokens.filter((t: any) => t.user_id === u.id) })) });
  }));
  r.post("/users", requireRole("admin"), wrap(async (req, res) => {
    const b = parse(z.object({ email: z.string().email(), name: z.string().min(1), password: z.string().min(12), role: roleEnum, must_change_password: z.boolean().default(true) }), req.body);
    const { hashPassword } = await import("../crypto/index.js");
    if (await db("users").where({ email: b.email }).first()) throw Object.assign(new Error("email already exists"), { status: 409 });
    const [id] = await db("users").insert({ email: b.email, name: b.name, password_hash: hashPassword(b.password), role: b.role, must_change_password: b.must_change_password }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "user.created", { id, email: b.email, role: b.role });
    res.status(201).json(pubUser(await db("users").where({ id }).first()));
  }));
  r.put("/users/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = parse(z.object({ name: z.string().min(1).optional(), role: roleEnum.optional(), disabled: z.boolean().optional(), locale: z.enum(["ja", "en"]).optional() }), req.body);
    const u = await db("users").where({ id }).first();
    if (!u) return res.status(404).json({ error: "user not found" });
    // never lock everyone out: the last active admin cannot be demoted or disabled
    const losesAdmin = u.role === "admin" && !u.disabled && ((b.role && b.role !== "admin") || b.disabled === true);
    if (losesAdmin && (await adminCount()) <= 1) throw Object.assign(new Error("cannot demote/disable the last admin"), { status: 400 });
    if (id === req.user!.id && (b.disabled === true || (b.role && b.role !== "admin"))) throw Object.assign(new Error("you cannot disable or demote yourself"), { status: 400 });
    await db("users").where({ id }).update({ ...b, updated_at: db.fn.now() });
    if (b.disabled === true) await db("auth_sessions").where({ user_id: id }).delete();
    await audit.log("user", req.user!.id, "user.updated", { id, email: u.email, fields: b });
    res.json(pubUser(await db("users").where({ id }).first()));
  }));
  r.post("/users/:id/reset-password", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = parse(z.object({ password: z.string().min(12), must_change_password: z.boolean().default(true) }), req.body);
    const u = await db("users").where({ id }).first();
    if (!u) return res.status(404).json({ error: "user not found" });
    const { hashPassword } = await import("../crypto/index.js");
    await db("users").where({ id }).update({ password_hash: hashPassword(b.password), must_change_password: b.must_change_password, updated_at: db.fn.now() });
    await db("auth_sessions").where({ user_id: id }).delete();
    await audit.log("user", req.user!.id, "user.password_reset", { id, email: u.email });
    res.json({ ok: true });
  }));
  // EDR-90: reset someone's MFA (lost phone / new phone). The next sign-in registers an authenticator again.
  r.post("/users/:id/mfa/reset", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const u = await db("users").where({ id }).first();
    if (!u) return res.status(404).json({ error: "user not found" });
    await auth.mfaReset(id);
    await audit.log("user", req.user!.id, "user.mfa_reset", { id, email: u.email });
    res.json({ ok: true });
  }));
  r.delete("/users/:id", requireRole("admin"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const u = await db("users").where({ id }).first();
    if (!u) return res.status(404).json({ error: "user not found" });
    if (id === req.user!.id) throw Object.assign(new Error("you cannot delete yourself"), { status: 400 });
    if (u.role === "admin" && !u.disabled && (await adminCount()) <= 1) throw Object.assign(new Error("cannot delete the last admin"), { status: 400 });
    await db("users").where({ id }).delete();
    await audit.log("user", req.user!.id, "user.deleted", { id, email: u.email });
    res.json({ ok: true });
  }));

  // ---------- API tokens (service accounts; e.g. an external AI agent testing via the API) ----------
  // admin: any user's tokens. operator/viewer: only their own (same role as the user, never more).
  r.post("/users/:id/tokens", requireRole("viewer"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (req.user!.role !== "admin" && id !== req.user!.id) return res.status(403).json({ error: "forbidden" });
    // EDR-90: every new token has an expiry and (by default) a source-IP allow list
    const ipRe = /^(\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?|[0-9a-fA-F:]+)$/;
    const b = parse(z.object({ name: z.string().min(1).max(128), expires_days: z.number().int().min(1).max(ctx.cfg.API_TOKEN_MAX_DAYS), allowed_ips: z.array(z.string().trim().regex(ipRe, "IP or IPv4 CIDR")).max(32).default([]) }), req.body);
    if (ctx.cfg.API_TOKEN_REQUIRE_IP && !b.allowed_ips.length) throw Object.assign(new Error("allowed_ips is required (IP or CIDR the token may be used from)"), { status: 400 });
    const u = await db("users").where({ id, disabled: false }).first();
    if (!u) return res.status(404).json({ error: "user not found" });
    const exp = new Date(Date.now() + b.expires_days * 86400_000);
    const t = await auth.createToken(id, b.name, req.user!.id, exp, b.allowed_ips);
    await audit.log("user", req.user!.id, "api_token.created", { token_id: t.id, user_id: id, email: u.email, name: b.name, expires_at: exp, allowed_ips: b.allowed_ips });
    res.status(201).json({ id: t.id, name: b.name, prefix: t.prefix, token: t.token, expires_at: exp, allowed_ips: b.allowed_ips, note: "store this token now; it is not shown again" });
  }));
  r.delete("/users/:id/tokens/:tid", requireRole("viewer"), wrap(async (req, res) => {
    const id = Number(req.params.id), tid = Number(req.params.tid);
    if (req.user!.role !== "admin" && id !== req.user!.id) return res.status(403).json({ error: "forbidden" });
    await db("api_tokens").where({ id: tid, user_id: id }).delete();
    await audit.log("user", req.user!.id, "api_token.revoked", { token_id: tid, user_id: id });
    res.json({ ok: true });
  }));
  // EDR-119: global On/Off for API (bearer token) access. Changing it is cookie-only (a token can't switch the API back on or off).
  r.get("/settings/api-access", requireRole("viewer"), wrap(async (_req, res) => res.json(await auth.apiAccess())));
  r.put("/settings/api-access", requireRole("admin"), wrap(async (req, res) => {
    if (req.authVia !== "cookie") return res.status(403).json({ error: "sign in to the console to change this" });
    const b = parse(z.object({ on: z.boolean(), reason: z.string().max(300).optional() }), req.body);
    await auth.setApiAccess(b.on, req.user!.id, b.reason);
    await audit.log("user", req.user!.id, b.on ? "api_access.enabled" : "api_access.disabled", { reason: b.reason ?? null });
    res.json(await auth.apiAccess());
  }));
  // EDR-120: idle timeout for console sessions (1h/6h/12h/24h/7d/none). Cookie sign-in only.
  r.get("/settings/session-timeout", requireRole("viewer"), wrap(async (_req, res) => res.json({ ...(await auth.sessionTimeout()), options: Object.keys(SESSION_TIMEOUTS) })));
  r.put("/settings/session-timeout", requireRole("admin"), wrap(async (req, res) => {
    if (req.authVia !== "cookie") return res.status(403).json({ error: "sign in to the console to change this" });
    const b = parse(z.object({ timeout: z.enum(Object.keys(SESSION_TIMEOUTS) as [string, ...string[]]) }), req.body);
    const prev = await auth.setSessionTimeout(b.timeout, req.user!.id);
    const ms = (k: string) => SESSION_TIMEOUTS[k] ?? Number.MAX_SAFE_INTEGER;
    if (prev !== b.timeout) await audit.log("user", req.user!.id, ms(b.timeout) > ms(prev) ? "auth.session_timeout_extended" : "auth.session_timeout_shortened", { from: prev, to: b.timeout });
    res.json({ ...(await auth.sessionTimeout()), options: Object.keys(SESSION_TIMEOUTS) });
  }));
  // EDR-118: change the expiry of an issued token (shorten, extend, or re-enable an expired one).
  // body: { expires_at: "YYYY-MM-DD" | ISO } or { expires_days: n } (from now). Capped at API_TOKEN_MAX_DAYS from now.
  r.patch("/users/:id/tokens/:tid", requireRole("viewer"), wrap(async (req, res) => {
    const id = Number(req.params.id), tid = Number(req.params.tid);
    if (req.user!.role !== "admin" && id !== req.user!.id) return res.status(403).json({ error: "forbidden" });
    const b = parse(z.object({ expires_at: z.string().min(8).max(40).optional(), expires_days: z.number().int().min(1).max(ctx.cfg.API_TOKEN_MAX_DAYS).optional() }).refine((x) => !!x.expires_at !== (x.expires_days !== undefined), "give expires_at or expires_days"), req.body);
    const row = await db("api_tokens").where({ id: tid, user_id: id }).first();
    if (!row) return res.status(404).json({ error: "token not found" });
    let exp: Date;
    if (b.expires_days !== undefined) exp = new Date(Date.now() + b.expires_days * 86400_000);
    else {
      // a bare date means "valid through that day" (end of day, server local time)
      exp = /^\d{4}-\d{2}-\d{2}$/.test(b.expires_at!) ? new Date(b.expires_at! + "T23:59:59") : new Date(b.expires_at!);
      if (Number.isNaN(exp.getTime())) return res.status(400).json({ error: "expires_at: invalid date" });
    }
    if (exp.getTime() <= Date.now()) return res.status(400).json({ error: "expires_at must be in the future (use 失効 to stop a token now)" });
    if (exp.getTime() > Date.now() + ctx.cfg.API_TOKEN_MAX_DAYS * 86400_000) return res.status(400).json({ error: `expiry must be within ${ctx.cfg.API_TOKEN_MAX_DAYS} days from now (API_TOKEN_MAX_DAYS)` });
    await db("api_tokens").where({ id: tid }).update({ expires_at: exp });
    const old = row.expires_at ? new Date(Number(row.expires_at) || row.expires_at) : null;
    await audit.log("user", req.user!.id, "api_token.updated", { token_id: tid, user_id: id, name: row.name, old_expires_at: old, expires_at: exp, reactivated: !!old && old.getTime() < Date.now() });
    res.json({ ok: true, id: tid, expires_at: exp });
  }));

  return r;
}
