/**
 * EDR-130: agent pack API
 *   GET  /agent-pack                    settings + current revision per OS + history (viewer)
 *   PUT  /agent-pack/settings           change what goes into the packs → new revision (admin, console sign-in only)
 *   PUT  /agent-pack/secrets            Tailscale auth key / enrollment password kept encrypted, put into every pack (admin)
 *   GET  /agent-pack/addon              Windows add-on version per host (viewer)            — EDR-169
 *   POST /agent-pack/addon/update-all   update every Windows add-on to the published one, no approval card (operator)
 *   POST /agent-pack/:os/download       build and download the zip, encrypted when it contains secrets (operator, console sign-in)
 */
import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Ctx } from "./context.js";
import { requireRole } from "../auth/index.js";

type H = (req: Request, res: Response) => Promise<unknown>;
const wrap = (fn: H) => (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);
function parse<S extends z.ZodTypeAny>(schema: S, data: unknown): z.infer<S> {
  const r = schema.safeParse(data);
  if (!r.success) throw Object.assign(new Error("validation: " + r.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join(", ")), { status: 400 });
  return r.data;
}

export function agentPackRouter(ctx: Ctx): Router {
  const r = Router();
  const { audit } = ctx;

  r.get("/agent-pack", requireRole("viewer"), wrap(async (_req, res) => {
    const ap = await import("../agentpack/index.js");
    res.json(await ap.overview(ctx));
  }));

  // EDR-169: Windows add-on versions and 「全てのエージェントを更新」 (no approval card; see hosts/actions.ts startAddonUpdate)
  r.get("/agent-pack/addon", requireRole("viewer"), wrap(async (_req, res) => {
    const { addonStatus } = await import("../hosts/actions.js");
    res.json(await addonStatus(ctx));
  }));
  r.post("/agent-pack/windows/update-all", requireRole("operator"), wrap(async (req, res) => { // EDR-171
    const { startPackUpdateAll } = await import("../hosts/actions.js");
    try { res.json(await startPackUpdateAll(ctx, req.user!.id)); }
    catch (e: any) { res.status(e?.status ?? 400).json({ error: String(e?.message ?? e) }); }
  }));
  r.post("/agent-pack/windows/publish", requireRole("operator"), wrap(async (_req, res) => { // EDR-171: put the pack into the shared folder now
    const ap = await import("../agentpack/index.js");
    res.json({ state: await ap.publishRemotePack(ctx, true), remote: ap.remotePackStatus(ctx) });
  }));
  r.post("/agent-pack/addon/update-all", requireRole("operator"), wrap(async (req, res) => {
    const { startAddonUpdateAll } = await import("../hosts/actions.js");
    try { res.json(await startAddonUpdateAll(ctx, req.user!.id)); }
    catch (e: any) { res.status(e?.status ?? 400).json({ error: String(e?.message ?? e) }); }
  }));

  r.put("/agent-pack/settings", requireRole("admin"), wrap(async (req, res) => {
    if (req.authVia !== "cookie") return res.status(403).json({ error: "sign in to the console to change this" });
    const ap = await import("../agentpack/index.js");
    const before = await ap.getSettings(ctx);
    const merged = { ...before, ...req.body, manager: { ...before.manager, ...(req.body?.manager ?? {}) }, windows: { ...before.windows, ...(req.body?.windows ?? {}) },
      linux: { ...before.linux, ...(req.body?.linux ?? {}), ssh: { ...before.linux.ssh, ...(req.body?.linux?.ssh ?? {}) } } };
    const s = parse(ap.settingsSchema, merged);
    await ap.saveSettings(ctx, s, req.user!.id);
    await audit.log("user", req.user!.id, "agent_pack.settings_changed", { manager: s.manager, wazuh_version: s.wazuh_version, windows: s.windows, linux: { ...s.linux, ssh: { ...s.linux.ssh } } });
    const revs = await ap.refresh(ctx, "settings");
    res.json({ ...(await ap.overview(ctx)), refreshed: revs });
  }));

  // EDR-137: secrets are kept by MamorAI (encrypted) and go into every pack; values are never returned
  r.put("/agent-pack/secrets", requireRole("admin"), wrap(async (req, res) => {
    if (req.authVia !== "cookie") return res.status(403).json({ error: "sign in to the console to change this" });
    const b = parse(z.object({
      tailscale_auth_key: z.string().max(256).nullable().optional(),
      tailscale_expires_at: z.string().max(40).nullable().optional(),
      registration_password: z.string().max(256).nullable().optional(),
    }), req.body ?? {});
    const ap = await import("../agentpack/index.js");
    const changed = await ap.setSecrets(ctx, b, req.user!.id);
    await audit.log("user", req.user!.id, "agent_pack.secret_changed", { changed, tailscale_expires_at: b.tailscale_expires_at ?? undefined });
    const revs = await ap.refresh(ctx, "secrets");
    // EDR-149: a new Tailscale key also lets the MamorAI server itself join the tailnet (host bridge, when installed)
    let join: string | undefined;
    if (b.tailscale_auth_key) { join = ap.requestTailscaleJoin(ctx, b.tailscale_auth_key, b.tailscale_expires_at ?? null); if (join === "requested") await audit.log("user", req.user!.id, "host.tailscale_join_requested", {}); }
    res.json({ ...(await ap.overview(ctx)), refreshed: revs, manager_join: join });
  }));
  /** EDR-149: retry joining the tailnet with the stored key */
  r.post("/agent-pack/tailscale-join", requireRole("admin"), wrap(async (req, res) => {
    if (req.authVia !== "cookie") return res.status(403).json({ error: "sign in to the console to change this" });
    const ap = await import("../agentpack/index.js");
    const sec = await ap.getSecrets(ctx);
    if (!sec.tailscale_auth_key) return res.status(409).json({ error: "Tailscale の認証キーが登録されていません" });
    const join = ap.requestTailscaleJoin(ctx, sec.tailscale_auth_key, sec.tailscale_expires_at ?? null);
    if (join === "unavailable") return res.status(409).json({ error: "このサーバーにはホスト連携（installer/modules/62-host-bridge.sh）が入っていません" });
    await audit.log("user", req.user!.id, "host.tailscale_join_requested", { retry: true });
    res.json(ap.tailscaleJoinStatus(ctx));
  }));
  r.get("/agent-pack/tailscale-join", requireRole("viewer"), wrap(async (_req, res) => {
    const ap = await import("../agentpack/index.js");
    res.json(ap.tailscaleJoinStatus(ctx));
  }));

  r.post("/agent-pack/:os/download", requireRole("operator"), wrap(async (req, res) => {
    const os = z.enum(["windows", "linux"]).parse(req.params.os);
    const b = parse(z.object({ offline: z.boolean().optional() }), req.body ?? {});
    if (req.authVia !== "cookie") return res.status(403).json({ error: "sign in to the console to download agent packs" });
    const ap = await import("../agentpack/index.js");
    const z1 = await ap.buildZip(ctx, os, { offline: !!b.offline });
    const withSecrets = z1.contains.tailscale || z1.contains.registration;
    await audit.log("user", req.user!.id, withSecrets ? "agent_pack.downloaded_with_secrets" : "agent_pack.downloaded", {
      os, rev: z1.rev, offline: !!b.offline, sha256: z1.sha256, bytes: z1.buf.length, encrypted: !!z1.password,
      with_registration_password: z1.contains.registration, with_tailscale_key: z1.contains.tailscale, ip: req.ip,
    });
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${z1.name}"`);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Pack-Rev", String(z1.rev));
    res.setHeader("X-Pack-Sha256", z1.sha256);
    if (z1.password) res.setHeader("X-Pack-Password", z1.password); // shown once in the dialog; not stored anywhere
    res.end(z1.buf);
  }));

  return r;
}
