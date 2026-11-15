/**
 * EDR-90: MamorAI is the front door of the Wazuh dashboard.
 * The dashboard listens on loopback only and uses OpenSearch Security "proxy" authentication; this handler forwards
 * requests of a fully signed-in MamorAI user (password + TOTP) and sets x-proxy-user / x-proxy-roles itself.
 * Whatever the browser sends in x-proxy-* / x-forwarded-* / Authorization is dropped, so the headers cannot be forged.
 */
import https from "node:https";
import type { Request, Response } from "express";
import type { Ctx } from "./context.js";
import { normIp } from "../auth/throttle.js";

export function wazuhDashboardProxy(ctx: Ctx) {
  const target = new URL(ctx.cfg.WAZUH_DASHBOARD_URL);
  // loopback hop to the dashboard's own self-signed certificate (issued for its hostname, not 127.0.0.1)
  const agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true, maxSockets: 32 });
  const seen = new Set<string>();
  return (req: Request, res: Response) => {
    if (!req.user || req.authVia !== "cookie") {
      if (req.method === "GET" && /text\/html/.test(String(req.headers.accept ?? ""))) return res.redirect(302, "/");
      return res.status(401).json({ error: req.mfaPending ? "mfa_required" : "sign in to MamorAI first" });
    }
    if (req.user.role !== "admin") return res.status(403).type("text/plain").send("Wazuh ダッシュボードは管理者だけが使えます");
    const headers: Record<string, any> = { ...req.headers };
    for (const h of Object.keys(headers)) if (/^(x-proxy-|x-forwarded-|x-real-ip$|authorization$|securitytenant$)/i.test(h)) delete headers[h];
    if (headers.cookie) headers.cookie = String(headers.cookie).split(/;\s*/).filter((c) => !c.startsWith("edr_sid=")).join("; ") || undefined;
    if (!headers.cookie) delete headers.cookie;
    headers["x-proxy-user"] = req.user.email;
    headers["x-proxy-roles"] = "admin";
    headers["x-forwarded-for"] = normIp(req.ip);
    headers.host = target.host;
    const key = `${req.sid ?? ""}`;
    if (key && !seen.has(key)) { seen.add(key); if (seen.size > 5000) seen.clear(); ctx.audit.log("user", req.user.id, "wazuh_dashboard.opened", { ip: req.ip }).catch(() => {}); }
    const up = https.request({ hostname: target.hostname, port: target.port || 443, method: req.method, path: req.originalUrl, headers, agent, timeout: 120_000 }, (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    });
    up.on("timeout", () => up.destroy(new Error("timeout")));
    up.on("error", (e) => { if (!res.headersSent) res.status(502).type("text/plain").send(`Wazuh ダッシュボードに接続できません: ${e.message}`); else res.end(); });
    req.pipe(up);
  };
}
