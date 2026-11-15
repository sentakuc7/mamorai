/**
 * edr-console admin CLI (runs inside the container against the same DB):
 *   node server/dist/cli.js user list
 *   node server/dist/cli.js user add <email> <name> <role> [password]     (password generated if omitted; printed once)
 *   node server/dist/cli.js user role <email> <admin|operator|viewer>
 *   node server/dist/cli.js user enable|disable <email>
 *   node server/dist/cli.js user reset-password <email> [password]
 *   node server/dist/cli.js token create <email> <name> <expires_days> [allowed_ips,comma,separated]   (token printed once)
 *   node server/dist/cli.js token list
 *   node server/dist/cli.js session-timeout 1h|6h|12h|24h|7d|none|status   (EDR-120: console idle timeout)
 *   node server/dist/cli.js api on|off|status   (EDR-119: switch API token access on/off for everyone)
 *   node server/dist/cli.js token expire <id> <days | YYYY-MM-DD>   (change the expiry of an issued token)
 *   node server/dist/cli.js token revoke <id>
 *   node server/dist/cli.js user mfa-reset <email>                        (lost authenticator: next login re-enrolls)
 *   node server/dist/cli.js user mfa-status
 *   node server/dist/cli.js agent-pack show                               (EDR-130: pack settings + current revisions)
 *   node server/dist/cli.js agent-pack set '<json>'                       (merge into the pack settings, e.g. '{"manager":{"lan":"10.20.30.10"}}')
 *   node server/dist/cli.js agent-pack refresh                            (record a new revision if the contents changed)
 *   node server/dist/cli.js agent-pack secret status
 *   echo "$KEY" | node server/dist/cli.js agent-pack secret tailscale-key [YYYY-MM-DD]   (EDR-137: read from stdin, never from argv)
 *   echo "$PW"  | node server/dist/cli.js agent-pack secret registration-password
 *   node server/dist/cli.js agent-pack secret clear tailscale-key|registration-password
 */
import { loadConfig } from "./config/index.js";
import { createDb, migrate } from "./db/index.js";
import { AuthService } from "./auth/index.js";
import { hashPassword, randomToken } from "./crypto/index.js";
import { Audit } from "./audit/index.js";

const ROLES = ["admin", "operator", "viewer"];

async function main() {
  const [group, cmd, ...args] = process.argv.slice(2);
  const cfg = loadConfig();
  const db = createDb(cfg);
  await migrate(db);
  const auth = new AuthService(db, true);
  const au = new Audit(db);
  const audit = (event: string, payload: unknown) => au.log("system", "cli", event, payload);
  const findUser = async (email: string) => { const u = await db("users").where({ email }).first(); if (!u) throw new Error(`no such user: ${email}`); return u; };
  try {
    if (group === "user" && cmd === "list") {
      for (const u of await db("users").orderBy("id")) console.log(`${u.id}\t${u.email}\t${u.name}\t${u.role}${u.disabled ? "\t(disabled)" : ""}${u.must_change_password ? "\t(must change pw)" : ""}`);
    } else if (group === "user" && cmd === "add") {
      const [email, name, role, pw] = args;
      if (!email || !name || !ROLES.includes(role)) throw new Error("usage: user add <email> <name> <admin|operator|viewer> [password]");
      const password = pw ?? randomToken(18);
      const [id] = await db("users").insert({ email, name, password_hash: hashPassword(password), role, must_change_password: !pw }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
      await audit("user.created", { id, email, role, via: "cli" });
      console.log(`created user #${id} ${email} role=${role}`);
      if (!pw) console.log(`PASSWORD=${password}`);
    } else if (group === "user" && cmd === "role") {
      const [email, role] = args; if (!ROLES.includes(role)) throw new Error("role must be admin|operator|viewer");
      const u = await findUser(email);
      await db("users").where({ id: u.id }).update({ role, updated_at: db.fn.now() });
      await audit("user.updated", { id: u.id, email, fields: { role }, via: "cli" });
      console.log(`${email}: ${u.role} -> ${role}`);
    } else if (group === "user" && (cmd === "enable" || cmd === "disable")) {
      const u = await findUser(args[0]);
      await db("users").where({ id: u.id }).update({ disabled: cmd === "disable", updated_at: db.fn.now() });
      if (cmd === "disable") await db("auth_sessions").where({ user_id: u.id }).delete();
      await audit("user.updated", { id: u.id, email: u.email, fields: { disabled: cmd === "disable" }, via: "cli" });
      console.log(`${u.email}: ${cmd}d`);
    } else if (group === "user" && cmd === "reset-password") {
      const u = await findUser(args[0]); const password = args[1] ?? randomToken(18);
      await db("users").where({ id: u.id }).update({ password_hash: hashPassword(password), must_change_password: !args[1], updated_at: db.fn.now() });
      await db("auth_sessions").where({ user_id: u.id }).delete();
      await audit("user.password_reset", { id: u.id, email: u.email, via: "cli" });
      console.log(`${u.email}: password reset`); if (!args[1]) console.log(`PASSWORD=${password}`);
    } else if (group === "user" && cmd === "mfa-reset") {
      const u = await findUser(args[0]);
      await auth.mfaReset(u.id);
      await audit("user.mfa_reset", { id: u.id, email: u.email, via: "cli" });
      console.log(`${u.email}: MFA reset — the next sign-in asks to register an authenticator again`);
    } else if (group === "user" && cmd === "mfa-status") {
      for (const u of await db("users").orderBy("id")) console.log(`${u.id}\t${u.email}\tmfa=${u.totp_enabled ? "on" : "off"}${u.totp_locked_until_ms && Number(u.totp_locked_until_ms) > Date.now() ? "\t(locked)" : ""}`);
    } else if (group === "token" && cmd === "create") {
      const [email, name, days, ipsArg] = args; if (!email || !name || !days) throw new Error("usage: token create <email> <name> <expires_days> [allowed_ips,comma,separated]");
      const u = await findUser(email);
      const nDays = Number(days);
      if (!Number.isInteger(nDays) || nDays < 1 || nDays > cfg.API_TOKEN_MAX_DAYS) throw new Error(`expires_days must be 1..${cfg.API_TOKEN_MAX_DAYS}`);
      const ips = (ipsArg ?? "").split(",").map((x) => x.trim()).filter(Boolean);
      if (ips.some((x) => !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(x))) throw new Error("allowed_ips: IP or CIDR, comma separated");
      if (cfg.API_TOKEN_REQUIRE_IP && !ips.length) throw new Error("allowed_ips is required (API_TOKEN_REQUIRE_IP=true)");
      const exp = new Date(Date.now() + nDays * 86400_000);
      const t = await auth.createToken(u.id, name, null, exp, ips);
      await audit("api_token.created", { token_id: t.id, user_id: u.id, email, name, expires_at: exp, allowed_ips: ips, via: "cli" });
      console.log(`created token #${t.id} for ${email} (${u.role}) expires ${exp.toISOString()} from ${ips.length ? ips.join(",") : "anywhere"}`);
      console.log(`TOKEN=${t.token}`);
    } else if (group === "token" && cmd === "list") {
      for (const t of await db("api_tokens as t").join("users as u", "u.id", "t.user_id").select("t.*", "u.email").orderBy("t.id")) console.log(`${t.id}\t${t.prefix}…\t${t.email}\t${t.name}\tlast_used=${t.last_used_at ?? "-"}\texpires=${t.expires_at ? new Date(Number(t.expires_at) || t.expires_at).toISOString() : "-"}\tfrom=${t.allowed_ips ?? "anywhere"}`);
    } else if (group === "session-timeout") {
      if (cmd && cmd !== "status") {
        const prev = await auth.setSessionTimeout(cmd, null);
        const order = ["1h", "6h", "12h", "24h", "7d", "none"];
        if (prev !== cmd) await audit(order.indexOf(cmd) > order.indexOf(prev) ? "auth.session_timeout_extended" : "auth.session_timeout_shortened", { from: prev, to: cmd, via: "cli" });
      }
      const st = await auth.sessionTimeout();
      console.log(`console idle timeout: ${st.key}${st.updated_at ? " (changed " + st.updated_at + ")" : " (default)"}`);
    } else if (group === "api" && (cmd === "on" || cmd === "off" || cmd === "status")) {
      if (cmd !== "status") {
        await auth.setApiAccess(cmd === "on", null, args.join(" ") || `cli: api ${cmd}`);
        await audit(cmd === "on" ? "api_access.enabled" : "api_access.disabled", { reason: args.join(" ") || null, via: "cli" });
      }
      const st = await auth.apiAccess();
      console.log(`API access: ${st.on ? "ON" : "OFF"}${st.updated_at ? " (changed " + st.updated_at + ")" : ""}${st.reason ? " — " + st.reason : ""}`);
    } else if (group === "token" && cmd === "expire") {
      const [tidArg, when] = args; const tid = Number(tidArg);
      if (!tid || !when) throw new Error("usage: token expire <id> <days | YYYY-MM-DD>");
      const row = await db("api_tokens").where({ id: tid }).first(); if (!row) throw new Error("token not found");
      const exp = /^\d+$/.test(when) ? new Date(Date.now() + Number(when) * 86400_000) : new Date(/^\d{4}-\d{2}-\d{2}$/.test(when) ? when + "T23:59:59" : when);
      if (Number.isNaN(exp.getTime()) || exp.getTime() <= Date.now()) throw new Error("expiry must be a future date (use token revoke to stop it now)");
      if (exp.getTime() > Date.now() + cfg.API_TOKEN_MAX_DAYS * 86400_000) throw new Error(`expiry must be within ${cfg.API_TOKEN_MAX_DAYS} days (API_TOKEN_MAX_DAYS)`);
      const old = row.expires_at ? new Date(Number(row.expires_at) || row.expires_at) : null;
      await db("api_tokens").where({ id: tid }).update({ expires_at: exp });
      await audit("api_token.updated", { token_id: tid, user_id: row.user_id, name: row.name, old_expires_at: old, expires_at: exp, via: "cli" });
      console.log(`token #${tid} (${row.name}) expires ${exp.toISOString()} (was ${old ? old.toISOString() : "-"})`);
    } else if (group === "agent-pack" && cmd === "secret") {
      const ap = await import("./agentpack/index.js");
      const { SecretBox } = await import("./crypto/index.js");
      const ctx: any = { cfg, db, box: new SecretBox(cfg.APP_SECRET) };
      const [what, arg] = args;
      const readStdin = async () => { if (process.stdin.isTTY) throw new Error("pipe the value on stdin (it is never taken from the command line)"); let d = ""; for await (const c of process.stdin) d += c; return d.trim(); };
      let changed: Record<string, string> | null = null;
      if (what === "tailscale-key") changed = await ap.setSecrets(ctx, { tailscale_auth_key: await readStdin(), ...(arg ? { tailscale_expires_at: arg } : {}) }, null);
      else if (what === "registration-password") changed = await ap.setSecrets(ctx, { registration_password: await readStdin() }, null);
      else if (what === "clear" && (arg === "tailscale-key" || arg === "registration-password")) changed = await ap.setSecrets(ctx, arg === "tailscale-key" ? { tailscale_auth_key: null } : { registration_password: null }, null);
      else if (what !== "status") throw new Error("usage: agent-pack secret status | tailscale-key [YYYY-MM-DD] | registration-password | clear tailscale-key|registration-password");
      if (changed) {
        await audit("agent_pack.secret_changed", { changed, via: "cli" });
        const actx: any = { ...ctx, audit: { log: (a: any, _id: unknown, ev: string, p: unknown) => au.log(a, "cli", ev, p) }, log: { warn: () => {} }, version: "cli" };
        console.log(JSON.stringify(await ap.refresh(actx, "secrets")));
      }
      console.log(JSON.stringify(ap.secretStatus(await ap.getSecrets(ctx)), null, 2));
    } else if (group === "agent-pack" && ["show", "set", "refresh"].includes(cmd)) {
      const ap = await import("./agentpack/index.js");
      const { SecretBox } = await import("./crypto/index.js");
      const pino = (await import("pino")).default;
      const ctx: any = { cfg, db, box: new SecretBox(cfg.APP_SECRET), audit: { log: (a: any, _id: unknown, ev: string, p: unknown) => au.log(a, "cli", ev, p) }, auth, log: pino({ level: "warn" }), version: "cli" }; // actor_id "cli" → relayed to Wazuh by the server
      if (cmd === "set") {
        const patch = JSON.parse(args.join(" ") || "{}");
        const before = await ap.getSettings(ctx);
        const merged = { ...before, ...patch, manager: { ...before.manager, ...(patch.manager ?? {}) }, windows: { ...before.windows, ...(patch.windows ?? {}) },
          linux: { ...before.linux, ...(patch.linux ?? {}), ssh: { ...before.linux.ssh, ...(patch.linux?.ssh ?? {}) } } };
        const st = ap.settingsSchema.parse(merged);
        await ap.saveSettings(ctx, st, null);
        await audit("agent_pack.settings_changed", { manager: st.manager, wazuh_version: st.wazuh_version, windows: st.windows, linux: st.linux, via: "cli" });
      }
      if (cmd !== "show") console.log(JSON.stringify(await ap.refresh(ctx, cmd === "set" ? "settings" : "cli")));
      const o = await ap.overview(ctx);
      console.log(JSON.stringify({ settings: o.settings, ssh_key: o.ssh_key, packs: Object.fromEntries(Object.entries(o.packs).map(([k, v]: any) => [k, { rev: v.rev, up_to_date: v.up_to_date, wazuh: v.wazuh_version, addon: v.addon_version, problems: v.problems, last_changes: v.history[0]?.changes }])) }, null, 2));
    } else if (group === "token" && cmd === "revoke") {
      const n = await db("api_tokens").where({ id: Number(args[0]) }).delete();
      await audit("api_token.revoked", { token_id: Number(args[0]), via: "cli" });
      console.log(n ? "revoked" : "not found");
    } else {
      console.log("usage: cli.js user list|add|role|enable|disable|reset-password ... | token create|list|revoke ...");
      process.exitCode = 2;
    }
  } finally { await db.destroy(); }
}
main().catch((e) => { console.error(e.message); process.exit(1); });
