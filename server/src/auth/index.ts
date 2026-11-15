import type { Request, Response, NextFunction } from "express";
import type { DB } from "../db/index.js";
import { hashPassword, verifyPassword, randomToken, sha256, type SecretBox } from "../crypto/index.js";
import { verifyTotp, newSecret, otpauthUri, newRecoveryCodes, normalizeRecovery } from "./totp.js";
import { ipAllowed, normIp } from "./throttle.js";

export type Role = "admin" | "operator" | "viewer";
export interface AuthUser { id: number; email: string; name: string; role: Role; locale: string; must_change_password: boolean; mfa_enabled: boolean }
/** EDR-90: a browser session that passed the password but not yet the second factor */
export interface MfaPending { userId: number; email: string; stage: "verify" | "enroll" }

const COOKIE = "edr_sid";
// EDR-120: idle timeout for console sessions is configurable (app_flags "session_timeout"); default 24h.
export const SESSION_TIMEOUTS: Record<string, number | null> = { "1h": 3600_000, "6h": 6 * 3600_000, "12h": 12 * 3600_000, "24h": 24 * 3600_000, "7d": 7 * 86400_000, none: null };
export const SESSION_TIMEOUT_DEFAULT = "24h";
const NONE_DB_MS = 10 * 365 * 86400_000; // "none": effectively never expires in the DB
const COOKIE_MAX_MS = 400 * 86400_000;   // browsers cap cookie lifetime at 400 days; refreshed on use
const EXTEND_EVERY_MS = 60_000;          // sliding expiry is written at most once a minute per session
const PENDING_TTL_MS = 10 * 60 * 1000;
const ROLE_RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

declare module "express-serve-static-core" {
  interface Request { user?: AuthUser; sid?: string; authVia?: "cookie" | "token"; mfaPending?: MfaPending }
}

export interface MfaPolicy { required: boolean; maxFails: number; lockMin: number }

export class AuthService {
  box?: SecretBox;
  mfa: MfaPolicy = { required: true, maxFails: 5, lockMin: 15 };
  constructor(private db: DB, private secureCookie: boolean) {}

  async ensureAdmin(email: string, password: string | undefined, mustChange = true): Promise<"created" | "exists" | "skipped"> {
    const n = await this.db("users").count<{ c: number }[]>({ c: "*" }).first();
    if (Number(n?.c ?? 0) > 0) return "exists";
    if (!password) return "skipped";
    await this.db("users").insert({
      email, name: "Administrator", password_hash: hashPassword(password), role: "admin", must_change_password: mustChange,
    });
    return "created";
  }

  /** Password step. With MFA the returned session is "pending" until verify/enroll succeeds. */
  async login(email: string, password: string, meta: { ip?: string; ua?: string }): Promise<{ user: AuthUser; sid: string; stage: "verify" | "enroll" | null } | null> {
    const row = await this.db("users").where({ email, disabled: false }).first();
    if (!row || !verifyPassword(password, row.password_hash)) return null;
    const stage: "verify" | "enroll" | null = row.totp_enabled ? "verify" : this.mfa.required ? "enroll" : null;
    const sid = await this.newSession(row.id, meta, stage);
    return { user: this.toUser(row), sid, stage };
  }

  // ---- EDR-120: configurable idle timeout ----
  private ttlKey = SESSION_TIMEOUT_DEFAULT; private ttlAt = 0;
  private get ttlMs(): number { const v = SESSION_TIMEOUTS[this.ttlKey]; return v === undefined ? SESSION_TIMEOUTS[SESSION_TIMEOUT_DEFAULT]! : v === null ? NONE_DB_MS : v; }
  async sessionTimeout(): Promise<{ key: string; updated_at: string | null; updated_by: number | null }> {
    const r = await this.db("app_flags").where({ key: "session_timeout" }).first();
    this.ttlKey = r?.value && r.value in SESSION_TIMEOUTS ? r.value : SESSION_TIMEOUT_DEFAULT; this.ttlAt = Date.now();
    return { key: this.ttlKey, updated_at: r?.updated_at ?? null, updated_by: r?.updated_by ?? null };
  }
  private async refreshTtl(): Promise<void> { if (Date.now() - this.ttlAt > 5000) await this.sessionTimeout(); }
  /** Change the idle timeout. Shortening also clamps the expiry of sessions already signed in. Returns the previous key. */
  async setSessionTimeout(key: string, userId: number | null): Promise<string> {
    if (!(key in SESSION_TIMEOUTS)) throw Object.assign(new Error("invalid timeout"), { status: 400 });
    const prev = (await this.sessionTimeout()).key;
    const ex = await this.db("app_flags").where({ key: "session_timeout" }).first();
    if (ex) await this.db("app_flags").where({ key: "session_timeout" }).update({ value: key, updated_by: userId, updated_at: this.db.fn.now() });
    else await this.db("app_flags").insert({ key: "session_timeout", value: key, updated_by: userId });
    this.ttlKey = key; this.ttlAt = Date.now();
    const limit = new Date(Date.now() + this.ttlMs);
    await this.db("auth_sessions").whereNull("mfa_state").andWhere("expires_at", ">", limit).update({ expires_at: limit });
    return prev;
  }

  private async newSession(userId: number, meta: { ip?: string; ua?: string }, stage: string | null): Promise<string> {
    const raw = randomToken(32);
    if (!stage) await this.refreshTtl();
    await this.db("auth_sessions").insert({ id: sha256(raw), user_id: userId, expires_at: new Date(Date.now() + (stage ? PENDING_TTL_MS : this.ttlMs)), ip: meta.ip, user_agent: meta.ua?.slice(0, 500), mfa_state: stage });
    return raw;
  }

  /** After the second factor: replace the pending session with a full one (new id → no session fixation). */
  async upgradeSession(rawSid: string | undefined, userId: number, meta: { ip?: string; ua?: string }): Promise<string> {
    if (rawSid) await this.db("auth_sessions").where({ id: sha256(rawSid) }).delete();
    return this.newSession(userId, meta, null);
  }

  async logout(rawSid: string | undefined): Promise<void> {
    if (!rawSid) return;
    await this.db("auth_sessions").where({ id: sha256(rawSid) }).delete();
  }

  async resolveSession(rawSid: string | undefined): Promise<{ user: AuthUser; pending: MfaPending | null; expiresAt?: number } | null> {
    if (!rawSid) return null;
    const sid = sha256(rawSid);
    const s = await this.db("auth_sessions").where({ id: sid }).first();
    if (!s) return null;
    if (new Date(s.expires_at).getTime() < Date.now()) { await this.db("auth_sessions").where({ id: sid }).delete(); return null; }
    const u = await this.db("users").where({ id: s.user_id, disabled: false }).first();
    if (!u) return null;
    const pending = s.mfa_state === "verify" || s.mfa_state === "enroll" ? { userId: u.id, email: u.email, stage: s.mfa_state as "verify" | "enroll" } : null;
    // a full session of a user who still has no TOTP (created before MFA became required) is downgraded to "enroll"
    if (!pending && this.mfa.required && !u.totp_enabled) return { user: this.toUser(u), pending: { userId: u.id, email: u.email, stage: "enroll" } };
    return { user: this.toUser(u), pending, expiresAt: new Date(s.expires_at).getTime() };
  }

  /** kept for callers that only need a fully authenticated user */
  async resolve(rawSid: string | undefined): Promise<AuthUser | null> {
    const r = await this.resolveSession(rawSid);
    return r && !r.pending ? r.user : null;
  }

  async changePassword(userId: number, current: string, next: string): Promise<boolean> {
    const u = await this.db("users").where({ id: userId }).first();
    if (!u || !verifyPassword(current, u.password_hash)) return false;
    await this.db("users").where({ id: userId }).update({ password_hash: hashPassword(next), must_change_password: false, updated_at: this.db.fn.now() });
    await this.db("auth_sessions").where({ user_id: userId }).delete();
    return true;
  }

  // ---------------- TOTP ----------------
  private requireBox(): SecretBox { if (!this.box) throw new Error("auth: secret box not configured"); return this.box; }

  /** Start (re-)enrollment: a new secret is kept as "pending" until a code from it is confirmed. */
  async mfaEnrollStart(userId: number): Promise<{ secret: string; otpauth: string }> {
    const u = await this.db("users").where({ id: userId }).first();
    const secret = newSecret();
    await this.db("users").where({ id: userId }).update({ totp_pending_enc: this.requireBox().encrypt(secret), updated_at: this.db.fn.now() });
    return { secret, otpauth: otpauthUri(secret, u.email) };
  }

  /** Confirm enrollment with a code from the new secret. Returns fresh recovery codes (shown once), or null. */
  async mfaEnrollConfirm(userId: number, code: string): Promise<string[] | null> {
    const u = await this.db("users").where({ id: userId }).first();
    if (!u?.totp_pending_enc) return null;
    const secret = this.requireBox().decrypt(u.totp_pending_enc);
    const step = verifyTotp(secret, code);
    if (step == null) return null;
    await this.db("users").where({ id: userId }).update({ totp_secret_enc: u.totp_pending_enc, totp_pending_enc: null, totp_enabled: true, totp_last_step: step, totp_failed: 0, totp_locked_until_ms: null, mfa_enrolled_at: this.db.fn.now(), updated_at: this.db.fn.now() });
    return this.regenerateRecoveryCodes(userId);
  }

  async regenerateRecoveryCodes(userId: number): Promise<string[]> {
    const codes = newRecoveryCodes(10);
    await this.db("user_recovery_codes").where({ user_id: userId }).delete();
    await this.db("user_recovery_codes").insert(codes.map((c) => ({ user_id: userId, code_hash: sha256(normalizeRecovery(c)) })));
    return codes;
  }

  /**
   * Check a 6-digit code (or a recovery code) for a user with TOTP enabled. Handles replay, failure counting and lockout.
   * result: ok | bad | locked | recovery (ok via recovery code) | not_enrolled
   */
  async mfaCheck(userId: number, input: { code?: string; recovery_code?: string }): Promise<{ result: "ok" | "recovery" | "bad" | "locked" | "not_enrolled"; locked_until?: number; justLocked?: boolean; remaining_recovery?: number }> {
    const u = await this.db("users").where({ id: userId }).first();
    if (!u?.totp_enabled || !u.totp_secret_enc) return { result: "not_enrolled" };
    const now = Date.now();
    if (u.totp_locked_until_ms && Number(u.totp_locked_until_ms) > now) return { result: "locked", locked_until: Number(u.totp_locked_until_ms) };
    if (input.recovery_code) {
      const h = sha256(normalizeRecovery(input.recovery_code));
      const rc = await this.db("user_recovery_codes").where({ user_id: userId, code_hash: h }).whereNull("used_at").first();
      if (rc) {
        await this.db("user_recovery_codes").where({ id: rc.id }).update({ used_at: this.db.fn.now() });
        await this.db("users").where({ id: userId }).update({ totp_failed: 0 });
        const left = Number((await this.db("user_recovery_codes").where({ user_id: userId }).whereNull("used_at").count<{ c: number }[]>({ c: "*" }).first())?.c ?? 0);
        return { result: "recovery", remaining_recovery: left };
      }
    } else {
      const step = verifyTotp(this.requireBox().decrypt(u.totp_secret_enc), input.code ?? "", { lastStep: u.totp_last_step == null ? null : Number(u.totp_last_step) });
      if (step != null) { await this.db("users").where({ id: userId }).update({ totp_last_step: step, totp_failed: 0 }); return { result: "ok" }; }
    }
    const fails = Number(u.totp_failed ?? 0) + 1;
    const lock = fails >= this.mfa.maxFails ? now + this.mfa.lockMin * 60_000 : null;
    await this.db("users").where({ id: userId }).update({ totp_failed: lock ? 0 : fails, totp_locked_until_ms: lock });
    return lock ? { result: "locked", locked_until: lock, justLocked: true } : { result: "bad" };
  }

  async mfaReset(userId: number): Promise<void> {
    await this.db("users").where({ id: userId }).update({ totp_secret_enc: null, totp_pending_enc: null, totp_enabled: false, totp_last_step: null, totp_failed: 0, totp_locked_until_ms: null, mfa_enrolled_at: null, updated_at: this.db.fn.now() });
    await this.db("user_recovery_codes").where({ user_id: userId }).delete();
    await this.db("auth_sessions").where({ user_id: userId }).delete();
  }

  setCookie(res: Response, rawSid: string, pending = false) {
    res.cookie(COOKIE, rawSid, { httpOnly: true, secure: this.secureCookie, sameSite: "lax", maxAge: pending ? PENDING_TTL_MS : Math.min(this.ttlMs, COOKIE_MAX_MS), path: "/" });
  }
  clearCookie(res: Response) { res.clearCookie(COOKIE, { path: "/" }); }

  /** API token (service account): `Authorization: Bearer edrc_...`. Returns the owning user. EDR-90: source IP must be allowed. */
  async resolveToken(bearer: string, ip?: string): Promise<AuthUser | null> {
    if (!bearer.startsWith("edrc_")) return null;
    const row = await this.db("api_tokens").where({ token_hash: sha256(bearer) }).first();
    if (!row) return null;
    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return null;
    if (row.allowed_ips && !ipAllowed(normIp(ip), String(row.allowed_ips).split(","))) return null;
    const u = await this.db("users").where({ id: row.user_id, disabled: false }).first();
    if (!u) return null;
    await this.db("api_tokens").where({ id: row.id }).update({ last_used_at: this.db.fn.now() });
    return this.toUser(u);
  }

  /** Create an API token for a user; the raw token is returned ONCE and only its hash is stored. */
  async createToken(userId: number, name: string, createdBy: number | null, expiresAt: Date | null, allowedIps: string[] | null = null): Promise<{ id: number; token: string; prefix: string }> {
    const token = "edrc_" + randomToken(32);
    const prefix = token.slice(0, 10);
    const [id] = await this.db("api_tokens").insert({ user_id: userId, name, token_hash: sha256(token), prefix, created_by: createdBy, expires_at: expiresAt, allowed_ips: allowedIps?.length ? allowedIps.join(",") : null }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    return { id, token, prefix };
  }

  // ---- EDR-119: global On/Off for API (bearer token) access. Stored in app_flags; unset = on. ----
  private apiCache: { on: boolean; at: number } | null = null;
  async apiAccess(): Promise<{ on: boolean; updated_at: string | null; updated_by: number | null; reason: string | null }> {
    const r = await this.db("app_flags").where({ key: "api_access_disabled" }).first();
    let v: any = null; try { v = r?.value ? JSON.parse(r.value) : null; } catch { v = null; }
    const off = !!v?.off;
    this.apiCache = { on: !off, at: Date.now() };
    return { on: !off, updated_at: r?.updated_at ?? null, updated_by: r?.updated_by ?? null, reason: v?.reason ?? null };
  }
  async apiAccessOn(): Promise<boolean> {
    if (this.apiCache && Date.now() - this.apiCache.at < 3000) return this.apiCache.on;
    return (await this.apiAccess()).on;
  }
  async setApiAccess(on: boolean, userId: number | null, reason?: string): Promise<void> {
    const value = JSON.stringify({ off: !on, reason: reason ?? null });
    const ex = await this.db("app_flags").where({ key: "api_access_disabled" }).first();
    if (ex) await this.db("app_flags").where({ key: "api_access_disabled" }).update({ value, updated_by: userId, updated_at: this.db.fn.now() });
    else await this.db("app_flags").insert({ key: "api_access_disabled", value, updated_by: userId });
    this.apiCache = { on, at: Date.now() };
  }

  /** Express middleware: attaches req.user from a bearer token or a fully authenticated session cookie; a session waiting for MFA only sets req.mfaPending. */
  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const authz = req.headers.authorization;
        if (authz && /^Bearer\s+/i.test(authz)) {
          // EDR-119: API switched off -> every bearer request is refused before the token is even looked up
          if (!(await this.apiAccessOn())) return res.status(403).json({ error: "api access disabled" });
          const u = await this.resolveToken(authz.replace(/^Bearer\s+/i, "").trim(), req.ip);
          if (u) { req.user = u; req.authVia = "token"; }
          return next();
        }
        const raw = (req as any).cookies?.[COOKIE] as string | undefined;
        req.sid = raw;
        const r = await this.resolveSession(raw);
        if (r?.pending) req.mfaPending = r.pending;
        else if (r) {
          req.user = r.user; req.authVia = "cookie";
          // EDR-120: sliding idle timeout — every request pushes the expiry out again (written at most once a minute)
          await this.refreshTtl();
          const want = Date.now() + this.ttlMs;
          if (raw && r.expiresAt !== undefined && want - r.expiresAt > EXTEND_EVERY_MS) {
            await this.db("auth_sessions").where({ id: sha256(raw) }).update({ expires_at: new Date(want) });
            if (!res.headersSent) this.setCookie(res, raw);
          }
        }
        next();
      } catch (e) { next(e); }
    };
  }

  private toUser(row: any): AuthUser {
    return { id: row.id, email: row.email, name: row.name, role: row.role, locale: row.locale, must_change_password: !!row.must_change_password, mfa_enabled: !!row.totp_enabled };
  }
}

export function requireRole(min: Role) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ error: req.mfaPending ? "mfa_required" : "unauthenticated" });
    if (ROLE_RANK[req.user.role] < ROLE_RANK[min]) return res.status(403).json({ error: "forbidden" });
    next();
  };
}

/** CSRF: state-changing requests must carry X-Requested-With and a same-origin Origin (when present). */
export function csrfGuard(baseUrl: string) {
  let allowed: string | null = null;
  try { allowed = new URL(baseUrl).origin; } catch { allowed = null; }
  return (req: Request, res: Response, next: NextFunction) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
    if (req.authVia === "token") return next(); // bearer tokens are never sent by a browser automatically: no CSRF surface
    if (req.headers["x-requested-with"] !== "edr-console") return res.status(403).json({ error: "csrf: missing X-Requested-With" });
    const origin = req.headers.origin;
    if (origin && allowed && origin !== allowed) {
      // Allow when host header matches origin host (e.g. accessed via LAN IP instead of base URL)
      const hostHdr = req.headers.host;
      try { if (new URL(origin).host !== hostHdr) return res.status(403).json({ error: "csrf: bad origin" }); } catch { return res.status(403).json({ error: "csrf: bad origin" }); }
    }
    next();
  };
}
