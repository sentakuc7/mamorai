/** EDR-90: login throttling per account and per source IP, stored in the DB (survives restarts, works with 1 container). */
import type { DB } from "../db/index.js";

export class Throttle {
  constructor(private db: DB, private opts: { windowMin: number; lockMin: number }) {}

  /** null if allowed, otherwise the ms timestamp until which the key is locked */
  async lockedUntil(keys: string[]): Promise<number | null> {
    const rows = await this.db("login_throttle").whereIn("key", keys);
    const now = Date.now();
    const until = rows.map((r: any) => Number(r.locked_until_ms ?? 0)).filter((x: number) => x > now);
    return until.length ? Math.max(...until) : null;
  }

  /** count a failure; returns true when this failure locked the key */
  async fail(key: string, max: number): Promise<boolean> {
    const now = Date.now();
    const win = this.opts.windowMin * 60_000;
    const row = await this.db("login_throttle").where({ key }).first();
    let fails = 1, start = now;
    if (row && now - Number(row.window_start_ms) < win) { fails = Number(row.fails) + 1; start = Number(row.window_start_ms); }
    const lock = fails >= max ? now + this.opts.lockMin * 60_000 : null;
    if (row) await this.db("login_throttle").where({ key }).update({ fails: lock ? 0 : fails, window_start_ms: lock ? now : start, locked_until_ms: lock ?? row.locked_until_ms ?? null });
    else await this.db("login_throttle").insert({ key, fails: lock ? 0 : fails, window_start_ms: start, locked_until_ms: lock });
    return !!lock;
  }

  async reset(key: string): Promise<void> { await this.db("login_throttle").where({ key }).delete(); }
}

export const normIp = (ip: string | undefined) => String(ip ?? "").replace(/^::ffff:/, "");

/** IPv4 CIDR / exact IPv4 / exact IPv6 match */
export function ipAllowed(ip: string, list: string[]): boolean {
  const a = normIp(ip);
  for (const raw of list) {
    const e = raw.trim(); if (!e) continue;
    if (!e.includes("/")) { if (normIp(e) === a) return true; continue; }
    const [net, bitsS] = e.split("/"); const bits = Number(bitsS);
    const toInt = (s: string) => { const p = s.split(".").map(Number); return p.length === 4 && p.every((x) => x >= 0 && x <= 255) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null; };
    const x = toInt(a), n = toInt(net);
    if (x == null || n == null || !(bits >= 0 && bits <= 32)) continue;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    if ((x & mask) >>> 0 === (n & mask) >>> 0) return true;
  }
  return false;
}
