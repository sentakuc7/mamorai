/**
 * EDR-90: TOTP (RFC 6238 / RFC 4226) without external services.
 * SHA-1, 6 digits, 30 s period — the defaults every authenticator app (Google Authenticator, Microsoft
 * Authenticator, 1Password, FreeOTP ...) understands from a plain otpauth:// QR code.
 */
import crypto from "node:crypto";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0, value = 0; const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32");
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

/** RFC 4226 HOTP */
export function hotp(key: Buffer, counter: number, digits = 6, algo: "sha1" | "sha256" | "sha512" = "sha1"): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac(algo, key).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export const PERIOD = 30;
export const stepAt = (ms: number) => Math.floor(ms / 1000 / PERIOD);

/**
 * Verify a 6-digit code. Accepts the current step ±window, but never a step <= lastStep (replay protection).
 * Returns the matched step, or null.
 */
export function verifyTotp(secretB32: string, code: string, opts: { now?: number; window?: number; lastStep?: number | null } = {}): number | null {
  const c = String(code ?? "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(c)) return null;
  const key = base32Decode(secretB32);
  const now = stepAt(opts.now ?? Date.now());
  const w = opts.window ?? 1;
  for (let s = now - w; s <= now + w; s++) {
    if (opts.lastStep != null && s <= opts.lastStep) continue;
    const exp = hotp(key, s);
    if (crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(c))) return s;
  }
  return null;
}

export function newSecret(): string { return base32Encode(crypto.randomBytes(20)); }

export function otpauthUri(secretB32: string, account: string, issuer = "MamorAI"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${PERIOD}`;
}

/** 10 single-use recovery codes like "k7q2-m9xd" (40 bits each). Only their SHA-256 is stored. */
export function newRecoveryCodes(n = 10): string[] {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  return Array.from({ length: n }, () => {
    const b = crypto.randomBytes(8);
    const s = Array.from(b, (x) => alphabet[x % alphabet.length]).join("");
    return `${s.slice(0, 4)}-${s.slice(4, 8)}`;
  });
}
export const normalizeRecovery = (s: string) => String(s ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
