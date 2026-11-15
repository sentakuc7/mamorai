import crypto from "node:crypto";

/**
 * Secrets at rest: AES-256-GCM with a key derived from APP_SECRET.
 * Format: v1.<iv b64>.<tag b64>.<ciphertext b64>
 */
export class SecretBox {
  private key: Buffer;
  constructor(appSecret: string) {
    this.key = crypto.hkdfSync("sha256", appSecret, "edr-console", "secretbox-v1", 32) as unknown as Buffer;
    this.key = Buffer.from(this.key);
  }
  encrypt(plain: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, iv);
    const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1.${iv.toString("base64")}.${tag.toString("base64")}.${ct.toString("base64")}`;
  }
  decrypt(blob: string): string {
    const [v, ivB, tagB, ctB] = blob.split(".");
    if (v !== "v1" || !ivB || !tagB || !ctB) throw new Error("bad secret blob");
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.key, Buffer.from(ivB, "base64"));
    decipher.setAuthTag(Buffer.from(tagB, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(ctB, "base64")), decipher.final()]).toString("utf8");
  }
}

/** Password hashing: scrypt (Node built-in, no native deps). */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const hash = crypto.scryptSync(password, salt, 32, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [alg, N, r, p, saltB, hashB] = stored.split("$");
  if (alg !== "scrypt") return false;
  const salt = Buffer.from(saltB, "base64");
  const expected = Buffer.from(hashB, "base64");
  const actual = crypto.scryptSync(password, salt, expected.length, { N: Number(N), r: Number(r), p: Number(p) });
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

/** Mask secrets in free text before logging / sending to LLM. */
export function redactSecrets(text: string): string {
  return text
    .replace(/(password|passwd|pwd|token|api[_-]?key|secret)(\s*[:=]\s*)(["']?)[^\s"']{4,}/gi, "$1$2$3***")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[PRIVATE KEY REDACTED]")
    .replace(/\b(sk|or)-[A-Za-z0-9_-]{20,}\b/g, "[API KEY REDACTED]");
}
