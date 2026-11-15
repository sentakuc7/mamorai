import { describe, it, expect } from "vitest";
import { base32Encode, base32Decode, hotp, verifyTotp, stepAt, newSecret, otpauthUri, newRecoveryCodes, normalizeRecovery } from "./totp.js";

describe("TOTP (RFC 6238 / 4226)", () => {
  const key = Buffer.from("12345678901234567890");
  it("RFC 4226 HOTP vectors", () => {
    expect(["755224", "287082", "359152", "969429", "338314"]).toEqual([0, 1, 2, 3, 4].map((c) => hotp(key, c)));
  });
  it("RFC 6238 SHA-1 vectors (8 digits)", () => {
    for (const [t, code] of [[59, "94287082"], [1111111109, "07081804"], [1234567890, "89005924"], [2000000000, "69279037"]] as const) expect(hotp(key, Math.floor(t / 30), 8)).toBe(code);
  });
  it("base32 round trip", () => {
    const s = base32Encode(key);
    expect(s).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(base32Decode(s).equals(key)).toBe(true);
  });
  it("verifies within ±1 step and rejects replay", () => {
    const secret = newSecret();
    const now = Date.now();
    const s = stepAt(now);
    const code = hotp(base32Decode(secret), s);
    expect(verifyTotp(secret, code, { now })).toBe(s);
    expect(verifyTotp(secret, code, { now: now + 30_000 })).toBe(s);
    expect(verifyTotp(secret, code, { now: now + 90_000 })).toBeNull();
    expect(verifyTotp(secret, code, { now, lastStep: s })).toBeNull();
    expect(verifyTotp(secret, "12345", { now })).toBeNull();
  });
  it("otpauth uri and recovery codes", () => {
    expect(otpauthUri("ABC", "a@b.c")).toBe("otpauth://totp/MamorAI%3Aa%40b.c?secret=ABC&issuer=MamorAI&algorithm=SHA1&digits=6&period=30");
    const rc = newRecoveryCodes();
    expect(rc).toHaveLength(10);
    expect(new Set(rc).size).toBe(10);
    expect(normalizeRecovery("K7Q2-M9XD ")).toBe("k7q2m9xd");
  });
});
