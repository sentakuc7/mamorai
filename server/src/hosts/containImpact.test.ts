import { describe, it, expect } from "vitest";
import { impactSchema } from "./containImpact.js";

describe("EDR-142 contain impact schema", () => {
  it("normalizes loose AI output", () => {
    const p = impactSchema.parse({
      summary: "テスト", use_now_if: ["a", 1, null, ""], keeps: [{ name: "Wazuh", why: null }, { why: "no name" }],
      stops: [{ name: "Web", impact: "見られない", who: "U01", severity: "CRITICAL", group: "Internet" }, { name: "SMB", severity: "weird", group: "x" }],
    });
    expect(p.use_now_if).toEqual(["a"]);
    expect(p.keeps).toEqual([{ name: "Wazuh", why: "" }]);
    expect(p.stops[0]).toMatchObject({ severity: "high", group: "internet" });
    expect(p.stops[1]).toMatchObject({ severity: "medium", group: "other", impact: "", who: "" });
    expect(p.before).toEqual([]);
  });
});

describe("EDR-142 contain impact lists", () => {
  it("flattens objects and strings", () => {
    const p = impactSchema.parse({ summary: "x", use_now_if: [{ sign: "暗号化", why: "広がる" }], avoid_if: "- 業務中\n- サーバー", stops: [] });
    expect(p.use_now_if).toEqual(["暗号化 — 広がる"]);
    expect(p.avoid_if).toEqual(["業務中", "サーバー"]);
  });
});
