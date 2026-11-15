import { describe, it, expect } from "vitest";
import { isVulnQuestion, matchCycle, cmpVer, normalizeVersion, normalizeProduct } from "./versionCheck.js";

describe("isVulnQuestion", () => {
  it("vulnerability / version questions", () => {
    for (const t of ["直近のNode.jsの脆弱性の対象バージョンってなんだっけ？", "20.20.2なら安心なの？", "CVE-2026-48618 の影響ある？", "nodeってEOLじゃない？", "openssl 古い版じゃない？", "パッチ当たってる？"]) expect(isVulnQuestion(t)).toBe(true);
  });
  it("other questions do not trigger", () => {
    for (const t of ["このアラート見てみて", "SSH のブルートフォースが増えてる理由は？", "fail2ban の BAN 一覧を出して", "完了にして", "10.20.30.40 からの通信は？"]) expect(isVulnQuestion(t)).toBe(false);
  });
});

describe("helpers", () => {
  it("normalize", () => {
    expect(normalizeVersion("v20.20.2")).toBe("20.20.2");
    expect(normalizeVersion("OpenSSL 3.0.13 30 Jan 2024".replace(/^OpenSSL /, ""))).toBe("3.0.13");
    expect(normalizeProduct("Node")).toBe("nodejs");
  });
  it("cycle match is longest-prefix", () => {
    const rel = [{ name: "3" }, { name: "3.12" }, { name: "3.1" }];
    expect(matchCycle(rel, "3.12.4")?.name).toBe("3.12");
    expect(matchCycle([{ name: "20" }, { name: "2" }], "20.20.2")?.name).toBe("20");
    expect(matchCycle([{ name: "22" }], "20.20.2")).toBeUndefined();
  });
  it("cmpVer", () => {
    expect(cmpVer("20.20.2", "20.20.10")).toBeLessThan(0);
    expect(cmpVer("24.22.0", "24.22.0")).toBe(0);
  });
});
