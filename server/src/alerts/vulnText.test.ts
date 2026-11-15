import { describe, it, expect } from "vitest";
import { buildVulnText, isVulnAlert, vulnIdentity, parseVulnDescription } from "./vulnText.js";
import { groupKey, decorateAlert } from "./keys.js";

const linux = {
  agent: { id: "011", name: "lightsail-x", os: "linux" },
  rule: { id: "23506", level: 13, groups: ["vulnerability-detector"], description: "CVE-2026-80668 affects linux-image-cloud-amd64" },
  data: { vulnerability: { cve: "CVE-2026-80668", severity: "Critical", package: { name: "linux-image-cloud-amd64", version: "6.1.0" } } },
};
const win = {
  agent: { id: "001", name: "pc-a", os: "windows" },
  rule: { id: "23506", level: 13, groups: ["vulnerability-detector"], description: "CVE-2026-11111 affects Google Chrome" },
  data: { vulnerability: { cve: "CVE-2026-11111", severity: "Critical", score: { base: "8.800000" }, package: { name: "Google Chrome", version: "130.0" } } },
};
const winOs = {
  agent: { id: "001", name: "pc-a" },
  rule: { id: "23506", level: 13, groups: ["vulnerability-detector"], description: "CVE-2026-69886 affects Microsoft Windows 11 Pro" },
  data: { vulnerability: { cve: "CVE-2026-69886", severity: "Critical", package: { name: "Microsoft Windows 11 Pro", version: "10.0.22631.3447" } } },
};
const sysmon = { agent: { id: "001", name: "pc-a" }, rule: { id: "92213", level: 12, groups: ["sysmon"] }, data: { win: { eventdata: { image: "C:\\x\\a.exe" } } } };

describe("EDR-80 脆弱性アラートの文言", () => {
  it("脆弱性アラートを判定できる", () => {
    expect(isVulnAlert(linux)).toBe(true);
    expect(isVulnAlert(sysmon)).toBe(false);
  });
  it("同じ rule.id でも文言が混ざらない", () => {
    expect(buildVulnText(win).title).toContain("Google Chrome");
    expect(buildVulnText(win).plain).not.toMatch(/linux/i);
    expect(buildVulnText(win).plain).toContain("CVE-2026-11111");
    expect(buildVulnText(win).plain).toContain("CVSS 8.8");
    expect(buildVulnText(linux).title).toContain("linux-image-cloud-amd64");
    expect(buildVulnText(winOs).action).toContain("Windows Update");
  });
  it("Critical は危険、それ以外は要確認", () => {
    expect(buildVulnText(win).triage).toBe("danger");
    expect(buildVulnText({ ...win, rule: { ...win.rule, level: 10 }, data: { vulnerability: { ...win.data.vulnerability, severity: "High" } } }).triage).toBe("check");
  });
  it("data.vulnerability が無い古いスナップショットでも description から CVE/パッケージを取れる", () => {
    expect(parseVulnDescription("CVE-2026-80668 affects linux-image-cloud-amd64")).toEqual({ cve: "CVE-2026-80668", package: "linux-image-cloud-amd64" });
    const legacy = { agent: { id: "011" }, rule: { id: "23506", level: 13, groups: ["vulnerability-detector"], description: "CVE-2026-80668 affects linux-image-cloud-amd64" } };
    expect(vulnIdentity(legacy)).toEqual({ cve: "CVE-2026-80668", package: "linux-image-cloud-amd64" });
    expect(buildVulnText(legacy).severity).toBe("Critical");
  });
  it("一致キーは CVE+パッケージで分かれる（同じ rule.id でも別物）", () => {
    expect(vulnIdentity(win)).not.toEqual(vulnIdentity(winOs));
    expect(vulnIdentity(sysmon)).toBeNull();
  });
  it("集約キーはホスト×深刻度、脆弱性以外は従来どおりホスト×rule.id", () => {
    expect(groupKey(win)).toBe("vuln|001|Critical");
    expect(groupKey(winOs)).toBe(groupKey(win));
    expect(groupKey(linux)).toBe("vuln|011|Critical");
    expect(groupKey(sysmon)).toBe("rule|001|92213");
  });
  it("一覧 API の装飾: 脆弱性だけ simple が付く", () => {
    expect(decorateAlert(win).simple?.title).toContain("Google Chrome");
    expect(decorateAlert(sysmon).simple).toBeUndefined();
    expect(decorateAlert(sysmon).group_key).toBe("rule|001|92213");
  });
});
