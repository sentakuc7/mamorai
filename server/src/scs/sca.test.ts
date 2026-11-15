import { describe, it, expect } from "vitest";
import { pickChecks, verdict } from "./sca.js";

// タイトルは lab の cis_win11_enterprise / cis_debian12 の実物（2026-11-09 確認）
const win = [
  { id: 26003, title: "Ensure 'Minimum password length' is set to '14 or more character(s)'.", result: "failed" },
  { id: 26004, title: "Ensure 'Relax minimum password length limits' is set to 'Enabled'.", result: "failed" },
  { id: 26006, title: "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'.", result: "failed" },
  { id: 26009, title: "Ensure 'Accounts: Guest account status' is set to 'Disabled'.", result: "passed" },
  { id: 26011, title: "Configure 'Accounts: Rename administrator account'.", result: "failed" },
  { id: 26024, title: "Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'.", result: "failed" },
  { id: 26116, title: "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'.", result: "passed" },
  { id: 26123, title: "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'.", result: "passed" },
  { id: 26130, title: "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'.", result: "passed" },
  { id: 26301, title: "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'.", result: "failed" },
  { id: 26302, title: "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'.", result: "failed" },
  { id: 26303, title: "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'.", result: "failed" },
];

describe("EDR-178 SCA → SCS", () => {
  it("タイトルで拾う（似た別チェックは拾わない）", () => {
    const c = pickChecks(win, "windows");
    expect(c.filter((x) => x.key === "pwlen").map((x) => x.id)).toEqual([26003]);
    expect(c.filter((x) => x.key === "lockout").map((x) => x.id)).toEqual([26006]);
    expect(c.filter((x) => x.key === "autorun").map((x) => x.id)).toEqual([26302, 26303]);
    expect(c.filter((x) => x.key === "fw")).toHaveLength(3);
  });
  it("判定", () => {
    const c = pickChecks(win, "windows");
    expect(verdict("fw", c, "windows")).toBe("ok");
    expect(verdict("autorun", c, "windows")).toBe("ng");
    expect(verdict("lockout", c, "windows")).toBe("check");
    expect(verdict("guest", c, "windows")).toBe("ok");
    expect(verdict("admin_account", c, "windows")).toBe("check");
    const fw2 = pickChecks(win.map((x) => (x.id === 26130 ? { ...x, result: "failed" } : x)), "windows");
    expect(verdict("fw", fw2, "windows")).toBe("ng");
    expect(verdict("autorun", [], "linux")).toBe("na");
    expect(verdict("pwlen", [], "windows")).toBe("unknown");
    expect(verdict("root_login", c, "windows")).toBe("na");
    expect(verdict("guest", [], "linux")).toBe("na");
  });
  it("独自ポリシー（scs_windows）があればそちらで判定", () => {
    const c = pickChecks([...win, { id: 90001, title: "SCS 4-1-4-1: アカウントロックアウトのしきい値が 1〜10 回", result: "passed" }, { id: 90002, title: "SCS 4-1-4-2: パスワードの最小文字数が 6 文字以上", result: "failed" }], "windows");
    expect(verdict("lockout", c, "windows")).toBe("ok");
    expect(verdict("pwlen", c, "windows")).toBe("ng");
  });
  it("Linux", () => {
    const c = pickChecks([{ id: 1, title: "Ensure ufw service is enabled.", result: "failed" }, { id: 2, title: "Ensure nftables default deny firewall policy.", result: "passed" }, { id: 3, title: "Ensure sshd PermitRootLogin is disabled.", result: "passed" }, { id: 4, title: "Ensure ufw is installed.", result: "passed" }], "linux");
    expect(c.map((x) => x.id)).toEqual([1, 2, 3]);
    expect(verdict("fw", c, "linux")).toBe("ok");
    expect(verdict("root_login", c, "linux")).toBe("ok");
  });
});
