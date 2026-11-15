import { describe, it, expect } from "vitest";
import * as K from "./classify.js";

describe("EDR-176 SCS 14日 SLA の判定", () => {
  it("対象区分", () => {
    expect(K.targetClass("pc", "Microsoft Windows 11 Pro 10.0.22631.3447", "win")).toBe("pc_os");
    expect(K.targetClass("pc", "Google Chrome", "win")).toBe("pc_browser");
    expect(K.targetClass("pc", "Microsoft Office Professional Plus 2019", "win")).toBe("pc_office");
    expect(K.targetClass("pc", "7-Zip 23.01 (x64)", "win")).toBe("undetermined");
    expect(K.targetClass("server", "php8.3-cli", "deb")).toBe("server_middleware");
    expect(K.targetClass("server", "php", "rpm")).toBe("server_middleware");
    expect(K.targetClass("server", "openssl", "rpm")).toBe("server_middleware");
    expect(K.targetClass("server", "systemd", "deb")).toBe("server_os");
    expect(K.targetClass("server", "linux-image-6.8.0-45-generic", "deb")).toBe("server_os");
    expect(K.targetClass("server", "Microsoft Windows Server 2022 Standard", "win")).toBe("server_os");
    expect(K.targetClass("server", "NVIDIA GeForce Experience", "win")).toBe("undetermined");
    expect(K.targetClass("network_device", "SFOS", null)).toBe("boundary_fw");
    expect(K.targetClass("pc", "Microsoft Windows Desktop Runtime - 8.0.15 (x64)", "win")).toBe("undetermined");
    expect(K.targetClass("server", "Microsoft Windows Desktop Runtime - 8.0.15 (x64)", "win")).toBe("server_middleware");
  });
  it("14日対象（深刻度不明も対象）", () => {
    expect(K.slaTarget("pc_os", "High", 7.8)).toBe(true);
    expect(K.slaTarget("pc_os", "Medium", 6.5)).toBe(false);
    expect(K.slaTarget("pc_os", "Medium", 7.0)).toBe(true);
    expect(K.slaTarget("server_os", "-", null)).toBe(true);
    expect(K.slaTarget("server_os", "-", 0)).toBe(true);
    expect(K.slaTarget("undetermined", "Critical", 9.8)).toBe(false);
    expect(K.slaTarget("other", "Critical", 9.8)).toBe(false);
    expect(K.isCandidate("Medium", 5)).toBe(false);
    expect(K.isCandidate("-", null)).toBe(true);
  });
  it("優先度と期限", () => {
    expect(K.priority(true, true, "server_middleware", 9.8)).toBe("P0");
    expect(K.priority(true, false, "pc_os", 7.5)).toBe("P1");
    expect(K.priority(false, true, "boundary_fw", 6.8)).toBe("P2");
    expect(K.priority(false, false, "pc_os", 5)).toBe("P3");
    const fix = K.defaultFixReleased("2026-10-29T00:00:00Z", "2026-10-30T07:00:00Z");
    expect(fix).toBe("2026-10-29T00:00:00.000Z");
    expect(K.dueAt("P0", true, fix, "2026-10-30T07:00:00Z", null)).toBe("2026-11-12T00:00:00.000Z");
    expect(K.dueAt("P2", false, null, "2026-11-09T00:00:00Z", null)).toBe("2026-11-16T00:00:00.000Z");
  });
  it("端末の区分", () => {
    expect(K.assetCategory("Microsoft Windows 11 Pro", "windows")).toBe("pc");
    expect(K.assetCategory("Microsoft Windows Server 2016 Standard", "windows")).toBe("server");
    expect(K.assetCategory("Ubuntu", "ubuntu")).toBe("server");
    expect(K.assetCategory("Ubuntu", "ubuntu", "client")).toBe("pc");
    expect(K.assetCategory("VMware ESXi", null)).toBe("hypervisor");
  });
  it("入力のルール（指示書 §8-3）", () => {
    const cur = { priority: "P1" as const, due_at: "2026-11-20T00:00:00Z", status: "未対応" };
    expect(K.validateChange(cur, { status: "緩和策適用中" })).toContain("緩和策の種類");
    expect(K.validateChange(cur, { status: "緩和策適用中", mitigation_type: "監視・遮断の強化" })).toBeNull();
    expect(K.validateChange(cur, { status: "対象外", exclusion_reason: "短い" })).toContain("理由");
    expect(K.validateChange(cur, { status: "計画中", plan_due_at: "2026-11-25T00:00:00Z" })).toContain("予定日と理由");
    expect(K.validateChange(cur, { status: "計画中", plan_due_at: "2026-11-25T00:00:00Z", plan_reason: "業務停止できない" })).toBeNull();
    expect(K.validateChange({ ...cur, priority: "P0" }, { status: "計画中", plan_due_at: "2026-11-25T00:00:00Z", plan_reason: "x" })).toContain("P0");
  });
});
