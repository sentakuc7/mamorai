import { describe as d, it, expect } from "vitest";
import { describe, paramsSchema, parseUpdateScan, previewSteps } from "./actions.js";

d("EDR-168 Windows updates", () => {
  it("parses the add-on scan line", () => {
    const s = parseUpdateScan({ wu_count: "2", wu_security: "1", updates: "KB5044284|Critical|sec|Security Updates|cve:12|mb:812|2026-11 Cumulative Update for Windows 11 ;; KB890830|-|other|Update Rollups|cve:0|mb:70|Windows Malicious Software Removal Tool", app_count: "1", apps: "Google.Chrome|130.0.1|130.0.2|Google Chrome", winget: "ok", reboot_pending: "true", wsus: "", boot: "2026-11-04T00:00:00Z" });
    expect(s.wu_count).toBe(2); expect(s.updates[0]).toMatchObject({ kb: "KB5044284", severity: "Critical", security: true, cves: 12, size_mb: 812 });
    expect(s.updates[1].severity).toBeNull(); expect(s.apps[0]).toMatchObject({ id: "Google.Chrome", available: "130.0.2" });
    expect(s.reboot_pending).toBe(true); expect(s.wsus).toBeNull();
  });
  it("validates params", () => {
    expect(paramsSchema.parse({ wu: "kb", kbs: ["KB5044284"], apps: ["Google.Chrome"] })).toBeTruthy();
    expect(() => paramsSchema.parse({ kbs: ["5044284; rm"] })).toThrow();
    expect(() => paramsSchema.parse({ apps: ["a b"] })).toThrow();
    expect(() => paramsSchema.parse({ minutes: 500 })).toThrow();
  });
  it("describes and previews", () => {
    expect(describe("update_install", { wu: "security", apps: "all" })).toContain("セキュリティ更新");
    expect(describe("reboot", { minutes: 10 })).toContain("10 分後");
    const st = previewSteps({ os_family: "windows", agent_id: "008", kind: "agent_only", name: "smtp" }, "update_install", { wu: "kb", kbs: ["KB5044284"] }, false, 7);
    expect(st[0].command).toContain('"update-install","--wu","kb","--kb","KB5044284","--id","ma7"');
    const rb = previewSteps({ os_family: "windows", agent_id: "008", kind: "agent_only", name: "smtp" }, "reboot", { minutes: 15 }, false, 8);
    expect(rb[0].command).toContain('"reboot","--minutes","15"');
    expect(previewSteps({ os_family: "windows", agent_id: "008", kind: "agent_only", name: "smtp" }, "reboot", {}, true, 8)[0].command).toContain("reboot-cancel");
  });
});

import { applyWinProgress, type WinUpdateState } from "./actions.js";
d("EDR-168 per-update progress", () => {
  const scan = { updates: [{ kb: "KB1", title: "CU", size_mb: 800, security: true }, { kb: "KB2", title: "Defender", size_mb: 200, security: true }], apps: [] };
  const st0: WinUpdateState = { phase: "x", items: [], started_at: "t0", last_seen_at: null, finished_at: null, reboot_required: null, ok: null };
  it("follows add-on 1.2 lines", () => {
    let st = applyWinProgress(st0, { phase: "progress", detail: "downloading 2 update(s): KB1,KB2" }, scan, "t1");
    expect(st.items.map((i) => [i.key, i.state, i.size_mb])).toEqual([["KB1", "downloading", 800], ["KB2", "downloading", 200]]);
    st = applyWinProgress(st, { phase: "progress", detail: "installing 2 update(s)" }, scan, "t2");
    expect(st.phase).toBe("インストール中"); expect(st.items.every((i) => i.state === "installing")).toBe(true);
    st = applyWinProgress(st, { phase: "done", ok: "false", installed: "KB2", failed: "KB1(code 4, 0x80240022)", reboot_required: "true", detail: "installed 1, failed 1" }, scan, "t3");
    expect(st.items.find((i) => i.key === "KB1")).toMatchObject({ state: "failed", note: "code 4, 0x80240022" });
    expect(st.items.find((i) => i.key === "KB2")?.state).toBe("installed");
    expect(st.reboot_required).toBe(true); expect(st.ok).toBe(false);
  });
  it("uses items from add-on 1.3", () => {
    const st = applyWinProgress(st0, { phase: "progress", detail: "downloading KB1 (1/2)", items: "KB1=downloaded;KB2=downloading;app:Google.Chrome=pending" }, scan, "t1");
    expect(st.items.map((i) => `${i.kind}:${i.key}=${i.state}`)).toEqual(["wu:KB1=downloaded", "wu:KB2=downloading", "app:Google.Chrome=pending"]);
  });
});

import { firstRun, nextRun } from "../scheduler/index.js";
d("EDR-168 first run of a daily schedule", () => {
  it("runs today at 22:00 JST when it is still ahead", () => {
    const now = new Date("2026-11-05T01:13:52Z"); // 10:13 JST
    expect(firstRun(now, 1440, "22:00").toISOString()).toBe("2026-11-05T13:00:00.000Z");
    expect(nextRun(now, 1440, "22:00").toISOString()).toBe("2026-11-06T13:00:00.000Z"); // later runs: the day after
  });
  it("moves to tomorrow when the time has passed", () => {
    expect(firstRun(new Date("2026-11-05T13:30:00Z"), 1440, "22:00").toISOString()).toBe("2026-11-06T13:00:00.000Z");
  });
  it("describes install + reboot", () => {
    expect(describe("update_install", { wu: "kb", kbs: ["KB5123099"], reboot_after: 10 })).toContain("10 分後に再起動まで");
  });
});

d("EDR-168 1.3.0 recipes / cancel / add-on update", () => {
  const h = { os_family: "windows", agent_id: "008", kind: "agent_only", name: "pc-b" };
  it("parses via", () => {
    const s = parseUpdateScan({ app_count: "2", apps: "Google.Chrome|130.0.1|131.0.0|Google Chrome|recipe ;; 7zip.7zip|23.01|24.08|7-Zip|winget", winget: "ok" });
    expect(s.apps[0]).toMatchObject({ id: "Google.Chrome", via: "recipe", name: "Google Chrome" });
    expect(s.apps[1].via).toBe("winget");
    const old = parseUpdateScan({ app_count: "1", apps: "Foo.Bar|1|2|Foo Bar", winget: "ok" });
    expect(old.apps[0]).toMatchObject({ via: "winget", name: "Foo Bar" });
  });
  it("cancel and add-on update commands", () => {
    expect(previewSteps(h, "update_install", { wu: "all" }, true, 9)[0].command).toContain("update-cancel");
    expect(describe("addon_update", { target: "1.3.1" } as any)).toContain("v1.3.1");
    expect(previewSteps(h, "addon_update", { target: "1.3.1" } as any, false, 10)[0].command).toContain('"addon-update","1.3.1"');
  });
});

import { hhmmJst } from "./actions.js";
d("EDR-168 1.3.1 restart prompt", () => {
  it("formats JST times", () => {
    expect(hhmmJst(Date.parse("2026-11-06T02:42:00Z"))).toBe("11:42");
    expect(hhmmJst(Date.parse("2026-11-06T15:05:00Z"))).toBe("00:05");
  });
});

import { protectApps } from "./actions.js";
d("EDR-168 Wazuh agent is never upgraded by winget", () => {
  it("hides and filters it", () => {
    const s = parseUpdateScan({ app_count: "2", apps: "Wazuh.WazuhAgent|4.14.1|4.14.3|Wazuh Agent|winget ;; Google.Chrome|1|2|Google Chrome|recipe" });
    expect(s.apps.map((a) => a.id)).toEqual(["Google.Chrome"]); expect(s.app_count).toBe(1);
    expect(protectApps({ ar_addon_version: "1.3.0" }, { apps: ["Wazuh.WazuhAgent", "Google.Chrome"] }).apps).toEqual(["Google.Chrome"]);
    const h = { ar_addon_version: "1.3.0", win_updates: JSON.stringify({ apps: [{ id: "Wazuh.WazuhAgent" }, { id: "Zoom.Zoom" }] }) };
    expect(protectApps(h, { apps: "all" }).apps).toEqual(["Zoom.Zoom"]);
    expect(protectApps({ ar_addon_version: "1.3.2" }, { apps: "all" }).apps).toBe("all");
  });
});

import { sameButAddon, windowsGroups } from "../agentpack/index.js";
d("EDR-171 remote pack", () => {
  it("treats add-on-only differences as the same pack", () => {
    const a = { files: { "Install-EdrAgent.ps1": "x", "config.json": "c", "addon/mamorai-ar.ps1": "1" }, settings: { m: 1 }, wazuh_version: "4.14.1-1", installer: "i", addon_version: "1.3.0" };
    expect(sameButAddon(a, { ...a, files: { ...a.files, "addon/mamorai-ar.ps1": "2" }, addon_version: "1.3.3" })).toBe(true);
    expect(sameButAddon(a, { ...a, files: { ...a.files, "config.json": "d" } })).toBe(false);
    expect(sameButAddon(a, { ...a, wazuh_version: "4.14.2-1" })).toBe(false);
  });
  it("lists the Windows groups", () => {
    expect(windowsGroups({ windows: { group_laptop: "windows,laptop", group_desktop: "windows" } } as any)).toEqual(["windows", "laptop"]);
  });
});
