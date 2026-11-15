import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ZipReader, Uint8ArrayReader, TextWriter } from "@zip.js/zip.js";
import { createDb, migrate } from "../db/index.js";
import { SecretBox } from "../crypto/index.js";
import * as ap from "./index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoTemplates = path.resolve(here, "../../../installer/agent-pack");
async function unzip(buf: Buffer, password?: string | null): Promise<Record<string, { text: string; mode: number }>> {
  const r = new ZipReader(new Uint8ArrayReader(new Uint8Array(buf)), password ? { password } : {});
  const out: Record<string, { text: string; mode: number }> = {};
  for (const e of await r.getEntries()) if (!e.directory) out[e.filename] = { text: await e.getData!(new TextWriter()), mode: (e.externalFileAttributes >>> 16) & 0o777 };
  await r.close(); return out;
}

describe("agent pack", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mamorai-pack-"));
  const addon = path.join(tmp, "addon");
  const events: { event: string; payload: any }[] = [];
  const cfg: any = { APP_SECRET: "x".repeat(40), DB_DRIVER: "sqlite", DB_PATH: path.join(tmp, "t.db"), APP_DATA_DIR: tmp, AGENT_PACK_TEMPLATE_DIR: repoTemplates, AGENT_PACK_ADDON_DIR: addon, AGENT_PACK_CHECK_MIN: 10 };
  const db = createDb(cfg);
  const ctx: any = { cfg, db, box: new SecretBox("x".repeat(40)), version: "test", log: { warn: () => {}, info: () => {} }, audit: { log: async (_a: string, _i: unknown, event: string, payload: any) => { events.push({ event, payload }); } } };

  beforeAll(async () => {
    await migrate(db);
    fs.mkdirSync(addon);
    fs.writeFileSync(path.join(addon, "manifest.json"), JSON.stringify({ name: "mamorai-ar", version: "1.1.0" }));
    fs.writeFileSync(path.join(addon, "mamorai-ar.ps1"), "# signed body\r\n");
  });
  afterAll(async () => { await db.destroy(); fs.rmSync(tmp, { recursive: true, force: true }); });

  it("refuses to build before the manager address is set", async () => {
    const r = await ap.refresh(ctx, "startup");
    expect(r.windows.rev).toBeNull();
    await expect(ap.buildZip(ctx, "windows", {})).rejects.toThrow(/manager/);
  });

  it("creates r1 per OS once configured, and a new revision only when the contents change", async () => {
    const s = ap.settingsSchema.parse({ manager: { lan: "10.0.0.5", tailnet: "100.64.0.5" }, wazuh_version: "4.14.7-1", linux: { tailscale: true, ssh: { offer: true, allow_from: ["10.0.0.5"] } } });
    await ap.saveSettings(ctx, s, 1);
    const a = await ap.refresh(ctx, "settings");
    expect(a.windows.created && a.linux.created).toBe(true);
    const b = await ap.refresh(ctx, "auto");
    expect(b.windows.created || b.linux.created).toBe(false);
    // a new add-on version → only the Windows pack changes
    fs.writeFileSync(path.join(addon, "manifest.json"), JSON.stringify({ name: "mamorai-ar", version: "1.2.0" }));
    const c = await ap.refresh(ctx, "auto");
    expect(c.windows.created).toBe(true);
    expect(c.linux.created).toBe(false);
    const last = await ap.latestRev(ctx, "windows");
    expect(JSON.parse(last.changes)).toContain("Windows アドオン 1.1.0 → 1.2.0");
    expect(events.some((e) => e.event === "sshkey.generated")).toBe(true);
  });

  it("plain zip without secrets; once secrets are stored they go in automatically, encrypted, and make a new revision", async () => {
    const plain = await ap.buildZip(ctx, "linux", {});
    expect(plain.password).toBeNull();
    let z = await unzip(plain.buf);
    let top = `MamorAI-Agent-Linux-r${plain.rev}/`;
    let conf = JSON.parse(z[top + "config.json"].text);
    expect(conf.registrationPassword).toBe("");
    expect(conf.managerAddresses).toEqual(["100.64.0.5", "10.0.0.5"]);
    expect(conf.mamoraiSsh.publicKey).toMatch(/^ssh-ed25519 /);
    expect(JSON.parse(z[top + "pack.json"].text).rev).toBe(plain.rev);
    expect(z[top + "SHA256SUMS.txt"].text).toContain("  install-edr-agent-linux.sh");
    expect(z[top + "install-edr-agent-linux.sh"].mode).toBe(0o755);

    await expect(ap.setSecrets(ctx, { tailscale_auth_key: "not-a-key" }, 1)).rejects.toThrow(/tskey/);
    await ap.setSecrets(ctx, { tailscale_auth_key: "tskey-auth-dummy-value-for-tests-efgh", tailscale_expires_at: new Date(Date.now() + 5 * 86400_000).toISOString(), registration_password: "dummy-pass" }, 1);
    const st = ap.secretStatus(await ap.getSecrets(ctx));
    expect(st.tailscale.hint).toBe("tskey-…efgh");
    expect(JSON.stringify(st)).not.toContain("dummy-pass");
    const sec = await ap.buildZip(ctx, "linux", {});
    expect(sec.rev).toBeGreaterThan(plain.rev);           // new key / password → new revision
    expect(sec.password).toMatch(/^[A-Za-z2-9]{5}(-[A-Za-z2-9]{5}){3}$/);
    await expect(unzip(sec.buf, "wrong-pass")).rejects.toThrow();
    z = await unzip(sec.buf, sec.password);
    top = `MamorAI-Agent-Linux-r${sec.rev}/`;
    conf = JSON.parse(z[top + "config.json"].text);
    expect(conf.registrationPassword).toBe("dummy-pass");
    expect(conf.tailscaleAuthKey).toBe("tskey-auth-dummy-value-for-tests-efgh");
    const last = await ap.latestRev(ctx, "linux");
    expect(JSON.parse(last.changes)).toEqual(expect.arrayContaining(["Tailscale の認証キーを更新", "Wazuh の登録パスワードを更新"]));
    const o = await ap.overview(ctx);
    expect((o.packs as any).linux.problems.join()).toMatch(/あと \d+ 日で期限切れ/);
    const stored = JSON.stringify(await db("agent_pack_revs").select()) + JSON.stringify(await db("app_flags").select());
    expect(stored).not.toContain("dummy-pass");
    expect(stored).not.toContain("kTEST1234CNTRL");
  });

  it("windows pack carries the add-on and the laptop / desktop manager order", async () => {
    const w = await ap.buildZip(ctx, "windows", {});
    const z = await unzip(w.buf, w.password);
    const top = `MamorAI-Agent-Windows-r${w.rev}/`;
    expect(z[top + "addon/manifest.json"]).toBeTruthy();
    expect(z[top + "Install-EdrAgent.ps1"]).toBeTruthy();
    const conf = JSON.parse(z[top + "config.json"].text);
    expect(conf.managerTailnetIp).toBe("100.64.0.5");
    expect(conf.groupDesktop).toBe("default");
    expect(conf.tailscaleAuthKey).toMatch(/^tskey-/);
  });

  it("tailscale key reminders: 14 / 7 / 3 / 1 / 0 days, then once a day after expiry", () => {
    expect(ap.tsNoticeDue(30, null)).toBeNull();
    expect(ap.tsNoticeDue(14, null)).toBe("d14");
    expect(ap.tsNoticeDue(12, "d14")).toBeNull();
    expect(ap.tsNoticeDue(7, "d14")).toBe("d7");
    expect(ap.tsNoticeDue(2, "d7")).toBe("d3");
    expect(ap.tsNoticeDue(0, "d1")).toBe("d0");
    expect(ap.tsNoticeDue(-1, "d0", "2027-01-24")).toBe("expired:2027-01-24");
    expect(ap.tsNoticeDue(-2, "expired:2027-01-24", "2027-01-24")).toBeNull();
    expect(ap.tsNoticeDue(null, null)).toBeNull();
  });

  it("describeChanges names what changed", () => {
    expect(ap.describeChanges(null, {})).toEqual(["最初の版"]);
    expect(ap.describeChanges({ wazuh_version: "4.14.7-1", settings: { manager: { lan: "a" } } }, { wazuh_version: "4.14.8-1", settings: { manager: { lan: "b" } } }))
      .toEqual(["Wazuh エージェント 4.14.7-1 → 4.14.8-1", "manager のアドレスを変更"]);
  });
});
