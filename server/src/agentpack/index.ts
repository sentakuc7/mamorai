/**
 * EDR-130: agent packs — one zip per OS with everything an endpoint needs (Wazuh agent installer wrapper,
 * config generated from MamorAI's settings, the signed Windows active-response add-on, README, checksums).
 *
 *   - The pack is built on demand from: installer templates (installer/agent-pack/<os>), the pack settings
 *     (app_flags "agent_pack_settings"), the Wazuh agent version and — for Windows — the signed add-on folder.
 *   - Whatever goes in is hashed. When the hash changes (settings saved, add-on rebuilt, Wazuh upgraded, MamorAI
 *     updated with a new installer) a new revision rN is recorded automatically, with a list of what changed.
 *   - Secrets (Tailscale auth key, Wazuh enrollment password) are entered once (setup / settings / CLI), kept
 *     encrypted (SecretBox, key derived from APP_SECRET) and put into every pack automatically (EDR-137).
 *     The zip is then encrypted (ZipCrypto, so Windows Explorer and unzip open it without extra tools) with a
 *     password generated per download; the installers delete the extracted files after a successful run (EDR-138).
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader, configure as zipConfigure } from "@zip.js/zip.js";
import { fetch as ufetch } from "undici";
import { z } from "zod";
import type { Ctx } from "../api/context.js";
import { managerApi } from "../api/context.js";
import { generateEd25519, keyFingerprint } from "../ssh/index.js";

export type PackOs = "windows" | "linux";
export const PACK_OSES: PackOs[] = ["windows", "linux"];
const FLAG = "agent_pack_settings";
const SECRET_FLAG = "agent_pack_secrets";
zipConfigure({ useWebWorkers: false });

const addr = z.string().trim().max(253).regex(/^$|^[A-Za-z0-9.:\-]+$/, "IP address or host name");
const group = z.string().trim().min(1).max(255).regex(/^[A-Za-z0-9_.\-]+(,[A-Za-z0-9_.\-]+)*$/, "Wazuh group names, comma separated");
export const settingsSchema = z.object({
  manager: z.object({
    lan: addr.default(""),      // address on the office / home LAN
    tailnet: addr.default(""),  // Tailscale address (100.x) — empty if Tailscale is not used
    public: addr.default(""),   // address / DNS name reachable from the internet (optional)
  }).default({}),
  wazuh_version: z.string().trim().regex(/^(auto|\d+\.\d+\.\d+-\d+)$/, "auto or like 4.14.7-1").default("auto"),
  windows: z.object({
    group_laptop: group.default("default"),
    group_desktop: group.default("default"),
    device_type: z.enum(["ask", "laptop", "desktop"]).default("ask"),
    sysmon: z.boolean().default(true),
    sysmon_config_url: z.string().url().max(500).default("https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"),
  }).default({}),
  linux: z.object({
    group: group.default("default"),
    tailscale: z.boolean().default(false),
    auditd: z.boolean().default(true),
    docker: z.enum(["auto", "yes", "no"]).default("auto"),
    ssh: z.object({
      offer: z.boolean().default(true),          // the installer asks "let MamorAI operate this server?" (default answer: no)
      user: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/).default("mamorai"),
      key_id: z.number().int().nullable().default(null), // MamorAI SSH key put into authorized_keys (created on first save)
      allow_from: z.array(z.string().regex(/^[0-9a-fA-F:.]+(\/\d{1,3})?$/)).max(16).default([]), // source addresses of MamorAI
      sudo: z.enum(["full", "none"]).default("full"), // full = scans + host actions; none = scans with what a normal user can read
    }).default({}),
  }).default({}),
});
export type PackSettings = z.infer<typeof settingsSchema>;

export function templateDir(ctx: Ctx): string { return ctx.cfg.AGENT_PACK_TEMPLATE_DIR; }
export function addonDir(ctx: Ctx): string { return ctx.cfg.AGENT_PACK_ADDON_DIR; }
function cacheDir(ctx: Ctx): string { return path.join(ctx.cfg.APP_DATA_DIR, "agentpack-cache"); }

export async function getSettings(ctx: Ctx): Promise<PackSettings> {
  const r = await ctx.db("app_flags").where({ key: FLAG }).first();
  let raw: unknown = {};
  try { raw = r?.value ? JSON.parse(r.value) : {}; } catch { raw = {}; }
  const p = settingsSchema.safeParse(raw);
  return p.success ? p.data : settingsSchema.parse({});
}

export async function saveSettings(ctx: Ctx, s: PackSettings, userId: number | null): Promise<PackSettings> {
  const { db } = ctx;
  // the Linux "let MamorAI operate this server" option needs a key: create a dedicated one the first time
  if (s.linux.ssh.offer && !s.linux.ssh.key_id) s.linux.ssh.key_id = await ensurePackKey(ctx);
  if (s.linux.ssh.key_id && !(await db("ssh_keys").where({ id: s.linux.ssh.key_id }).first())) throw Object.assign(new Error("linux.ssh.key_id: SSH key not found"), { status: 400 });
  const value = JSON.stringify(s);
  const ex = await db("app_flags").where({ key: FLAG }).first();
  if (ex) await db("app_flags").where({ key: FLAG }).update({ value, updated_by: userId, updated_at: db.fn.now() });
  else await db("app_flags").insert({ key: FLAG, value, updated_by: userId });
  return s;
}

async function ensurePackKey(ctx: Ctx): Promise<number> {
  const { db } = ctx;
  const name = "agent-pack (mamorai)";
  const ex = await db("ssh_keys").where({ name }).first();
  if (ex) return ex.id;
  const k = generateEd25519("mamorai-agent-pack");
  const [id] = await db("ssh_keys").insert({ name, public_key: k.publicKey, private_key_enc: ctx.box.encrypt(k.privateKey), fingerprint: keyFingerprint(k.publicKey) })
    .returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
  await ctx.audit.log("system", null, "sshkey.generated", { id, name, purpose: "agent pack (Linux: let MamorAI operate the server)" });
  return id;
}

// ---- EDR-137: secrets kept by MamorAI (encrypted) and put into every pack ----
export interface StoredSecrets { tailscale_auth_key?: string; tailscale_expires_at?: string | null; registration_password?: string; updated_at?: string }
export const TS_KEY_RE = /^tskey-[A-Za-z0-9_-]{8,200}$/;
export async function getSecrets(ctx: Ctx): Promise<StoredSecrets> {
  const r = await ctx.db("app_flags").where({ key: SECRET_FLAG }).first();
  if (!r?.value) return {};
  try { return JSON.parse(ctx.box.decrypt(r.value)); } catch { return {}; }
}
/** patch: a string sets, null clears, undefined keeps */
export async function setSecrets(ctx: Ctx, patch: { tailscale_auth_key?: string | null; tailscale_expires_at?: string | null; registration_password?: string | null }, userId: number | null): Promise<Record<string, string>> {
  const cur = await getSecrets(ctx);
  const changed: Record<string, string> = {};
  if (patch.tailscale_auth_key !== undefined) {
    if (patch.tailscale_auth_key && !TS_KEY_RE.test(patch.tailscale_auth_key)) throw Object.assign(new Error("Tailscale の認証キーは tskey-... の形です"), { status: 400 });
    if (patch.tailscale_auth_key) { cur.tailscale_auth_key = patch.tailscale_auth_key; changed.tailscale = "set"; } else { delete cur.tailscale_auth_key; delete cur.tailscale_expires_at; changed.tailscale = "cleared"; }
  }
  if (patch.tailscale_expires_at !== undefined) {
    if (patch.tailscale_expires_at && isNaN(new Date(patch.tailscale_expires_at).getTime())) throw Object.assign(new Error("tailscale_expires_at: 日付の形が正しくありません"), { status: 400 });
    cur.tailscale_expires_at = patch.tailscale_expires_at || null; changed.tailscale_expires = patch.tailscale_expires_at ? "set" : "cleared";
  }
  if (patch.registration_password !== undefined) {
    if (patch.registration_password && (patch.registration_password.length < 8 || /[\s"'`$]/.test(patch.registration_password))) throw Object.assign(new Error("登録パスワードは 8 文字以上で、空白・引用符・$ を含めないでください"), { status: 400 });
    if (patch.registration_password) { cur.registration_password = patch.registration_password; changed.registration = "set"; } else { delete cur.registration_password; changed.registration = "cleared"; }
  }
  cur.updated_at = new Date().toISOString();
  const value = ctx.box.encrypt(JSON.stringify(cur));
  const ex = await ctx.db("app_flags").where({ key: SECRET_FLAG }).first();
  if (ex) await ctx.db("app_flags").where({ key: SECRET_FLAG }).update({ value, updated_by: userId, updated_at: ctx.db.fn.now() });
  else await ctx.db("app_flags").insert({ key: SECRET_FLAG, value, updated_by: userId });
  return changed;
}
/** what the UI may see: never the values */
export function secretStatus(sec: StoredSecrets) {
  const exp = sec.tailscale_expires_at ? new Date(sec.tailscale_expires_at) : null;
  const days = exp ? Math.floor((exp.getTime() - Date.now()) / 86400_000) : null;
  return {
    tailscale: { set: !!sec.tailscale_auth_key, hint: sec.tailscale_auth_key ? `tskey-…${sec.tailscale_auth_key.slice(-4)}` : null, expires_at: sec.tailscale_expires_at ?? null, days_left: days },
    registration: { set: !!sec.registration_password },
    updated_at: sec.updated_at ?? null,
  };
}
/** keyed fingerprint (so a new key / password makes a new pack revision without storing anything guessable) */
function secretFp(ctx: Ctx, v?: string): string | null { return v ? crypto.createHmac("sha256", ctx.cfg.APP_SECRET).update("agent-pack:" + v).digest("hex").slice(0, 12) : null; }
function usesTailscale(s: PackSettings, os: PackOs): boolean { return os === "windows" ? !!s.manager.tailnet : s.linux.tailscale; }

/** what is missing before a pack can be downloaded (shown in the dialog) */
export function problems(s: PackSettings, os: PackOs, extra: { wazuhVersion: string | null; addonVersion: string | null; templates: boolean; secrets?: ReturnType<typeof secretStatus> }): string[] {
  const p: string[] = [];
  if (!extra.templates) p.push("インストーラーのひな形が見つかりません（AGENT_PACK_TEMPLATE_DIR）");
  if (!s.manager.lan && !s.manager.tailnet && !s.manager.public) p.push("Wazuh manager のアドレスが未設定です（設定 › エージェントパック）");
  if (!extra.wazuhVersion) p.push("Wazuh エージェントの版が分かりません。設定で版を指定するか、Wazuh API に接続してください");
  if (os === "linux" && s.linux.tailscale && !s.manager.tailnet) p.push("Linux で Tailscale を使う設定ですが、manager の Tailscale アドレスが未設定です");
  if (os === "linux" && s.linux.ssh.offer && !s.linux.ssh.allow_from.length) p.push("MamorAI から SSH するときの接続元アドレス（allow_from）が未設定です");
  const st = extra.secrets;
  if (st && usesTailscale(s, os)) {
    if (!st.tailscale.set) p.push(`（注意）Tailscale の認証キーが未登録です。${os === "windows" ? "ノート PC" : "サーバー"}ではブラウザでのログインが必要になります（設定 › エージェントパック › 秘密情報）`);
    else if (st.tailscale.days_left !== null && st.tailscale.days_left < 0) p.push("（注意）Tailscale の認証キーの期限が切れています。新しいキーを登録してください");
    else if (st.tailscale.days_left !== null && st.tailscale.days_left <= 14) p.push(`（注意）Tailscale の認証キーはあと ${st.tailscale.days_left} 日で期限切れです`);
  }
  if (st && !st.registration.set) p.push("（注意）Wazuh の登録パスワードが未登録です。新規インストールの途中で入力を求めます（設定 › エージェントパック › 秘密情報）");
  if (os === "windows" && !extra.addonVersion) p.push("（注意）Windows 用アドオンが見つかりません。パックは作れますが、MamorAI からの遮断操作は使えません（docs/host-actions.md 2.2）");
  return p;
}
const blocking = (p: string[]) => p.filter((x) => !x.startsWith("（注意）"));

let wazuhCache: { at: number; v: string | null } | null = null;
export async function resolveWazuhVersion(ctx: Ctx, s: PackSettings): Promise<string | null> {
  if (s.wazuh_version !== "auto") return s.wazuh_version;
  if (wazuhCache && Date.now() - wazuhCache.at < 10 * 60_000) return wazuhCache.v;
  let v: string | null = null;
  try {
    const inst = await ctx.db("wazuh_instances").orderBy("id").first();
    if (inst) {
      const api = await managerApi(ctx, inst.id);
      const r: any = await api.get("/");
      const m = String(r?.data?.api_version ?? "").match(/^(\d+\.\d+\.\d+)/);
      if (m) v = `${m[1]}-1`;
    }
  } catch { v = null; }
  wazuhCache = { at: Date.now(), v: v ?? wazuhCache?.v ?? null };
  return wazuhCache.v;
}

function readTree(root: string, prefix = ""): { path: string; data: Buffer }[] {
  if (!fs.existsSync(root)) return [];
  const out: { path: string; data: Buffer }[] = [];
  for (const e of fs.readdirSync(root, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (e.name.startsWith(".")) continue;
    const p = path.join(root, e.name);
    if (e.isDirectory()) out.push(...readTree(p, prefix + e.name + "/"));
    else if (e.isFile()) out.push({ path: prefix + e.name, data: fs.readFileSync(p) });
  }
  return out;
}
const sha = (b: Buffer | string) => crypto.createHash("sha256").update(b).digest("hex");

export function addonInfo(ctx: Ctx): { version: string | null; files: { path: string; data: Buffer }[] } {
  const dir = addonDir(ctx);
  const man = path.join(dir, "manifest.json");
  if (!fs.existsSync(man)) return { version: null, files: [] };
  try {
    const m = JSON.parse(fs.readFileSync(man, "utf8"));
    const files = readTree(dir).filter((f) => !f.path.includes("/"));
    return { version: String(m.version ?? "") || null, files };
  } catch { return { version: null, files: [] }; }
}

/** config.json for the installer (no secrets here; they are added per download) */
export function packConfig(os: PackOs, s: PackSettings, wazuhVersion: string, sshPub: string | null): Record<string, unknown> {
  if (os === "windows") {
    return {
      managerLanIp: s.manager.lan, managerTailnetIp: s.manager.tailnet, managerPublicAddress: s.manager.public,
      groupLaptop: s.windows.group_laptop, groupDesktop: s.windows.group_desktop,
      deviceType: s.windows.device_type === "ask" ? "" : s.windows.device_type,
      wazuhVersion, sysmon: s.windows.sysmon, sysmonConfigUrl: s.windows.sysmon_config_url,
      registrationPassword: "", tailscaleAuthKey: "",
    };
  }
  const order = s.linux.tailscale ? [s.manager.tailnet, s.manager.lan, s.manager.public] : [s.manager.lan, s.manager.public, s.manager.tailnet];
  return {
    managerAddresses: [...new Set(order.filter(Boolean))],
    useTailscale: s.linux.tailscale, group: s.linux.group, auditd: s.linux.auditd, docker: s.linux.docker, wazuhVersion,
    mamoraiSsh: s.linux.ssh.offer && sshPub ? { offer: true, user: s.linux.ssh.user, publicKey: sshPub, allowFrom: s.linux.ssh.allow_from, sudo: s.linux.ssh.sudo } : { offer: false },
    registrationPassword: "", tailscaleAuthKey: "",
  };
}

export interface PackParts {
  os: PackOs; settings: PackSettings; wazuhVersion: string | null; addonVersion: string | null;
  files: { path: string; data: Buffer }[];           // without pack.json / SHA256SUMS.txt
  hash: string; components: Record<string, unknown>; problems: string[];
}

export async function parts(ctx: Ctx, os: PackOs): Promise<PackParts> {
  const s = await getSettings(ctx);
  const sec = await getSecrets(ctx);
  const wazuhVersion = await resolveWazuhVersion(ctx, s);
  const tpl = readTree(path.join(templateDir(ctx), os));
  const addon = os === "windows" ? addonInfo(ctx) : { version: null, files: [] };
  let sshPub: string | null = null;
  if (os === "linux" && s.linux.ssh.offer && s.linux.ssh.key_id) sshPub = (await ctx.db("ssh_keys").where({ id: s.linux.ssh.key_id }).first())?.public_key ?? null;
  const files: { path: string; data: Buffer }[] = [...tpl];
  for (const f of addon.files) files.push({ path: `addon/${f.path}`, data: f.data });
  files.push({ path: "config.json", data: Buffer.from(JSON.stringify(packConfig(os, s, wazuhVersion ?? "", sshPub), null, 2) + "\n") });
  files.sort((a, b) => a.path.localeCompare(b.path));
  const fileHashes = Object.fromEntries(files.map((f) => [f.path, sha(f.data)]));
  const relevant = os === "windows" ? { manager: s.manager, windows: s.windows } : { manager: s.manager, linux: { ...s.linux, ssh: { ...s.linux.ssh, key_fp: sshPub ? sha(sshPub).slice(0, 16) : null } } };
  const secrets = { tailscale: usesTailscale(s, os) ? secretFp(ctx, sec.tailscale_auth_key) : null, registration: secretFp(ctx, sec.registration_password) };
  const components = { files: fileHashes, settings: relevant, wazuh_version: wazuhVersion, addon_version: addon.version, installer: sha(tpl.map((f) => `${f.path}:${sha(f.data)}`).join("\n")).slice(0, 16), secrets };
  const hash = sha(JSON.stringify({ fileHashes, secrets }));
  const pr = problems(s, os, { wazuhVersion, addonVersion: addon.version, templates: tpl.length > 0, secrets: secretStatus(sec) });
  return { os, settings: s, wazuhVersion, addonVersion: addon.version, files, hash, components, problems: pr };
}

/** human readable list of what changed between two revisions */
export function describeChanges(prev: any | null, next: any): string[] {
  if (!prev) return ["最初の版"];
  const out: string[] = [];
  if (prev.wazuh_version !== next.wazuh_version) out.push(`Wazuh エージェント ${prev.wazuh_version ?? "?"} → ${next.wazuh_version ?? "?"}`);
  if (prev.addon_version !== next.addon_version) out.push(`Windows アドオン ${prev.addon_version ?? "なし"} → ${next.addon_version ?? "なし"}`);
  const ps = prev.settings ?? {}, ns = next.settings ?? {};
  const names: Record<string, string> = { manager: "manager のアドレス", windows: "Windows の設定（グループ・端末の種類・Sysmon）", linux: "Linux の設定（グループ・Tailscale・auditd・SSH）" };
  for (const k of Object.keys(names)) if (JSON.stringify(ps[k]) !== JSON.stringify(ns[k])) out.push(`${names[k]}を変更`);
  if (prev.installer !== next.installer) out.push("インストーラー本体を更新");
  if ((prev.secrets?.tailscale ?? null) !== (next.secrets?.tailscale ?? null)) out.push(next.secrets?.tailscale ? "Tailscale の認証キーを更新" : "Tailscale の認証キーを外した");
  if ((prev.secrets?.registration ?? null) !== (next.secrets?.registration ?? null)) out.push(next.secrets?.registration ? "Wazuh の登録パスワードを更新" : "Wazuh の登録パスワードを外した");
  const pf = prev.files ?? {}, nf = next.files ?? {};
  const other = Object.keys({ ...pf, ...nf }).filter((f) => pf[f] !== nf[f] && !f.startsWith("addon/") && f !== "config.json");
  if (!out.length && other.length) out.push(`ファイルを更新: ${other.slice(0, 5).join(", ")}`);
  if (!out.length) out.push("内容を更新");
  return out;
}

export async function latestRev(ctx: Ctx, os: PackOs): Promise<any | null> {
  return (await ctx.db("agent_pack_revs").where({ os }).orderBy("id", "desc").first()) ?? null;
}

/** record a new revision when the contents changed; returns the current revision per OS */
export async function refresh(ctx: Ctx, reason: string): Promise<Record<PackOs, { rev: number | null; created: boolean }>> {
  const out = {} as Record<PackOs, { rev: number | null; created: boolean }>;
  for (const os of PACK_OSES) {
    const p = await parts(ctx, os);
    const last = await latestRev(ctx, os);
    if (blocking(p.problems).length && !last) { out[os] = { rev: null, created: false }; continue; } // nothing usable yet
    if (last && last.hash === p.hash) { out[os] = { rev: last.id, created: false }; continue; }
    if (blocking(p.problems).length) { out[os] = { rev: last?.id ?? null, created: false }; continue; } // keep the last good one
    const prevComp = last ? JSON.parse(last.components) : null;
    const changes = describeChanges(prevComp, p.components);
    const [id] = await ctx.db("agent_pack_revs").insert({ os, hash: p.hash, components: JSON.stringify(p.components), changes: JSON.stringify(changes), reason })
      .returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await ctx.audit.log("system", null, "agent_pack.updated", { os, rev: id, reason, changes });
    out[os] = { rev: id, created: true };
  }
  return out;
}


/** payloads for an offline Windows pack (agent MSI, Sysmon, Sysmon config), cached under the data dir */
async function offlinePayloads(ctx: Ctx, s: PackSettings, wazuhVersion: string): Promise<{ path: string; data: Buffer }[]> {
  const dir = cacheDir(ctx); fs.mkdirSync(dir, { recursive: true });
  const want = [
    { name: `wazuh-agent-${wazuhVersion}.msi`, url: `https://packages.wazuh.com/4.x/windows/wazuh-agent-${wazuhVersion}.msi`, maxAgeDays: 3650 },
    ...(s.windows.sysmon ? [
      { name: "Sysmon.zip", url: "https://download.sysinternals.com/files/Sysmon.zip", maxAgeDays: 30 },
      { name: "sysmonconfig.xml", url: s.windows.sysmon_config_url, maxAgeDays: 7 },
    ] : []),
  ];
  const out: { path: string; data: Buffer }[] = [];
  for (const w of want) {
    const f = path.join(dir, w.name.replace(/[^\w.\-]/g, "_"));
    const fresh = fs.existsSync(f) && (Date.now() - fs.statSync(f).mtimeMs) < w.maxAgeDays * 86400_000 && fs.statSync(f).size > 0;
    if (!fresh) {
      const res = await ufetch(w.url, { signal: AbortSignal.timeout(180_000) });
      if (!res.ok) throw Object.assign(new Error(`オフライン用ファイルを取得できません: ${w.url} → ${res.status}`), { status: 502 });
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length < 100) throw Object.assign(new Error(`オフライン用ファイルが空です: ${w.url}`), { status: 502 });
      fs.writeFileSync(f + ".tmp", buf); fs.renameSync(f + ".tmp", f);
    }
    out.push({ path: w.name, data: fs.readFileSync(f) });
  }
  return out;
}

/** readable, unambiguous password for the encrypted zip (shown once in the dialog) */
export function zipPassword(): string {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const pick = () => Array.from(crypto.randomBytes(5), (b) => a[b % a.length]).join("");
  return [pick(), pick(), pick(), pick()].join("-");
}

export async function buildZip(ctx: Ctx, os: PackOs, opts: { offline?: boolean; encrypt?: boolean }): Promise<{ buf: Buffer; name: string; rev: number; sha256: string; password: string | null; contains: { tailscale: boolean; registration: boolean } }> {
  await refresh(ctx, "download");
  const p = await parts(ctx, os);
  const bl = blocking(p.problems);
  if (bl.length) throw Object.assign(new Error(bl.join(" / ")), { status: 409 });
  const last = await latestRev(ctx, os);
  if (!last) throw Object.assign(new Error("パックの版がまだありません"), { status: 409 });
  const rev = last.id as number;
  const files = p.files.map((f) => ({ ...f }));
  const sec = await getSecrets(ctx);
  const contains = { tailscale: usesTailscale(p.settings, os) && !!sec.tailscale_auth_key, registration: !!sec.registration_password };
  if (contains.tailscale || contains.registration) {
    const i = files.findIndex((f) => f.path === "config.json");
    const c = JSON.parse(files[i].data.toString("utf8"));
    if (contains.registration) c.registrationPassword = sec.registration_password;
    if (contains.tailscale) c.tailscaleAuthKey = sec.tailscale_auth_key;
    files[i] = { path: "config.json", data: Buffer.from(JSON.stringify(c, null, 2) + "\n") };
  }
  if (opts.offline) {
    if (os !== "windows") throw Object.assign(new Error("オフライン版は Windows だけです（Linux はパッケージリポジトリから入れます）"), { status: 400 });
    files.push(...(await offlinePayloads(ctx, p.settings, p.wazuhVersion!)));
  }
  const withSecrets = contains.tailscale || contains.registration;
  const packJson = {
    product: "MamorAI agent pack", os, rev, built_at: new Date().toISOString(), mamorai_version: ctx.version,
    wazuh_version: p.wazuhVersion, addon_version: p.addonVersion, offline: !!opts.offline, contains_secrets: withSecrets,
    changes: JSON.parse(last.changes ?? "[]"),
  };
  files.push({ path: "pack.json", data: Buffer.from(JSON.stringify(packJson, null, 2) + "\n") });
  files.sort((a, b) => a.path.localeCompare(b.path));
  const sums = files.map((f) => `${sha(f.data)}  ${f.path}`).join("\n") + "\n";
  files.push({ path: "SHA256SUMS.txt", data: Buffer.from(sums) });
  const top = `MamorAI-Agent-${os === "windows" ? "Windows" : "Linux"}-r${rev}`;
  // encrypted whenever secrets are inside (or when asked). ZipCrypto: opened by Windows Explorer and Info-ZIP unzip as is.
  const password = (opts.encrypt ?? withSecrets) ? zipPassword() : null;
  const writer = new ZipWriter(new Uint8ArrayWriter(), { level: 9, ...(password ? { password, zipCrypto: true } : {}) });
  const fixed = new Date(last.created_at ? new Date(last.created_at).getTime() : Date.now());
  for (const f of files) {
    const mode = os === "linux" && f.path.endsWith(".sh") ? 0o100755 : 0o100644;
    await writer.add(`${top}/${f.path}`, new Uint8ArrayReader(new Uint8Array(f.data)), { lastModDate: fixed, msDosCompatible: false, externalFileAttributes: (mode << 16) >>> 0 });
  }
  const buf = Buffer.from(await writer.close());
  const name = `${top}${opts.offline ? "-offline" : ""}.zip`;
  return { buf, name, rev, sha256: sha(buf), password, contains };
}

/** summary for the dialog / settings tab */
export function sameButAddon(a: any, b: any): boolean {
  const strip = (c: any) => { const f = { ...(c?.files ?? {}) }; for (const k of Object.keys(f)) if (k.startsWith("addon/")) delete f[k]; return JSON.stringify({ f, s: c?.settings ?? null, w: c?.wazuh_version ?? null, i: c?.installer ?? null }); };
  return strip(a) === strip(b);
}
async function addonOnlyRevs(ctx: Ctx, os: PackOs, last: any): Promise<number[]> {
  const lc = JSON.parse(last.components ?? "{}");
  const rows = await ctx.db("agent_pack_revs").where({ os }).select("id", "components");
  return rows.filter((r: any) => { try { return sameButAddon(JSON.parse(r.components ?? "{}"), lc); } catch { return false; } }).map((r: any) => r.id);
}

export async function overview(ctx: Ctx) {
  const s = await getSettings(ctx);
  const out: Record<string, unknown> = {};
  for (const os of PACK_OSES) {
    const p = await parts(ctx, os);
    const revs = await ctx.db("agent_pack_revs").where({ os }).orderBy("id", "desc").limit(5);
    const last = revs[0];
    out[os] = {
      rev: last?.id ?? null, created_at: last?.created_at ?? null, up_to_date: !!last && last.hash === p.hash,
      wazuh_version: p.wazuhVersion, addon_version: p.addonVersion, problems: p.problems,
      files: p.files.map((f) => f.path),
      history: revs.map((r: any) => ({ rev: r.id, created_at: r.created_at, reason: r.reason, changes: JSON.parse(r.changes ?? "[]") })),
      // EDR-168: older revisions with exactly the same content as the latest one (a change and its undo make a new number)
      same_as: last ? (await ctx.db("agent_pack_revs").where({ os, hash: last.hash }).select("id")).map((r: any) => r.id) : [],
      // EDR-171: revisions that differ from the latest only in the add-on (and secrets): a PC with such a pack and the
      // latest add-on (updated from MamorAI) is not out of date
      addon_only: last ? await addonOnlyRevs(ctx, os, last) : [],
    };
  }
  let sshKey: any = null;
  if (s.linux.ssh.key_id) { const k = await ctx.db("ssh_keys").where({ id: s.linux.ssh.key_id }).first(); if (k) sshKey = { id: k.id, name: k.name, fingerprint: k.fingerprint }; }
  return { settings: s, ssh_key: sshKey, secrets: secretStatus(await getSecrets(ctx)), packs: out, manager_tailscale: tailscaleJoinStatus(ctx), remote: remotePackStatus(ctx) };
}

// ---------------- EDR-149: the MamorAI server itself joins the tailnet (through the host bridge) ----------------
/** The container cannot run `tailscale up` on the host. A root helper on the host (installer module 62) watches
 *  <HOST_BRIDGE_DIR>/requests/*.json, runs module 60 with the key and writes the outcome to results/<name>.json.
 *  The request file is taken away by the helper at once; the key never stays on disk. */
function bridgeDir(ctx: Ctx) { return ctx.cfg.HOST_BRIDGE_DIR; }
export function hostBridgeAvailable(ctx: Ctx): boolean {
  try { fs.accessSync(path.join(bridgeDir(ctx), "requests"), fs.constants.W_OK); return true; } catch { return false; }
}
export function requestTailscaleJoin(ctx: Ctx, key: string, expiresAt: string | null): "requested" | "unavailable" {
  if (!hostBridgeAvailable(ctx)) return "unavailable";
  const dir = path.join(bridgeDir(ctx), "requests");
  const tmp = path.join(dir, `.tailscale-join.${process.pid}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify({ key, expires: expiresAt ? expiresAt.slice(0, 10) : null, requested_at: new Date().toISOString() }), { mode: 0o600 });
  fs.renameSync(tmp, path.join(dir, "tailscale-join.json"));
  try { fs.rmSync(path.join(bridgeDir(ctx), "results", "tailscale-join.json"), { force: true }); } catch { /* results/ is root-owned: the helper overwrites it */ }
  return "requested";
}
export function tailscaleJoinStatus(ctx: Ctx): { bridge: boolean; pending: boolean; result: { ok: boolean; ip?: string | null; error?: string | null; at?: string } | null } {
  const bridge = hostBridgeAvailable(ctx);
  const pending = bridge && fs.existsSync(path.join(bridgeDir(ctx), "requests", "tailscale-join.json"));
  let result: any = null;
  try { result = JSON.parse(fs.readFileSync(path.join(bridgeDir(ctx), "results", "tailscale-join.json"), "utf8")); } catch { /* none yet */ }
  return { bridge, pending, result };
}

// ---------------- EDR-171: remote pack update — publish the Windows pack (no secrets) into the Wazuh shared folder ----------------
/** groups the Windows pack is used with (laptop + desktop settings, comma separated) */
export function windowsGroups(s: PackSettings): string[] {
  return [...new Set(`${s.windows.group_laptop},${s.windows.group_desktop}`.split(",").map((g) => g.trim()).filter(Boolean))];
}
/** the files the endpoint needs for "Install-EdrAgent.ps1 -Mode update" (no .bat / README / secrets) */
export async function remotePackFiles(ctx: Ctx): Promise<{ rev: number; hash: string; addon_version: string; groups: string[]; files: Record<string, Buffer> } | null> {
  const last = await latestRev(ctx, "windows"); if (!last) return null;
  const p = await parts(ctx, "windows");
  if (p.hash !== last.hash || !p.addonVersion) return null; // the latest revision is not built yet (next refresh)
  const pick = (n: string) => p.files.find((f) => f.path === n)?.data;
  const inst = pick("Install-EdrAgent.ps1"), ai = pick("addon/Install-MamoraiAddon.ps1"), cfgB = pick("config.json");
  if (!inst || !ai || !cfgB) return null;
  const c = JSON.parse(cfgB.toString("utf8")); c.registrationPassword = ""; c.tailscaleAuthKey = "";
  const packJson = { product: "MamorAI agent pack", os: "windows", rev: last.id, built_at: new Date(last.created_at ?? Date.now()).toISOString(), mamorai_version: ctx.version,
    wazuh_version: p.wazuhVersion, addon_version: p.addonVersion, offline: false, contains_secrets: false, remote: true, changes: JSON.parse(last.changes ?? "[]") };
  return { rev: last.id, hash: last.hash, addon_version: p.addonVersion, groups: windowsGroups(p.settings),
    files: { "Install-EdrAgent.ps1": inst, "Install-MamoraiAddon.ps1": ai, "config.json": Buffer.from(JSON.stringify(c, null, 2) + "\n"), "pack.json": Buffer.from(JSON.stringify(packJson, null, 2) + "\n") } };
}
export function remotePackStatus(ctx: Ctx): { bridge: boolean; pending: boolean; published_rev: number | null; ok: boolean | null; message: string | null; at: string | null } {
  const bridge = hostBridgeAvailable(ctx);
  const pending = bridge && fs.existsSync(path.join(bridgeDir(ctx), "requests", "pack-publish.json"));
  let r: any = null; try { r = JSON.parse(fs.readFileSync(path.join(bridgeDir(ctx), "results", "pack-publish.json"), "utf8")); } catch { /* none yet */ }
  const m = r?.ok ? String(r.message ?? "").match(/published pack r(\d+)/) : null;
  return { bridge, pending, published_rev: m ? Number(m[1]) : null, ok: r ? !!r.ok : null, message: r?.message ?? null, at: r?.at ?? null };
}
/** ask the host bridge to publish the latest Windows pack when the shared folder has another revision */
let lastPublishReq = 0;
export async function publishRemotePack(ctx: Ctx, force = false): Promise<"requested" | "current" | "pending" | "unavailable" | "not_ready"> {
  const st = remotePackStatus(ctx);
  if (!st.bridge) return "unavailable";
  if (st.pending) return "pending";
  const rp = await remotePackFiles(ctx); if (!rp) return "not_ready";
  if (!force && st.published_rev === rp.rev) return "current";
  if (!force && st.ok === false && Date.now() - lastPublishReq < 30 * 60_000) return "pending"; // failed: retry every 30 min
  const dir = path.join(bridgeDir(ctx), "requests");
  const tmp = path.join(dir, `.pack-publish.${process.pid}.tmp`);
  const body = { rev: rp.rev, addon_version: rp.addon_version, groups: rp.groups, files: Object.fromEntries(Object.entries(rp.files).map(([k, v]) => [k, v.toString("base64")])) };
  fs.writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 });
  fs.renameSync(tmp, path.join(dir, "pack-publish.json"));
  lastPublishReq = Date.now();
  ctx.log.info({ rev: rp.rev, groups: rp.groups }, "agent pack: publish to the Wazuh shared folder requested");
  return "requested";
}

/** periodic check (add-on folder rebuilt, Wazuh upgraded, MamorAI updated) — called from the host scanner tick */
let lastTick = 0;
export async function tick(ctx: Ctx): Promise<void> {
  if (Date.now() - lastTick < ctx.cfg.AGENT_PACK_CHECK_MIN * 60_000) return;
  lastTick = Date.now();
  try { await refresh(ctx, "auto"); } catch (e) { ctx.log.warn({ err: String(e) }, "agent pack refresh failed"); }
  try { await publishRemotePack(ctx); } catch (e) { ctx.log.warn({ err: String(e) }, "agent pack remote publish failed"); }
  try { await checkTailscaleKeyExpiry(ctx); } catch (e) { ctx.log.warn({ err: String(e) }, "tailscale key expiry check failed"); }
}

// ---- EDR-140: remind before the Tailscale auth key (max 90 days) expires ----
export const TS_NOTICE_DAYS = [14, 7, 3, 1, 0];
/** which reminder is due: the smallest threshold reached, or "expired" (once a day after expiry) */
export function tsNoticeDue(daysLeft: number | null, lastSent: string | null, today = new Date().toISOString().slice(0, 10)): string | null {
  if (daysLeft === null || daysLeft > TS_NOTICE_DAYS[0]) return null;
  const key = daysLeft < 0 ? `expired:${today}` : `d${TS_NOTICE_DAYS.filter((d) => daysLeft <= d).pop()}`;
  return key === lastSent ? null : key;
}
async function checkTailscaleKeyExpiry(ctx: Ctx): Promise<void> {
  const sec = await getSecrets(ctx);
  if (!sec.tailscale_auth_key || !sec.tailscale_expires_at) return;
  const st = secretStatus(sec);
  const FLAG_N = "agent_pack_ts_notice";
  const row = await ctx.db("app_flags").where({ key: FLAG_N }).first();
  let last: { exp?: string; key?: string } = {}; try { last = JSON.parse(row?.value ?? "{}"); } catch { last = {}; }
  const due = tsNoticeDue(st.tailscale.days_left, last.exp === sec.tailscale_expires_at ? last.key ?? null : null);
  if (!due) return;
  const days = st.tailscale.days_left!;
  const expired = days < 0;
  await ctx.audit.log("system", null, expired ? "agent_pack.tailscale_key_expired" : "agent_pack.tailscale_key_expiring", { days_left: days, expires_at: sec.tailscale_expires_at, hint: st.tailscale.hint });
  const url = ctx.cfg.DISCORD_WEBHOOK_URL;
  const text = expired
    ? `[MamorAI] Tailscale の認証キー（${st.tailscale.hint}）の期限が切れています。新しい端末をエージェントパックで入れる前に、キーを入れ替えてください（設定 › エージェントパック › 秘密情報 / 手順: ヘルプ「Tailscale の認証キーを入れ替える」）。`
    : `[MamorAI] Tailscale の認証キー（${st.tailscale.hint}）はあと ${days} 日で期限切れです。新しいキーを作って、設定 › エージェントパック › 秘密情報 に貼り替えてください（5 分ほど）。`;
  if (url) await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: text }) }).catch(() => {});
  const value = JSON.stringify({ exp: sec.tailscale_expires_at, key: due });
  if (row) await ctx.db("app_flags").where({ key: FLAG_N }).update({ value, updated_at: ctx.db.fn.now() });
  else await ctx.db("app_flags").insert({ key: FLAG_N, value });
}
