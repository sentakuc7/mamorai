/**
 * EDR-121 S5–S7: actions on a host from the host screen (or proposed by the AI), always through the approval queue.
 *   stop_service · block_port · block_ip · isolate   (+ the reverse of each, also approved)
 *  - Linux with SSH: nftables (table inet mamorai / mamorai_iso), iptables as fallback. Network changes schedule an automatic
 *    revert on the host first and cancel it only after MamorAI can still log in (no lock-out).
 *  - Windows (agent only): Wazuh active response "!mamorai-ar.cmd" (signed add-on on the endpoint), sent with a dedicated
 *    API user that may only run active responses. The result comes back through active-responses.log → alert (rule 10074x).
 * Guards: action_locked hosts (the Wazuh manager agent 000 always), protected_ranges, the console/Wazuh addresses,
 * critical services, the management SSH port, one active action of a kind per target, the kill switch does not apply
 * (every action needs a human click anyway).
 */
import { z } from "zod";
import type { Ctx } from "../api/context.js";
import { indexer, wazuhConn } from "../api/context.js";
import { ManagerApiClient } from "../wazuh/index.js";
import { sshExec } from "../ssh/index.js";
import { j, pj } from "../db/index.js";
import fs from "node:fs";
import path from "node:path";

export const OPS = ["stop_service", "block_port", "block_ip", "isolate", "update_install", "reboot", "addon_update"] as const;
export type Op = (typeof OPS)[number];
/** EDR-168: patching ops (Windows add-on ≥ 1.2.1). Not containment: allowed on "遮断の対象外" hosts, never auto-reverted. */
export const UPDATE_OPS: readonly Op[] = ["update_install", "reboot", "addon_update"];
/** add-on 1.3.0: cancel a running update, update the add-on itself through the Wazuh shared folder (EDR-169) */
export const ADDON_SELF_MIN = "1.3.0";
export const UPDATE_ADDON_MIN = "1.2.1"; // 1.2.0 mixed up --wu/--kb/--apps/--minutes (fixed in 1.2.1)
export const OP_JA: Record<Op, string> = { stop_service: "サービスを止める", block_port: "ポートを遮断", block_ip: "相手 IP を遮断", isolate: "インターネット通信遮断（Contain・端末の隔離）", update_install: "更新プログラムをインストール", reboot: "再起動を予約", addon_update: "自動対処アドオンを更新" };
export const REVERT_JA: Record<Op, string> = { stop_service: "サービスを起動し直す", block_port: "ポート遮断を解除", block_ip: "IP 遮断を解除", isolate: "通信遮断（Contain）を解除", update_install: "実行中の更新を中止", reboot: "再起動の予約を取り消す", addon_update: "（取り消せません）" };

export const paramsSchema = z.object({
  service: z.string().regex(/^[\w@.$-][\w@.$ -]{0,127}$/, "service name").optional(),
  disable: z.boolean().optional(),
  proto: z.enum(["tcp", "udp"]).optional(),
  port: z.number().int().min(1).max(65535).optional(),
  ip: z.string().regex(/^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})$/, "IPv4 or IPv6 address").optional(),
  allow_dns: z.boolean().optional(),
  allow_ad: z.boolean().optional(),
  // EDR-168 update_install: Windows Update scope (security = MSRC-rated / security / critical / definition updates; kb = only the listed KBs)
  wu: z.enum(["security", "all", "kb", "none"]).optional(),
  kbs: z.array(z.string().regex(/^KB\d{5,8}$/, "KB number like KB5044284")).max(50).optional(),
  apps: z.union([z.literal("all"), z.array(z.string().regex(/^[\w.+-]{2,100}$/, "winget package id")).max(50)]).optional(),
  // reboot: minutes until restart (signed-in users get a warning)
  minutes: z.number().int().min(1).max(120).optional(),
  // update_install: restart N minutes after a successful install that needs a restart (only when the human asked for both)
  reboot_after: z.number().int().min(1).max(120).optional(),
}).strict();
export type Params = z.infer<typeof paramsSchema>;

const CRITICAL_LINUX = /^(ssh|sshd|wazuh-agent|wazuh-manager|wazuh-indexer|wazuh-dashboard|tailscaled|systemd-.*|dbus|dbus-broker|networking|NetworkManager|network|systemd-networkd|polkit|auditd|cron|crond|edr-console|docker|containerd)$/i;
const CRITICAL_WIN = /^(WazuhSvc|OssecSvc|Tailscale|RpcSs|RpcEptMapper|DcomLaunch|EventLog|Winmgmt|MpsSvc|BFE|Dnscache|LSM|SamSs|Netlogon|NlaSvc|nsi|Dhcp|CryptSvc|gpsvc|ProfSvc|Schedule|TermService)$/i;
const AR_SCRIPT = "!mamorai-ar.cmd";

function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsStr] = cidr.split("/"); const bits = bitsStr ? Number(bitsStr) : 32;
  const v4 = /^\d{1,3}(\.\d{1,3}){3}$/; if (!v4.test(base) || !v4.test(ip)) return false;
  const toInt = (x: string) => x.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (toInt(base) & mask) === (toInt(ip) & mask);
}
const err = (msg: string, status = 400) => Object.assign(new Error(msg), { status });
const vcmp = (a: string, b: string) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0); } return 0; };

export function platformOf(host: any): "linux_ssh" | "windows_ar" | "none" {
  if ((host.kind ?? "managed") === "managed" && host.ssh_key_id) return host.os_family === "windows" ? "none" : "linux_ssh";
  if (host.os_family === "windows" && host.agent_id) return "windows_ar";
  return "none";
}

/** What the host screen needs to know before it shows the action buttons. */
export async function capability(ctx: Ctx, host: any, opts: { ignoreLock?: boolean } = {}): Promise<{ ok: boolean; via: string; locked?: boolean; reason?: string; addon?: { version: string | null; min: string; checked_at: string | null; ok: boolean } }> {
  if (host.action_locked && !opts.ignoreLock) return { ok: false, via: "none", locked: true, reason: String(host.agent_id) === "000"
    ? "このホストは Wazuh manager 本体です。遮断すると全端末の監視と MamorAI からの操作が止まるため、遮断・隔離・サービス停止の対象外です（変更できません）。"
    : "このホストは「遮断の対象外」に設定されています（AD・業務サーバーなど、止めると全体が困るホスト用）。変更はホストの「編集」から。" };
  const p = platformOf(host);
  if (p === "linux_ssh") return host.sudo_mode === "nopasswd" ? { ok: true, via: "ssh" } : { ok: false, via: "ssh", reason: "sudo（NOPASSWD）が無いため、ファイアウォールやサービスを操作できません" };
  if (p === "windows_ar") {
    const addon = { version: host.ar_addon_version ?? null, min: ctx.cfg.AR_ADDON_MIN_VERSION, checked_at: host.ar_addon_checked_at ? new Date(host.ar_addon_checked_at).toISOString() : null, ok: !!host.ar_addon_version && vcmp(String(host.ar_addon_version), ctx.cfg.AR_ADDON_MIN_VERSION) >= 0 };
    if (!ctx.cfg.WAZUH_AR_USER || !ctx.cfg.WAZUH_AR_PASSWORD) return { ok: false, via: "wazuh_ar", addon, reason: "Wazuh の自動対処用 API ユーザー（WAZUH_AR_USER）が未設定です。docs/host-actions.md の手順で作成してください" };
    if (!addon.ok) return { ok: false, via: "wazuh_ar", addon, reason: addon.version ? `自動対処アドオンが古い（v${addon.version}、必要 v${addon.min} 以上）。インストーラーを -AddonOnly で配り直してください` : "自動対処アドオンが未導入、または版を未確認です。「アドオンの版を確認」を押すか、インストーラーを -AddonOnly で配ってください" };
    return { ok: true, via: "wazuh_ar", addon };
  }
  return { ok: false, via: "none", reason: host.os_family === "windows" ? "Wazuh エージェントが紐づいていません" : "Linux は SSH の登録が必要です（エージェントだけのホストは遮断できません）" };
}

/** addresses that must never be blocked: protected_ranges + the console and Wazuh endpoints */
async function protectedHit(ctx: Ctx, host: any, ip: string): Promise<string | null> {
  const ranges = await ctx.db("protected_ranges").where((q) => q.whereNull("host_id").orWhere("host_id", host.id));
  const r = ranges.find((x: any) => cidrContains(x.cidr, ip));
  if (r) return `保護アドレス「${r.label}」（${r.cidr}）`;
  const self: string[] = [];
  for (const w of await ctx.db("wazuh_instances")) for (const u of [w.api_url, w.indexer_url]) { try { self.push(new URL(u).hostname); } catch { /* ignore */ } }
  try { self.push(new URL(ctx.cfg.APP_BASE_URL).hostname); } catch { /* ignore */ }
  if (self.includes(ip)) return "Wazuh / MamorAI 自身のアドレス";
  if (/^(127\.|0\.0\.0\.0$|::1$|169\.254\.)/.test(ip)) return "ループバック / リンクローカル";
  return null;
}

export async function validate(ctx: Ctx, host: any, op: Op, params: Params, revert = false, selfId: number | null = null): Promise<void> {
  // a revert (e.g. un-isolate) must stay possible even if the host was locked or the add-on check went stale afterwards
  const plat = platformOf(host);
  if (revert) { if (plat === "none") throw err("このホストでは操作できません"); if (plat === "windows_ar" && (!ctx.cfg.WAZUH_AR_USER || !ctx.cfg.WAZUH_AR_PASSWORD)) throw err("WAZUH_AR_USER が未設定です"); }
  else { const cap = await capability(ctx, host, { ignoreLock: UPDATE_OPS.includes(op) }); if (!cap.ok) throw err(cap.reason ?? "このホストでは操作できません"); }
  const win = plat === "windows_ar";
  if (UPDATE_OPS.includes(op)) { // EDR-168
    if (!win) throw err(plat === "linux_ssh" ? "Linux の更新は apply_change（パッケージ更新）で行います" : "このホストでは更新を操作できません");
    if (!host.ar_addon_version || vcmp(String(host.ar_addon_version), UPDATE_ADDON_MIN) < 0) throw err(`更新・再起動には自動対処アドオン v${UPDATE_ADDON_MIN} 以上が必要です（今: ${host.ar_addon_version ? "v" + host.ar_addon_version : "未確認"}）。エージェントパックを入れ直してから「アドオンの版を確認」を押してください`);
    if (op === "update_install" && revert && vcmp(String(host.ar_addon_version ?? "0"), ADDON_SELF_MIN) < 0) throw err(`実行中の更新を止めるには自動対処アドオン v${ADDON_SELF_MIN} 以上が必要です`);
    if (op === "addon_update") {
      if (revert) throw err("アドオンの更新は取り消せません");
      const cur = String(host.ar_addon_version ?? "0");
      if (vcmp(cur, ADDON_SELF_MIN) < 0) throw err(`v${cur} には自動更新の仕組みがありません。今回だけエージェントパックを入れ直してください（v${ADDON_SELF_MIN} 以降は MamorAI から更新できます）`);
      const pub = publishedAddon(ctx);
      if (!pub) throw err("配布用のアドオンが見つかりません（installer/windows/build-addon.sh --publish-group windows を実行してください）");
      if (vcmp(pub, cur) <= 0) throw err(`すでに最新です（端末 v${cur}、配布 v${pub}）`);
    }
    if (op === "update_install") {
      const wu = params.wu ?? "security"; const apps = params.apps;
      if (wu === "kb" && !params.kbs?.length) throw err("wu=kb のときは kbs（KB 番号）を指定してください");
      if (wu === "none" && (!apps || (Array.isArray(apps) && !apps.length))) throw err("インストールする対象がありません（wu か apps を指定）");
    }
    if (op === "reboot" && !revert && !params.minutes) throw err("minutes（何分後に再起動するか）を指定してください");
    if (op !== "update_install" && params.reboot_after) throw err("reboot_after は update_install だけで使えます");
  }
  if (op === "stop_service") {
    if (!params.service) throw err("service を指定してください");
    if (!revert && (win ? CRITICAL_WIN : CRITICAL_LINUX).test(params.service)) throw err(`「${params.service}」は止めると管理や監視ができなくなるため、MamorAI からは止めません`);
    if (!win && !/^[\w@.-]{1,128}$/.test(params.service)) throw err("service name");
  }
  if (op === "block_port") {
    if (!params.port || !params.proto) throw err("proto と port を指定してください");
    if (!revert && !win && params.proto === "tcp" && params.port === Number(host.port ?? 22)) throw err(`TCP ${params.port} は MamorAI が SSH で入る口なので遮断できません（隔離を使うと MamorAI からの SSH だけ残ります）`);
    if (!revert && [1514, 1515].includes(params.port) && String(host.agent_id) === "000") throw err("Wazuh manager の受信ポートは遮断できません");
  }
  if (op === "block_ip") {
    if (!params.ip) throw err("ip を指定してください");
    const hit = await protectedHit(ctx, host, params.ip);
    if (hit && !revert) throw err(`${params.ip} は ${hit} のため遮断できません`);
  }
  if (!revert) {
    // EDR-168: a finished / timed-out update ("unconfirmed") must not block the next install; only one waiting for approval does
    const blocking = op === "update_install" ? ["pending", "running"] : op === "reboot" ? ["pending", "running", "active"] : ["pending", "running", "active", "unconfirmed"];
    const active = (await ctx.db("host_actions").where({ host_id: host.id, op }).whereIn("status", blocking)).filter((a: any) => a.id !== selfId);
    const same = active.find((a: any) => { const p = pj<any>(a.params) ?? {}; return op === "isolate" || UPDATE_OPS.includes(op) || (p.service ?? "") === (params.service ?? "") && Number(p.port ?? 0) === Number(params.port ?? 0) && (p.proto ?? "") === (params.proto ?? "") && (p.ip ?? "") === (params.ip ?? ""); });
    if (same) throw err(same.status === "running" ? `同じ操作がいま実行中です（操作 #${same.id}。承認済みで端末で動いています。終わるまで待つか、ホスト画面から状況を確認してください）` : `同じ操作がすでに${same.status === "pending" ? "承認待ち（承認キューのカード）" : "有効"}です（操作 #${same.id}）`, 409);
  }
}

/** EDR-169: the add-on version the manager publishes (the same files go into the agent pack and the Wazuh "windows" group) */
export function publishedAddon(ctx: Ctx): string | null {
  try { const m = JSON.parse(fs.readFileSync(path.join(ctx.cfg.AGENT_PACK_ADDON_DIR, "manifest.json"), "utf8")); return /^\d+\.\d+\.\d+$/.test(String(m.version)) ? String(m.version) : null; } catch { return null; }
}

export function describe(op: Op, p: Params, revert = false): string {
  if (op === "addon_update") return `${OP_JA[op]}: v${(p as any).target ?? "?"} へ（Wazuh の共有フォルダ経由。署名と中身を確認してから入れ替え、失敗したら元に戻す）`;
  if (op === "update_install" && revert) return `${REVERT_JA[op]}（Windows が途中までの更新を元に戻すことがあり、しばらく重くなる場合があります）`;
  if (op === "update_install") {
    const wu = p.wu ?? "security";
    const parts = [wu === "security" ? "Windows Update（セキュリティ更新）" : wu === "all" ? "Windows Update（すべて・機能アップグレードとドライバーは除く）" : wu === "kb" ? `Windows Update ${p.kbs?.join(", ")}` : ""];
    if (wu !== "kb" && p.kbs?.length) parts.push(`＋ ${p.kbs.join(", ")}`);
    if (p.apps) parts.push(p.apps === "all" ? "アプリ（winget で更新できるものすべて）" : `アプリ ${p.apps.join(", ")}`);
    return `${OP_JA[op]}: ${parts.filter(Boolean).join(" / ")}${p.reboot_after ? `、必要なら ${p.reboot_after} 分後に再起動まで` : ""}`;
  }
  if (op === "reboot") return revert ? REVERT_JA[op] : `${OP_JA[op]}: ${p.minutes} 分後（サインイン中の人には予告が出ます）`;
  const t = op === "stop_service" ? `サービス ${p.service}${p.disable ? "（自動起動も無効化）" : ""}` : op === "block_port" ? `${(p.proto ?? "tcp").toUpperCase()} ${p.port}（受信）` : op === "block_ip" ? `${p.ip}（送受信）` : `${p.allow_dns ? "DNS " : ""}${p.allow_ad ? "AD " : ""}以外の通信を遮断（Wazuh との通信は残す）`;
  return `${revert ? REVERT_JA[op] : OP_JA[op]}: ${t}`;
}

// ---------------- Linux (SSH) scripts ----------------
const q = (s: string) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const fam = (ip: string) => (ip.includes(":") ? "ip6" : "ip");

export function linuxScript(id: number, op: Op, p: Params, revert: boolean, mip: string, sshPort: number): { apply: string; revert: string; network: boolean } {
  const tag = `mamorai-${id}`;
  const hdr = `set -u; D=/var/tmp/mamorai-act; mkdir -p $D; chmod 700 $D; HAS_NFT=$(command -v nft >/dev/null 2>&1 && echo 1 || echo 0)`;
  const delByTag = (table: string) => `if [ "$HAS_NFT" = 1 ]; then for ch in in out fwd; do nft -a list chain inet ${table} $ch 2>/dev/null | grep 'comment "${tag}"' | awk '{print $NF}' | while read h; do nft delete rule inet ${table} $ch handle $h; done; done; fi`;
  const nftBase = `nft list table inet mamorai >/dev/null 2>&1 || { nft add table inet mamorai; nft 'add chain inet mamorai in { type filter hook input priority -5; policy accept; }'; nft 'add chain inet mamorai out { type filter hook output priority -5; policy accept; }'; }`;
  if (op === "stop_service") {
    const u = q(p.service!);
    const start = `systemctl ${p.disable ? "enable --now" : "start"} ${u} && systemctl is-active ${u}`;
    const stop = `systemctl ${p.disable ? "disable --now" : "stop"} ${u}; sleep 1; echo "state: $(systemctl is-active ${u})"; ! systemctl is-active --quiet ${u}`;
    return { apply: revert ? start : stop, revert: revert ? stop : start, network: false };
  }
  if (op === "block_port") {
    const pr = p.proto!, port = p.port!;
    const add = `${hdr}; if [ "$HAS_NFT" = 1 ]; then ${nftBase}; nft add rule inet mamorai in meta l4proto ${pr} ${pr} dport ${port} drop comment '"${tag}"'; else iptables -I INPUT -p ${pr} --dport ${port} -m comment --comment ${tag} -j DROP; ip6tables -I INPUT -p ${pr} --dport ${port} -m comment --comment ${tag} -j DROP 2>/dev/null || true; fi; echo "blocked ${pr}/${port}"`;
    const del = `${hdr}; ${delByTag("mamorai")}; if [ "$HAS_NFT" = 0 ]; then while iptables -D INPUT -p ${pr} --dport ${port} -m comment --comment ${tag} -j DROP 2>/dev/null; do :; done; while ip6tables -D INPUT -p ${pr} --dport ${port} -m comment --comment ${tag} -j DROP 2>/dev/null; do :; done; fi; echo "unblocked ${pr}/${port}"`;
    return { apply: revert ? del : add, revert: revert ? add : del, network: true };
  }
  if (op === "block_ip") {
    const ip = p.ip!, f = fam(ip), ipt = f === "ip6" ? "ip6tables" : "iptables";
    const add = `${hdr}; if [ "$HAS_NFT" = 1 ]; then ${nftBase}; nft add rule inet mamorai in ${f} saddr ${ip} drop comment '"${tag}"'; nft add rule inet mamorai out ${f} daddr ${ip} drop comment '"${tag}"'; else ${ipt} -I INPUT -s ${ip} -m comment --comment ${tag} -j DROP; ${ipt} -I OUTPUT -d ${ip} -m comment --comment ${tag} -j DROP; fi; echo "blocked ${ip}"`;
    const del = `${hdr}; ${delByTag("mamorai")}; if [ "$HAS_NFT" = 0 ]; then while ${ipt} -D INPUT -s ${ip} -m comment --comment ${tag} -j DROP 2>/dev/null; do :; done; while ${ipt} -D OUTPUT -d ${ip} -m comment --comment ${tag} -j DROP 2>/dev/null; do :; done; fi; echo "unblocked ${ip}"`;
    return { apply: revert ? del : add, revert: revert ? add : del, network: true };
  }
  // isolate: drop everything except loopback, established, SSH from MamorAI, Wazuh manager 1514/1515, (DNS), (tailscale underlay)
  const mf = fam(mip);
  const iso = [
    hdr,
    `MGR=$(grep -oP '(?<=<address>)[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null | while read a; do getent ahosts "$a" | awk '{print $1}'; done | sort -u | tr '\\n' ' ')`,
    `echo "manager: $MGR"`,
    `DNS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | tr '\\n' ' ')`,
    `if [ "$HAS_NFT" = 1 ]; then`,
    `  nft delete table inet mamorai_iso 2>/dev/null; nft add table inet mamorai_iso`,
    `  nft 'add chain inet mamorai_iso in { type filter hook input priority -10; policy drop; }'`,
    `  nft 'add chain inet mamorai_iso out { type filter hook output priority -10; policy drop; }'`,
    `  nft 'add chain inet mamorai_iso fwd { type filter hook forward priority -10; policy drop; }'`,
    `  nft add rule inet mamorai_iso in iif lo accept; nft add rule inet mamorai_iso out oif lo accept`,
    `  nft add rule inet mamorai_iso in ct state established,related accept; nft add rule inet mamorai_iso out ct state established,related accept`,
    `  nft add rule inet mamorai_iso in ${mf} saddr ${mip} tcp dport ${sshPort} accept; nft add rule inet mamorai_iso out ${mf} daddr ${mip} accept`,
    `  for m in $MGR; do f=ip; case $m in *:*) f=ip6;; esac; nft add rule inet mamorai_iso out $f daddr $m tcp dport '{ 1514, 1515 }' accept; done`,
    p.allow_dns ? `  for d in $DNS; do f=ip; case $d in *:*) f=ip6;; esac; nft add rule inet mamorai_iso out $f daddr $d meta l4proto '{ tcp, udp }' th dport 53 accept; done` : `  :`,
    `  if systemctl is-active --quiet tailscaled 2>/dev/null; then nft add rule inet mamorai_iso out socket cgroupv2 level 2 '"system.slice/tailscaled.service"' accept 2>/dev/null || { nft add rule inet mamorai_iso out udp dport '{ 41641, 3478 }' accept; nft add rule inet mamorai_iso out tcp dport 443 accept; echo "tailscale: port-based allow (cgroup match unavailable)"; }; nft add rule inet mamorai_iso in iifname tailscale0 ${mf} saddr ${mip} accept; nft add rule inet mamorai_iso in udp dport 41641 accept; fi`,
    `else`,
    `  for t in iptables ip6tables; do $t -N MAMORAI_ISO_IN 2>/dev/null; $t -N MAMORAI_ISO_OUT 2>/dev/null; $t -F MAMORAI_ISO_IN; $t -F MAMORAI_ISO_OUT; $t -A MAMORAI_ISO_IN -i lo -j ACCEPT; $t -A MAMORAI_ISO_OUT -o lo -j ACCEPT; $t -A MAMORAI_ISO_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; $t -A MAMORAI_ISO_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; done`,
    `  ${mf === "ip6" ? "ip6tables" : "iptables"} -A MAMORAI_ISO_IN -s ${mip} -p tcp --dport ${sshPort} -j ACCEPT; ${mf === "ip6" ? "ip6tables" : "iptables"} -A MAMORAI_ISO_OUT -d ${mip} -j ACCEPT`,
    `  for m in $MGR; do t=iptables; case $m in *:*) t=ip6tables;; esac; $t -A MAMORAI_ISO_OUT -d $m -p tcp -m multiport --dports 1514,1515 -j ACCEPT; done`,
    p.allow_dns ? `  for d in $DNS; do t=iptables; case $d in *:*) t=ip6tables;; esac; $t -A MAMORAI_ISO_OUT -d $d -p udp --dport 53 -j ACCEPT; $t -A MAMORAI_ISO_OUT -d $d -p tcp --dport 53 -j ACCEPT; done` : `  :`,
    `  if systemctl is-active --quiet tailscaled 2>/dev/null; then iptables -A MAMORAI_ISO_OUT -p udp -m multiport --dports 41641,3478 -j ACCEPT; iptables -A MAMORAI_ISO_OUT -p tcp --dport 443 -j ACCEPT; iptables -A MAMORAI_ISO_IN -p udp --dport 41641 -j ACCEPT; fi`,
    `  for t in iptables ip6tables; do $t -A MAMORAI_ISO_IN -j DROP; $t -A MAMORAI_ISO_OUT -j DROP; $t -C INPUT -j MAMORAI_ISO_IN 2>/dev/null || $t -I INPUT 1 -j MAMORAI_ISO_IN; $t -C OUTPUT -j MAMORAI_ISO_OUT 2>/dev/null || $t -I OUTPUT 1 -j MAMORAI_ISO_OUT; $t -C FORWARD -m comment --comment mamorai-iso -j DROP 2>/dev/null || $t -I FORWARD 1 -m comment --comment mamorai-iso -j DROP; done`,
    `fi`,
    `echo isolated`,
  ].join("\n");
  const uniso = `${hdr}; if [ "$HAS_NFT" = 1 ]; then nft delete table inet mamorai_iso 2>/dev/null || true; fi; for t in iptables ip6tables; do while $t -D INPUT -j MAMORAI_ISO_IN 2>/dev/null; do :; done; while $t -D OUTPUT -j MAMORAI_ISO_OUT 2>/dev/null; do :; done; while $t -D FORWARD -m comment --comment mamorai-iso -j DROP 2>/dev/null; do :; done; $t -F MAMORAI_ISO_IN 2>/dev/null; $t -X MAMORAI_ISO_IN 2>/dev/null; $t -F MAMORAI_ISO_OUT 2>/dev/null; $t -X MAMORAI_ISO_OUT 2>/dev/null; done; echo unisolated`;
  return { apply: revert ? uniso : iso, revert: revert ? iso : uniso, network: true };
}

/** human readable preview for the approval card */
export function previewSteps(host: any, op: Op, p: Params, revert: boolean, actionId: number): { purpose: string; command: string }[] {
  if (platformOf(host) === "windows_ar") {
    const args = arArgs(op, p, revert, actionId, actionId);
    const wait = op === "update_install" ? (p.reboot_after ? `端末がバックグラウンドでダウンロード・インストールし、結果を返すのを待つ（最大 3 時間）→ 成功して再起動が必要なら ${p.reboot_after} 分後に再起動を予約し、戻ってきたことを確認` : "端末がバックグラウンドでダウンロード・インストールし、進み具合と結果を返すのを待つ（最大 3 時間。再起動はしない）")
      : op === "reboot" && !revert ? `予約を確認し、${p.minutes} 分後の再起動のあと端末が戻ってくる（起動時刻が変わる）ことを確認` : "端末からの結果（active-responses.log → アラート）を最大 2 分待って確認";
    return [{ purpose: `${describe(op, p, revert)}（Wazuh の自動対処で ${host.name} に送る）`, command: `PUT /active-response?agents_list=${host.agent_id}  command=${AR_SCRIPT}  arguments=${JSON.stringify(args)}` }, { purpose: wait, command: "（自動）" }];
  }
  const s = linuxScript(actionId, op, p, revert, "<MamorAI の接続元 IP>", Number(host.port ?? 22));
  const steps = [{ purpose: describe(op, p, revert), command: s.apply }];
  if (s.network) steps.unshift({ purpose: "締め出し防止: 先に「一定時間後に自動で元に戻す」予約を入れる", command: `（自動）元に戻すスクリプトを /var/tmp/mamorai-act/ に置き、sleep のあと実行する予約` });
  if (s.network) steps.push({ purpose: "MamorAI から SSH で入り直せることを確認できたら予約を取り消す（入れなければ自動で元に戻る）", command: "（自動）" });
  return steps;
}

function arArgs(op: Op, p: Params, revert: boolean, runId: number, refId: number): string[] {
  const id = ["--id", `ma${runId}`, "--ref", `ma${refId}`];
  if (op === "stop_service") return [revert ? "service-start" : "service-stop", p.service!, ...id];
  if (op === "block_port") return [revert ? "unblock-port" : "block-port", p.proto!, String(p.port), ...id];
  if (op === "block_ip") return [revert ? "unblock-ip" : "block-ip", p.ip!, ...id];
  if (op === "update_install" && revert) return ["update-cancel", ...id];
  if (op === "update_install") {
    const wu = p.wu ?? "security";
    return ["update-install", "--wu", wu, ...(p.kbs?.length ? ["--kb", p.kbs.join(",")] : []), ...(p.apps ? ["--apps", p.apps === "all" ? "all" : p.apps.join(",")] : []), ...id];
  }
  if (op === "reboot") return revert ? ["reboot-cancel", ...id] : ["reboot", "--minutes", String(p.minutes), ...id];
  if (op === "addon_update") return ["addon-update", String((p as any).target ?? ""), ...id];
  return [revert ? "unisolate" : "isolate", ...(p.allow_dns ? ["allow-dns"] : []), ...(p.allow_ad ? ["allow-ad"] : []), ...id];
}

// ---------------- request (creates the approval) ----------------
export async function requestAction(ctx: Ctx, opts: { host: any; op: Op; params: Params; userId: number | null; reason?: string; revertOf?: number; sessionId?: number | null; toolCallId?: number | null; runAfter?: Date | null }): Promise<{ approval_id: number; action_id: number }> {
  const { db } = ctx; let { host } = opts;
  const params = paramsSchema.parse(opts.params ?? {});
  let actionId: number; let op = opts.op; let p = params; const revert = !!opts.revertOf;
  if (!revert && UPDATE_OPS.includes(opts.op)) host = await ensureAddon(ctx, host); // EDR-168
  if (revert) {
    const orig = await db("host_actions").where({ id: opts.revertOf, host_id: host.id }).first();
    if (!orig) throw err("元の操作が見つかりません", 404);
    if (orig.op === "update_install" ? orig.status !== "running" : !(orig.op === "reboot" ? ["running", "active"] : ["active", "unconfirmed", "failed"]).includes(orig.status)) throw err(orig.op === "update_install" ? "中止できるのは実行中の更新だけです" : `この操作は ${orig.status} のため解除できません`, 409);
    if (orig.revert_approval_id) { const ra = await db("approvals").where({ id: orig.revert_approval_id }).first(); if (ra?.decision === "pending") throw err("解除はすでに承認待ちです", 409); }
    op = orig.op; p = pj<Params>(orig.params) ?? {}; actionId = orig.id;
    await validate(ctx, host, op, p, true);
  } else {
    if (!(OPS as readonly string[]).includes(op)) throw err("unknown op");
    if (op === "addon_update") p = { ...p, target: publishedAddon(ctx) } as any; // the version to install is decided by the manager
    if (op === "update_install") p = protectApps(host, p);
    await validate(ctx, host, op, p);
    const [id] = await db("host_actions").insert({ host_id: host.id, op, params: j(p), status: "pending", requested_by: opts.userId, via: platformOf(host) === "windows_ar" ? "wazuh_ar" : "ssh" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    actionId = id;
  }
  const runAfter = opts.runAfter && opts.runAfter.getTime() > Date.now() + 60_000 ? opts.runAfter : null;
  if (runAfter && runAfter.getTime() > Date.now() + 7 * 86_400_000) throw err("予約できるのは 7 日先までです");
  const jst = (d: Date) => new Date(d.getTime() + 9 * 3600_000).toISOString().replace(/^\d{4}-(\d{2})-(\d{2})T(\d{2}:\d{2}).*/, "$1/$2 $3");
  const title = `${host.name}: ${describe(op, p, revert)}${runAfter ? `（${jst(runAfter)} に実行）` : ""}`;
  const steps = previewSteps(host, op, p, revert, actionId);
  const risk = op === "isolate" && !revert ? "high" : (op === "stop_service" || UPDATE_OPS.includes(op)) && host.environment === "production" && !revert ? "high" : "medium";
  const checks = [{ name: "host_action", level: "warn", detail: "毎回人が確認する操作（自動承認・自動再実行の対象外）" }, ...(host.environment === "production" ? [{ name: "production", level: "warn", detail: "本番ホストへの操作" }] : [])];
  const [apId] = await db("approvals").insert({
    tool_call_id: opts.toolCallId ?? null, session_id: opts.sessionId ?? null, host_id: host.id, title, command: steps.map((s) => s.command).join("\n"),
    intent: opts.reason ?? "（ホスト画面から依頼）",
    rollback: revert ? "元の操作をもう一度承認すれば戻せます" : op === "update_install" ? "自動の取り消しはありません。問題が出たら設定 › Windows Update › 更新の履歴 › 更新プログラムをアンインストールする（アプリは winget / アプリの設定から前の版へ）" : op === "reboot" ? "再起動の前なら「再起動の予約を取り消す」（ホスト画面）で止められます" : REVERT_JA[op] + "（ホスト画面の「有効な遮断」から、承認を通して解除）",
    steps: j(steps), auto_checks: j({ classification: "write", reason: "host action", checks: runAfter ? [...checks, { name: "scheduled", level: "warn", detail: `承認すると、すぐではなく ${jst(runAfter)}（日本時間）に実行します。それまでは承認キュー / このカードから取り消せます` }] : checks }), risk, host_action: j({ action_id: actionId, revert }),
    run_after: runAfter ? runAfter.toISOString() : null,
  }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
  if (revert) await db("host_actions").where({ id: actionId }).update({ revert_approval_id: apId });
  else await db("host_actions").where({ id: actionId }).update({ approval_id: apId });
  // nav badge / approval queue refresh on every open page (the UI listens on /sessions/0/events)
  ctx.runtime?.events.emit("event", { type: "approval", session_id: opts.sessionId ?? 0, approval: { id: apId, decision: "pending", host_id: host.id, title } });
  await ctx.audit.log(opts.userId ? "user" : "agent", opts.userId, "host.action.requested", { approval_id: apId, action_id: actionId, host: host.name, op, params: p, revert }, opts.sessionId ?? undefined);
  return { approval_id: apId, action_id: actionId };
}

// ---------------- execute (called from AgentRuntime.decide after a human approved) ----------------
export async function executeAction(ctx: Ctx, approval: any, onProgress: (purpose: string, extra?: Record<string, unknown>) => Promise<void>): Promise<{ status: string; exit_code: number; stdout: string; stderr: string; host_action: any; win_update?: WinUpdateState }> {
  const { db } = ctx;
  const ha = pj<any>(approval.host_action);
  const act = await db("host_actions").where({ id: ha.action_id }).first();
  if (!act) throw new Error("host action not found");
  const host = await db("hosts").where({ id: act.host_id }).first();
  if (!host) throw new Error("host not found");
  const revert = !!ha.revert; const op: Op = act.op; const p: Params = pj<Params>(act.params) ?? {};
  let out: { ok: boolean; confirmed: boolean; log: string; detail?: any; win_update?: WinUpdateState };
  try {
    await validate(ctx, host, op, p, revert, act.id); // state may have changed since the request
    // EDR-168: approved and now running — no longer "waiting for approval" (the AI kept telling the human to reject a card that was already running)
    if (!revert) await db("host_actions").where({ id: act.id }).update({ status: "running" });
    if (platformOf(host) === "windows_ar") out = await runWindows(ctx, host, act, op, p, revert, approval.id, onProgress);
    else out = await runLinux(ctx, host, act, op, p, revert, onProgress);
  } catch (e: any) {
    out = { ok: false, confirmed: false, log: `実行できませんでした: ${String(e?.message ?? e)}` };
  }
  const now = db.fn.now();
  if (revert) {
    if (out.ok) await db("host_actions").where({ id: act.id }).update({ status: op === "reboot" || op === "update_install" ? "cancelled" : "reverted", reverted_at: now, result: j({ ...(pj<any>(act.result) ?? {}), revert: out }) });
    if (out.ok && op === "isolate") await db("hosts").where({ id: host.id }).update({ isolation_state: null });
  } else {
    // EDR-168: patching is finished once confirmed ("done", nothing to release); a reboot that is only scheduled stays "active" (can be cancelled)
    const okStatus = UPDATE_OPS.includes(op) ? (out.confirmed ? "done" : op === "reboot" ? "active" : "unconfirmed") : (out.confirmed ? "active" : "unconfirmed");
    const nowRow = await db("host_actions").where({ id: act.id }).first();
    if (nowRow?.status === "cancelled") await db("host_actions").where({ id: act.id }).update({ result: j(out) }); // EDR-168: stopped by 中止 meanwhile
    else await db("host_actions").where({ id: act.id }).update({ status: out.ok ? okStatus : "failed", applied_at: out.ok ? now : null, result: j(out) });
    if (out.ok && op === "isolate") await db("hosts").where({ id: host.id }).update({ isolation_state: "isolated" });
  }
  const ev = out.ok ? (revert ? "host.action.reverted" : "host.action.applied") : "host.action.failed";
  await ctx.audit.log("system", null, ev, { action_id: act.id, approval_id: approval.id, host: host.name, op, params: p, revert, confirmed: out.confirmed, via: act.via }, approval.session_id ?? undefined);
  discord(ctx, `[MamorAI] ${host.name}: ${describe(op, p, revert)} → ${out.ok ? (out.confirmed ? "完了" : "送信済み（端末からの結果は未確認）") : "失敗"}（承認 #${approval.id}）`);
  return { status: out.ok ? "executed" : "failed", exit_code: out.ok ? 0 : 1, stdout: out.log, stderr: "", host_action: { action_id: act.id, op, revert, confirmed: out.confirmed, detail: out.detail ?? null }, ...(out.win_update ? { win_update: out.win_update } : {}) };
}

function discord(ctx: Ctx, text: string) {
  const url = ctx.cfg.DISCORD_WEBHOOK_URL;
  if (url) fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: text.slice(0, 1900) }) }).catch(() => {});
}

async function sshTarget(ctx: Ctx, host: any, sudo = true) {
  const key = await ctx.db("ssh_keys").where({ id: host.ssh_key_id }).first();
  if (!key) throw new Error("SSH key missing");
  return { address: host.address, port: host.port, user: host.ssh_user, privateKey: ctx.box.decrypt(key.private_key_enc), sudoMode: (sudo ? host.sudo_mode : "none") as "none" | "nopasswd", hostKey: host.host_key };
}

async function runLinux(ctx: Ctx, host: any, act: any, op: Op, p: Params, revert: boolean, onProgress: (s: string) => Promise<void>) {
  const plain = await sshTarget(ctx, host, false);
  const probe = await sshExec(plain, `echo "$SSH_CONNECTION"`, 20_000);
  const mip = String(probe.stdout).trim().split(/\s+/)[0];
  if (!/^[0-9a-fA-F.:]+$/.test(mip)) throw new Error(`MamorAI の接続元 IP を判定できません（SSH_CONNECTION=${probe.stdout.trim().slice(0, 80)}）`);
  const s = linuxScript(act.id, op, p, revert, mip, Number(host.port ?? 22));
  const target = await sshTarget(ctx, host, true);
  const D = "/var/tmp/mamorai-act";
  const log: string[] = [`MamorAI の接続元: ${mip}`];
  const runId = `${act.id}-${revert ? "r" : "a"}-${Date.now()}`;
  if (s.network) {
    const sec = ctx.cfg.HOST_ACTION_LINUX_AUTOREVERT_SEC;
    await onProgress(`締め出し防止の予約（${sec} 秒後に自動で元に戻す）`);
    const b64 = Buffer.from(s.revert, "utf8").toString("base64");
    // note: "a && b && c &" would background the whole chain — keep the setup and the timer separate
    const arm = `{ mkdir -p ${D} && chmod 700 ${D} && echo ${b64} | base64 -d > ${D}/${runId}.undo.sh; } || exit 1\nsetsid nohup bash -c 'sleep ${sec}; bash ${D}/${runId}.undo.sh > ${D}/${runId}.undo.log 2>&1; echo auto-reverted > ${D}/${runId}.state' </dev/null >/dev/null 2>&1 &\necho $! > ${D}/${runId}.timer\necho ARMED`;
    const r0 = await sshExec(target, arm, 30_000);
    if (!/ARMED/.test(r0.stdout)) return { ok: false, confirmed: false, log: [...log, `予約に失敗: ${r0.stderr || r0.stdout}`].join("\n") };
  }
  await onProgress(describe(op, p, revert));
  const r1 = await sshExec(target, s.apply, 120_000).catch((e: any) => ({ code: null, stdout: "", stderr: String(e?.message ?? e), durationMs: 0, truncated: false, hostKey: "" }));
  log.push(`$ ${describe(op, p, revert)}`, r1.stdout.trim(), r1.stderr ? `[stderr] ${r1.stderr.trim()}` : "");
  if (!s.network) return { ok: r1.code === 0, confirmed: r1.code === 0, log: log.filter(Boolean).join("\n") };
  // reconnect from scratch: if MamorAI can still log in, cancel the automatic revert
  await onProgress("MamorAI から入り直せるか確認し、予約を取り消す");
  await new Promise((r) => setTimeout(r, 2000));
  const r2 = await sshExec(target, `if [ -f ${D}/${runId}.state ]; then cat ${D}/${runId}.state; exit 3; fi; kill $(cat ${D}/${runId}.timer) 2>/dev/null; rm -f ${D}/${runId}.timer; echo CONFIRMED`, 30_000).catch((e: any) => ({ code: null, stdout: "", stderr: String(e?.message ?? e) } as any));
  if (/CONFIRMED/.test(r2.stdout)) {
    if (r1.code !== 0) { // the apply itself failed: put things back now instead of waiting for the timer
      const r3 = await sshExec(target, s.revert, 120_000).catch(() => null);
      log.push("適用が失敗したため、すぐに元に戻しました", r3?.stdout?.trim() ?? "");
      return { ok: false, confirmed: false, log: log.filter(Boolean).join("\n") };
    }
    log.push("入り直しを確認 → 自動で戻す予約を取り消しました");
    return { ok: true, confirmed: true, log: log.filter(Boolean).join("\n") };
  }
  log.push(`入り直せませんでした（${(r2.stderr || r2.stdout || "").trim().slice(0, 200)}）。${ctx.cfg.HOST_ACTION_LINUX_AUTOREVERT_SEC} 秒以内にホスト側で自動的に元に戻ります`);
  return { ok: false, confirmed: false, log: log.filter(Boolean).join("\n") };
}

async function arClient(ctx: Ctx, host: any): Promise<ManagerApiClient> {
  const { conn } = await wazuhConn(ctx, host.wazuh_instance_id ?? (await ctx.db("wazuh_instances").orderBy("id").first())?.id);
  if (!ctx.cfg.WAZUH_AR_USER || !ctx.cfg.WAZUH_AR_PASSWORD) throw new Error("WAZUH_AR_USER / WAZUH_AR_PASSWORD が未設定です");
  return new ManagerApiClient({ ...conn, apiUser: ctx.cfg.WAZUH_AR_USER, apiPassword: ctx.cfg.WAZUH_AR_PASSWORD });
}

/** send one AR command and wait for the endpoint's result line (rule group mamorai_ar) */
export async function sendAr(ctx: Ctx, host: any, args: string[], runTag: string, waitMs = 120_000): Promise<{ sent: boolean; result: any | null; error?: string }> {
  const api = await arClient(ctx, host);
  const sentAt = new Date(Date.now() - 5_000).toISOString();
  try { await api.put(`/active-response?agents_list=${encodeURIComponent(String(host.agent_id))}`, { command: AR_SCRIPT, arguments: args, alert: { data: { mamorai_ar_request: runTag } } }); }
  catch (e: any) { return { sent: false, result: null, error: String(e.message ?? e) }; }
  const ix = await indexer(ctx, host.wazuh_instance_id ?? (await ctx.db("wazuh_instances").orderBy("id").first())?.id);
  const until = Date.now() + waitMs;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 5_000));
    const r = await ix.search("wazuh-alerts-*", { query: { bool: { filter: [{ term: { "agent.id": String(host.agent_id) } }, { term: { "data.mamorai_ar.id": runTag } }, { range: { timestamp: { gte: sentAt } } }] } }, sort: [{ timestamp: { order: "desc" } }] }, 1).catch(() => null);
    const hit = r?.hits?.hits?.[0]?._source?.data?.mamorai_ar;
    if (hit) return { sent: true, result: hit };
  }
  return { sent: true, result: null };
}

async function runWindows(ctx: Ctx, host: any, act: any, op: Op, p: Params, revert: boolean, approvalId: number, onProgress: (s: string, extra?: Record<string, unknown>) => Promise<void>) {
  const runTag = `ma${approvalId}`;
  const args = arArgs(op, p, revert, approvalId, act.id);
  if (op === "update_install" && !revert) return runWindowsUpdate(ctx, host, p, args, runTag, onProgress);
  if (op === "addon_update") return runAddonUpdate(ctx, host, args, runTag, onProgress);
  if (op === "reboot" && !revert) return runWindowsReboot(ctx, host, args, runTag, p.minutes ?? 10, onProgress);
  await onProgress(`${describe(op, p, revert)}（Wazuh の自動対処で送信）`);
  const r = await sendAr(ctx, host, args, runTag, op === "isolate" ? 150_000 : 120_000);
  if (!r.sent) return { ok: false, confirmed: false, log: `Wazuh API への送信に失敗: ${r.error}` };
  if (!r.result) return { ok: true, confirmed: false, log: `送信しました（agent ${host.agent_id}）。2 分以内に端末からの結果が届きませんでした。端末がオフライン、アドオン未導入、または active-responses.log が転送されていない可能性があります。端末側の ossec-agent\\active-response\\active-responses.log を確認してください。` };
  const ok = r.result.ok === true || r.result.ok === "true";
  return { ok, confirmed: ok, log: `端末からの結果: ${ok ? "成功" : "失敗"}\n${String(r.result.detail ?? "").slice(0, 2000)}`, detail: r.result };
}

const truthy = (v: any) => v === true || v === "true";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** the latest result line of one AR run (phase progress / done ...) */
async function latestAr(ctx: Ctx, host: any, runTag: string, sinceIso: string): Promise<any | null> {
  const ix = await indexer(ctx, host.wazuh_instance_id ?? (await ctx.db("wazuh_instances").orderBy("id").first())?.id);
  const r = await ix.search("wazuh-alerts-*", { query: { bool: { filter: [{ term: { "agent.id": String(host.agent_id) } }, { term: { "data.mamorai_ar.id": runTag } }, { range: { timestamp: { gte: sinceIso } } }] } }, sort: [{ timestamp: { order: "desc" } }] }, 1).catch(() => null);
  return r?.hits?.hits?.[0]?._source?.data?.mamorai_ar ?? null;
}

/**
 * EDR-168: per-update status shown on the approval card while Windows Update / winget runs on the endpoint.
 * Built from the add-on's progress lines: add-on ≥ 1.3.0 sends "items" (KB=state;...) per update; older ones send
 * "downloading N update(s): KB..,KB..", "installing N update(s)", "winget upgrade <id>" and a final installed / failed list.
 */
export type WinItemState = "pending" | "downloading" | "downloaded" | "installing" | "installed" | "failed" | "unknown";
export interface WinUpdateItem { key: string; kind: "wu" | "app"; title: string | null; size_mb: number | null; state: WinItemState; note?: string }
export interface WinUpdateState { phase: string; items: WinUpdateItem[]; started_at: string; last_seen_at: string | null; finished_at: string | null; reboot_required: boolean | null; ok: boolean | null }

export function applyWinProgress(st: WinUpdateState, x: any, scan: any | null, at: string): WinUpdateState {
  const items = [...st.items];
  const find = (key: string, kind: "wu" | "app") => {
    let it = items.find((i) => i.key === key);
    if (!it) {
      const u = kind === "wu" ? (scan?.updates ?? []).find((v: any) => v.kb === key) : (scan?.apps ?? []).find((v: any) => v.id === key);
      it = { key, kind, title: u ? (kind === "wu" ? u.title : `${u.name}（${u.version} → ${u.available}）`) : null, size_mb: kind === "wu" ? (u?.size_mb ?? null) : null, state: "pending" };
      items.push(it);
    }
    return it;
  };
  const d = String(x.detail ?? "");
  if (x.items) { // add-on ≥ 1.3.0: "KB5044284=downloading;app:Google.Chrome=pending"
    for (const part of String(x.items).split(";")) {
      const [k, v] = part.split("="); if (!k || !v) continue;
      const app = k.startsWith("app:"); const it = find(app ? k.slice(4) : k, app ? "app" : "wu");
      it.state = (["pending", "downloading", "downloaded", "installing", "installed", "failed"].includes(v) ? v : "unknown") as WinItemState;
    }
  }
  let m: RegExpMatchArray | null;
  if ((m = d.match(/^downloading \d+ update\(s\): (.+)$/))) for (const kb of m[1].split(",").map((t) => t.trim()).filter(Boolean)) { const it = find(kb, "wu"); if (it.state === "pending") it.state = "downloading"; }
  if (/^installing \d+ update/.test(d)) for (const it of items) if (it.kind === "wu" && ["pending", "downloading", "downloaded"].includes(it.state)) it.state = "installing";
  if ((m = d.match(/^winget upgrade (\S+)/))) { for (const it of items) if (it.kind === "app" && it.state === "installing") it.state = "unknown"; find(m[1], "app").state = "installing"; }
  let { phase, finished_at, reboot_required, ok } = st;
  if (x.phase === "done") {
    finished_at = at; ok = x.ok === true || x.ok === "true"; reboot_required = x.reboot_required === true || x.reboot_required === "true";
    for (const t of String(x.installed ?? "").split(",").map((v) => v.trim()).filter(Boolean)) { const app = t.startsWith("app:"); find(app ? t.slice(4) : t, app ? "app" : "wu").state = "installed"; }
    for (const t of (String(x.failed ?? "").match(/(?:app:)?[^,(]+(?:\([^)]*\))?/g) ?? []).map((v) => v.trim()).filter(Boolean)) { const mm = t.match(/^(app:)?([^(]+)(\((.*)\))?$/); if (!mm) continue; const it = find(mm[2], mm[1] ? "app" : "wu"); it.state = "failed"; if (mm[4]) it.note = mm[4]; }
    for (const it of items) if (!["installed", "failed"].includes(it.state)) it.state = "unknown";
    phase = ok ? "完了" : "一部または全部が失敗";
  } else if (d) {
    phase = /^searching/.test(d) ? "更新を検索中" : /^downloading/.test(d) ? "ダウンロード中" : /^installing/.test(d) ? "インストール中" : /^winget/.test(d) ? "アプリを更新中" : d.slice(0, 80);
  }
  return { ...st, items, phase, last_seen_at: at, finished_at, reboot_required, ok };
}

/** EDR-168: Windows Update / winget on the endpoint. The add-on starts a background task and reports progress lines. */
async function runWindowsUpdate(ctx: Ctx, host: any, p: Params, args: string[], runTag: string, onProgress: (s: string, extra?: Record<string, unknown>) => Promise<void>) {
  const since = new Date(Date.now() - 5_000).toISOString();
  const scan = pj<any>(host.win_updates);
  // planned items from the last scan, so the card shows the list before the PC answers
  const planned: WinUpdateItem[] = [];
  const wu = p.wu ?? "security";
  for (const u of scan?.updates ?? []) {
    const pick = wu === "all" || (wu === "security" && u.security) || ((wu === "kb" || wu === "security") && p.kbs?.includes(u.kb));
    if (pick && u.kb) planned.push({ key: u.kb, kind: "wu", title: u.title, size_mb: u.size_mb ?? null, state: "pending" });
  }
  for (const a of scan?.apps ?? []) if (p.apps === "all" || (Array.isArray(p.apps) && p.apps.includes(a.id))) planned.push({ key: a.id, kind: "app", title: `${a.name}（${a.version} → ${a.available}）`, size_mb: null, state: "pending" });
  let st: WinUpdateState = { phase: "端末に開始を依頼", items: planned, started_at: new Date().toISOString(), last_seen_at: null, finished_at: null, reboot_required: null, ok: null };
  const push = (purpose: string) => onProgress(purpose, { win_update: st });
  await push("端末に更新の開始を依頼（Wazuh の自動対処で送信）");
  const r = await sendAr(ctx, host, args, runTag, 120_000);
  if (!r.sent) return { ok: false, confirmed: false, log: `Wazuh API への送信に失敗: ${r.error}` };
  if (!r.result) return { ok: false, confirmed: false, log: "2 分以内に端末から応答がありませんでした（オフライン、アドオンが 1.2.1 未満、または active-responses.log が転送されていない）" };
  if (!truthy(r.result.ok)) return { ok: false, confirmed: false, log: `端末が開始を断りました: ${r.result.detail ?? ""}`, detail: r.result };
  st = { ...st, phase: "端末で開始", last_seen_at: new Date().toISOString() };
  await push("端末で更新を開始しました");
  const until = Date.now() + ctx.cfg.WIN_UPDATE_WAIT_MIN * 60_000; let lastKey = ""; let lastBeat = Date.now(); const log: string[] = ["端末で更新を開始しました"];
  while (Date.now() < until) {
    await sleep(15_000);
    const x = await latestAr(ctx, host, runTag, since);
    const key = x ? `${x.phase}|${x.detail}|${x.items ?? ""}` : "";
    if (x && key !== lastKey) {
      lastKey = key; st = applyWinProgress(st, x, scan, new Date().toISOString());
      if (x.detail && x.phase !== "done") log.push(`… ${x.detail}`);
      await push(`端末: ${st.phase}`); lastBeat = Date.now();
    } else if (Date.now() - lastBeat > 60_000) { await push(`端末: ${st.phase}`); lastBeat = Date.now(); } // keep the elapsed time on the card moving
    if (x?.phase === "done") {
      const ok = truthy(x.ok); const reboot = truthy(x.reboot_required);
      log.push(`結果: ${ok ? "成功" : "一部または全部が失敗"} — ${x.detail ?? ""}`, x.installed ? `入ったもの: ${x.installed}` : "", x.failed ? `失敗: ${x.failed}` : "", reboot ? "再起動が必要です（再起動は別の承認: host_action op=reboot）" : "再起動は不要です");
      await ctx.db("hosts").where({ id: host.id }).update({ win_updates: null, win_updates_at: null }); // the old scan is stale now
      if (ok && reboot && p.reboot_after) { // EDR-168: the human approved install + restart together
        st = { ...st, phase: `インストール完了 → ${p.reboot_after} 分後に再起動` }; await push(`再起動を予約（${p.reboot_after} 分後）`);
        const tag = `${runTag}r`;
        const rb = await runWindowsReboot(ctx, host, ["reboot", "--minutes", String(p.reboot_after), "--id", tag, "--ref", tag], tag, p.reboot_after, (s2) => push(s2));
        st = { ...st, phase: rb.confirmed ? "完了（再起動も確認）" : rb.ok ? "インストール完了・再起動は未確認" : "インストール完了・再起動の予約に失敗" };
        log.push("— 再起動 —", rb.log);
        return { ok: ok && rb.ok, confirmed: rb.confirmed, log: log.filter(Boolean).join("\n"), detail: { ...x, reboot_required: reboot, reboot: rb.detail ?? null }, win_update: st };
      }
      if (ok && !reboot && p.reboot_after) log.push("再起動は不要だったので、再起動はしませんでした");
      return { ok, confirmed: true, log: log.filter(Boolean).join("\n"), detail: { ...x, reboot_required: reboot }, win_update: st };
    }
  }
  st = { ...st, phase: "待ち時間切れ（端末ではまだ続いている可能性）" };
  log.push(`${ctx.cfg.WIN_UPDATE_WAIT_MIN} 分待っても終わりませんでした。端末ではまだ続いている可能性があります。あとで「更新の確認」（win_updates）で状態を確かめてください`);
  return { ok: true, confirmed: false, log: log.join("\n"), win_update: st };
}

/** EDR-169: replace the add-on with the copy published in the Wazuh shared folder; confirm the new version answers */
export async function runAddonUpdate(ctx: Ctx, host: any, args: string[], runTag: string, onProgress: (s: string) => Promise<void>) {
  const target = args[1];
  await onProgress(`端末に v${target} への更新を依頼`);
  const since = new Date(Date.now() - 5_000).toISOString();
  const r = await sendAr(ctx, host, args, runTag, 120_000);
  if (!r.sent) return { ok: false, confirmed: false, log: `Wazuh API への送信に失敗: ${r.error}` };
  if (!r.result) return { ok: false, confirmed: false, log: "2 分以内に端末から応答がありませんでした" };
  if (!truthy(r.result.ok)) return { ok: false, confirmed: false, log: `端末が更新を断りました: ${r.result.detail ?? ""}`, detail: r.result };
  await onProgress("端末で入れ替え中（署名と中身を確認済み）。新しい版の応答を待っています");
  const until = Date.now() + 5 * 60_000;
  while (Date.now() < until) {
    await sleep(15_000);
    const ok = await latestAr(ctx, host, `${runTag}u`, since);
    if (ok?.version) {
      await ctx.db("hosts").where({ id: host.id }).update({ ar_addon_version: String(ok.version), ar_addon_checked_at: ctx.db.fn.now() });
      const good = vcmp(String(ok.version), target) >= 0;
      return { ok: good, confirmed: good, log: `${r.result.detail ?? ""}\n新しい版が応答しました: v${ok.version}`, detail: { version: ok.version } };
    }
    const back = await latestAr(ctx, host, `${runTag}r`, since);
    if (back) return { ok: false, confirmed: true, log: `新しい版が自己テストに失敗したため、元の v${back.version ?? "?"} に戻しました`, detail: back };
  }
  return { ok: false, confirmed: false, log: "5 分以内に新しい版からの応答がありませんでした。ホスト画面の「アドオンの版を確認」で状態を確かめてください" };
}

/** EDR-168: schedule a restart, then confirm the endpoint came back (boot time changed) */
export function hhmmJst(ms: number): string {
  const d = new Date(ms + 9 * 3600_000);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

async function runWindowsReboot(ctx: Ctx, host: any, args: string[], runTag: string, minutes: number, onProgress: (s: string) => Promise<void>) {
  await onProgress(`${minutes} 分後の再起動を予約`);
  const since = new Date(Date.now() - 5 * 60_000).toISOString();
  const r = await sendAr(ctx, host, args, runTag, 120_000);
  if (!r.sent) return { ok: false, confirmed: false, log: `Wazuh API への送信に失敗: ${r.error}` };
  if (!r.result) return { ok: false, confirmed: false, log: "2 分以内に端末から応答がありませんでした" };
  if (!truthy(r.result.ok)) return { ok: false, confirmed: false, log: `再起動を予約できませんでした: ${r.result.detail ?? ""}`, detail: r.result };
  const bootBefore = String(r.result.boot ?? ""); const log = [`予約しました: ${r.result.detail ?? ""}`];
  // 1.3.1: when someone is signed in the endpoint shows a Japanese prompt and the user may postpone (5 min / 1 h / 4 h,
  // at most 4 h after the first notice). Follow the "postponed" lines so we wait for the real restart time.
  const prompt = truthy(r.result.prompt);
  let dueMs = Date.parse(String(r.result.at ?? "")) || Date.now() + minutes * 60_000;
  const maxMs = Date.parse(String(r.result.max ?? "")) || dueMs;
  if (prompt) {
    log.push(`サインイン中の人に日本語の案内を出しました（5分後・1時間後・4時間後に延期できます。最大 ${hhmmJst(maxMs)} まで）`);
    await onProgress(`再起動の予約済み（${hhmmJst(dueMs)} の予定）。サインイン中の人が延期できます（最大 ${hhmmJst(maxMs)} まで）`);
  } else await onProgress(`再起動の予約済み（${minutes} 分後）。端末が戻ってくるのを待っています`);
  let lastLine = "";
  while (Date.now() < dueMs + 60_000 && Date.now() < maxMs + 5 * 60_000) {
    await sleep(Math.max(1_000, Math.min(30_000, dueMs + 60_000 - Date.now())));
    if (!prompt) continue;
    const x = await latestAr(ctx, host, runTag, since).catch(() => null);
    const key = x ? `${x.phase}|${x.at}|${x.minutes}` : "";
    if (!x || key === lastLine) continue;
    lastLine = key;
    const at = Date.parse(String(x.at ?? ""));
    if (x.phase === "postponed" && at) {
      dueMs = at;
      const m = Number(x.minutes);
      const msg = m === 0 ? "サインイン中の人が「今すぐ再起動」を選びました" : `サインイン中の人が ${m >= 60 ? `${m / 60} 時間` : `${m} 分`}後に延期しました（${hhmmJst(dueMs)} に再起動）`;
      log.push(msg); await onProgress(`${msg}。端末が戻ってくるのを待っています`);
    } else if (x.phase === "rebooting" && at) {
      dueMs = Math.min(dueMs, at); await onProgress("再起動の 1 分前の予告を出しました。端末が戻ってくるのを待っています");
    } else if (x.phase === "failed" || !truthy(x.ok)) {
      log.push(`端末側の再起動の処理でエラー: ${x.detail ?? ""}`);
      return { ok: false, confirmed: false, log: log.join("\n"), detail: x };
    }
  }
  const until = Date.now() + 20 * 60_000; let sawOld = false;
  while (Date.now() < until) {
    const tag = `mb${host.id}x${Date.now().toString(36)}`;
    const v = await sendAr(ctx, host, ["version", "--id", tag, "--ref", tag], tag, 60_000).catch(() => null);
    const boot = String(v?.result?.boot ?? "");
    if (boot && boot !== bootBefore) {
      log.push(`再起動を確認しました（起動 ${boot}）${truthy(v?.result?.reboot_pending) ? "。まだ再起動待ちの更新があります（もう一度再起動が必要な場合があります）" : ""}`);
      return { ok: true, confirmed: true, log: log.join("\n"), detail: { boot_before: bootBefore, boot_after: boot, reboot_pending: truthy(v?.result?.reboot_pending) } };
    }
    // EDR-168: after a cumulative update Windows keeps answering while it "prepares to restart" (a lab Windows Server, 11/5: shutdown
    // started 15:20, the old boot time was still reported at 15:32, the agent came back at 15:38). Keep waiting until the deadline.
    if (boot && boot === bootBefore) sawOld = true;
    await sleep(30_000);
  }
  if (sawOld) { log.push("待ち時間（20 分）の間、端末は応答しましたが起動時刻が変わりませんでした（更新の構成に時間がかかっている、予約が取り消された、または延期された可能性）。あとで「更新の確認」で再起動待ちが消えたか確かめてください"); return { ok: true, confirmed: false, log: log.join("\n") }; }
  log.push("20 分待っても端末が戻ってきません。電源・ネットワーク・起動の状態を確認してください");
  return { ok: true, confirmed: false, log: log.join("\n") };
}

/**
 * EDR-168: the add-on version is only known after the endpoint answered a "version" request. After a pack install nobody
 * pressed 「アドオンの版を確認」, so the update ops were refused with "未確認" although 1.2.1 was installed (a lab domain controller, 2026-11-05).
 * Ask the endpoint once (read-only, ~10-60 s) before refusing.
 */
export async function ensureAddon(ctx: Ctx, host: any, min = UPDATE_ADDON_MIN): Promise<any> {
  if (platformOf(host) !== "windows_ar") return host;
  if (host.ar_addon_version && vcmp(String(host.ar_addon_version), min) >= 0) return host;
  // the pack installer's self-test already reported the version (rule 100753) — use it without bothering the endpoint
  try {
    const ix = await indexer(ctx, host.wazuh_instance_id ?? (await ctx.db("wazuh_instances").orderBy("id").first())?.id);
    const r = await ix.search("wazuh-alerts-*", { query: { bool: { filter: [{ term: { "agent.id": String(host.agent_id) } }, { term: { "data.mamorai_ar.op": "version" } }, { range: { timestamp: { gte: "now-30d" } } }] } }, sort: [{ timestamp: { order: "desc" } }] }, 1);
    const v = r?.hits?.hits?.[0]?._source?.data?.mamorai_ar?.version;
    if (v && /^\d+\.\d+\.\d+$/.test(String(v)) && vcmp(String(v), min) >= 0) {
      await ctx.db("hosts").where({ id: host.id }).update({ ar_addon_version: String(v), ar_addon_checked_at: ctx.db.fn.now() });
      return { ...host, ar_addon_version: String(v) };
    }
  } catch { /* fall back to asking the endpoint */ }
  await checkAddon(ctx, host).catch(() => null);
  return (await ctx.db("hosts").where({ id: host.id }).first()) ?? host;
}

/** EDR-168: read-only scan of available Windows updates (+ winget app upgrades). No approval, like checkAddon. */
export async function scanWindowsUpdates(ctx: Ctx, host0: any, withApps = true): Promise<{ ok: boolean; message: string; scan?: any }> {
  if (platformOf(host0) !== "windows_ar") return { ok: false, message: "Windows のエージェントだけのホストが対象です" };
  const host = await ensureAddon(ctx, host0);
  if (!host.ar_addon_version || vcmp(String(host.ar_addon_version), UPDATE_ADDON_MIN) < 0) return { ok: false, message: `自動対処アドオン v${UPDATE_ADDON_MIN} 以上が必要です（今: ${host.ar_addon_version ? "v" + host.ar_addon_version : "未確認"}）` };
  const tag = `mu${host.id}x${Date.now().toString(36)}`;
  const r = await sendAr(ctx, host, ["update-scan", ...(withApps ? ["--apps", "yes"] : []), "--id", tag, "--ref", tag], tag, 300_000);
  if (!r.sent) return { ok: false, message: `送信に失敗: ${r.error}` };
  if (!r.result) return { ok: false, message: "5 分以内に端末から結果が届きませんでした（オフライン、または Windows Update の検索に時間がかかっています）" };
  if (!truthy(r.result.ok)) return { ok: false, message: `端末での検索に失敗: ${r.result.detail ?? ""}` };
  const scan = parseUpdateScan(r.result);
  await ctx.db("hosts").where({ id: host.id }).update({ win_updates: j(scan), win_updates_at: ctx.db.fn.now() });
  return { ok: true, message: r.result.detail ?? "", scan };
}

/**
 * EDR-168: never upgrade the Wazuh agent through winget — an agent newer than the manager cannot connect (a lab PC
 * 2026-11-06: winget offered Wazuh.WazuhAgent). Add-on 1.3.2 refuses it on the endpoint; for older add-ons "all" is
 * turned into the explicit list from the last scan without it.
 */
export const PROTECTED_APPS = ["Wazuh.WazuhAgent"];
export function protectApps(host: any, p: Params): Params {
  if (Array.isArray(p.apps)) return { ...p, apps: p.apps.filter((a) => !PROTECTED_APPS.includes(a)) };
  if (p.apps === "all" && vcmp(String(host.ar_addon_version ?? "0"), "1.3.2") < 0) {
    const scan = pj<any>(host.win_updates);
    const ids = (scan?.apps ?? []).map((a: any) => String(a.id)).filter((id: string) => id && !PROTECTED_APPS.includes(id));
    return { ...p, apps: ids.length ? ids : undefined } as Params;
  }
  return p;
}

export function parseUpdateScan(x: any) {
  const split = (s: any) => String(s ?? "").split(" ;; ").map((t) => t.trim()).filter(Boolean);
  const updates = split(x.updates).map((l) => { const [kb, severity, kind, categories, cve, mb, ...title] = l.split("|"); return { kb: kb || null, severity: severity === "-" ? null : severity, security: kind === "sec", categories, cves: Number(String(cve).replace("cve:", "")) || 0, size_mb: Number(String(mb).replace("mb:", "")) || 0, title: title.join("|") }; });
  const all = split(x.apps).map((l) => { const [id, version, available, ...rest] = l.split("|"); const via = ["recipe", "winget"].includes(rest[rest.length - 1]) ? rest.pop() : "winget"; return { id, version, available, name: rest.join("|"), via }; });
  const apps = all.filter((a) => !PROTECTED_APPS.includes(a.id)); // the Wazuh agent is upgraded only by the agent pack
  return { checked_at: new Date().toISOString(), wu_count: Number(x.wu_count ?? updates.length) || 0, wu_security: Number(x.wu_security ?? 0) || 0, updates, app_count: apps.length, apps, winget: x.winget ?? null, reboot_pending: truthy(x.reboot_pending), wsus: x.wsus || null, boot: x.boot || null };
}

/** ask the endpoint which add-on version it has (no approval: read-only action of the add-on) */
export async function checkAddon(ctx: Ctx, host: any): Promise<{ version: string | null; message: string }> {
  if (platformOf(host) !== "windows_ar") return { version: null, message: "Windows のエージェントだけのホストが対象です" };
  const tag = `mv${host.id}x${Date.now().toString(36)}`;
  const r = await sendAr(ctx, host, ["version", "--id", tag, "--ref", tag], tag, 90_000);
  if (!r.sent) return { version: null, message: `送信に失敗: ${r.error}` };
  const v = r.result?.version ? String(r.result.version).slice(0, 16) : null;
  const pr = r.result?.pack && /^\d{1,6}$/.test(String(r.result.pack)) ? Number(r.result.pack) : null; // EDR-130: pack revision on the PC (add-on ≥ 1.1.0)
  await ctx.db("hosts").where({ id: host.id }).update({ ar_addon_version: v, ar_addon_checked_at: ctx.db.fn.now(), ...(pr ? { pack_rev: pr, pack_checked_at: ctx.db.fn.now() } : {}) });
  return { version: v, message: v ? `アドオン v${v}` : "応答なし（アドオン未導入、または端末がオフライン）" };
}

/** S7: remind about hosts that stay isolated (no automatic release, by decision) */
export async function remindIsolation(ctx: Ctx): Promise<void> {
  const h = ctx.cfg.HOST_ACTION_ISOLATION_REMIND_HOURS; if (!h) return;
  const { db } = ctx;
  const since = new Date(Date.now() - h * 3600_000);
  for (const a of await db("host_actions").where({ op: "isolate" }).whereIn("status", ["active", "unconfirmed"])) {
    const last = a.last_reminded_at ?? a.applied_at; if (last && new Date(last) > since) continue;
    const host = await db("hosts").where({ id: a.host_id }).first();
    await db("host_actions").where({ id: a.id }).update({ last_reminded_at: db.fn.now() });
    await ctx.audit.log("system", null, "host.action.still_isolated", { action_id: a.id, host: host?.name, since: a.applied_at });
    discord(ctx, `[MamorAI] ${host?.name ?? a.host_id} はまだ通信遮断（Contain）中です（${a.applied_at ?? "?"} から）。不要になったらホスト画面から解除してください。`);
  }
}


/**
 * EDR-169: the add-on update runs WITHOUT an approval card (owner decision 2026-11-06).
 * It only installs the copy the manager published, signed by the same certificate as the installed add-on, and the
 * endpoint rolls back by itself if the new version fails its self-test. Who started it is in the audit log.
 */
const addonRunning = new Set<number>();
export async function startAddonUpdate(ctx: Ctx, host0: any, userId: number | null, opts: { wait?: boolean } = {}): Promise<{ action_id: number; target: string; done?: Promise<void> }> {
  const { db } = ctx;
  if (platformOf(host0) !== "windows_ar") throw err("Windows のエージェントだけのホストが対象です");
  const host = await ensureAddon(ctx, host0, ADDON_SELF_MIN);
  if (addonRunning.has(host.id) || await db("host_actions").where({ host_id: host.id, op: "addon_update" }).whereIn("status", ["pending", "running"]).first()) throw err("このホストのアドオン更新はすでに実行中です", 409);
  const target = publishedAddon(ctx) ?? "";
  const p = { target } as any;
  await validate(ctx, host, "addon_update", p, false);
  const [id] = await db("host_actions").insert({ host_id: host.id, op: "addon_update", params: j(p), status: "running", requested_by: userId, via: "wazuh_ar" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
  await ctx.audit.log(userId ? "user" : "system", userId, "host.addon_update.started", { action_id: id, host: host.name, from: host.ar_addon_version, to: target });
  addonRunning.add(host.id);
  const run = (async () => {
    const tag = `mz${id}`;
    let out: { ok: boolean; confirmed: boolean; log: string; detail?: any };
    const steps: string[] = [];
    try {
      out = await runAddonUpdate(ctx, host, ["addon-update", target, "--id", tag, "--ref", tag], tag, async (s) => { steps.push(s); await db("host_actions").where({ id }).update({ result: j({ progress: s }) }); });
    } catch (e: any) { out = { ok: false, confirmed: false, log: `実行できませんでした: ${String(e?.message ?? e)}` }; }
    finally { addonRunning.delete(host.id); }
    await db("host_actions").where({ id }).update({ status: out.ok ? "done" : "failed", applied_at: out.ok ? db.fn.now() : null, result: j(out) });
    await ctx.audit.log("system", null, out.ok ? "host.addon_update.done" : "host.addon_update.failed", { action_id: id, host: host.name, to: target, log: out.log.slice(0, 500) });
    if (!out.ok) discord(ctx, `[MamorAI] ${host.name}: 自動対処アドオンの更新（v${target}）に失敗: ${out.log.slice(0, 300)}`);
  })();
  return { action_id: id, target, ...(opts.wait ? { done: run } : {}) };
}

/** EDR-169: 「全てのエージェントを更新」— every Windows host whose add-on is older than the published one, 3 at a time */
let bulkRunning = false;
export async function startAddonUpdateAll(ctx: Ctx, userId: number | null): Promise<{ target: string | null; queued: string[]; skipped: { name: string; reason: string }[] }> {
  const target = publishedAddon(ctx);
  if (!target) throw err("配布用のアドオンが見つかりません（installer/windows/build-addon.sh --publish-group windows を実行してください）");
  if (bulkRunning) throw err("全エージェントの更新はすでに実行中です", 409);
  const hosts = (await ctx.db("hosts").whereNotNull("agent_id")).filter((h: any) => platformOf(h) === "windows_ar");
  const queued: any[] = []; const skipped: { name: string; reason: string }[] = [];
  for (const h of hosts) {
    const v = h.ar_addon_version ? String(h.ar_addon_version) : null;
    if (v && vcmp(v, target) >= 0) continue;                                     // already current
    if (v && vcmp(v, ADDON_SELF_MIN) < 0) { skipped.push({ name: h.name, reason: `v${v}（エージェントパックの入れ直しが必要）` }); continue; }
    queued.push(h);                                                               // unknown version: asked first (ensureAddon)
  }
  await ctx.audit.log(userId ? "user" : "system", userId, "host.addon_update.bulk", { to: target, queued: queued.map((h) => h.name), skipped });
  bulkRunning = true;
  (async () => {
    const q = [...queued];
    const worker = async () => {
      for (let h = q.shift(); h; h = q.shift()) {
        try { const r = await startAddonUpdate(ctx, h, userId, { wait: true }); await r.done; }
        catch (e: any) { await ctx.audit.log("system", null, "host.addon_update.skipped", { host: h.name, reason: String(e?.message ?? e) }); }
      }
    };
    try { await Promise.all([worker(), worker(), worker()]); } finally { bulkRunning = false; }
  })();
  return { target, queued: queued.map((h) => h.name), skipped };
}

/** EDR-169: add-on version per Windows host for the agent pack page */
export async function addonStatus(ctx: Ctx): Promise<{ published: string | null; bulk_running: boolean; pack: any; hosts: any[] }> {
  const { db } = ctx;
  const hosts = (await db("hosts").whereNotNull("agent_id").orderBy("name")).filter((h: any) => platformOf(h) === "windows_ar");
  const last = await db("host_actions").where({ op: "addon_update" }).whereIn("host_id", hosts.map((h: any) => h.id)).orderBy("id", "desc");
  const lastPack = await db("host_actions").where({ op: "pack_update" }).whereIn("host_id", hosts.map((h: any) => h.id)).orderBy("id", "desc");
  const ap = await import("../agentpack/index.js");
  const lr = await ap.latestRev(ctx, "windows");
  const addonOnly = lr ? ((await ap.overview(ctx)).packs as any).windows?.addon_only ?? [] : [];
  const note = (r: any) => r?.progress ?? (r?.log ? String(r.log).split("\n")[0] : null);
  return {
    published: publishedAddon(ctx), bulk_running: bulkRunning,
    pack: { latest: lr?.id ?? null, addon_only: addonOnly, remote: ap.remotePackStatus(ctx), bulk_running: packBulk },
    hosts: hosts.map((h: any) => {
      const a = last.find((x: any) => x.host_id === h.id); const r = a ? pj<any>(a.result) : null;
      const pa = lastPack.find((x: any) => x.host_id === h.id); const pr = pa ? pj<any>(pa.result) : null;
      return { id: h.id, name: h.name, version: h.ar_addon_version ?? null, checked_at: h.ar_addon_checked_at ?? null, pack_rev: h.pack_rev ?? null,
        last: a ? { id: a.id, status: a.status, target: pj<any>(a.params)?.target ?? null, at: a.created_at, note: note(r) } : null,
        last_pack: pa ? { id: pa.id, status: pa.status, rev: pj<any>(pa.params)?.rev ?? null, at: pa.created_at, note: note(pr) } : null };
    }),
  };
}


/* ---------------- EDR-171: remote agent pack update (no approval card; owner decision 2026-11-06) ----------------
 * The manager publishes the Windows pack without secrets into the agent group folder (agentpack publishRemotePack →
 * host bridge → installer/windows/publish-pack.sh). The add-on (>= 1.3.3) checks hashes + signer, then runs
 * "Install-EdrAgent.ps1 -Mode update -Unattended" as SYSTEM. Older add-ons (>= 1.3.0) are updated first. */
export const PACK_REMOTE_MIN = "1.3.3";
const packRunning = new Set<number>();
export async function startPackUpdate(ctx: Ctx, host0: any, userId: number | null, opts: { wait?: boolean } = {}): Promise<{ action_id: number; rev: number; done?: Promise<void> }> {
  const { db } = ctx;
  if (platformOf(host0) !== "windows_ar") throw err("Windows のエージェントだけのホストが対象です");
  const ap = await import("../agentpack/index.js");
  const st = ap.remotePackStatus(ctx);
  const last = await ap.latestRev(ctx, "windows");
  if (!last) throw err("Windows のエージェントパックがまだありません");
  if (!st.bridge) throw err("ホストブリッジ（installer/modules/62-host-bridge.sh）が無いため、パックを共有フォルダに置けません");
  if (st.published_rev !== last.id) { await ap.publishRemotePack(ctx).catch(() => null); throw err(`共有フォルダのパックを r${last.id} に置き換えています（1〜2 分）。少し待ってからもう一度押してください${st.ok === false && st.message ? `（前回のエラー: ${st.message}）` : ""}`, 409); }
  let host = await ensureAddon(ctx, host0, ADDON_SELF_MIN);
  const cur = String(host.ar_addon_version ?? "0");
  if (vcmp(cur, ADDON_SELF_MIN) < 0) throw err(`アドオン v${cur} からはリモート更新できません。今回だけパックを手で入れ直してください`);
  if (host.pack_rev && Number(host.pack_rev) >= last.id) throw err(`すでに r${host.pack_rev} です`);
  if (packRunning.has(host.id) || await db("host_actions").where({ host_id: host.id }).whereIn("op", ["pack_update", "update_install"]).whereIn("status", ["pending", "running"]).first()) throw err("このホストではパック更新か Windows の更新が実行中です", 409);
  const [id] = await db("host_actions").insert({ host_id: host.id, op: "pack_update", params: j({ rev: last.id, from: host.pack_rev ?? null }), status: "running", requested_by: userId, via: "wazuh_ar" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
  await ctx.audit.log(userId ? "user" : "system", userId, "host.pack_update.started", { action_id: id, host: host.name, from: host.pack_rev ?? null, to: last.id });
  packRunning.add(host.id);
  const progress = async (s: string) => { await db("host_actions").where({ id }).update({ result: j({ progress: s }) }); };
  const run = (async () => {
    let out: { ok: boolean; log: string };
    try {
      if (vcmp(cur, PACK_REMOTE_MIN) < 0) { // add-on first (it has to know "pack-update")
        await progress(`先にアドオンを v${publishedAddon(ctx)} に更新しています`);
        const a = await startAddonUpdate(ctx, host, userId, { wait: true }); await a.done;
        host = (await db("hosts").where({ id: host.id }).first()) ?? host;
        if (vcmp(String(host.ar_addon_version ?? "0"), PACK_REMOTE_MIN) < 0) throw new Error(`アドオンを v${PACK_REMOTE_MIN} 以上にできませんでした（今 v${host.ar_addon_version ?? "?"}）`);
      }
      out = await runPackUpdate(ctx, host, last.id, `mp${id}`, progress);
    } catch (e: any) { out = { ok: false, log: `実行できませんでした: ${String(e?.message ?? e)}` }; }
    finally { packRunning.delete(host.id); }
    await db("host_actions").where({ id }).update({ status: out.ok ? "done" : "failed", applied_at: out.ok ? db.fn.now() : null, result: j(out) });
    await ctx.audit.log("system", null, out.ok ? "host.pack_update.done" : "host.pack_update.failed", { action_id: id, host: host.name, to: last.id, log: out.log.slice(0, 500) });
    if (!out.ok) discord(ctx, `[MamorAI] ${host.name}: エージェントパックの更新（r${last.id}）に失敗: ${out.log.slice(0, 300)}`);
  })();
  return { action_id: id, rev: last.id, ...(opts.wait ? { done: run } : {}) };
}

async function runPackUpdate(ctx: Ctx, host: any, rev: number, tag: string, progress: (s: string) => Promise<void>): Promise<{ ok: boolean; log: string }> {
  const since = new Date(Date.now() - 5_000).toISOString();
  let r: Awaited<ReturnType<typeof sendAr>> | null = null;
  // the agent may not have synced the shared folder yet: retry for up to 10 minutes
  for (let i = 0; i < 10; i++) {
    await progress(i ? `端末がパック r${rev} を受け取るのを待っています（${i} 分）` : `端末にパック r${rev} への更新を依頼`);
    r = await sendAr(ctx, host, ["pack-update", String(rev), "--id", tag, "--ref", tag], tag, 120_000);
    if (!r.sent) return { ok: false, log: `Wazuh API への送信に失敗: ${r.error}` };
    if (!r.result) return { ok: false, log: "2 分以内に端末から応答がありませんでした（電源・ネットワークを確認してください）" };
    if (truthy(r.result.ok)) break;
    if (!/shared folder|not in the shared folder/.test(String(r.result.detail ?? ""))) return { ok: false, log: `端末が更新を断りました: ${r.result.detail ?? ""}` };
    await sleep(60_000);
  }
  if (!r?.result || !truthy(r.result.ok)) return { ok: false, log: `10 分待っても端末に r${rev} が届きませんでした: ${r?.result?.detail ?? ""}` };
  await progress(`端末でインストーラーを実行中（r${rev}。最後に Wazuh エージェントが再起動します）`);
  const until = Date.now() + 55 * 60_000; let lastNote = "";
  while (Date.now() < until) {
    await sleep(20_000);
    const x = await latestAr(ctx, host, tag, since);
    if (!x) continue;
    if (x.phase === "done") {
      const ok = truthy(x.ok);
      if (ok) await checkAddon(ctx, host).catch(() => null);
      const h = await ctx.db("hosts").where({ id: host.id }).first();
      return { ok, log: `${ok ? `パック r${rev} を入れました` : `パック r${rev} の更新に失敗しました（終了コード ${x.rc ?? "?"}）`}（端末のパック r${h?.pack_rev ?? "?"}・アドオン v${h?.ar_addon_version ?? "?"}）\n${x.detail ?? ""}` };
    }
    if (x.detail && x.detail !== lastNote) { lastNote = String(x.detail); await progress(lastNote); }
  }
  return { ok: false, log: "55 分以内に端末から結果が届きませんでした。端末の C:\\ProgramData\\MamorAI\\agent-install.log を確認してください" };
}

/** EDR-171: 「古い端末を全部更新」— Windows hosts whose pack is older than the latest (and not just add-on-only), 2 at a time */
let packBulk = false;
export async function startPackUpdateAll(ctx: Ctx, userId: number | null): Promise<{ rev: number; queued: string[]; skipped: { name: string; reason: string }[] }> {
  const ap = await import("../agentpack/index.js");
  const last = await ap.latestRev(ctx, "windows"); if (!last) throw err("Windows のエージェントパックがまだありません");
  if (packBulk) throw err("パックの一括更新はすでに実行中です", 409);
  const st = ap.remotePackStatus(ctx);
  if (st.published_rev !== last.id) { await ap.publishRemotePack(ctx).catch(() => null); throw err(`共有フォルダのパックを r${last.id} に置き換えています（1〜2 分）。少し待ってからもう一度押してください`, 409); }
  const ov = await ap.overview(ctx); const addonOnly: number[] = (ov.packs as any).windows?.addon_only ?? [];
  const pub = publishedAddon(ctx);
  const hosts = (await ctx.db("hosts").whereNotNull("agent_id")).filter((h: any) => platformOf(h) === "windows_ar");
  const queued: any[] = []; const skipped: { name: string; reason: string }[] = [];
  for (const h of hosts) {
    const rev = h.pack_rev ? Number(h.pack_rev) : null;
    if (rev && rev >= last.id) continue;
    if (rev && addonOnly.includes(rev) && pub && h.ar_addon_version && vcmp(String(h.ar_addon_version), pub) >= 0) continue; // only the add-on differed and it is current
    if (h.ar_addon_version && vcmp(String(h.ar_addon_version), ADDON_SELF_MIN) < 0) { skipped.push({ name: h.name, reason: `アドオン v${h.ar_addon_version}（手で入れ直しが必要）` }); continue; }
    queued.push(h);
  }
  await ctx.audit.log(userId ? "user" : "system", userId, "host.pack_update.bulk", { to: last.id, queued: queued.map((h) => h.name), skipped });
  packBulk = true;
  (async () => {
    const q = [...queued];
    const worker = async () => { for (let h = q.shift(); h; h = q.shift()) { try { const r = await startPackUpdate(ctx, h, userId, { wait: true }); await r.done; } catch (e: any) { await ctx.audit.log("system", null, "host.pack_update.skipped", { host: h.name, reason: String(e?.message ?? e) }); } } };
    try { await Promise.all([worker(), worker()]); } finally { packBulk = false; }
  })();
  return { rev: last.id, queued: queued.map((h) => h.name), skipped };
}
export function packBulkRunning() { return packBulk; }
