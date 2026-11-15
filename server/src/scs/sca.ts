/**
 * EDR-178（SCS P1-6）: Wazuh SCA（CIS ベンチマーク）の結果を SCS の評価基準に対応付ける。
 *
 * - チェック ID は OS ごと・ポリシーの版ごとに違うので、ID ではなくチェックのタイトル（CIS の文言）で拾う。
 * - CIS の基準は SCS より厳しいものがある（例: ロックアウトは CIS が「5 回以下」、SCS は「10 回」）。
 *   そのため CIS で「合格」なら SCS も満たすが、CIS で「不合格」でも SCS を満たしている可能性がある → 「要確認」にする。
 *   値まで見て判定するのは独自ポリシー（installer/wazuh/sca/scs_windows.yml）を配った後。
 * - 取得は 1 日 1 回（SCA のスキャン間隔は既定 12 時間）。同じスキャン結果は重ねて保存しない。
 */
import type { Ctx } from "../api/context.js";
import { managerApi } from "../api/context.js";

export type ScaKey = "fw" | "autorun" | "guest" | "admin_account" | "lockout" | "pwlen" | "root_login";
/** タイトルの正規表現。Windows（CIS Win10/11/2012〜2025）と Linux（Debian / Ubuntu / Amazon Linux 2023）で確認済み */
export const SCA_RULES: { key: ScaKey; re: RegExp; os: "windows" | "linux" }[] = [
  { key: "fw", os: "windows", re: /Windows Firewall: (Domain|Private|Public): Firewall state/i },
  { key: "fw", os: "linux", re: /^Ensure (ufw service is enabled|nftables service is enabled|(nftables|iptables) default deny firewall policy)/i },
  { key: "autorun", os: "windows", re: /(Set the default behavior for AutoRun|Turn off Autoplay)/i },
  { key: "guest", os: "windows", re: /Accounts: Guest account status/i },
  { key: "admin_account", os: "windows", re: /Accounts: (Administrator account status|Rename administrator account)/i },
  { key: "lockout", os: "windows", re: /^(Ensure 'Account lockout threshold'|SCS 4-1-4-1:)/i },
  { key: "lockout", os: "linux", re: /(lockout for failed password attempts is configured|password failed attempts lockout is configured|pam_faillock module is enabled)/i },
  { key: "pwlen", os: "windows", re: /^(Ensure 'Minimum password length'|SCS 4-1-4-2:)/i },
  { key: "root_login", os: "linux", re: /(SSH root login is disabled|sshd PermitRootLogin is disabled)/i },
];
export interface ScaCheck { key: ScaKey; id: number; title: string; result: string }

export function pickChecks(items: { id: number; title: string; result?: string }[], os: "windows" | "linux"): ScaCheck[] {
  const out: ScaCheck[] = [];
  for (const c of items) { const r = SCA_RULES.find((x) => x.os === os && x.re.test(c.title)); if (r) out.push({ key: r.key, id: c.id, title: c.title, result: c.result ?? "" }); }
  return out;
}

export type HostVerdict = "ok" | "ng" | "check" | "na" | "unknown";
/** 1 台分の判定。ok=満たす / ng=満たさない / check=CIS 不合格だが SCS は満たす可能性 / na=対象外 / unknown=チェックが無い */
export function verdict(key: ScaKey, checks: ScaCheck[], os: "windows" | "linux"): HostVerdict {
  const cs = checks.filter((c) => c.key === key && c.result !== "not applicable");
  const passed = cs.filter((c) => c.result === "passed").length;
  if (key === "autorun" && os === "linux") return "na";
  if (!SCA_RULES.some((r) => r.key === key && r.os === os)) return "na"; // その OS には無い観点（Linux の Guest、Windows の root ログインなど）
  if (!cs.length) return "unknown";
  // 独自ポリシー（scs_windows.yml）の結果があれば、SCS の値で見たものなのでそれを優先する
  const own = cs.filter((c) => /^SCS \d/.test(c.title));
  if (own.length) return own.every((c) => c.result === "passed") ? "ok" : "ng";
  switch (key) {
    case "fw": return os === "windows" ? (cs.length >= 3 && passed === cs.length ? "ok" : "ng") : passed ? "ok" : "ng"; // Windows は 3 プロファイルとも有効
    case "autorun": return passed ? "ok" : "ng";                     // 自動実行・自動再生のどちらかを全ドライブで無効
    case "guest": case "root_login": return passed === cs.length ? "ok" : "ng";
    case "admin_account": return passed ? "ok" : "check";            // 無効化かリネームのどちらか。どちらも不合格なら MFA 等の代替策を人が確認
    case "lockout": case "pwlen": return passed ? "ok" : "check";    // CIS（5 回以下 / 14 文字以上）より SCS（10 回 / 6 文字以上）が緩い
  }
}

const osOf = (a: any): "windows" | "linux" => (/windows/i.test(a.os_name ?? "") ? "windows" : "linux");
const iso = (s: string | null | undefined) => (s ? new Date(s).toISOString() : new Date().toISOString());

/** Wazuh API から SCA の最新結果を取り、SCS に関係するチェックだけ保存する */
export async function syncSca(ctx: Ctx): Promise<{ agents: number; saved: number; errors: number }> {
  const { db } = ctx;
  const assets = await db("scs_assets").whereNull("removed_at").where({ in_scope: true }).whereNotNull("agent_id").whereNotNull("wazuh_instance_id");
  let saved = 0, errors = 0;
  const apis = new Map<number, any>();
  for (const a of assets) {
    try {
      if (!apis.has(a.wazuh_instance_id)) apis.set(a.wazuh_instance_id, await managerApi(ctx, a.wazuh_instance_id));
      const api = apis.get(a.wazuh_instance_id);
      const pol: any = await api.get(`/sca/${encodeURIComponent(a.agent_id)}`);
      for (const p of pol?.data?.affected_items ?? []) {
        const scanEnd = iso(p.end_scan);
        if (await db("scs_sca_results").where({ asset_id: a.id, policy_id: p.policy_id, scan_end: scanEnd }).first()) continue;
        const ck: any = await api.get(`/sca/${encodeURIComponent(a.agent_id)}/checks/${encodeURIComponent(p.policy_id)}?limit=1000&select=id,title,result`);
        const checks = pickChecks(ck?.data?.affected_items ?? [], osOf(a));
        await db("scs_sca_results").insert({ asset_id: a.id, policy_id: p.policy_id, policy_name: p.name ?? null, scan_end: scanEnd, pass: p.pass ?? 0, fail: p.fail ?? 0, invalid: p.invalid ?? 0, score: p.score ?? null, checks_json: JSON.stringify(checks) });
        saved++;
      }
    } catch (e: any) { errors++; ctx.log.warn({ asset: a.name, err: e.message }, "scs: sca fetch failed"); }
  }
  return { agents: assets.length, saved, errors };
}

/** 端末ごとの最新スナップショット */
export async function latestPerAsset(ctx: Ctx): Promise<{ asset: any; row: any | null; checks: ScaCheck[]; os: "windows" | "linux" }[]> {
  const { db } = ctx;
  const assets = await db("scs_assets").whereNull("removed_at").where({ in_scope: true }).whereIn("category", ["pc", "server", "hypervisor"]);
  // ポリシーごとの最新（CIS と独自ポリシーの両方がある端末はチェックを合わせる）
  const rows = await db("scs_sca_results").whereIn("id", db("scs_sca_results").max("id").groupBy("asset_id", "policy_id"));
  const by = new Map<number, any[]>(); for (const r of rows) by.set(r.asset_id, [...(by.get(r.asset_id) ?? []), r]);
  return assets.map((a: any) => {
    const rs = (by.get(a.id) ?? []).sort((x: any, y: any) => (x.policy_id === "scs_windows" ? 1 : 0) - (y.policy_id === "scs_windows" ? 1 : 0));
    const row = rs[0] ?? null; // 表示用は CIS 側
    return { asset: a, row, checks: rs.flatMap((r: any) => JSON.parse(r.checks_json)), os: osOf(a) };
  });
}
