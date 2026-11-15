/**
 * EDR-174/179（SCS）: 評価基準ごとの状態（適合 / 要対応 / 未接続 / 対象外）を、MamorAI が持っているデータから出す。
 * 根拠の無い「適合」は出さない（機能がまだ無いものは「未接続」、人の入力が要るものは「要対応」）。
 */
import type { Ctx } from "../api/context.js";
import { latestPerAsset, verdict, type ScaKey, type HostVerdict } from "./sca.js";

export type CriteriaState = "適合" | "要対応" | "未接続" | "対象外";
export interface Evaluation { state: CriteriaState; evidence: string; checked_at: string | null; link?: string }

// ---- サポート期限（4-4-4-1）。Microsoft / 各ディストリビューションの公開ライフサイクルに基づく内蔵表（MamorAI 更新時に見直す）----
interface Eol { match: (os: string, ver: string) => boolean; label: string; end: string }
const win = (build: string) => (os: string, ver: string) => /windows/i.test(os) && new RegExp(`^10\\.0\\.${build}(\\.|$)`).test(ver);
const isServer = (os: string) => /server/i.test(os); const isEnt = (os: string) => /enterprise|education|iot/i.test(os); const isLtsc = (os: string) => /ltsc|ltsb/i.test(os);
export const EOL_TABLE: Eol[] = [
  { label: "Windows Server 2012 / 2012 R2", end: "2023-10-10", match: (o) => /windows server 2012/i.test(o) },
  { label: "Windows Server 2016", end: "2027-01-12", match: (o) => /windows server 2016/i.test(o) },
  { label: "Windows Server 2019", end: "2029-01-09", match: (o) => /windows server 2019/i.test(o) },
  { label: "Windows Server 2022", end: "2031-10-14", match: (o) => /windows server 2022/i.test(o) },
  { label: "Windows Server 2025", end: "2034-10-10", match: (o) => /windows server 2025/i.test(o) },
  { label: "Windows 10 Enterprise LTSB 2016", end: "2026-10-13", match: (o, v) => !isServer(o) && isLtsc(o) && win("14393")(o, v) },
  { label: "Windows 10 Enterprise LTSC 2019", end: "2029-01-09", match: (o, v) => !isServer(o) && isLtsc(o) && win("17763")(o, v) },
  { label: "Windows 10 Enterprise LTSC 2021", end: "2027-01-12", match: (o, v) => !isServer(o) && isLtsc(o) && win("19044")(o, v) },
  { label: "Windows 10（22H2 ほか）", end: "2025-10-14", match: (o) => /windows 10/i.test(o) && !isLtsc(o) },
  { label: "Windows 11 21H2（Home / Pro）", end: "2023-10-10", match: (o, v) => /windows 11/i.test(o) && !isEnt(o) && win("22000")(o, v) },
  { label: "Windows 11 21H2（Enterprise / Education）", end: "2024-10-08", match: (o, v) => /windows 11/i.test(o) && isEnt(o) && win("22000")(o, v) },
  { label: "Windows 11 22H2（Home / Pro）", end: "2024-10-08", match: (o, v) => /windows 11/i.test(o) && !isEnt(o) && win("22621")(o, v) },
  { label: "Windows 11 22H2（Enterprise / Education）", end: "2025-10-14", match: (o, v) => /windows 11/i.test(o) && isEnt(o) && win("22621")(o, v) },
  { label: "Windows 11 23H2（Home / Pro）", end: "2025-11-11", match: (o, v) => /windows 11/i.test(o) && !isEnt(o) && win("22631")(o, v) },
  { label: "Windows 11 23H2（Enterprise / Education）", end: "2026-11-10", match: (o, v) => /windows 11/i.test(o) && isEnt(o) && win("22631")(o, v) },
  { label: "Windows 11 24H2（Home / Pro）", end: "2026-10-13", match: (o, v) => /windows 11/i.test(o) && !isEnt(o) && win("26100")(o, v) },
  { label: "Windows 11 24H2（Enterprise / Education）", end: "2027-10-12", match: (o, v) => /windows 11/i.test(o) && isEnt(o) && win("26100")(o, v) },
  { label: "Windows 11 25H2（Home / Pro）", end: "2027-10-12", match: (o, v) => /windows 11/i.test(o) && !isEnt(o) && win("26200")(o, v) },
  { label: "Windows 11 25H2（Enterprise / Education）", end: "2028-10-10", match: (o, v) => /windows 11/i.test(o) && isEnt(o) && win("26200")(o, v) },
  { label: "Ubuntu 20.04 LTS（標準サポート）", end: "2025-05-31", match: (o, v) => /ubuntu/i.test(o) && /^20\.04/.test(v) },
  { label: "Ubuntu 22.04 LTS（標準サポート）", end: "2027-06-01", match: (o, v) => /ubuntu/i.test(o) && /^22\.04/.test(v) },
  { label: "Ubuntu 24.04 LTS（標準サポート）", end: "2029-05-31", match: (o, v) => /ubuntu/i.test(o) && /^24\.04/.test(v) },
  { label: "Debian 11（LTS）", end: "2026-08-31", match: (o, v) => /debian/i.test(o) && (/^11(\.|$)/.test(v) || /bullseye/i.test(o)) },
  { label: "Debian 12（LTS）", end: "2028-06-30", match: (o, v) => /debian/i.test(o) && (/^12(\.|$)/.test(v) || /bookworm/i.test(o)) },
  { label: "Amazon Linux 2", end: "2026-06-30", match: (o, v) => /amazon linux/i.test(o) && /^2(\.|$)/.test(v) && !/2023/.test(v) },
  { label: "Amazon Linux 2023", end: "2029-06-30", match: (o, v) => /amazon linux/i.test(o) && /2023/.test(`${o} ${v}`) },
];
export function eolOf(os: string | null, ver: string | null): { label: string; end: string; expired: boolean; days: number } | null {
  const o = os ?? "", v = ver ?? ""; const e = EOL_TABLE.find((x) => x.match(o, v)); if (!e) return null;
  const days = Math.ceil((Date.parse(e.end + "T00:00:00+09:00") - Date.now()) / 86_400_000);
  return { label: e.label, end: e.end, expired: days < 0, days };
}

export async function evaluateAll(ctx: Ctx): Promise<Record<string, Evaluation>> {
  const { db } = ctx; const out: Record<string, Evaluation> = {}; const t = new Date().toISOString();
  const flags = Object.fromEntries((await db("app_flags").whereIn("key", ["scs_vulns_at", "scs_feeds_at"])).map((f: any) => [f.key, f.value]));
  const assets = await db("scs_assets").whereNull("removed_at").where({ in_scope: true });
  const cat = (c: string[]) => assets.filter((a: any) => c.includes(a.category));
  const fresh = (iso: string | undefined, hours: number) => !!iso && Date.now() - Date.parse(iso) < hours * 3600_000;
  const assetEval = (list: any[], label: string): Evaluation => {
    if (!list.length) return { state: "要対応", evidence: `${label}が台帳にありません`, checked_at: t, link: "/scs/assets" };
    const noMaker = list.filter((a) => !a.manufacturer).length;
    return noMaker ? { state: "要対応", evidence: `${label} ${list.length} 台。うち製造元が未入力 ${noMaker} 台（Wazuh から取れないので手で入れる）`, checked_at: t, link: "/scs/assets" }
      : { state: "適合", evidence: `${label} ${list.length} 台（製造元・OS を把握）`, checked_at: t, link: "/scs/assets" };
  };
  out["3-1-1-1"] = assetEval(cat(["pc"]), "PC");
  out["3-1-1-2"] = assetEval(cat(["server", "hypervisor"]), "サーバ・ハイパーバイザ");
  const nw = cat(["network_device"]);
  out["3-1-2-2"] = !nw.length ? { state: "要対応", evidence: "ネットワーク機器が台帳にありません（ルータ・FW・スイッチを手で追加）", checked_at: t, link: "/scs/assets" }
    : nw.some((a: any) => !a.manufacturer || !a.model || !a.maintainer) ? { state: "要対応", evidence: `ネットワーク機器 ${nw.length} 台。製造元・モデル・保守事業者の未入力あり`, checked_at: t, link: "/scs/assets" }
    : { state: "適合", evidence: `ネットワーク機器 ${nw.length} 台（製造元・モデル・保守事業者あり）`, checked_at: t, link: "/scs/assets" };
  out["3-1-1-5"] = cat(["smart_device"]).length ? { state: "適合", evidence: `スマートデバイス ${cat(["smart_device"]).length} 台`, checked_at: t, link: "/scs/assets" } : { state: "要対応", evidence: "スマートデバイスが台帳にありません（無い場合はその旨を点検記録に）", checked_at: t, link: "/scs/assets" };

  // 脆弱性（4-4-4-2 / 3-2-1-4）
  const now = new Date().toISOString();
  const open = () => db("scs_vulns").whereNull("resolved_at").whereNotIn("status", ["適用済", "対象外"]).where("sla_target", true);
  const overdue = Number((await open().where("due_at", "<", now).count({ n: "*" }).first())?.n ?? 0);
  const backlog = Number((await open().where("due_at", "<", now).whereRaw("created_at > due_at").count({ n: "*" }).first())?.n ?? 0);
  const undet = Number((await db("scs_vulns").whereNull("resolved_at").where("target_class", "undetermined").countDistinct({ n: "package_name" }).first())?.n ?? 0);
  if (!flags.scs_vulns_at) out["4-4-4-2"] = { state: "未接続", evidence: "脆弱性をまだ取り込んでいません", checked_at: null, link: "/scs/vulns" };
  else out["4-4-4-2"] = { state: overdue || undet ? "要対応" : "適合", evidence: overdue ? `期限超過 ${overdue} 件（うち取り込み前からの持ち越し ${backlog} 件）${undet ? `・要判定のソフト ${undet} 種類` : ""}` : undet ? `要判定のソフト ${undet} 種類（14日対象かを決める）` : "期限超過なし", checked_at: flags.scs_vulns_at, link: overdue ? "/scs/vulns?tab=overdue" : "/scs/vulns" };
  out["3-2-1-4"] = flags.scs_vulns_at && fresh(flags.scs_vulns_at, 3) ? { state: "適合", evidence: `脆弱性台帳を毎時更新（14日対象の未対応 ${Number((await open().count({ n: "*" }).first())?.n ?? 0)} 件）`, checked_at: flags.scs_vulns_at, link: "/scs/vulns" } : { state: "要対応", evidence: "脆弱性台帳の取り込みが 3 時間以上止まっています", checked_at: flags.scs_vulns_at ?? null, link: "/scs" };

  // 脅威情報（1-2-2-1）
  const runs = await db("scs_feed_runs").whereIn("id", db("scs_feed_runs").max("id").groupBy("source"));
  const bad = runs.filter((r: any) => !r.ok || !fresh(r.started_at, 48));
  out["1-2-2-1"] = !runs.length ? { state: "未接続", evidence: "脅威情報をまだ取り込んでいません", checked_at: null, link: "/scs" }
    : bad.length ? { state: "要対応", evidence: `取り込みに失敗・停止: ${bad.map((r: any) => r.source).join(", ")}`, checked_at: flags.scs_feeds_at ?? null, link: "/scs" }
    : { state: "適合", evidence: `CISA KEV・IPA・JPCERT/CC を毎日取り込み（${runs.length} 系統）`, checked_at: flags.scs_feeds_at ?? null, link: "/scs" };

  // サポート切れ（4-4-4-1 / 4-4-2-1）
  const eol = assets.map((a: any) => ({ a, e: eolOf(a.os_name, a.os_version) }));
  const expired = eol.filter((x) => x.e?.expired); const unknown = eol.filter((x) => !x.e && ["pc", "server", "hypervisor"].includes(x.a.category));
  const eolEval: Evaluation = expired.length ? { state: "要対応", evidence: `サポート切れ ${expired.length} 台: ${expired.slice(0, 6).map((x) => `${x.a.name}（${x.e!.label}・${x.e!.end} 終了）`).join("、")}${expired.length > 6 ? " ほか" : ""}`, checked_at: t, link: "/scs/assets" }
    : { state: "適合", evidence: `サポート切れの OS なし${unknown.length ? `（期限表に無い OS ${unknown.length} 台は要確認）` : ""}`, checked_at: t, link: "/scs/assets" };
  out["4-4-4-1"] = eolEval; out["4-4-2-1"] = eolEval;

  // 検知・遮断（5-1-1-1）: エージェントの稼働
  const hosts = await db("hosts").whereNotNull("agent_id");
  const active = hosts.filter((h: any) => h.agent_status === "active").length;
  out["5-1-1-1"] = { state: active ? "適合" : "要対応", evidence: `Wazuh エージェント active ${active} / ${hosts.length} 台・自動対処アドオン ${hosts.filter((h: any) => h.ar_addon_version).length} 台`, checked_at: t, link: "/hosts" };
  // SCA（EDR-178）: 4-1-4-1 / 4-1-4-2 / 4-4-1-2 / 4-5-1-8 / 4-4-1-5 / 3-1-1-6
  const sca = await latestPerAsset(ctx);
  const scaAt = (await db("app_flags").where({ key: "scs_sca_at" }).first())?.value ?? null;
  const scaEval = (keys: ScaKey[], cats: string[], label: string, checkNote: string): Evaluation => {
    const list = sca.filter((x) => cats.includes(x.asset.category));
    if (!list.length) return { state: "要対応", evidence: `対象の機器（${cats.map((c) => ({ pc: "PC", server: "サーバ", hypervisor: "ハイパーバイザ" } as any)[c]).join("・")}）が台帳にありません`, checked_at: t, link: "/scs/assets" };
    const withData = list.filter((x) => x.row);
    if (!withData.length) return { state: "未接続", evidence: "Wazuh の SCA 結果をまだ取り込んでいません（1 日 1 回）", checked_at: scaAt, link: "/scs" };
    const per = withData.map((x) => {
      const vs = keys.map((k) => verdict(k, x.checks, x.os)).filter((v) => v !== "na");
      const v: HostVerdict = !vs.length ? "na" : vs.includes("ng") ? "ng" : vs.includes("unknown") ? "unknown" : vs.includes("check") ? "check" : "ok";
      return { name: x.asset.name, v };
    }).filter((p) => p.v !== "na");
    const names = (v: HostVerdict) => per.filter((p) => p.v === v).map((p) => p.name);
    const ng = names("ng"), ck = names("check"), unk = names("unknown"), ok = names("ok"); const nodata = list.length - withData.length;
    const tail = `${nodata ? `・SCA 結果なし ${nodata} 台` : ""}${unk.length ? `・該当チェックなし ${unk.length} 台（${unk.slice(0, 4).join("、")}）` : ""}`;
    if (!per.length) return { state: "対象外", evidence: `${label}: 対象の OS がありません`, checked_at: scaAt };
    if (ng.length) return { state: "要対応", evidence: `${label}: 満たさない ${ng.length} 台（${ng.slice(0, 6).join("、")}${ng.length > 6 ? " ほか" : ""}）・満たす ${ok.length} 台${ck.length ? `・要確認 ${ck.length} 台` : ""}${tail}`, checked_at: scaAt, link: "/scs" };
    if (ck.length || unk.length || nodata) return { state: "要対応", evidence: `${label}: 満たす ${ok.length} 台${ck.length ? `・要確認 ${ck.length} 台（${checkNote}）` : ""}${tail}`, checked_at: scaAt, link: "/scs" };
    return { state: "適合", evidence: `${label}: ${ok.length} 台すべて満たす（Wazuh SCA / CIS）`, checked_at: scaAt, link: "/scs" };
  };
  const strict = "CIS の基準を満たさないが、SCS の基準は満たす可能性。値の確認が要る";
  out["4-1-4-1"] = scaEval(["lockout"], ["pc"], "ログオン試行の制限", strict);
  out["4-1-4-2"] = scaEval(["pwlen"], ["pc"], "パスワードの長さ", strict);
  out["4-4-1-2"] = scaEval(["autorun"], ["pc", "server", "hypervisor"], "自動実行・自動再生の無効化", "");
  out["4-5-1-8"] = scaEval(["fw"], ["pc", "server", "hypervisor"], "ソフトウェア FW の有効化", "");
  out["4-4-1-5"] = scaEval(["guest", "admin_account", "root_login"], ["pc", "server", "hypervisor"], "デフォルトユーザ ID の停止", "Administrator が有効かつ名前もそのまま。MFA などの代替策があるか確認");
  const imp = sca.filter((x) => x.asset.important_system);
  out["3-1-1-6"] = !imp.length ? { state: "要対応", evidence: "重要なシステムの機器が指定されていません（資産台帳で「重要システム」を付ける）", checked_at: t, link: "/scs/assets" }
    : imp.every((x) => x.row) ? { state: "適合", evidence: `重要なシステムの機器 ${imp.length} 台の設定（SCA）を毎日保存`, checked_at: scaAt, link: "/scs" }
    : { state: "要対応", evidence: `重要なシステムの機器 ${imp.length} 台のうち SCA 結果なし ${imp.filter((x) => !x.row).length} 台`, checked_at: scaAt, link: "/scs" };
  return out;
}
