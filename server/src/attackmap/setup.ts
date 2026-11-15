/**
 * 攻撃可視化セットアップ・ウィザード（EDR-74）のサーバー側:
 * 診断（readiness）/ レシピ描画 / 拠点 / デモデータ。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Knex } from "knex";
import type { IndexerClient } from "../wazuh/index.js";
import { probe, loadConfig, type AttackMap } from "./index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const cfgDir = path.resolve(here, "..", "..", "..", "config");

export interface Recipes { assets: any[]; vendors: Record<string, { label: string; stock: boolean; howto: string }> }
let recipesCache: Recipes | null = null;
export function loadRecipes(): Recipes { if (!recipesCache) recipesCache = JSON.parse(fs.readFileSync(path.join(cfgDir, "ingest-recipes.json"), "utf8")); return recipesCache!; }
export function decoderPack(): { decoders: string; rules: string } {
  return { decoders: fs.readFileSync(path.join(cfgDir, "ingest", "edr-fw-decoders.xml"), "utf8"), rules: fs.readFileSync(path.join(cfgDir, "ingest", "edr-fw-rules.xml"), "utf8") };
}
export function render(tpl: string, vars: Record<string, string>): string { return tpl.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k] ?? `{{${k}}}`); }

/** manager の agents 一覧（API が設定されていれば） */
async function agents(managerApi: (() => Promise<any>) | null): Promise<{ name: string; status: string; ip: string | null }[]> {
  if (!managerApi) return [];
  try { const api = await managerApi(); const r: any = await api.get("/agents?select=id,name,status,ip&limit=500"); return (r?.data?.affected_items ?? []).filter((a: any) => a.id !== "000").map((a: any) => ({ name: a.name, status: a.status, ip: a.ip ?? null })); }
  catch { return []; }
}

export interface Readiness {
  ok: boolean; level: "ready" | "partial" | "empty" | "error"; window: string;
  indexer: { ok: boolean; error?: string }; geo_rate: number | null; total_src: number;
  profiles: { id: string; name: string; total: number; with_geo: number; agents: string[]; error?: string }[];
  agents: { name: string; status: string; ip: string | null }[];
  manager_remote: boolean | null; // manager が syslog を受信する設定か（API の manager/configuration から）
  hints: string[];
}

export async function readiness(ix: IndexerClient, managerApi: (() => Promise<any>) | null, window = "now-24h"): Promise<Readiness> {
  const out: Readiness = { ok: false, level: "empty", window, indexer: { ok: true }, geo_rate: null, total_src: 0, profiles: [], agents: [], manager_remote: null, hints: [] };
  try { const p = await probe(ix, window); out.profiles = p.profiles; } catch (e: any) { out.indexer = { ok: false, error: e.message }; out.level = "error"; return out; }
  const attack = out.profiles.filter((p) => p.id !== "blocked");
  out.total_src = attack.reduce((a, p) => a + (p.total ?? 0), 0);
  const geo = attack.reduce((a, p) => a + (p.with_geo ?? 0), 0);
  out.geo_rate = out.total_src ? Math.round((geo / out.total_src) * 100) : null;
  out.agents = await agents(managerApi);
  if (managerApi) { try { const api = await managerApi(); const r: any = await api.get("/manager/configuration?section=remote"); const rem = r?.data?.affected_items?.[0]?.remote ?? []; out.manager_remote = (Array.isArray(rem) ? rem : [rem]).some((x: any) => x?.connection === "syslog"); } catch { out.manager_remote = null; } }
  const okProfiles = attack.filter((p) => (p.total ?? 0) > 0);
  const failed = attack.filter((p) => p.error);
  out.level = okProfiles.length === 0 ? (failed.length ? "error" : "empty") : okProfiles.length < 2 && out.total_src < 50 ? "partial" : "ready";
  if (failed.length) out.hints.push(`集計に失敗したプロファイルがあります（${failed.map((p) => p.name).join("、")}）: ${failed[0].error}`);
  out.ok = out.level === "ready";
  if (out.level === "empty") out.hints.push("外部からの攻撃通信を含むアラートがまだありません。公開サーバーのログかルーター/FW の拒否ログを Wazuh に取り込む必要があります。");
  if (out.geo_rate != null && out.geo_rate < 50 && out.total_src > 0) out.hints.push(`送信元 IP に国情報（GeoLocation）が付いているのは ${out.geo_rate}% です。Wazuh の filebeat ingest pipeline で GeoIP が無効になっていないか確認してください。`);
  if (out.manager_remote === false) out.hints.push("manager は syslog を受信する設定になっていません。機器（FW / ルーター）のログを使う場合は <remote> の追加が必要です。");
  if (!out.agents.length && managerApi) out.hints.push("エージェントが 1 台も登録されていません。");
  return out;
}

// ---------- sites ----------
export async function listSites(db: Knex) {
  const sites = await db("sites").orderBy("id"); const members = await db("site_members");
  return sites.map((s: any) => ({ ...s, is_default: !!s.is_default, members: members.filter((m: any) => m.site_id === s.id).map((m: any) => m.agent_name) }));
}
export async function siteOfAgent(db: Knex): Promise<{ byAgent: Map<string, any>; def: any | null }> {
  const sites = await listSites(db); const byAgent = new Map<string, any>();
  for (const s of sites) for (const a of s.members) byAgent.set(a, s);
  return { byAgent, def: sites.find((s) => s.is_default) ?? null };
}

// ---------- demo ----------
export function demoData(window = "now-24h"): AttackMap {
  const rnd = (n: number) => Math.floor(Math.random() * n);
  const C = [["China", "CN", "中国", 36.8, 114.8, 1642], ["United States", "US", "米国", 37.2, -98.6, 858], ["Russia", "RU", "ロシア", 58, 60, 561], ["Netherlands", "NL", "オランダ", 52.3, 5.3, 366], ["Brazil", "BR", "ブラジル", -15.8, -47.9, 259], ["India", "IN", "インド", 22, 78, 214], ["Germany", "DE", "ドイツ", 51, 10, 171], ["Vietnam", "VN", "ベトナム", 16, 107, 128], ["South Korea", "KR", "韓国", 36.5, 127.8, 77], ["Ukraine", "UA", "ウクライナ", 49, 32, 64], ["Singapore", "SG", "シンガポール", 1.35, 103.8, 51], ["Iran", "IR", "イラン", 32, 53, 40]] as const;
  const kinds = ["ssh", "web", "vpn"]; const colors: Record<string, string> = { ssh: "#f43f5e", web: "#fb923c", vpn: "#facc15" };
  const countries = C.map(([name, iso2, ja, lat, lon, n]) => { const ssh = Math.round(n * .6), web = Math.round(n * .3), vpn = n - ssh - web; return { name, iso2, name_ja: ja, lat, lon, total: n, by_kind: { ssh, web, vpn }, blocked: Math.round(n * .95), top_ips: [1, 2, 3].map((i) => ({ ip: `${10 + rnd(200)}.${rnd(255)}.${rnd(255)}.${rnd(255)}`, n: Math.round(n / (i * 2)) })), targets: [{ host: "demo-web01", n: Math.round(n * .5) }, { host: "demo-vpn", n: Math.round(n * .3) }, { host: "demo-mail", n: Math.round(n * .2) }], rules: [{ id: "5710", n: ssh }, { id: "31101", n: web }] }; });
  const total = countries.reduce((a, c) => a + c.total, 0);
  const now = Date.now();
  const recent = Array.from({ length: 30 }, (_, i) => { const c = countries[rnd(countries.length)]; const k = kinds[rnd(3)]; return { ts: new Date(now - i * 47_000).toISOString(), country: c.name_ja, iso2: c.iso2, ip: c.top_ips[0].ip, dst: ["demo-web01", "demo-vpn", "demo-mail"][rnd(3)], kind: k, color: colors[k], rule_id: k === "ssh" ? "5710" : "31101", what_ja: k === "ssh" ? "SSH で存在しないユーザーへのログイン試行" : k === "web" ? "秘密ファイルの探索（/.env など）" : "VPN ポータルの認証失敗", level: 5 }; });
  const timeline = Array.from({ length: 24 }, (_, i) => ({ t: new Date(now - (23 - i) * 3600_000).toISOString(), n: 100 + rnd(200), by_kind: {} }));
  return { window, generated_at: new Date().toISOString(), profiles: loadConfig().profiles.map((p) => ({ id: p.id, name: p.name, kind: p.kind, color: p.color, role: p.role ?? "attack", total: 0 })), kpi: { total, countries: countries.length, targets: 3, blocked: Math.round(total * .95), internal: 0, cdn_unknown: 0, no_geo: 0 }, countries, targets: [{ host: "demo-web01", total: Math.round(total * .5), by_kind: {} }, { host: "demo-vpn", total: Math.round(total * .3), by_kind: {} }, { host: "demo-mail", total: Math.round(total * .2), by_kind: {} }], recent, timeline };
}
