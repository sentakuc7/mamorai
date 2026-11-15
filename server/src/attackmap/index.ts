/**
 * 攻撃可視化（EDR-70 / EDR-71）: 攻撃ソース定義（Attack Source Profile）に従って indexer を集計し、
 * 国別 × 種類 × 遮断、上位 IP、拠点、直近イベント、時系列を返す。
 * Wazuh ダッシュボードには依存しない。GeoIP は Wazuh 標準の GeoLocation.* を使う。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { IndexerClient } from "../wazuh/index.js";
import { COUNTRIES } from "./countries.js";

const here = path.dirname(fileURLToPath(import.meta.url));

export interface Profile {
  id: string; name: string; kind: string; color: string; builtin: boolean; role?: "attack" | "block";
  match: { any_groups?: string[]; all_groups?: string[]; exclude_groups?: string[]; any_rule_ids?: string[]; exclude_rule_ids?: string[]; min_level?: number };
  src_fields: string[]; dst_field: string; what_ja?: string;
}
interface Config { profiles: Profile[]; cdn_ranges: Record<string, string[]>; private_ranges: string[] }

let cfgCache: Config | null = null;
export function loadConfig(): Config {
  if (cfgCache) return cfgCache;
  const p = path.resolve(here, "..", "..", "..", "config", "attack-profiles.json");
  cfgCache = JSON.parse(fs.readFileSync(p, "utf8"));
  return cfgCache!;
}

// ---------- CIDR helpers (IPv4 only; IPv6 ranges are matched by prefix) ----------
function ip4(s: string): number | null { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s); if (!m) return null; const p = m.slice(1).map(Number); if (p.some((x) => x > 255)) return null; return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0; }
function inCidr(ip: string, cidr: string): boolean {
  const [net, bitsS] = cidr.split("/"); const bits = Number(bitsS);
  if (net.includes(":")) return ip.includes(":") && ip.toLowerCase().startsWith(net.toLowerCase().replace(/::$/, "").replace(/:$/, "")); // coarse
  const a = ip4(ip), b = ip4(net); if (a == null || b == null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}
export function classifyIp(ip: string): "external" | "internal" | "cdn" {
  const c = loadConfig();
  if (c.private_ranges.some((r) => inCidr(ip, r))) return "internal";
  for (const list of Object.values(c.cdn_ranges)) if (Array.isArray(list) && list.some((r) => inCidr(ip, r))) return "cdn";
  return "external";
}

// ---------- query building ----------
function matchClause(p: Profile): any {
  const must: any[] = [], should: any[] = [], must_not: any[] = [];
  if (p.match.any_groups?.length) should.push({ terms: { "rule.groups": p.match.any_groups } });
  if (p.match.any_rule_ids?.length) should.push({ terms: { "rule.id": p.match.any_rule_ids } });
  if (p.match.all_groups?.length) for (const g of p.match.all_groups) must.push({ term: { "rule.groups": g } });
  if (p.match.exclude_groups?.length) must_not.push({ terms: { "rule.groups": p.match.exclude_groups } });
  if (p.match.exclude_rule_ids?.length) must_not.push({ terms: { "rule.id": p.match.exclude_rule_ids } });
  if (p.match.min_level != null) must.push({ range: { "rule.level": { gte: p.match.min_level } } });
  return { bool: { must, should, must_not, minimum_should_match: should.length ? 1 : 0 } };
}
/** ip-typed fields accept CIDR terms; keyword fields (Wazuh maps data.srcip as keyword) get the CIDR expanded into dotted prefixes
 *  (/16 granularity below 16 bits, /24 granularity otherwise), so e.g. 104.16.0.0/13 → "104.16." … "104.23." and never a bare "104.". */
export function cidrPrefixes(cidr: string): string[] {
  if (cidr.includes(":")) return [];
  const [net, b] = cidr.split("/"); const bits = Number(b); const base = ip4(net); if (base == null) return [];
  const out: string[] = [];
  if (bits <= 8) { const n = 1 << (8 - bits); const start = (base >>> 24) & 255; for (let i = 0; i < n; i++) out.push(`${start + i}.`); }
  else if (bits >= 24) { const o = net.split("."); out.push(o.slice(0, 3).join(".") + "."); }
  else if (bits >= 16) { const start = (base >>> 8) & 0xffffff; const n = 1 << (24 - bits); for (let i = 0; i < n; i++) { const v = start + i; out.push(`${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}.`); } }
  else { const start = (base >>> 16) & 0xffff; const n = 1 << (16 - bits); for (let i = 0; i < n; i++) { const v = start + i; out.push(`${(v >>> 8) & 255}.${v & 255}.`); } }
  return out;
}
function rangeClauses(field: string, isIp: boolean, cidrs: string[]): any[] {
  if (isIp) return cidrs.filter((c) => !c.includes(":")).map((c) => ({ term: { [field]: c } }));
  const prefixes = new Set<string>(); for (const c of cidrs) for (const pre of cidrPrefixes(c)) prefixes.add(pre);
  return [...prefixes].map((pre) => ({ prefix: { [field]: pre } }));
}

const mappingCache = new Map<string, Map<string, string>>();
async function fieldTypes(ix: IndexerClient, key: string, fields: string[]): Promise<Map<string, string>> {
  const cached = mappingCache.get(key); if (cached) return cached;
  const m = new Map<string, string>();
  try {
    const r: any = await ix.request("GET", `/wazuh-alerts-*/_mapping/field/${encodeURIComponent(fields.join(","))}?ignore_unavailable=true`);
    for (const idx of Object.values<any>(r)) for (const [f, v] of Object.entries<any>(idx.mappings ?? {})) { const t = Object.values<any>(v.mapping ?? {})[0]?.type; if (t && !m.has(f)) m.set(f, t); }
  } catch { /* unknown → keyword approximations */ }
  mappingCache.set(key, m); setTimeout(() => mappingCache.delete(key), 10 * 60_000).unref?.();
  return m;
}

// ---------- result types ----------
export interface CountryRow { name: string; iso2: string | null; name_ja: string; lat: number | null; lon: number | null; total: number; by_kind: Record<string, number>; blocked: number; top_ips: { ip: string; n: number }[]; targets: { host: string; n: number }[]; rules: { id: string; n: number }[] }
export interface AttackMap {
  window: string; generated_at: string; profiles: { id: string; name: string; kind: string; color: string; role: string; total: number; error?: string }[];
  kpi: { total: number; countries: number; targets: number; blocked: number; internal: number; cdn_unknown: number; no_geo: number };
  countries: CountryRow[]; targets: { host: string; total: number; by_kind: Record<string, number> }[];
  recent: { ts: string; country: string | null; iso2: string | null; ip: string; dst: string; kind: string; color: string; rule_id: string; what_ja: string; level: number }[];
  timeline: { t: string; n: number; by_kind: Record<string, number> }[];
}

const cache = new Map<string, { at: number; v: AttackMap }>();

export async function attackMap(ix: IndexerClient, cacheKey: string, window = "now-24h", ruleTitles: Record<string, string> = {}): Promise<AttackMap> {
  const ck = `${cacheKey}|${window}`; const hit = cache.get(ck); if (hit && Date.now() - hit.at < 30_000) return hit.v;
  const cfg = loadConfig();
  const allFields = [...new Set(cfg.profiles.flatMap((p) => p.src_fields))];
  const types = await fieldTypes(ix, cacheKey, allFields);
  const privateR = cfg.private_ranges, cdnR = Object.values(cfg.cdn_ranges).filter(Array.isArray).flat() as string[];
  const interval = /7d|30d/.test(window) ? "6h" : "1h";

  const perProfile = await Promise.all(cfg.profiles.map(async (p) => {
    // one query per profile; the src field is the first one that exists in the document (should/exists), aggs use the first mapped field
    const srcExists = { bool: { should: p.src_fields.map((f) => ({ exists: { field: f } })), minimum_should_match: 1 } };
    const primary = p.src_fields.find((f) => types.has(f)) ?? p.src_fields[p.src_fields.length - 1];
    const isIp = types.get(primary) === "ip";
    const excl = { bool: { should: [...rangeClauses(primary, isIp, privateR), ...rangeClauses(primary, isIp, cdnR)], minimum_should_match: 1 } };
    const body = {
      query: { bool: { filter: [{ range: { timestamp: { gte: window } } }, matchClause(p), srcExists] } },
      sort: [{ timestamp: "desc" }],
      _source: ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "GeoLocation.country_name", ...p.src_fields],
      aggs: {
        external: { filter: { bool: { must_not: [excl] } }, aggs: {
          countries: { terms: { field: "GeoLocation.country_name", size: 80 }, aggs: {
            centroid: { geo_centroid: { field: "GeoLocation.location" } },
            ips: { terms: { field: primary, size: 5 } },
            agents: { terms: { field: "agent.name", size: 10 } },
            rules: { terms: { field: "rule.id", size: 5 } },
          } },
          agents: { terms: { field: "agent.name", size: 30 } },
          timeline: { date_histogram: { field: "timestamp", fixed_interval: interval, min_doc_count: 0 } },
          nogeo: { missing: { field: "GeoLocation.country_name" } },
        } },
        internal: { filter: { bool: { should: rangeClauses(primary, isIp, privateR), minimum_should_match: 1 } } },
        cdn: { filter: { bool: { should: rangeClauses(primary, isIp, cdnR), minimum_should_match: 1 } } },
      },
    };
    try { const r = await ix.search("wazuh-alerts-*", body, 8); return { p, primary, r, error: null as string | null }; }
    catch (e: any) { return { p, primary, r: null, error: String(e.message).slice(0, 300) }; }
  }));

  const countries = new Map<string, CountryRow>();
  type TargetRow = { host: string; total: number; by_kind: Record<string, number> };
  type TlRow = { t: string; n: number; by_kind: Record<string, number> };
  const targets = new Map<string, TargetRow>();
  const timeline = new Map<string, TlRow>();
  const recent: AttackMap["recent"] = [];
  const kpi = { total: 0, countries: 0, targets: 0, blocked: 0, internal: 0, cdn_unknown: 0, no_geo: 0 };
  const profilesOut: AttackMap["profiles"] = [];

  for (const { p, primary, r, error } of perProfile) {
    const isBlock = p.role === "block";
    if (!r) { profilesOut.push({ id: p.id, name: p.name, kind: p.kind, color: p.color, role: p.role ?? "attack", total: 0, error: error ?? undefined }); continue; }
    const ext = r.aggregations.external;
    const total = ext.doc_count as number;
    profilesOut.push({ id: p.id, name: p.name, kind: p.kind, color: p.color, role: p.role ?? "attack", total });
    if (!isBlock) { kpi.total += total; kpi.internal += r.aggregations.internal.doc_count; kpi.cdn_unknown += r.aggregations.cdn.doc_count; kpi.no_geo += ext.nogeo.doc_count; }
    else kpi.blocked += total;
    for (const b of ext.countries.buckets) {
      const name = b.key as string; const meta = COUNTRIES[name];
      const row: CountryRow = countries.get(name) ?? { name, iso2: meta?.iso2 ?? null, name_ja: meta?.ja ?? name, lat: null, lon: null, total: 0, by_kind: {}, blocked: 0, top_ips: [], targets: [], rules: [] };
      if (row.lat == null) { const c = b.centroid?.location; if (c) { row.lat = c.lat; row.lon = c.lon; } else if (meta) { row.lat = meta.lat; row.lon = meta.lon; } }
      if (isBlock) row.blocked += b.doc_count;
      else {
        row.total += b.doc_count; row.by_kind[p.kind] = (row.by_kind[p.kind] ?? 0) + b.doc_count;
        for (const ib of b.ips.buckets) { const ex = row.top_ips.find((x) => x.ip === ib.key); if (ex) ex.n += ib.doc_count; else row.top_ips.push({ ip: ib.key, n: ib.doc_count }); }
        for (const ab of b.agents.buckets) { const ex = row.targets.find((x) => x.host === ab.key); if (ex) ex.n += ab.doc_count; else row.targets.push({ host: ab.key, n: ab.doc_count }); }
        for (const rb of b.rules.buckets) { const ex = row.rules.find((x) => x.id === String(rb.key)); if (ex) ex.n += rb.doc_count; else row.rules.push({ id: String(rb.key), n: rb.doc_count }); }
      }
      countries.set(name, row);
    }
    if (!isBlock) {
      for (const ab of ext.agents.buckets) { const t: TargetRow = targets.get(ab.key) ?? { host: ab.key, total: 0, by_kind: {} }; t.total += ab.doc_count; t.by_kind[p.kind] = (t.by_kind[p.kind] ?? 0) + ab.doc_count; targets.set(ab.key, t); }
      for (const tb of ext.timeline.buckets) { const t: TlRow = timeline.get(tb.key_as_string) ?? { t: tb.key_as_string, n: 0, by_kind: {} }; t.n += tb.doc_count; t.by_kind[p.kind] = (t.by_kind[p.kind] ?? 0) + tb.doc_count; timeline.set(tb.key_as_string, t); }
    }
    for (const h of r.hits.hits) {
      const s = h._source; const ip = p.src_fields.map((f) => f.split(".").reduce((o: any, k) => o?.[k], s)).find((v) => typeof v === "string") as string | undefined;
      if (!ip || classifyIp(ip) !== "external") continue;
      const cn = s.GeoLocation?.country_name ?? null; const meta = cn ? COUNTRIES[cn] : null;
      recent.push({ ts: s.timestamp, country: cn ? (meta?.ja ?? cn) : null, iso2: meta?.iso2 ?? null, ip, dst: s.agent?.name ?? "?", kind: p.kind, color: p.color, rule_id: String(s.rule?.id ?? ""), what_ja: ruleTitles[String(s.rule?.id)] ?? p.what_ja ?? s.rule?.description ?? "", level: Number(s.rule?.level ?? 0) });
    }
    void primary;
  }
  const countryRows = [...countries.values()].filter((c) => c.total > 0 || c.blocked > 0).map((c) => ({ ...c, top_ips: c.top_ips.sort((a, b) => b.n - a.n).slice(0, 5), targets: c.targets.sort((a, b) => b.n - a.n).slice(0, 10), rules: c.rules.sort((a, b) => b.n - a.n).slice(0, 5) })).sort((a, b) => b.total - a.total);
  kpi.countries = countryRows.filter((c) => c.total > 0).length; kpi.targets = targets.size;
  recent.sort((a, b) => (a.ts < b.ts ? 1 : -1));
  const out: AttackMap = { window, generated_at: new Date().toISOString(), profiles: profilesOut, kpi, countries: countryRows, targets: [...targets.values()].sort((a, b) => b.total - a.total), recent: recent.slice(0, 40), timeline: [...timeline.values()].sort((a, b) => (a.t < b.t ? -1 : 1)) };
  cache.set(ck, { at: Date.now(), v: out });
  return out;
}

/** セットアップ・ガイド用の診断（EDR-74 で使用）: プロファイルごとの件数と GeoLocation 付与率。 */
export async function probe(ix: IndexerClient, window = "now-24h"): Promise<any> {
  const cfg = loadConfig();
  const out: any[] = [];
  const types = await fieldTypes(ix, "probe", [...new Set(cfg.profiles.flatMap((p) => p.src_fields))]);
  const cidrs = [...cfg.private_ranges, ...(Object.values(cfg.cdn_ranges).filter(Array.isArray).flat() as string[])];
  for (const p of cfg.profiles) {
    const srcExists = { bool: { should: p.src_fields.map((f) => ({ exists: { field: f } })), minimum_should_match: 1 } };
    const primary = p.src_fields.find((f) => types.has(f)) ?? p.src_fields[p.src_fields.length - 1];
    const excl = { bool: { should: rangeClauses(primary, types.get(primary) === "ip", cidrs), minimum_should_match: 1 } };
    const body = { track_total_hits: true, query: { bool: { filter: [{ range: { timestamp: { gte: window } } }, matchClause(p), srcExists], must_not: [excl] } }, aggs: { geo: { filter: { exists: { field: "GeoLocation.country_name" } } }, agents: { terms: { field: "agent.name", size: 10 } } } };
    try { const r = await ix.search("wazuh-alerts-*", body, 0); out.push({ id: p.id, name: p.name, total: r.hits.total.value ?? r.hits.total, with_geo: r.aggregations.geo.doc_count, agents: r.aggregations.agents.buckets.map((b: any) => b.key) }); }
    catch (e: any) { out.push({ id: p.id, name: p.name, error: String(e.message).slice(0, 200) }); }
  }
  return { window, profiles: out };
}

/** リプレイ（EDR-73）: 時間バケットごとの国別件数。24h → 1h、7d → 3h。countries は上位 40 か国。 */
export async function replay(ix: IndexerClient, cacheKey: string, window = "now-7d"): Promise<{ window: string; interval: string; frames: { t: string; total: number; countries: Record<string, number>; kinds: Record<string, number> }[] }> {
  const cfg = loadConfig();
  const interval = /7d/.test(window) ? "3h" : /30d/.test(window) ? "12h" : "1h";
  const allFields = [...new Set(cfg.profiles.flatMap((p) => p.src_fields))];
  const types = await fieldTypes(ix, cacheKey, allFields);
  const cidrs = [...cfg.private_ranges, ...(Object.values(cfg.cdn_ranges).filter(Array.isArray).flat() as string[])];
  type Frame = { t: string; total: number; countries: Record<string, number>; kinds: Record<string, number> };
  const frames = new Map<string, Frame>();
  await Promise.all(cfg.profiles.filter((p) => p.role !== "block").map(async (p) => {
    const srcExists = { bool: { should: p.src_fields.map((f) => ({ exists: { field: f } })), minimum_should_match: 1 } };
    const primary = p.src_fields.find((f) => types.has(f)) ?? p.src_fields[p.src_fields.length - 1];
    const excl = { bool: { should: rangeClauses(primary, types.get(primary) === "ip", cidrs), minimum_should_match: 1 } };
    const body = { query: { bool: { filter: [{ range: { timestamp: { gte: window } } }, matchClause(p), srcExists], must_not: [excl] } },
      aggs: { t: { date_histogram: { field: "timestamp", fixed_interval: interval, min_doc_count: 0 }, aggs: { c: { terms: { field: "GeoLocation.country_name", size: 40 } } } } } };
    try {
      const r = await ix.search("wazuh-alerts-*", body, 0);
      for (const b of r.aggregations.t.buckets) {
        const f: Frame = frames.get(b.key_as_string) ?? { t: b.key_as_string, total: 0, countries: {}, kinds: {} };
        f.total += b.doc_count; f.kinds[p.kind] = (f.kinds[p.kind] ?? 0) + b.doc_count;
        for (const cb of b.c.buckets) f.countries[cb.key] = (f.countries[cb.key] ?? 0) + cb.doc_count;
        frames.set(b.key_as_string, f);
      }
    } catch { /* profile without data */ }
  }));
  return { window, interval, frames: [...frames.values()].sort((a, b) => (a.t < b.t ? -1 : 1)) };
}
