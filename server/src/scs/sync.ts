/**
 * EDR-175/176/177（SCS Phase 1）: 資産台帳・脆弱性台帳（重ね書き方式）・脅威情報フィードの取り込み。
 *
 * - 資産: MamorAI のホスト（Wazuh エージェントあり）と wazuh-states-inventory-system/hardware から作る。区分は OS から自動判定
 *   （人が変えたものは上書きしない）。Wazuh から消えた端末は removed_at を付けて残す。
 * - 脆弱性: wazuh-states-vulnerabilities-* のうち 14日 SLA の候補（Critical / High / 深刻度不明 / CVSS 7.0 以上）だけ行を作る。
 *   全件たどれたときだけ「今回無かった行」を適用済にする（途中で失敗したら何も解消しない）。
 * - 脅威情報: CISA KEV（JSON）、IPA 重要なセキュリティ情報（RSS）、JPCERT/CC 注意喚起（RSS）。タイトルの CVE 番号を使う。
 */
import type { Ctx } from "../api/context.js";
import { indexer } from "../api/context.js";
import * as K from "./classify.js";

const VULN_INDEX = "wazuh-states-vulnerabilities-*";
const now = () => new Date().toISOString();
const chunk = <T,>(a: T[], n: number) => { const out: T[][] = []; for (let i = 0; i < a.length; i += n) out.push(a.slice(i, i + n)); return out; };

export function discord(ctx: Ctx, text: string) {
  const url = ctx.cfg.DISCORD_WEBHOOK_URL;
  if (url) fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: text.slice(0, 1900) }) }).catch(() => {});
}

export async function scsEnabled(ctx: Ctx): Promise<boolean> {
  const r = await ctx.db("app_flags").where({ key: "scs_enabled" }).first().catch(() => null);
  return r?.value !== "0"; // 既定はオン（設定で切れる）
}
async function flag(ctx: Ctx, key: string): Promise<string | null> { return (await ctx.db("app_flags").where({ key }).first())?.value ?? null; }
async function setFlag(ctx: Ctx, key: string, value: string) {
  const ex = await ctx.db("app_flags").where({ key }).first();
  if (ex) await ctx.db("app_flags").where({ key }).update({ value }); else await ctx.db("app_flags").insert({ key, value });
}

// ---------------------------------------------------------------- 資産台帳
export async function syncAssets(ctx: Ctx): Promise<{ upserted: number; removed: number }> {
  const { db } = ctx;
  const hosts = await db("hosts").whereNotNull("agent_id").whereNot("agent_id", "");
  const roles = Object.fromEntries((await db("node_roles")).map((r: any) => [r.agent_name, r.role]));
  const inst = new Map<number, { sys: Map<string, any>; hw: Map<string, any> }>();
  for (const wid of [...new Set(hosts.map((h: any) => h.wazuh_instance_id).filter(Boolean))] as number[]) {
    const sys = new Map<string, any>(), hw = new Map<string, any>();
    try {
      const ix = await indexer(ctx, wid);
      for (const h of (await ix.search("wazuh-states-inventory-system-*", { query: { match_all: {} } }, 500))?.hits?.hits ?? []) sys.set(String(h._source?.agent?.id), h._source);
      for (const h of (await ix.search("wazuh-states-inventory-hardware-*", { query: { match_all: {} } }, 500))?.hits?.hits ?? []) hw.set(String(h._source?.agent?.id), h._source);
    } catch (e: any) { ctx.log.warn({ err: e.message }, "scs: inventory read failed"); }
    inst.set(wid, { sys, hw });
  }
  const existing = await db("scs_assets").where({ source: "wazuh" });
  const byKey = new Map(existing.map((a: any) => [`${a.wazuh_instance_id}|${a.agent_id}`, a]));
  const seen = new Set<string>(); let upserted = 0;
  for (const h of hosts) {
    const wid = h.wazuh_instance_id ?? null; const key = `${wid}|${h.agent_id}`; seen.add(key);
    const s = inst.get(wid)?.sys.get(String(h.agent_id))?.host ?? null; const hw = inst.get(wid)?.hw.get(String(h.agent_id))?.host ?? null;
    const osName = s?.os?.name ?? h.agent_os ?? null; const osVer = s?.os?.version ?? null;
    const cur = byKey.get(key);
    const cat = cur?.category_source === "manual" ? cur.category : K.assetCategory(osName, s?.os?.platform ?? h.os_family, roles[h.name] ?? null);
    const row = { host_id: h.id, name: h.name, category: cat, os_name: osName, os_version: osVer, serial: hw?.serial_number && !/^\s*$/.test(hw.serial_number) ? String(hw.serial_number).slice(0, 128) : cur?.serial ?? null, last_seen_at: now(), removed_at: null, updated_at: now() };
    if (cur) await db("scs_assets").where({ id: cur.id }).update(row);
    else await db("scs_assets").insert({ ...row, source: "wazuh", wazuh_instance_id: wid, agent_id: String(h.agent_id), category_source: "auto" });
    upserted++;
  }
  let removed = 0;
  for (const a of existing) if (!seen.has(`${a.wazuh_instance_id}|${a.agent_id}`) && !a.removed_at) { await db("scs_assets").where({ id: a.id }).update({ removed_at: now(), updated_at: now() }); removed++; }
  return { upserted, removed };
}

// ---------------------------------------------------------------- 脅威情報フィード
const decode = (s: string) => s.replace(/<!\[CDATA\[|\]\]>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').trim();
const CVE_RE = /CVE-\d{4}-\d{4,7}/g;
function rssItems(xml: string): { title: string; link: string; date: string | null }[] {
  return [...xml.matchAll(/<item[^>]*>([\s\S]*?)<\/item>/g)].map((m) => {
    const g = (k: string) => decode((m[1].match(new RegExp(`<${k}>([\\s\\S]*?)</${k}>`)) ?? [])[1] ?? "");
    return { title: g("title"), link: g("link"), date: g("dc:date") || g("pubDate") || null };
  });
}
async function fetchText(url: string): Promise<string> {
  const r = await fetch(url, { signal: AbortSignal.timeout(60_000), headers: { "User-Agent": "MamorAI-SCS-feed" } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.text();
}
type Intel = { cve_id: string; source: string; listed_at: string | null; url: string | null; title: string | null };
async function storeIntel(ctx: Ctx, source: string, rows: Intel[], started: string, err?: string) {
  const { db } = ctx; let added = 0;
  for (const c of chunk(rows, 200)) {
    const before = Number((await db("scs_threat_intel").where({ source }).whereIn("cve_id", c.map((x) => x.cve_id)).count({ n: "*" }).first())?.n ?? 0);
    await db("scs_threat_intel").insert(c.map((x) => ({ ...x, fetched_at: now() }))).onConflict(["cve_id", "source"]).ignore();
    const after = Number((await db("scs_threat_intel").where({ source }).whereIn("cve_id", c.map((x) => x.cve_id)).count({ n: "*" }).first())?.n ?? 0);
    added += after - before;
  }
  await db("scs_feed_runs").insert({ source, started_at: started, ok: !err, fetched: rows.length, added, error: err ?? null });
  return added;
}
export async function syncFeeds(ctx: Ctx): Promise<Record<string, { ok: boolean; fetched: number; added: number; error?: string }>> {
  const out: Record<string, { ok: boolean; fetched: number; added: number; error?: string }> = {};
  const run = async (source: string, get: () => Promise<Intel[]>) => {
    const started = now();
    try { const rows = await get(); const uniq = [...new Map(rows.map((r) => [r.cve_id, r])).values()]; const added = await storeIntel(ctx, source, uniq, started); out[source] = { ok: true, fetched: uniq.length, added }; }
    catch (e: any) { await storeIntel(ctx, source, [], started, String(e?.message ?? e)); out[source] = { ok: false, fetched: 0, added: 0, error: String(e?.message ?? e) }; }
  };
  await run("CISA_KEV", async () => {
    const j = JSON.parse(await fetchText("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"));
    return (j.vulnerabilities ?? []).filter((v: any) => /^CVE-\d{4}-\d+$/.test(v.cveID)).map((v: any) => ({ cve_id: v.cveID, source: "CISA_KEV", listed_at: v.dateAdded ?? null, url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${v.cveID}`, title: String(v.vulnerabilityName ?? "").slice(0, 300) || null }));
  });
  // IPA / JPCERT: 項目のタイトルに CVE 番号が入っている（ページ本文はサイドバーに無関係な CVE も載るので見ない）
  const fromItems = (source: string, items: { title: string; link: string; date: string | null }[]) => {
    const rows: Intel[] = [];
    for (const it of [...items].sort((a, b) => String(a.date).localeCompare(String(b.date)))) for (const cve of new Set(it.title.match(CVE_RE) ?? [])) if (!rows.find((r) => r.cve_id === cve)) rows.push({ cve_id: cve, source, listed_at: it.date ? it.date.slice(0, 10) : null, url: it.link || null, title: it.title.slice(0, 300) });
    return rows;
  };
  await run("IPA_ALERT", async () => {
    const items = rssItems(await fetchText("https://www.ipa.go.jp/security/alert-rss.rdf"));
    // 一覧ページ（過去分）も見る: <a href="...security-alert/YYYY/....html">タイトル（CVE-...）</a>
    try {
      const html = await fetchText("https://www.ipa.go.jp/security/security-alert/index.html");
      for (const m of html.matchAll(/<a[^>]+href="([^"]*security-alert\/(\d{4})\/[^"]+\.html)"[^>]*>([\s\S]*?)<\/a>/g)) {
        const title = decode(m[3].replace(/<[^>]+>/g, "")); if (!CVE_RE.test(title)) continue; CVE_RE.lastIndex = 0;
        const d = m[1].match(/(\d{8})/)?.[1]; items.push({ title, link: new URL(m[1], "https://www.ipa.go.jp").toString(), date: d ? `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}` : `${m[2]}-01-01` });
      }
    } catch { /* RSS だけでも続ける */ }
    return fromItems("IPA_ALERT", items);
  });
  await run("JPCERT_AT", async () => fromItems("JPCERT_AT", rssItems(await fetchText("https://www.jpcert.or.jp/rss/jpcert.rdf")).filter((i) => /\/at\//.test(i.link))));
  await setFlag(ctx, "scs_feeds_at", now());
  return out;
}

// ---------------------------------------------------------------- 脆弱性台帳
const num = (x: any) => (x === null || x === undefined || x === "" || Number.isNaN(Number(x)) ? null : Number(x));
export interface VulnSyncResult { scanned: number; created: number; updated: number; resolved: number; reopened: number; complete: boolean; newP0: string[] }

export async function syncVulns(ctx: Ctx): Promise<VulnSyncResult> {
  const { db } = ctx;
  const res: VulnSyncResult = { scanned: 0, created: 0, updated: 0, resolved: 0, reopened: 0, complete: true, newP0: [] };
  const exploited = new Set((await db("scs_threat_intel").distinct("cve_id")).map((r: any) => r.cve_id));
  const assets = await db("scs_assets").where({ source: "wazuh" }).whereNull("removed_at");
  const byInst = new Map<number, any[]>(); for (const a of assets) { if (!a.wazuh_instance_id) continue; byInst.set(a.wazuh_instance_id, [...(byInst.get(a.wazuh_instance_id) ?? []), a]); }
  for (const [wid, list] of byInst) {
    const assetByAgent = new Map(list.map((a: any) => [String(a.agent_id), a]));
    const ids = list.map((a: any) => a.id);
    const existing = await db("scs_vulns").whereIn("asset_id", ids);
    const byKey = new Map(existing.map((v: any) => [`${v.asset_id}|${v.cve_id}|${v.package_name}`, v]));
    const seen = new Set<number>(); const inserts: any[] = []; const hist: any[] = []; const pendingKeys = new Set<string>();
    let ix; try { ix = await indexer(ctx, wid); } catch (e: any) { ctx.log.warn({ err: e.message }, "scs: indexer unavailable"); res.complete = false; continue; }
    const query = { bool: { should: [{ terms: { "vulnerability.severity": ["Critical", "High", "-", ""] } }, { range: { "vulnerability.score.base": { gte: 7 } } }, { bool: { must_not: { exists: { field: "vulnerability.severity" } } } }], minimum_should_match: 1 } };
    let after: any[] | undefined; let total = -1; let got = 0;
    try {
      for (let page = 0; page < 400; page++) {
        const r = await ix.search(VULN_INDEX, { query, sort: [{ "agent.id": "asc" }, { "vulnerability.id": "asc" }, { "package.name": "asc" }, { "package.version": "asc" }], track_total_hits: true, ...(after ? { search_after: after } : {}),
          _source: ["agent.id", "package.name", "package.version", "package.type", "vulnerability.id", "vulnerability.severity", "vulnerability.score.base", "vulnerability.score.version", "vulnerability.published_at", "vulnerability.detected_at"] }, 500);
        if (total < 0) total = Number(r?.hits?.total?.value ?? 0);
        const hits = r?.hits?.hits ?? []; if (!hits.length) break;
        for (const h of hits) {
          got++; const s = h._source ?? {}; const a = assetByAgent.get(String(s.agent?.id)); if (!a) continue;
          const cve = String(s.vulnerability?.id ?? ""); const pkg = String(s.package?.name ?? "").slice(0, 255); if (!/^CVE-|^GHSA-/.test(cve) || !pkg) continue;
          const sev = s.vulnerability?.severity ?? null; const cvss = num(s.vulnerability?.score?.base);
          if (!K.isCandidate(sev, cvss)) continue;
          res.scanned++;
          const key = `${a.id}|${cve}|${pkg}`; const cur = byKey.get(key);
          const cls: K.TargetClass = cur?.target_class_source === "manual" ? cur.target_class : K.targetClass(a.category, pkg, s.package?.type);
          const sla = K.slaTarget(cls, sev, cvss); const ex = exploited.has(cve); const pr = K.priority(sla, ex, cls, cvss);
          const detected = s.vulnerability?.detected_at ?? cur?.detected_at ?? now(); const published = s.vulnerability?.published_at ?? null;
          const fix = cur?.fix_released_source === "manual" ? cur.fix_released_at : K.defaultFixReleased(published, detected);
          const due = K.dueAt(pr, sla, fix, detected, cur?.plan_due_at ?? null);
          const fields = { package_version: s.package?.version ? String(s.package.version).slice(0, 128) : null, target_class: cls, severity_vendor: sev ? String(sev).slice(0, 16) : null, cvss_base: cvss, cvss_version: s.vulnerability?.score?.version ? String(s.vulnerability.score.version).slice(0, 8) : null, sla_target: sla, exploited: ex, priority: pr, published_at: published, detected_at: detected, fix_released_at: fix, due_at: due };
          if (!cur) {
            if (pendingKeys.has(key)) continue; // 同じソフトが複数の版で入っている（1 行にまとめる）
            pendingKeys.add(key);
            inserts.push({ asset_id: a.id, cve_id: cve, package_name: pkg, ...fields, status: "未対応", last_seen_at: now(), created_at: now(), updated_at: now() });
            if (pr === "P0" && existing.length) res.newP0.push(cve); // 最初の取り込みでは通知しない（既存分の一斉通知を避ける）
            continue;
          }
          if (seen.has(cur.id)) continue; // 同じ行の別の版（最初の 1 件で判定済み）
          seen.add(cur.id);
          const upd: Record<string, any> = {};
          for (const [k, v] of Object.entries(fields)) { const c = (cur as any)[k]; const same = typeof v === "boolean" ? !!c === v : (c ?? null) === (v ?? null) || (typeof v === "number" && Number(c) === v); if (!same) upd[k] = v; }
          if (cur.resolved_at) { upd.resolved_at = null; upd.status = "未対応"; res.reopened++; hist.push({ vuln_id: cur.id, changed_by: "system", field: "status", from_value: cur.status, to_value: "未対応", note: "Wazuh で再び検知された" }); }
          if (upd.priority && upd.priority !== cur.priority) { hist.push({ vuln_id: cur.id, changed_by: "system", field: "priority", from_value: cur.priority, to_value: upd.priority, note: upd.priority === "P0" ? "悪用情報（KEV / IPA / JPCERT）に掲載" : null }); if (upd.priority === "P0" && !cur.resolved_at) res.newP0.push(cve); }
          if (upd.due_at !== undefined && cur.due_at) hist.push({ vuln_id: cur.id, changed_by: "system", field: "due_at", from_value: cur.due_at, to_value: upd.due_at, note: null });
          if (Object.keys(upd).length) { await db("scs_vulns").where({ id: cur.id }).update({ ...upd, updated_at: now() }); res.updated++; }
        }
        after = hits[hits.length - 1].sort; if (hits.length < 500) break;
      }
    } catch (e: any) { ctx.log.warn({ err: e.message }, "scs: vulnerability read failed"); res.complete = false; }
    const complete = res.complete && total >= 0 && got >= total;
    // 新しい行: まとめて入れ、履歴に「台帳に登録」を残す
    for (const c of chunk(inserts, 200)) {
      await db.transaction(async (trx) => {
        for (const row of c) {
          const [id] = await trx("scs_vulns").insert(row).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
          seen.add(id); hist.push({ vuln_id: id, changed_by: "system", field: "status", from_value: null, to_value: "未対応", note: `台帳に登録（${K.CLASS_JA[row.target_class as K.TargetClass]}・${row.priority}${row.due_at ? `・期限 ${String(row.due_at).slice(0, 10)}` : ""}）` });
        }
      });
      res.created += c.length;
    }
    // 今回 Wazuh に無かった行 = 解消（全件たどれたときだけ）
    if (complete) {
      const gone = existing.filter((v: any) => !seen.has(v.id) && !v.resolved_at);
      for (const v of gone) {
        await db("scs_vulns").where({ id: v.id }).update({ status: "適用済", resolved_at: now(), updated_at: now() });
        hist.push({ vuln_id: v.id, changed_by: "system", field: "status", from_value: v.status, to_value: "適用済", note: "Wazuh の検知が消えた（パッチ適用または該当ソフトの削除）" });
        res.resolved++;
      }
    } else res.complete = false;
    for (const c of chunk([...seen], 400)) await db("scs_vulns").whereIn("id", c).update({ last_seen_at: now() });
    for (const c of chunk(hist, 200)) await db("scs_vuln_history").insert(c.map((h) => ({ ...h, changed_at: now() })));
  }
  await setFlag(ctx, "scs_vulns_at", now());
  return res;
}

/** 期限と優先度の再計算（フィードを取り込んだあと・人が起点日や区分を変えたあと）。対象の行だけ */
export async function recompute(ctx: Ctx, where: (q: any) => any, by = "system"): Promise<number> {
  const { db } = ctx;
  const exploited = new Set((await db("scs_threat_intel").distinct("cve_id")).map((r: any) => r.cve_id));
  const rows = await where(db("scs_vulns").whereNull("resolved_at"));
  let n = 0;
  for (const v of rows) {
    const cvss = num(v.cvss_base); const sla = K.slaTarget(v.target_class, v.severity_vendor, cvss); const ex = exploited.has(v.cve_id);
    const pr = K.priority(sla, ex, v.target_class, cvss); const due = K.dueAt(pr, sla, v.fix_released_at, v.detected_at, v.plan_due_at);
    if (!!v.sla_target !== sla || !!v.exploited !== ex || v.priority !== pr || (v.due_at ?? null) !== due) {
      await db("scs_vulns").where({ id: v.id }).update({ sla_target: sla, exploited: ex, priority: pr, due_at: due, updated_at: now() });
      if (v.priority !== pr) await db("scs_vuln_history").insert({ vuln_id: v.id, changed_by: by, field: "priority", from_value: v.priority, to_value: pr, note: null, changed_at: now() });
      n++;
    }
  }
  return n;
}

// ---------------------------------------------------------------- 通知
async function notifyP0(ctx: Ctx, cves: string[]) {
  const { db } = ctx;
  for (const cve of [...new Set(cves)].slice(0, 10)) {
    const rows = await db("scs_vulns as v").join("scs_assets as a", "a.id", "v.asset_id").where("v.cve_id", cve).whereNull("v.resolved_at").select("v.*", "a.name as asset_name");
    if (!rows.length) continue;
    const intel = await db("scs_threat_intel").where({ cve_id: cve });
    const due = rows.map((r: any) => r.due_at).filter(Boolean).sort()[0];
    const pk = [...new Set(rows.map((r: any) => `${r.package_name}${r.package_version ? " " + r.package_version : ""}`))].slice(0, 3).join(", ");
    discord(ctx, `🔴 [P0] ${cve}（${pk}）\n対象 ${rows.length} 台: ${[...new Set(rows.map((r: any) => r.asset_name))].slice(0, 8).join(", ")}\n期限 ${due ? jstDate(due) : "-"}（修正版のリリース + 14 日）・掲載: ${intel.map((i: any) => ({ CISA_KEV: "CISA KEV", IPA_ALERT: "IPA", JPCERT_AT: "JPCERT/CC" } as any)[i.source] ?? i.source).join(" / ")}\nMamorAI › SCS 評価制度 › 脆弱性台帳 で確認し、パッチ適用を依頼してください`);
  }
}
export const jstDate = (iso: string) => { const d = new Date(Date.parse(iso) + 9 * 3600_000); return `${d.getUTCMonth() + 1}/${d.getUTCDate()}`; };

/** 毎朝 9 時（JST）以降の最初の実行で 1 回: 期限 7 日以内・超過の P0 をまとめて通知 */
async function dailyReminder(ctx: Ctx) {
  const jstNow = new Date(Date.now() + 9 * 3600_000); const today = jstNow.toISOString().slice(0, 10);
  if (jstNow.getUTCHours() < 9 || (await flag(ctx, "scs_reminder_date")) === today) return;
  await setFlag(ctx, "scs_reminder_date", today);
  const lim = new Date(Date.now() + 7 * 86_400_000).toISOString();
  const rows = await ctx.db("scs_vulns").where({ priority: "P0" }).whereNull("resolved_at").whereNotIn("status", ["対象外", "適用済"]).where("due_at", "<=", lim).select("cve_id", "due_at");
  if (!rows.length) return;
  const by = new Map<string, { n: number; due: string }>(); for (const r of rows) { const c = by.get(r.cve_id); by.set(r.cve_id, { n: (c?.n ?? 0) + 1, due: c && c.due < r.due_at ? c.due : r.due_at }); }
  const lines = [...by.entries()].sort((a, b) => a[1].due.localeCompare(b[1].due)).slice(0, 15).map(([cve, x]) => `・${cve} 残り ${x.n} 台・期限 ${jstDate(x.due)}${Date.parse(x.due) < Date.now() ? "（超過）" : ""}`);
  discord(ctx, `⏰ SCS: 期限が近い P0（悪用確認あり）の脆弱性\n${lines.join("\n")}`);
}

// ---------------------------------------------------------------- 定期実行（ホストスキャンの tick から呼ぶ）
let running = false; let lastVuln = 0; let lastFeed = 0; let lastCriteria = 0;
export async function runAll(ctx: Ctx, opts: { feeds?: boolean } = {}): Promise<{ assets: any; feeds?: any; sca?: any; vulns: VulnSyncResult; recomputed: number }> {
  const assets = await syncAssets(ctx);
  let feeds; let recomputed = 0;
  if (opts.feeds) { feeds = await syncFeeds(ctx); lastFeed = Date.now(); recomputed = await recompute(ctx, (q) => q); }
  // EDR-178: SCA の結果も 1 日 1 回（脅威情報と同じタイミング）。失敗しても脆弱性の取り込みは続ける
  let sca;
  if (opts.feeds) { try { sca = await (await import("./sca.js")).syncSca(ctx); await setFlag(ctx, "scs_sca_at", now()); } catch (e: any) { ctx.log.warn({ err: e.message }, "scs: sca sync failed"); } }
  const vulns = await syncVulns(ctx);
  lastVuln = Date.now();
  if (vulns.newP0.length) await notifyP0(ctx, vulns.newP0);
  ctx.log.info({ assets, sca, vulns: { ...vulns, newP0: vulns.newP0.length }, recomputed }, "scs: sync done");
  return { assets, feeds, sca, vulns, recomputed };
}
export async function tick(ctx: Ctx): Promise<void> {
  if (running || !(await scsEnabled(ctx))) return;
  // EDR-174: 評価基準マスタが未取り込みなら IPA から 1 回取り込む（失敗時は 6 時間後に再試行）
  if (Date.now() - lastCriteria > 6 * 3600_000) {
    const c = await import("./criteria.js");
    if (!(await c.currentVersion(ctx))) {
      lastCriteria = Date.now();
      try { const r = await c.importCriteria(ctx); ctx.log.info(r, "scs: criteria imported"); }
      catch (e: any) { ctx.log.warn({ err: e.message }, "scs: criteria import failed"); }
    } else lastCriteria = Date.now();
  }
  const feedsAt = lastFeed || Date.parse((await flag(ctx, "scs_feeds_at")) ?? "") || 0;
  const vulnsAt = lastVuln || Date.parse((await flag(ctx, "scs_vulns_at")) ?? "") || 0;
  const needFeeds = Date.now() - feedsAt > 24 * 3600_000; const needVulns = Date.now() - vulnsAt > 3600_000;
  if (!needFeeds && !needVulns) { await dailyReminder(ctx).catch(() => {}); return; }
  running = true;
  // 失敗しても次の試行は通常の間隔のあと（30 秒ごとの tick で indexer や外部サイトを叩き続けない）
  lastVuln = Date.now(); if (needFeeds) lastFeed = Date.now();
  try { await runAll(ctx, { feeds: needFeeds }); await dailyReminder(ctx); }
  catch (e: any) { ctx.log.warn({ err: e.message }, "scs: sync failed"); }
  finally { running = false; }
}
export function isRunning() { return running; }
