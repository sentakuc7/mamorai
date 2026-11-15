/**
 * EDR-175/176/177（SCS Phase 1）API
 *   GET   /scs/summary                     ダッシュボードの数字（viewer）
 *   GET   /scs/vulns?tab=&q=               脆弱性台帳（CVE ごとにまとめた一覧）（viewer）
 *   GET   /scs/vulns/cve/:cve              CVE の詳細（端末・脅威情報・履歴）（viewer）
 *   PATCH /scs/vulns/:id                   状態・計画・緩和策・対象外の理由（operator。必須入力を確認して履歴に残す）
 *   PATCH /scs/vulns/:id/basis             期限の起点日と根拠（operator）
 *   PUT   /scs/packages/class              パッケージ名ごとの対象区分を決める（「要判定」の解消）（operator）
 *   POST  /scs/vulns/cve/:cve/request-patch Sidekick にパッチ適用を依頼（承認カードは Sidekick が出す）（operator）
 *   GET   /scs/assets / POST / PATCH /:id / DELETE /:id   資産台帳（手入力の機器を含む）
 *   GET   /scs/feeds                       脅威情報フィードの取り込み履歴（viewer）
 *   POST  /scs/sync                        今すぐ取り込む（operator）
 *   GET/PUT /scs/settings                  SCS 機能のオン / オフ（admin）
 */
import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import type { Ctx } from "./context.js";
import { requireRole } from "../auth/index.js";
import * as K from "../scs/classify.js";

const wrap = (fn: (req: Request, res: Response) => Promise<unknown>) => (req: Request, res: Response, next: NextFunction) => { fn(req, res).catch(next); };
const now = () => new Date().toISOString();
const bad = (res: Response, msg: string, code = 400) => res.status(code).json({ error: msg });
const SOURCE_JA: Record<string, string> = { CISA_KEV: "CISA KEV", IPA_ALERT: "IPA", JPCERT_AT: "JPCERT/CC", EUVD: "EUVD" };

export function scsRouter(ctx: Ctx): Router {
  const r = Router();
  const { db, audit } = ctx;
  const who = (req: Request) => String((req.user as any)?.name ?? (req.user as any)?.email ?? `user#${req.user?.id}`).slice(0, 64);
  const open = (q: any) => q.whereNull("v.resolved_at").whereNotIn("v.status", ["適用済", "対象外"]);

  r.get("/scs/summary", requireRole("viewer"), wrap(async (_req, res) => {
    const { scsEnabled } = await import("../scs/sync.js");
    const t = now(); const in7 = new Date(Date.now() + 7 * 86_400_000).toISOString(); const d90 = new Date(Date.now() - 90 * 86_400_000).toISOString();
    const cnt = async (q: any) => Number((await q.count({ n: "*" }).first())?.n ?? 0);
    const base = () => open(db("scs_vulns as v")).where("v.sla_target", true);
    const overdue = await cnt(base().where("v.due_at", "<", t));
    const overdueP0 = await cnt(base().where("v.due_at", "<", t).where("v.priority", "P0"));
    const due7 = await cnt(base().where("v.due_at", ">=", t).where("v.due_at", "<=", in7));
    const nextDue = (await base().where("v.due_at", ">=", t).min({ d: "v.due_at" }).first())?.d ?? null;
    const p0 = await cnt(open(db("scs_vulns as v")).where("v.priority", "P0"));
    const undetermined = Number((await db("scs_vulns").whereNull("resolved_at").where("target_class", "undetermined").countDistinct({ n: "package_name" }).first())?.n ?? 0);
    // 遵守率: 直近 90 日に期限が来たもの（14日対象）のうち、期限内に解消（適用済）したもの
    // 取り込んだ時点ですでに期限を過ぎていたもの（MamorAI が追う前からの持ち越し）は遵守率に入れず、別に数える
    const came = (await db("scs_vulns").where("sla_target", true).where("due_at", ">=", d90).where("due_at", "<", t).select("due_at", "resolved_at", "status", "created_at")).filter((v: any) => v.created_at <= v.due_at);
    const ok = came.filter((v: any) => v.resolved_at && v.resolved_at <= v.due_at).length;
    const backlog = Number((await open(db("scs_vulns as v")).where("v.sla_target", true).whereRaw("v.created_at > v.due_at").count({ n: "*" }).first())?.n ?? 0);
    const openTotal = await cnt(open(db("scs_vulns as v")).where("v.sla_target", true));
    const cveOpen = Number((await open(db("scs_vulns as v")).where("v.sla_target", true).countDistinct({ n: "v.cve_id" }).first())?.n ?? 0);
    const assets = await db("scs_assets").whereNull("removed_at").where({ in_scope: true }).select("category").count({ n: "*" }).groupBy("category");
    const feeds = await db("scs_feed_runs").whereIn("id", db("scs_feed_runs").max("id").groupBy("source")).orderBy("source");
    const intel = Object.fromEntries((await db("scs_threat_intel").select("source").count({ n: "*" }).groupBy("source")).map((x: any) => [x.source, Number(x.n)]));
    const flags = Object.fromEntries((await db("app_flags").whereIn("key", ["scs_vulns_at", "scs_feeds_at"])).map((f: any) => [f.key, f.value]));
    res.json({
      enabled: await scsEnabled(ctx),
      sla: { compliance: came.length ? Math.round((ok / came.length) * 1000) / 10 : null, came: came.length, in_time: ok, overdue, overdue_p0: overdueP0, due7, next_due: nextDue, open: openTotal, open_cves: cveOpen, p0_open: p0, undetermined_packages: undetermined, backlog },
      assets: Object.fromEntries(assets.map((a: any) => [a.category, Number(a.n)])),
      feeds: feeds.map((f: any) => ({ source: f.source, label: SOURCE_JA[f.source] ?? f.source, ok: !!f.ok, at: f.started_at, fetched: f.fetched, added: f.added, error: f.error, total: intel[f.source] ?? 0 })),
      synced_at: flags.scs_vulns_at ?? null, feeds_at: flags.scs_feeds_at ?? null,
    });
  }));

  // ---- 脆弱性台帳（CVE ごと）----
  r.get("/scs/vulns", requireRole("viewer"), wrap(async (req, res) => {
    const q = z.object({ tab: z.enum(["open", "p0", "overdue", "plan", "mitigated", "excluded", "resolved", "undetermined", "all_open"]).default("open"), q: z.string().max(100).optional(), limit: z.coerce.number().min(1).max(500).default(200) }).parse(req.query);
    const t = now();
    let qb = db("scs_vulns as v").join("scs_assets as a", "a.id", "v.asset_id");
    if (q.tab === "resolved") qb = qb.whereNotNull("v.resolved_at").where("v.resolved_at", ">=", new Date(Date.now() - 90 * 86_400_000).toISOString());
    else if (q.tab === "excluded") qb = qb.whereNull("v.resolved_at").where("v.status", "対象外");
    else if (q.tab === "undetermined") qb = qb.whereNull("v.resolved_at").where("v.target_class", "undetermined");
    else {
      qb = open(qb);
      if (q.tab === "open") qb = qb.where("v.sla_target", true);
      if (q.tab === "p0") qb = qb.where("v.priority", "P0");
      if (q.tab === "overdue") qb = qb.where("v.sla_target", true).where("v.due_at", "<", t);
      if (q.tab === "plan") qb = qb.where("v.status", "計画中");
      if (q.tab === "mitigated") qb = qb.where("v.status", "緩和策適用中");
    }
    if (q.q) { const like = `%${q.q}%`; qb = qb.where((w: any) => w.where("v.cve_id", "like", like).orWhere("v.package_name", "like", like).orWhere("a.name", "like", like)); }
    const rows = await qb.select("v.cve_id", "v.package_name", "v.package_version", "v.target_class", "v.severity_vendor", "v.cvss_base", "v.priority", "v.exploited", "v.due_at", "v.status", "v.resolved_at", "a.name as asset_name");
    const groups = new Map<string, any>();
    const prRank = { P0: 0, P1: 1, P2: 2, P3: 3 } as Record<string, number>;
    for (const v of rows) {
      const g = groups.get(v.cve_id) ?? { cve_id: v.cve_id, priority: "P3", packages: new Set<string>(), classes: new Set<string>(), severity: v.severity_vendor, cvss: v.cvss_base, exploited: false, due_at: null as string | null, hosts: new Set<string>(), statuses: {} as Record<string, number>, resolved_at: null as string | null };
      if (prRank[v.priority] < prRank[g.priority]) g.priority = v.priority;
      g.packages.add(`${v.package_name}${v.package_version ? " " + v.package_version : ""}`); g.classes.add(v.target_class); g.hosts.add(v.asset_name);
      if (v.cvss_base != null && (g.cvss == null || Number(v.cvss_base) > Number(g.cvss))) g.cvss = v.cvss_base;
      g.exploited = g.exploited || !!v.exploited;
      if (v.due_at && (!g.due_at || v.due_at < g.due_at)) g.due_at = v.due_at;
      if (v.resolved_at && (!g.resolved_at || v.resolved_at > g.resolved_at)) g.resolved_at = v.resolved_at;
      g.statuses[v.status] = (g.statuses[v.status] ?? 0) + 1;
      groups.set(v.cve_id, g);
    }
    const cves = [...groups.keys()];
    // 端末の「残 / 全」: 全 = 台帳にこの CVE がある端末（解消済みを含む）
    const totals = new Map<string, number>();
    for (const c of chunkArr(cves, 400)) for (const x of await db("scs_vulns").whereIn("cve_id", c).select("cve_id").countDistinct({ n: "asset_id" }).groupBy("cve_id") as any[]) totals.set(x.cve_id, Number(x.n));
    const intel = new Map<string, string[]>();
    for (const c of chunkArr(cves, 400)) for (const x of await db("scs_threat_intel").whereIn("cve_id", c)) intel.set(x.cve_id, [...(intel.get(x.cve_id) ?? []), SOURCE_JA[x.source] ?? x.source]);
    const items = [...groups.values()].map((g) => ({ ...g, packages: [...g.packages].slice(0, 3), package_count: g.packages.size, classes: [...g.classes].map((c) => ({ key: c, ja: K.CLASS_JA[c as K.TargetClass] ?? c })), hosts_open: g.hosts.size, hosts_total: totals.get(g.cve_id) ?? g.hosts.size, host_names: [...g.hosts].slice(0, 5), hosts: undefined, intel: intel.get(g.cve_id) ?? [] }))
      .sort((a, b) => (prRank[a.priority] - prRank[b.priority]) || String(a.due_at ?? "9999").localeCompare(String(b.due_at ?? "9999")) || (Number(b.cvss ?? 0) - Number(a.cvss ?? 0)));
    const counts: Record<string, number> = {};
    for (const tab of ["open", "p0", "overdue", "plan", "mitigated", "excluded", "undetermined"]) {
      let c = db("scs_vulns as v");
      if (tab === "excluded") c = c.whereNull("v.resolved_at").where("v.status", "対象外");
      else if (tab === "undetermined") c = c.whereNull("v.resolved_at").where("v.target_class", "undetermined");
      else { c = open(c); if (tab === "open") c = c.where("v.sla_target", true); if (tab === "p0") c = c.where("v.priority", "P0"); if (tab === "overdue") c = c.where("v.sla_target", true).where("v.due_at", "<", t); if (tab === "plan") c = c.where("v.status", "計画中"); if (tab === "mitigated") c = c.where("v.status", "緩和策適用中"); }
      counts[tab] = Number((await c.countDistinct({ n: "v.cve_id" }).first())?.n ?? 0);
    }
    counts.resolved = Number((await db("scs_vulns").whereNotNull("resolved_at").where("resolved_at", ">=", new Date(Date.now() - 90 * 86_400_000).toISOString()).countDistinct({ n: "cve_id" }).first())?.n ?? 0);
    res.json({ items: items.slice(0, q.limit), total: items.length, counts });
  }));

  r.get("/scs/vulns/cve/:cve", requireRole("viewer"), wrap(async (req, res) => {
    const cve = String(req.params.cve).slice(0, 32);
    const rows = await db("scs_vulns as v").join("scs_assets as a", "a.id", "v.asset_id").where("v.cve_id", cve).select("v.*", "a.name as asset_name", "a.category as asset_category", "a.host_id", "a.os_name").orderBy([{ column: "v.resolved_at", order: "desc" }, { column: "a.name" }]);
    if (!rows.length) return bad(res, "台帳にありません", 404);
    const intel = (await db("scs_threat_intel").where({ cve_id: cve })).map((x: any) => ({ ...x, label: SOURCE_JA[x.source] ?? x.source }));
    const history = await db("scs_vuln_history as h").join("scs_vulns as v", "v.id", "h.vuln_id").join("scs_assets as a", "a.id", "v.asset_id").where("v.cve_id", cve).select("h.*", "a.name as asset_name").orderBy("h.id", "desc").limit(200);
    // 説明・参照 URL は indexer から（台帳には持たない）
    let info: any = null;
    try {
      const a = await db("scs_assets").where({ id: rows[0].asset_id }).first();
      const { indexer } = await import("./context.js");
      const ix = await indexer(ctx, a.wazuh_instance_id);
      const h = (await ix.search("wazuh-states-vulnerabilities-*", { query: { term: { "vulnerability.id": cve } }, _source: ["vulnerability.description", "vulnerability.reference", "vulnerability.scanner.reference", "vulnerability.category"] }, 1))?.hits?.hits?.[0]?._source?.vulnerability;
      if (h) info = { description: h.description ?? null, reference: String(h.reference ?? "").split(/,\s*/).filter(Boolean).slice(0, 6), scanner_reference: h.scanner?.reference ?? null };
    } catch { /* 説明が無くても台帳は出す */ }
    res.json({ cve_id: cve, rows: rows.map((v: any) => ({ ...v, class_ja: K.CLASS_JA[v.target_class as K.TargetClass] ?? v.target_class, sla_target: !!v.sla_target, exploited: !!v.exploited })), intel, history, info, mitigations: K.MITIGATIONS, statuses: K.STATUSES });
  }));

  r.patch("/scs/vulns/:id", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = z.object({ status: z.enum(K.STATUSES).optional(), plan_due_at: z.string().datetime({ offset: true }).nullable().optional(), plan_reason: z.string().max(1000).nullable().optional(), mitigation_type: z.enum(K.MITIGATIONS).nullable().optional(), mitigation_note: z.string().max(2000).nullable().optional(), exclusion_reason: z.string().max(1000).nullable().optional(), note: z.string().max(1000).optional() }).parse(req.body);
    const cur = await db("scs_vulns").where({ id }).first(); if (!cur) return bad(res, "not found", 404);
    if (b.status === "適用済" && !cur.resolved_at) return bad(res, "「適用済」は Wazuh の検知が消えたときに自動で付きます。パッチを当てたら次の取り込み（毎時）を待つか、「今すぐ取り込む」を押してください");
    const merged = { mitigation_type: b.mitigation_type !== undefined ? b.mitigation_type : cur.mitigation_type, plan_due_at: b.plan_due_at !== undefined ? b.plan_due_at : cur.plan_due_at, plan_reason: b.plan_reason !== undefined ? b.plan_reason : cur.plan_reason, exclusion_reason: b.exclusion_reason !== undefined ? b.exclusion_reason : cur.exclusion_reason };
    const err = K.validateChange(cur, { status: b.status ?? cur.status, ...merged });
    if (err) return bad(res, err);
    const upd: Record<string, any> = { ...merged, ...(b.status ? { status: b.status } : {}), ...(b.mitigation_note !== undefined ? { mitigation_note: b.mitigation_note } : {}), updated_at: now() };
    // 期限は計画日に従う（14日対象で計画日が後ろなら延長として扱う）
    const due = K.dueAt(cur.priority, !!cur.sla_target, cur.fix_released_at, cur.detected_at, null);
    if (merged.plan_due_at && (!due || Date.parse(merged.plan_due_at) > Date.parse(due))) upd.due_at = merged.plan_due_at;
    else if (!merged.plan_due_at) upd.due_at = due;
    await db("scs_vulns").where({ id }).update(upd);
    const hist: any[] = [];
    for (const k of ["status", "due_at", "mitigation_type", "plan_due_at", "exclusion_reason"]) if (upd[k] !== undefined && (cur[k] ?? null) !== (upd[k] ?? null)) hist.push({ vuln_id: id, changed_by: who(req), field: k, from_value: cur[k] ?? null, to_value: upd[k] ?? null, note: k === "status" ? (b.note ?? merged.exclusion_reason ?? merged.plan_reason ?? b.mitigation_note ?? null) : null, changed_at: now() });
    if (hist.length) await db("scs_vuln_history").insert(hist);
    await audit.log("user", req.user!.id, "scs.vuln.updated", { id, cve: cur.cve_id, changes: hist.map((h) => `${h.field}: ${h.from_value ?? "-"} → ${h.to_value ?? "-"}`) });
    res.json({ ok: true });
  }));

  r.patch("/scs/vulns/:id/basis", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id);
    const b = z.object({ fix_released_at: z.string().datetime({ offset: true }), basis: z.string().min(3).max(1000), apply_same_cve: z.boolean().default(true) }).parse(req.body);
    const cur = await db("scs_vulns").where({ id }).first(); if (!cur) return bad(res, "not found", 404);
    const targets = b.apply_same_cve ? await db("scs_vulns").where({ cve_id: cur.cve_id, package_name: cur.package_name }) : [cur];
    for (const v of targets) {
      await db("scs_vulns").where({ id: v.id }).update({ fix_released_at: b.fix_released_at, fix_released_source: "manual", fix_released_basis: b.basis, updated_at: now() });
      await db("scs_vuln_history").insert({ vuln_id: v.id, changed_by: who(req), field: "fix_released_at", from_value: v.fix_released_at, to_value: b.fix_released_at, note: b.basis, changed_at: now() });
    }
    const { recompute } = await import("../scs/sync.js");
    await recompute(ctx, (q) => q.whereIn("id", targets.map((t: any) => t.id)), who(req));
    await audit.log("user", req.user!.id, "scs.vuln.basis", { cve: cur.cve_id, package: cur.package_name, fix_released_at: b.fix_released_at, rows: targets.length });
    res.json({ ok: true, rows: targets.length });
  }));

  r.put("/scs/packages/class", requireRole("operator"), wrap(async (req, res) => {
    const b = z.object({ package_name: z.string().min(1).max(255), target_class: z.enum(["pc_os", "pc_browser", "pc_office", "server_os", "server_middleware", "smart_os", "smart_app", "boundary_fw", "other"]), reason: z.string().max(500).optional() }).parse(req.body);
    const rows = await db("scs_vulns").where({ package_name: b.package_name }).whereNull("resolved_at");
    for (const v of rows) {
      await db("scs_vulns").where({ id: v.id }).update({ target_class: b.target_class, target_class_source: "manual", updated_at: now() });
      if (v.target_class !== b.target_class) await db("scs_vuln_history").insert({ vuln_id: v.id, changed_by: who(req), field: "target_class", from_value: v.target_class, to_value: b.target_class, note: b.reason ?? null, changed_at: now() });
    }
    const { recompute } = await import("../scs/sync.js");
    await recompute(ctx, (q) => q.where({ package_name: b.package_name }), who(req));
    await audit.log("user", req.user!.id, "scs.package.class", { package: b.package_name, target_class: b.target_class, rows: rows.length });
    res.json({ ok: true, rows: rows.length });
  }));

  r.get("/scs/packages/undetermined", requireRole("viewer"), wrap(async (_req, res) => {
    const rows = await db("scs_vulns as v").join("scs_assets as a", "a.id", "v.asset_id").whereNull("v.resolved_at").where("v.target_class", "undetermined").select("v.package_name", "a.category").count({ cves: "v.id" }).countDistinct({ hosts: "v.asset_id" }).max({ cvss: "v.cvss_base" }).groupBy("v.package_name", "a.category").orderBy("cves", "desc").limit(300);
    res.json({ items: rows });
  }));

  r.post("/scs/vulns/cve/:cve/request-patch", requireRole("operator"), wrap(async (req, res) => {
    const cve = String(req.params.cve).slice(0, 32);
    const rows = await db("scs_vulns as v").join("scs_assets as a", "a.id", "v.asset_id").where("v.cve_id", cve).whereNull("v.resolved_at").whereNotIn("v.status", ["対象外"]).select("v.*", "a.name as asset_name", "a.host_id");
    if (!rows.length) return bad(res, "未対応の端末がありません");
    if (!ctx.runtime) return bad(res, "AI エージェントが使えません", 503);
    const hostIds = [...new Set(rows.map((r: any) => r.host_id).filter(Boolean))] as number[];
    const due = rows.map((r: any) => r.due_at).filter(Boolean).sort()[0];
    const lines = rows.map((r: any) => `- ${r.asset_name}: ${r.package_name}${r.package_version ? " " + r.package_version : ""}（${r.priority}・期限 ${r.due_at ? String(r.due_at).slice(0, 10) : "-"}）`).join("\n");
    const msg = `SCS 脆弱性台帳から: ${cve} を解消するパッチを当てたい。\n${lines}\n期限は ${due ? String(due).slice(0, 10) : "-"}（評価基準 4-4-4-2: 修正版のリリースから 14 日）。\nまず各ホストの更新の有無を確認し（Windows は win_updates、Linux はパッケージの更新候補）、当てる内容を説明してから承認カードを出してください。再起動が必要なら別の承認にしてください。`;
    const sid = await ctx.runtime.createSession({ origin: "user", kind: "investigate", title: `SCS: ${cve} のパッチ適用`, userId: req.user!.id, hostIds, firstMessage: msg });
    const now2 = now();
    await db("scs_vuln_history").insert(rows.map((r: any) => ({ vuln_id: r.id, changed_by: who(req), field: "request", from_value: null, to_value: `sidekick#${sid}`, note: `Sidekick #${sid} にパッチ適用を依頼`, changed_at: now2 })));
    await audit.log("user", req.user!.id, "scs.patch.requested", { cve, session_id: sid, hosts: rows.map((r: any) => r.asset_name) });
    res.json({ session_id: sid });
  }));

  // ---- 資産台帳 ----
  const assetSchema = z.object({
    name: z.string().min(1).max(255), category: z.enum(["pc", "server", "hypervisor", "smart_device", "network_device", "other"]), manufacturer: z.string().max(255).nullable().optional(), model: z.string().max(255).nullable().optional(),
    serial: z.string().max(128).nullable().optional(), os_name: z.string().max(255).nullable().optional(), os_version: z.string().max(128).nullable().optional(), firmware: z.string().max(128).nullable().optional(), location: z.string().max(255).nullable().optional(),
    purpose: z.string().max(2000).nullable().optional(), maintainer: z.string().max(255).nullable().optional(), is_boundary: z.boolean().optional(), important_system: z.boolean().optional(), cpe: z.string().max(1000).nullable().optional(), open_ports: z.number().int().min(0).max(65535).nullable().optional(),
    in_scope: z.boolean().optional(), out_of_scope_reason: z.string().max(1000).nullable().optional(),
  });
  r.get("/scs/assets", requireRole("viewer"), wrap(async (req, res) => {
    const rows = await db("scs_assets").modify((q: any) => { if (req.query.removed !== "1") q.whereNull("removed_at"); }).orderBy([{ column: "category" }, { column: "name" }]);
    const open = new Map((await db("scs_vulns").whereNull("resolved_at").whereNotIn("status", ["適用済", "対象外"]).where("sla_target", true).select("asset_id").count({ n: "*" }).min({ due: "due_at" }).groupBy("asset_id")).map((x: any) => [x.asset_id, { n: Number(x.n), due: x.due }]));
    const counts: Record<string, number> = {}; for (const a of rows) if (!a.removed_at && a.in_scope) counts[a.category] = (counts[a.category] ?? 0) + 1;
    const last = await db("scs_inspections").where({ criteria_no: "3-1-1-7" }).orderBy("id", "desc").first();
    res.json({ items: rows.map((a: any) => ({ ...a, is_boundary: !!a.is_boundary, important_system: !!a.important_system, in_scope: !!a.in_scope, sla_open: open.get(a.id)?.n ?? 0, sla_next_due: open.get(a.id)?.due ?? null })), counts, last_inspection: last ?? null });
  }));
  r.post("/scs/assets", requireRole("operator"), wrap(async (req, res) => {
    const b = assetSchema.parse(req.body);
    const [id] = await db("scs_assets").insert({ ...b, source: "manual", category_source: "manual", first_seen_at: now(), last_seen_at: now(), updated_at: now() }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
    await audit.log("user", req.user!.id, "scs.asset.created", { id, name: b.name, category: b.category });
    res.json({ id });
  }));
  r.patch("/scs/assets/:id", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id); const cur = await db("scs_assets").where({ id }).first(); if (!cur) return bad(res, "not found", 404);
    const b = assetSchema.partial().parse(req.body);
    if (cur.source === "wazuh") { delete (b as any).name; delete (b as any).os_name; delete (b as any).os_version; } // Wazuh 由来の値は上書きしない
    if (b.in_scope === false && !(b.out_of_scope_reason ?? cur.out_of_scope_reason)) return bad(res, "対象外にするときは理由を書いてください");
    await db("scs_assets").where({ id }).update({ ...b, ...(b.category && b.category !== cur.category ? { category_source: "manual" } : {}), updated_at: now() });
    if (b.category && b.category !== cur.category) { // 区分が変わると対象区分（OS / ミドルウェア …）も変わる
      const { recompute } = await import("../scs/sync.js");
      const vs = await db("scs_vulns").where({ asset_id: id }).whereNull("resolved_at").where("target_class_source", "auto");
      for (const v of vs) await db("scs_vulns").where({ id: v.id }).update({ target_class: K.targetClass(b.category, v.package_name, null) });
      await recompute(ctx, (q) => q.where({ asset_id: id }), who(req));
    }
    await audit.log("user", req.user!.id, "scs.asset.updated", { id, name: cur.name, fields: Object.keys(b) });
    res.json({ ok: true });
  }));
  r.delete("/scs/assets/:id", requireRole("operator"), wrap(async (req, res) => {
    const id = Number(req.params.id); const cur = await db("scs_assets").where({ id }).first(); if (!cur) return bad(res, "not found", 404);
    if (cur.source !== "manual") return bad(res, "Wazuh 由来の機器は消せません（対象外にしてください）");
    await db("scs_assets").where({ id }).update({ removed_at: now(), updated_at: now() }); // 年次点検の差分のため行は残す
    await audit.log("user", req.user!.id, "scs.asset.removed", { id, name: cur.name });
    res.json({ ok: true });
  }));

  r.get("/scs/feeds", requireRole("viewer"), wrap(async (_req, res) => {
    res.json({ runs: await db("scs_feed_runs").orderBy("id", "desc").limit(60) });
  }));
  r.post("/scs/sync", requireRole("operator"), wrap(async (req, res) => {
    const s = await import("../scs/sync.js");
    if (s.isRunning()) return bad(res, "取り込み中です。少し待ってください", 409);
    const feeds = req.body?.feeds === true;
    const out = await s.runAll(ctx, { feeds });
    await audit.log("user", req.user!.id, "scs.sync", { feeds, created: out.vulns.created, resolved: out.vulns.resolved });
    res.json(out);
  }));
  r.get("/scs/settings", requireRole("viewer"), wrap(async (_req, res) => {
    const { scsEnabled } = await import("../scs/sync.js");
    res.json({ enabled: await scsEnabled(ctx) });
  }));
  r.put("/scs/settings", requireRole("admin"), wrap(async (req, res) => {
    const b = z.object({ enabled: z.boolean() }).parse(req.body);
    const ex = await db("app_flags").where({ key: "scs_enabled" }).first();
    if (ex) await db("app_flags").where({ key: "scs_enabled" }).update({ value: b.enabled ? "1" : "0" }); else await db("app_flags").insert({ key: "scs_enabled", value: b.enabled ? "1" : "0" });
    await audit.log("user", req.user!.id, "scs.settings", b);
    res.json({ ok: true });
  }));
  // ---- EDR-178: SCA（端末ごとの設定の確認）----
  r.get("/scs/sca", requireRole("viewer"), wrap(async (_req, res) => {
    const S = await import("../scs/sca.js");
    const keys: [string, string[]][] = [["4-1-4-1", ["lockout"]], ["4-1-4-2", ["pwlen"]], ["4-4-1-2", ["autorun"]], ["4-5-1-8", ["fw"]], ["4-4-1-5", ["guest", "admin_account", "root_login"]]];
    const list = await S.latestPerAsset(ctx);
    res.json({
      synced_at: (await db("app_flags").where({ key: "scs_sca_at" }).first())?.value ?? null,
      hosts: list.map((x) => ({ asset_id: x.asset.id, name: x.asset.name, category: x.asset.category, os: x.asset.os_name, policy: x.row?.policy_id ?? null, scan_end: x.row?.scan_end ?? null, pass: x.row?.pass ?? null, fail: x.row?.fail ?? null,
        verdicts: Object.fromEntries(keys.map(([no, ks]) => { const vs = ks.map((k) => S.verdict(k as any, x.checks, x.os)).filter((v) => v !== "na"); return [no, !x.row ? "nodata" : !vs.length ? "na" : vs.includes("ng") ? "ng" : vs.includes("unknown") ? "unknown" : vs.includes("check") ? "check" : "ok"]; })),
        checks: x.checks })).sort((a, b) => a.name.localeCompare(b.name)),
    });
  }));
  r.post("/scs/sca/sync", requireRole("operator"), wrap(async (req, res) => {
    const S = await import("../scs/sca.js");
    const out = await S.syncSca(ctx);
    const ex = await db("app_flags").where({ key: "scs_sca_at" }).first(); const v = new Date().toISOString();
    if (ex) await db("app_flags").where({ key: "scs_sca_at" }).update({ value: v }); else await db("app_flags").insert({ key: "scs_sca_at", value: v });
    await audit.log("user", req.user!.id, "scs.sca.sync", out);
    res.json(out);
  }));
  // ---- EDR-174: 評価基準マスタと状態 ----
  r.get("/scs/criteria", requireRole("viewer"), wrap(async (_req, res) => {
    const C = await import("../scs/criteria.js"); const E = await import("../scs/evaluate.js");
    const version = await C.currentVersion(ctx);
    if (!version) return res.json({ version: null, items: [], counts: null });
    const rows = await db("scs_criteria").where({ source_version: version });
    const ev = await E.evaluateAll(ctx);
    const items = rows.map((c: any) => {
      const e = c.mamorai_mode === "C" ? { state: "対象外", evidence: "MamorAI の対象外（社内規程・体制・契約など。人が文書で示す）", checked_at: null }
        : ev[c.criteria_no] ?? { state: "未接続", evidence: `${c.mamorai_feature ?? "対応機能"}は今後のバージョンでつなぎます`, checked_at: null };
      return { ...c, annual_check: !!c.annual_check, ...e };
    }).sort((a: any, b: any) => cmpNo(a.criteria_no, b.criteria_no));
    const counts: Record<string, Record<string, number>> = {};
    for (const i of items) { const k = `${i.level}`; counts[k] ??= { 適合: 0, 要対応: 0, 未接続: 0, 対象外: 0 }; counts[k][i.state]++; }
    res.json({ version, items, counts });
  }));
  r.post("/scs/criteria/import", requireRole("admin"), wrap(async (req, res) => {
    const C = await import("../scs/criteria.js");
    try {
      const out = await C.importCriteria(ctx);
      await audit.log("user", req.user!.id, "scs.criteria.imported", out);
      res.json(out);
    } catch (e: any) { bad(res, e.message, 502); }
  }));
  r.get("/scs/export/criteria.csv", requireRole("viewer"), wrap(async (_req, res) => {
    const C = await import("../scs/criteria.js"); const E = await import("../scs/evaluate.js");
    const version = await C.currentVersion(ctx); if (!version) return bad(res, "評価基準マスタが未取り込みです", 409);
    const ev = await E.evaluateAll(ctx);
    const rows = (await db("scs_criteria").where({ source_version: version })).sort((a: any, b: any) => cmpNo(a.criteria_no, b.criteria_no));
    const lines = [["評価基準No.", "★", "要求事項No.", "要求事項名", "MamorAI の扱い", "対応機能", "状態", "根拠", "確認日時", "年次点検"]];
    for (const c of rows) {
      const e = c.mamorai_mode === "C" ? { state: "対象外", evidence: "", checked_at: "" } : ev[c.criteria_no] ?? { state: "未接続", evidence: "", checked_at: "" };
      lines.push([c.criteria_no, c.level, c.requirement_no, c.title, { A: "自動証跡", B: "半自動", C: "対象外" }[c.mamorai_mode as "A"] ?? c.mamorai_mode, c.mamorai_feature ?? "", e.state, e.evidence, e.checked_at ?? "", c.annual_check ? "対象" : ""]);
    }
    sendCsv(res, `scs-criteria-${version}-${ymd()}.csv`, lines);
  }));
  r.get("/scs/export/vulns.csv", requireRole("viewer"), wrap(async (_req, res) => {
    const rows = await db("scs_vulns as v").leftJoin("scs_assets as a", "a.id", "v.asset_id").whereNull("v.resolved_at").where("v.sla_target", true)
      .select("v.*", "a.name as asset_name", "a.category as asset_category").orderBy([{ column: "v.due_at" }, { column: "v.cve_id" }]);
    const lines = [["CVE", "優先度", "資産", "資産区分", "パッケージ", "バージョン", "対象区分", "深刻度", "CVSS", "悪用あり", "修正公開日", "起点日の根拠", "検知日", "期限", "状態", "計画日", "計画の理由", "緩和策", "緩和策の内容", "対象外の理由", "持ち越し"]];
    const d = (x: any) => (x ? String(x).slice(0, 10) : "");
    for (const v of rows) lines.push([v.cve_id, v.priority, v.asset_name ?? "", v.asset_category ?? "", v.package_name, v.package_version ?? "", (K.CLASS_JA as any)[v.target_class] ?? v.target_class, v.severity_vendor ?? "", v.cvss_base ?? "", v.exploited ? "はい" : "", d(v.fix_released_at), v.fix_released_basis ?? "", d(v.detected_at), d(v.due_at), v.status, d(v.plan_due_at), v.plan_reason ?? "", v.mitigation_type ?? "", v.mitigation_note ?? "", v.exclusion_reason ?? "", v.due_at && v.created_at > v.due_at ? "はい" : ""]);
    sendCsv(res, `scs-vulns-${ymd()}.csv`, lines);
  }));
  return r;
}
function chunkArr<T>(a: T[], n: number): T[][] { const out: T[][] = []; for (let i = 0; i < a.length; i += n) out.push(a.slice(i, i + n)); return out; }

/** 4-4-4-2 と 10-4-4-2 を数字として並べる */
function cmpNo(a: string, b: string): number { const x = a.split("-").map(Number), y = b.split("-").map(Number); for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return (x[i] ?? 0) - (y[i] ?? 0); return 0; }
const ymd = () => new Date(Date.now() + 9 * 3600_000).toISOString().slice(0, 10).replace(/-/g, "");
/** Excel で文字化けしないよう BOM 付き UTF-8・CRLF */
function sendCsv(res: Response, name: string, lines: unknown[][]): void {
  const esc = (v: unknown) => { const s = v == null ? "" : String(v); return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
  res.send("\uFEFF" + lines.map((l) => l.map(esc).join(",")).join("\r\n") + "\r\n");
}
