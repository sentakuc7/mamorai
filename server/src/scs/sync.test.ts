import { describe, it, expect, vi, beforeAll } from "vitest";
import knex from "knex";
import path from "node:path";

// indexer の代わり: 呼ばれるたびに docs を返す（search_after で 2 ページ目は空）
let docs: any[] = [];
vi.mock("../api/context.js", () => ({
  indexer: async () => ({
    search: async (index: string, body: any) => {
      if (index.startsWith("wazuh-states-inventory-system")) return { hits: { hits: [{ _source: { agent: { id: "012" }, host: { os: { name: "Amazon Linux", platform: "amzn", version: "2023" } } } }, { _source: { agent: { id: "017" }, host: { os: { name: "Microsoft Windows 11 Pro", platform: "windows" } } } }] } };
      if (index.startsWith("wazuh-states-inventory-hardware")) return { hits: { hits: [] } };
      if (body.search_after) return { hits: { total: { value: docs.length }, hits: [] } };
      return { hits: { total: { value: docs.length }, hits: docs.map((d, i) => ({ _source: d, sort: [i] })) } };
    },
  }),
}));

const db = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
const ctx: any = { db, cfg: {}, log: { info() {}, warn() {} } };
const v = (agent: string, cve: string, pkg: string, ver: string, sev: string, cvss: number | null, type = "rpm") => ({ agent: { id: agent }, package: { name: pkg, version: ver, type }, vulnerability: { id: cve, severity: sev, score: { base: cvss, version: "3.1" }, published_at: "2026-10-29T00:00:00Z", detected_at: "2026-10-30T07:00:00Z" } });

beforeAll(async () => {
  await db.migrate.latest({ directory: path.resolve("src/db/migrations"), loadExtensions: [".ts"] });
  const [wid] = await db("wazuh_instances").insert({ name: "lab", indexer_url: "https://x", indexer_user: "u", indexer_secret_enc: "x" }).returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
  await db("hosts").insert([{ name: "web03", address: "", port: 22, ssh_user: "", environment: "production", agent_id: "012", wazuh_instance_id: wid, kind: "agent_only" }, { name: "pc-b", address: "", port: 22, ssh_user: "", environment: "lab", agent_id: "017", wazuh_instance_id: wid, kind: "agent_only" }]);
  await db("scs_threat_intel").insert({ cve_id: "CVE-2026-109618", source: "IPA_ALERT", listed_at: "2026-10-22" });
});

describe("EDR-176 SCS 台帳の取り込み（重ね書き方式）", () => {
  it("登録 → 解消 → 再検知", async () => {
    const s = await import("./sync.js");
    docs = [v("012", "CVE-2026-109618", "php", "8.3.14", "Critical", 9.8), v("017", "CVE-2026-83780", "Microsoft Windows 11 Pro 10.0.22000", "10.0.22000", "High", 7.8, "win"), v("017", "CVE-2026-88123", "7-Zip 23.01", "23.01", "-", null, "win"), v("017", "CVE-2026-88123", "7-Zip 23.01", "23.01.1", "-", null, "win")];
    const a = await s.syncAssets(ctx); expect(a.upserted).toBe(2);
    const r1 = await s.syncVulns(ctx);
    expect(r1.created).toBe(3); expect(r1.complete).toBe(true); expect(r1.newP0).toEqual([]); // 最初の取り込みでは通知しない
    const php = await db("scs_vulns").where({ cve_id: "CVE-2026-109618" }).first();
    expect(php).toMatchObject({ target_class: "server_middleware", priority: "P0", status: "未対応" }); expect(!!php.sla_target).toBe(true);
    expect(php.due_at).toBe("2026-11-12T00:00:00.000Z");
    expect((await db("scs_vulns").where({ cve_id: "CVE-2026-88123" }).first())).toMatchObject({ target_class: "undetermined", priority: "P3" });
    // php が直った（Wazuh から消えた）
    docs = docs.slice(1);
    const r2 = await s.syncVulns(ctx);
    expect(r2.resolved).toBe(1);
    expect(await db("scs_vulns").where({ cve_id: "CVE-2026-109618" }).first()).toMatchObject({ status: "適用済" });
    const h = await db("scs_vuln_history").where({ vuln_id: php.id }).orderBy("id");
    expect(h.map((x: any) => x.to_value)).toEqual(["未対応", "適用済"]);
    // 再び検知
    docs = [v("012", "CVE-2026-109618", "php", "8.3.14", "Critical", 9.8), ...docs];
    const r3 = await s.syncVulns(ctx);
    expect(r3.reopened).toBe(1);
    // 2 回目以降に新しく見つかった P0 は通知する
    docs = [...docs, v("017", "CVE-2026-109618", "php", "8.3.14", "Critical", 9.8, "win")];
    const r4 = await s.syncVulns(ctx);
    expect(r4.created).toBe(1);
    expect(await db("scs_vulns").where({ cve_id: "CVE-2026-109618" }).first()).toMatchObject({ status: "未対応", resolved_at: null });
  });
});
