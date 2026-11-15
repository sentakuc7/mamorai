import type { Knex } from "knex";
/** EDR-80: 脆弱性アラートの「対応済み」は rule.id ではなく agent + CVE + パッケージで一致させる。 */
export async function up(db: Knex): Promise<void> {
  await db.schema.alterTable("alert_marks", (t) => { t.string("vuln_cve", 64); t.string("vuln_package", 255); });
  // 既存の脆弱性マーク（rule 235xx）を alert_json / note から埋める。取れないものは null のまま＝どの脆弱性アラートにも一致しない（隠すより出す側に倒す）
  const rows = await db("alert_marks").where("rule_id", "like", "235%").select("id", "alert_json", "note");
  for (const r of rows) {
    let a: any = null; try { a = r.alert_json ? JSON.parse(r.alert_json) : null; } catch { a = null; }
    const v = a?.data?.vulnerability;
    const m = String(a?.rule?.description ?? "").match(/^(CVE-\d{4}-\d+)\s+affects\s+(.+?)\s*$/i);
    const cve = (v?.cve ?? m?.[1] ?? String(r.note ?? "").match(/CVE-\d{4}-\d+/i)?.[0] ?? "").toUpperCase() || null;
    const pkg = (v?.package?.name ?? m?.[2] ?? "").toLowerCase() || null;
    if (cve) await db("alert_marks").where({ id: r.id }).update({ vuln_cve: cve, vuln_package: pkg });
  }
}
export async function down(db: Knex): Promise<void> { await db.schema.alterTable("alert_marks", (t) => { t.dropColumn("vuln_cve"); t.dropColumn("vuln_package"); }); }
