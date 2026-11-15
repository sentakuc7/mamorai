/** アラート起因セッションのタイトル: 「アラート名（日本語の説明があればそれ） · 端末名」。rule id / level は末尾に小さく付ける。 */
import type { Knex } from "knex";
export async function alertTitle(db: Knex, a: any): Promise<string> {
  const rid = String(a?.rule?.id ?? "");
  const note = rid ? await db("rule_notes").where({ rule_id: rid }).first() : null;
  const name = String(note?.title_ja || a?.rule?.description || `rule ${rid}`).replace(/\s+/g, " ").trim();
  const agent = a?.agent?.name ? ` · ${a.agent.name}` : "";
  const lv = a?.rule?.level != null ? ` (L${a.rule.level})` : "";
  return `${name}${agent}${lv}`.slice(0, 255);
}
