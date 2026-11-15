/**
 * EDR-156: one vocabulary for alerts across MamorAI.
 *   重大度（Wazuh が付ける level）: 緊急 / 高 / 中 / 低         … LEVEL_JA / SEV_LABEL
 *   AI の判定（このアラートは危ないか）: 危険 / 要確認 / おそらく正常 … TRIAGE
 *   対応状況: 未対応 / 調査中 / 対応済み
 * The dashboard and the alerts page both use these, so the same alert never has two names.
 */
import { isVuln, vulnTextOf } from "./vuln";

export type Triage = "benign_likely" | "check" | "danger";
export interface RuleNote { rule_id: string; title_ja: string; meaning: string; cause: string; impact: string; action: string; triage: Triage; source: string }

export const TRIAGE: Record<Triage, { label: string; icon: string; dot: string; bar: string; chip: string; desc: string; num: string }> = {
  danger: { label: "危険", icon: "", dot: "#F2555A", bar: "bg-[#F2555A]", chip: "border-[#5A222A] bg-[#3A1418] text-[#FF9A9D]", desc: "攻撃の可能性が高い。すぐ確認", num: "text-[#FF9A9D]" },
  check: { label: "要確認", icon: "", dot: "#F5C542", bar: "bg-[#F5C542]", chip: "border-[#5A4318] bg-[#3A2A10] text-[#FFC27A]", desc: "攻撃かノイズか判断が必要", num: "text-[#FFC27A]" },
  benign_likely: { label: "おそらく正常", icon: "", dot: "#3CCB8C", bar: "bg-[#3CCB8C]", chip: "border-[#1F4A36] bg-[#12301F] text-[#7FE0B0]", desc: "よくある正常動作・誤検知の可能性大", num: "text-[#7FE0B0]" },
};
export const TRIAGE_ORDER: Triage[] = ["danger", "check", "benign_likely"];

/** 重大度（Wazuh level）の日本語 */
export const LEVEL_JA = (lv: number) => (lv >= 15 ? "緊急" : lv >= 12 ? "高" : lv >= 7 ? "中" : "低");

export function defaultTriage(a: any): Triage { return a.rule.level >= 15 ? "danger" : "check"; }

/** AI の判定: 脆弱性はデータから確定、それ以外はルール説明（AI 作成 / 手動編集）の判定、無ければ level から仮置き */
export function triageOf(a: any, notes: Record<string, RuleNote>): Triage {
  if (isVuln(a)) return vulnTextOf(a).triage;
  return notes[String(a.rule.id)]?.triage ?? defaultTriage(a);
}
