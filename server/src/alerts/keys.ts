// EDR-80: アラート一覧の集約キーと、一覧 API で付与する表示用フィールド。
import { buildVulnText, isVulnAlert, vulnSeverity } from "./vulnText.js";

/** 集約キー: 脆弱性はホスト×深刻度（行内にパッケージ別内訳を出す）、それ以外はホスト×rule.id（従来どおり）。 */
export function groupKey(alert: any): string {
  if (isVulnAlert(alert)) return `vuln|${alert?.agent?.id ?? ""}|${vulnSeverity(alert)}`;
  return `rule|${alert?.agent?.id ?? ""}|${alert?.rule?.id ?? ""}`;
}

/** /wazuh/:id/alerts の各要素に group_key と（脆弱性なら）確定的文言 simple を付ける。 */
export function decorateAlert<T extends Record<string, any>>(alert: T): T & { group_key: string; simple?: ReturnType<typeof buildVulnText> } {
  const out: any = { ...alert, group_key: groupKey(alert) };
  if (isVulnAlert(alert)) out.simple = buildVulnText(alert);
  return out;
}
