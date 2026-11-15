// EDR-80: 脆弱性アラート（rule.groups に vulnerability-detector）の表示文言を
// data.vulnerability.* から確定的に組み立てる。AI 生成・rule.id 単位の rule_notes は使わない。

export type VulnFields = {
  cve?: string;
  severity?: string;            // Critical / High / Medium / Low
  package?: { name?: string; version?: string; architecture?: string };
  title?: string;
  score?: { base?: number | string };
  status?: string;              // Active / Solved
  reference?: string;
};

export type VulnText = { title: string; plain: string; detail: string; action: string; triage: "danger" | "check"; severity: string; cve: string; package: string };

const SEV_JA: Record<string, string> = {
  Critical: "深刻な",
  High: "重要な",
  Medium: "中程度の",
  Low: "軽微な",
};

export function isVulnAlert(alert: any): boolean {
  const groups: string[] = Array.isArray(alert?.rule?.groups) ? alert.rule.groups : [];
  return groups.includes("vulnerability-detector") || !!alert?.data?.vulnerability;
}

/** "CVE-2026-80668 affects linux-image-cloud-amd64" 形式の rule.description から CVE / パッケージを取り出す（data.vulnerability が無い古いスナップショット用）。 */
export function parseVulnDescription(desc: unknown): { cve?: string; package?: string } {
  const m = String(desc ?? "").match(/^(CVE-\d{4}-\d+)\s+affects\s+(.+?)\s*$/i);
  return m ? { cve: m[1].toUpperCase(), package: m[2] } : {};
}

/** 一致判定用の CVE / パッケージ名（大文字小文字を正規化）。脆弱性アラートでなければ null。 */
export function vulnIdentity(alert: any): { cve: string; package: string } | null {
  if (!isVulnAlert(alert)) return null;
  const v: VulnFields = alert?.data?.vulnerability ?? {};
  const d = parseVulnDescription(alert?.rule?.description);
  const cve = (v.cve ?? d.cve ?? "").toUpperCase();
  const pkg = (v.package?.name ?? d.package ?? "").toLowerCase();
  return cve ? { cve, package: pkg } : null;
}

/** data.vulnerability.severity が無い場合は Wazuh の脆弱性ルールの level から推定する（23506=13→Critical, 23505=10→High …）。 */
export function vulnSeverity(alert: any): string {
  const s = alert?.data?.vulnerability?.severity;
  if (s) return String(s);
  const lv = Number(alert?.rule?.level ?? 0);
  return lv >= 13 ? "Critical" : lv >= 10 ? "High" : lv >= 7 ? "Medium" : "Low";
}

export function buildVulnText(alert: any): VulnText {
  const v: VulnFields = alert?.data?.vulnerability ?? {};
  const d = parseVulnDescription(alert?.rule?.description);
  const pkg = v.package?.name ?? d.package ?? "不明なソフト";
  const ver = v.package?.version ? ` ${v.package.version}` : "";
  const severity = vulnSeverity(alert);
  const sev = SEV_JA[severity] ?? "";
  const cve = v.cve ?? d.cve ?? "CVE不明";
  const base = v.score?.base != null && v.score.base !== "" ? Number(v.score.base) : NaN;
  const score = Number.isFinite(base) ? `（CVSS ${base.toFixed(1)}）` : "";
  const isOs = /^microsoft windows/i.test(pkg) || /^linux-image/i.test(pkg);

  return {
    title: `${pkg} に${sev}脆弱性が見つかりました`,
    plain: `${pkg}${ver} に ${cve}${score} という既知の脆弱性があります。` +
           `ソフトを最新版に更新すると解消できる場合がほとんどです。`,
    detail: `${cve} / ${pkg}${ver}${v.package?.architecture ? " (" + v.package.architecture + ")" : ""}` +
            ` / severity=${severity} / status=${v.status ?? "-"}`,
    action: isOs
      ? (/^microsoft windows/i.test(pkg) ? "Windows Update を実行して再起動してください。次回の脆弱性スキャンで自動的に消えます。" : "カーネルを更新して再起動してください。次回の脆弱性スキャンで自動的に消えます。")
      : `${pkg} を最新版に更新してください。次回の脆弱性スキャンで自動的に消えます。`,
    triage: severity === "Critical" ? "danger" : "check",
    severity,
    cve,
    package: pkg,
  };
}
