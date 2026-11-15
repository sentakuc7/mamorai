// EDR-80: 脆弱性アラートの表示ヘルパー（server/src/alerts/vulnText.ts と同じ規則。web と server は別ワークスペースなので移植している）
// 一覧 API が付ける a.simple / a.group_key を優先し、無い場合（対応済み履歴の古いスナップショット等）はここで組み立てる。

export type VulnText = { title: string; plain: string; detail: string; action: string; triage: "danger" | "check"; severity: string; cve: string; package: string };

export const SEV_LABEL: Record<string, string> = { Critical: "深刻", High: "重要", Medium: "中程度", Low: "軽微" };
const SEV_JA: Record<string, string> = { Critical: "深刻な", High: "重要な", Medium: "中程度の", Low: "軽微な" };

export const isVuln = (a: any): boolean => (a?.rule?.groups ?? []).includes("vulnerability-detector") || !!a?.data?.vulnerability || /^235\d\d$/.test(String(a?.rule?.id ?? ""));

const parseDesc = (desc: unknown): { cve?: string; package?: string } => { const m = String(desc ?? "").match(/^(CVE-\d{4}-\d+)\s+affects\s+(.+?)\s*$/i); return m ? { cve: m[1].toUpperCase(), package: m[2] } : {}; };

/** 一致判定用（CVE は大文字、パッケージは小文字） */
export function vulnOf(a: any): { cve: string; package: string } | null {
  if (!isVuln(a)) return null;
  const v = a?.data?.vulnerability ?? {}; const d = parseDesc(a?.rule?.description);
  const cve = String(v.cve ?? d.cve ?? "").toUpperCase(); const pkg = String(v.package?.name ?? d.package ?? "").toLowerCase();
  return cve ? { cve, package: pkg } : null;
}

export function vulnSev(a: any): string {
  const s = a?.simple?.severity ?? a?.data?.vulnerability?.severity; if (s) return String(s);
  const lv = Number(a?.rule?.level ?? 0); return lv >= 13 ? "Critical" : lv >= 10 ? "High" : lv >= 7 ? "Medium" : "Low";
}

export function vulnTextOf(a: any): VulnText {
  if (a?.simple?.title) return a.simple as VulnText;
  const v = a?.data?.vulnerability ?? {}; const d = parseDesc(a?.rule?.description);
  const pkg = v.package?.name ?? d.package ?? "不明なソフト"; const ver = v.package?.version ? ` ${v.package.version}` : "";
  const severity = vulnSev(a); const cve = v.cve ?? d.cve ?? "CVE不明";
  const base = v.score?.base != null && v.score.base !== "" ? Number(v.score.base) : NaN; const score = Number.isFinite(base) ? `（CVSS ${base.toFixed(1)}）` : "";
  const win = /^microsoft windows/i.test(pkg), kern = /^linux-image/i.test(pkg);
  return {
    title: `${pkg} に${SEV_JA[severity] ?? ""}脆弱性が見つかりました`,
    plain: `${pkg}${ver} に ${cve}${score} という既知の脆弱性があります。ソフトを最新版に更新すると解消できる場合がほとんどです。`,
    detail: `${cve} / ${pkg}${ver}${v.package?.architecture ? " (" + v.package.architecture + ")" : ""} / severity=${severity} / status=${v.status ?? "-"}`,
    action: win ? "Windows Update を実行して再起動してください。次回の脆弱性スキャンで自動的に消えます。" : kern ? "カーネルを更新して再起動してください。次回の脆弱性スキャンで自動的に消えます。" : `${pkg} を最新版に更新してください。次回の脆弱性スキャンで自動的に消えます。`,
    triage: severity === "Critical" ? "danger" : "check", severity, cve, package: pkg,
  };
}

/** 集約キー: 脆弱性はホスト×深刻度、それ以外はホスト×rule.id */
export const groupKeyOf = (a: any): string => a?.group_key ?? (isVuln(a) ? `vuln|${a?.agent?.id ?? ""}|${vulnSev(a)}` : `rule|${a?.agent?.id ?? ""}|${a?.rule?.id ?? ""}`);

/** 集約行の内訳: パッケージ別件数（多い順）と CVE 一覧 */
export function vulnBreakdown(list: any[]): { pkgs: [string, number][]; cves: { cve: string; pkg: string; version: string; severity: string; score: string; status: string; ref?: string; ts: string }[] } {
  const m = new Map<string, number>();
  const cves = list.map((x) => { const v = x?.data?.vulnerability ?? {}; const t = vulnTextOf(x); m.set(t.package, (m.get(t.package) ?? 0) + 1);
    const b = v.score?.base != null && v.score.base !== "" ? Number(v.score.base) : NaN;
    return { cve: t.cve, pkg: t.package, version: v.package?.version ?? "", severity: t.severity, score: Number.isFinite(b) ? b.toFixed(1) : "-", status: v.status ?? "-", ref: v.reference, ts: x.timestamp }; });
  return { pkgs: [...m.entries()].sort((p, q) => q[1] - p[1]), cves };
}
