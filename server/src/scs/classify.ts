/**
 * EDR-176（SCS P1-4）: 14日 SLA の判定（評価基準 4-4-4-2 の文言どおり）。DB や indexer に触らない純粋な関数だけを置く。
 *
 * 対象機器（[対象]）: 会社支給 PC の OS・ブラウザ・Office ／ サーバの OS・ミドルウェア ／ スマートデバイスの OS・アプリ
 *                    ／ インターネットとの境界にある NW 機器の OS・ファームウェア
 * 対象脆弱性: ベンダーが Critical / High ／ CVSS 基本値 7.0 以上 ／ 深刻度が示されていない（不明は対象に含める）
 * 期限の起点は「アップデートのリリース日」。取れないときは公開日と検知日の早い方。
 */

export type AssetCategory = "pc" | "server" | "hypervisor" | "smart_device" | "network_device" | "other";
export type TargetClass = "pc_os" | "pc_browser" | "pc_office" | "server_os" | "server_middleware" | "smart_os" | "smart_app" | "boundary_fw" | "other" | "undetermined";
export type Priority = "P0" | "P1" | "P2" | "P3";
export const SLA_CLASSES: TargetClass[] = ["pc_os", "pc_browser", "pc_office", "server_os", "server_middleware", "smart_os", "smart_app", "boundary_fw"];
export const STATUSES = ["未対応", "計画中", "緩和策適用中", "適用済", "対象外"] as const;
export type Status = (typeof STATUSES)[number];
export const MITIGATIONS = ["機能の無効化", "ベンダー回避策", "ネットワークからの分離", "監視・遮断の強化", "その他"] as const;

export const CLASS_JA: Record<TargetClass, string> = {
  pc_os: "PC / OS", pc_browser: "PC / ブラウザ", pc_office: "PC / Office", server_os: "サーバ / OS", server_middleware: "サーバ / ミドルウェア",
  smart_os: "スマートデバイス / OS", smart_app: "スマートデバイス / アプリ", boundary_fw: "境界機器 / ファーム", other: "対象外の種類", undetermined: "要判定",
};

/**
 * パッケージ名の辞書（設定）。上から順に見て最初に当たったもの。
 * 辞書に無い Windows アプリは「要判定」にして人が決める（推測で対象外にしない）。
 */
export const DICT: { re: RegExp; kind: "os" | "browser" | "office" | "middleware" }[] = [
  { re: /^microsoft windows (\d|server|xp|vista)/i, kind: "os" },        // "Microsoft Windows 11 Pro ..." / "Microsoft Windows Server 2022 ..."（Desktop Runtime などは含めない）
  { re: /^(linux|kernel)(-image|-modules|-headers|-core|-tools|-generic)?\b|^linux-|^kernel/i, kind: "os" },
  { re: /chrome|chromium|firefox|microsoft edge|^edge\b|brave|opera|vivaldi/i, kind: "browser" },
  { re: /microsoft office|microsoft 365|office 16|libreoffice|openoffice|microsoft (word|excel|powerpoint|outlook|visio|project)\b/i, kind: "office" },
  { re: /\b(php\d*(\.\d+)?|php-[\w-]+|apache2?|httpd|nginx|openssl|libssl\d*|openssh(-server)?|mysql|mariadb|postgres(ql)?|tomcat\d*|redis|mongodb|node(js)?|openjdk|java|jre|jdk|dotnet|\.net|aspnetcore|iis|sql server|windows desktop runtime|asp\.net core|bind9?|postfix|dovecot|exim|samba|haproxy|squid|docker|containerd|runc)\b/i, kind: "middleware" },
];

/** 端末の区分と、パッケージ名・種類から対象区分を決める */
export function targetClass(category: AssetCategory, pkgName: string, pkgType?: string | null): TargetClass {
  const hit = DICT.find((d) => d.re.test(pkgName))?.kind ?? null;
  const distro = !!pkgType && /^(deb|rpm|apk|pacman)$/i.test(pkgType); // Linux のディストリビューションのパッケージ
  if (category === "pc") {
    if (hit === "os") return "pc_os";
    if (hit === "browser") return "pc_browser";
    if (hit === "office") return "pc_office";
    if (distro) return "pc_os"; // Linux デスクトップのディストリビューション部品は OS の一部
    return "undetermined";
  }
  if (category === "server" || category === "hypervisor") {
    if (hit === "os") return "server_os";
    if (hit === "middleware") return "server_middleware";
    if (distro) return "server_os"; // ディストリビューションのパッケージは OS の一部として扱う
    return "undetermined";
  }
  if (category === "smart_device") return hit === "os" ? "smart_os" : "smart_app";
  if (category === "network_device") return "boundary_fw";
  return "undetermined";
}

/** 深刻度が示されていない（Wazuh では "-" や空、CVSS も無い） */
export function severityUnknown(severity: string | null | undefined, cvss: number | null | undefined): boolean {
  const s = (severity ?? "").trim();
  return (s === "" || s === "-" || /^(none|unknown)$/i.test(s)) && !(cvss && cvss > 0);
}

/** 14日 SLA の対象か */
export function slaTarget(cls: TargetClass, severity: string | null | undefined, cvss: number | null | undefined): boolean {
  if (!SLA_CLASSES.includes(cls)) return false;
  if (/^(critical|high|重大|高)$/i.test((severity ?? "").trim())) return true;
  if (cvss != null && cvss >= 7.0) return true;
  return severityUnknown(severity, cvss);
}

/** 台帳に行を作るか（重ね書き方式: 14日 SLA の候補だけ。区分が決まる前でも深刻度で拾う） */
export function isCandidate(severity: string | null | undefined, cvss: number | null | undefined): boolean {
  return /^(critical|high)$/i.test((severity ?? "").trim()) || (cvss != null && cvss >= 7.0) || severityUnknown(severity, cvss);
}

export function priority(sla: boolean, exploited: boolean, cls: TargetClass, cvss: number | null | undefined): Priority {
  if (sla && exploited) return "P0";
  if (sla) return "P1";
  if (cls === "boundary_fw" && exploited && (cvss == null || cvss < 7)) return "P2";
  return "P3";
}

const DAY = 86_400_000;
/** 期限の起点の初期値: 公開日と検知日の早い方 */
export function defaultFixReleased(published: string | null | undefined, detected: string | null | undefined): string | null {
  const t = [published, detected].map((x) => (x ? Date.parse(x) : NaN)).filter((x) => !Number.isNaN(x));
  return t.length ? new Date(Math.min(...t)).toISOString() : null;
}

/** 期限: 14日対象は起点 + 14 日、P2 は検知 + 7 日、それ以外は計画日（無ければ無し） */
export function dueAt(p: Priority, sla: boolean, fixReleased: string | null, detected: string | null, planDue: string | null): string | null {
  if (sla && fixReleased) return new Date(Date.parse(fixReleased) + 14 * DAY).toISOString();
  if (p === "P2" && detected) return new Date(Date.parse(detected) + 7 * DAY).toISOString();
  return planDue ?? null;
}

/** 端末の区分を OS 名から決める（画面で上書きできる） */
export function assetCategory(osName: string | null | undefined, platform: string | null | undefined, role?: string | null): AssetCategory {
  const n = `${osName ?? ""}`.toLowerCase(); const p = `${platform ?? ""}`.toLowerCase();
  if (/esxi|proxmox|xenserver|hyper-v server/.test(n)) return "hypervisor";
  if (/windows/.test(n) || p === "windows") return /server/.test(n) ? "server" : "pc";
  if (/darwin|mac ?os/.test(n) || p === "darwin") return "pc";
  if (/android|ios|ipados/.test(n)) return "smart_device";
  if (n || p) return role === "client" ? "pc" : "server"; // Linux はサーバ扱い（ホストの種別が「クライアント端末」なら PC）
  return "other";
}

/** 状態を変えるときの入力チェック（指示書 §4-2-5・§8-3）。問題が無ければ null */
export function validateChange(cur: { priority: Priority; due_at: string | null; status: string }, next: { status?: string; mitigation_type?: string | null; plan_due_at?: string | null; plan_reason?: string | null; exclusion_reason?: string | null }): string | null {
  const st = next.status ?? cur.status;
  if (!(STATUSES as readonly string[]).includes(st)) return "状態の値が正しくありません";
  if (st === "緩和策適用中" && !(next.mitigation_type && (MITIGATIONS as readonly string[]).includes(next.mitigation_type))) return "緩和策適用中にするときは、緩和策の種類を選んでください";
  if (st === "対象外" && !(next.exclusion_reason && next.exclusion_reason.trim().length >= 5)) return "対象外にするときは、理由を書いてください（5 文字以上）";
  if (st === "計画中" && !(next.plan_due_at && next.plan_reason && next.plan_reason.trim())) return "計画中にするときは、予定日と理由を入れてください";
  if (next.plan_due_at && cur.due_at && Date.parse(next.plan_due_at) > Date.parse(cur.due_at)) {
    if (cur.priority === "P0") return "P0（悪用が確認された脆弱性）は 14 日の期限を延ばせません。緩和策を当てるか、期限内に適用してください";
    if (cur.priority === "P1" && !(next.plan_reason && next.plan_reason.trim())) return "期限を延ばすときは、理由を書いてください";
  }
  return null;
}
