import { api } from "./api";
import { vulnOf } from "./vuln";

export type Scope = "agent" | "program" | "rule";
export interface Handling { kind: "session" | "manual"; mark_id?: number; session_id?: number | null; status: string; label: string; rule_id: string; agent_id: string; scope: Scope; program: string | null; alert_id: string | null; alert_ts: string | null; until: string; vuln_cve?: string | null; vuln_package?: string | null; alert?: any | null; created_at?: string }
export type HandleState = { state: "done" | "investigating"; h: Handling } | null;
export const SCOPE_JA: Record<Scope, string> = { agent: "この端末だけ", program: "同じプログラム・全端末", rule: "このルール・全端末" };

export const loadHandling = () => api.get<{ items: Handling[] }>("/alerts/handling").then((r) => r.items);

/** アラートの「プログラム名」（Sysmon の image、無ければ parentImage のファイル名・小文字） */
export function programOf(a: any): string | null { const img = a?.data?.win?.eventdata?.image ?? a?.data?.win?.eventdata?.parentImage; return img ? String(img).split(/[\\/]/).pop()!.toLowerCase() : null; }

/** 対応状況: 完了した Sidekick 調査 / 手動マークがあれば「対応済み」、進行中なら「調査中」。
 *  範囲: agent=同じ端末, program=同じルール＋同じプログラム（端末問わず）, rule=同じルール（端末問わず）。
 *  完了時刻より後に発生した同種アラートは未対応に戻る（対処が効いていない証拠になる）。 */
/** マーク（または比較元アラート）の範囲にアラート a が入るか。
 *  EDR-80: 脆弱性アラートは rule.id ではなく CVE + パッケージで一致させる（範囲 agent=この端末, rule=全端末）。CVE を持たない古いマークはどの脆弱性にも一致しない（パッケージ不明の旧マークは CVE＋端末で一致）。 */
export function scopeMatch(a: any, h: Pick<Handling, "rule_id" | "agent_id" | "scope" | "program" | "vuln_cve" | "vuln_package">): boolean {
  const rid = String(a?.rule?.id), aid = String(a?.agent?.id ?? ""), prog = programOf(a);
  if (h.rule_id !== rid) return false;
  const vi = vulnOf(a);
  if (vi) return !!h.vuln_cve && h.vuln_cve.toUpperCase() === vi.cve && (!h.vuln_package || h.vuln_package.toLowerCase() === vi.package) && (h.scope === "rule" || h.agent_id === aid);
  return h.scope === "rule" || (h.scope === "program" ? !!prog && h.program === prog : h.agent_id === aid);
}

export function handlingOf(a: any, items: Handling[]): HandleState {
  const ts = new Date(a.timestamp).getTime();
  const inScope = (h: Handling) => scopeMatch(a, h);
  const cands = items.filter((h) => inScope(h) && (h.alert_id && h.scope === "agent" ? h.alert_id === a._id : ts <= new Date(h.until).getTime() + 60_000));
  const done = cands.find((h) => h.status === "done"); if (done) return { state: "done", h: done };
  const run = items.find((h) => h.kind === "session" && inScope(h) && ["running", "waiting_approval", "waiting_user", "waiting_external"].includes(h.status));
  return run ? { state: "investigating", h: run } : null;
}
