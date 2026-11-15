/* EDR-172: the 14 states a session card shows (derived on the server from approvals / host actions / schedules) */
export interface SessionDisplay { key: string; note: string | null; extra: string[] }
export const DISPLAY_JA: Record<string, string> = {
  investigating: "調査中", waiting_user: "返答待ち", waiting_approval: "承認待ち", executing: "実行中", scheduled: "予約済み",
  reboot_wait: "再起動待ち", unconfirmed: "確認待ち", contained: "遮断中", monitoring: "定期確認中", waiting_external: "対応待ち",
  done: "完了", failed: "失敗", rejected: "却下", cancelled: "中止",
};
export const DISPLAY_COLOR: Record<string, string> = {
  investigating: "#5AB0FF", waiting_user: "#3CCB8C", waiting_approval: "#F5C542", executing: "#38BDF8", scheduled: "#C4B5FD",
  reboot_wait: "#FB923C", unconfirmed: "#93C5FD", contained: "#F2555A", monitoring: "#2DD4BF", waiting_external: "#A78BFA",
  done: "#7F8BA6", failed: "#F2555A", rejected: "#94A3B8", cancelled: "#7F8BA6",
};
export const DISPLAY_TIP: Record<string, string> = {
  investigating: "AI が調べています", waiting_user: "AI があなたの返事を待っています", waiting_approval: "承認カードが未処理です",
  executing: "承認した変更を実行中です", scheduled: "承認済み・指定の時刻に実行します", reboot_wait: "再起動の予約中、または利用者が延期中です",
  unconfirmed: "端末に送りましたが、結果がまだ届いていません", contained: "インターネット通信遮断（Contain）が有効なままです",
  monitoring: "スケジュール（定期確認）が動いています", waiting_external: "人の作業（パックの入れ直しなど）待ちです",
  done: "終わりました", failed: "実行に失敗しました。中身を確認してください", rejected: "承認カードを却下して止まりました", cancelled: "止めました",
};
const LEGACY: Record<string, string> = { running: "investigating" };
/** key to show; falls back to the stored status for old servers */
export function displayKey(x: { status: string; display?: SessionDisplay | null }): string { return x.display?.key ?? LEGACY[x.status] ?? x.status; }
export const PULSE = new Set(["investigating", "executing", "reboot_wait"]);
