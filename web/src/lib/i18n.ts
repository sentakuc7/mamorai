const ja: Record<string, string> = {
  "nav.dashboard": "ダッシュボード", "nav.alerts": "アラート", "nav.sidekick": "Sidekick", "nav.approvals": "承認キュー", "nav.settings": "設定", "nav.audit": "監査ログ",
  "login.title": "MamorAI にログイン", "login.email": "メールアドレス", "login.password": "パスワード", "login.submit": "ログイン", "login.failed": "メールアドレスまたはパスワードが違います",
  "pw.title": "初回ログイン: パスワードを変更してください", "pw.current": "現在のパスワード", "pw.next": "新しいパスワード（12文字以上）", "pw.submit": "変更する",
  "dash.last24h": "直近 24 時間", "dash.critical": "緊急", "dash.high": "高", "dash.medium": "中", "dash.low": "低", "dash.topRules": "上位ルール", "dash.agents": "エージェント", "dash.noWazuh": "Wazuh が登録されていません。設定から追加してください。",
  "settings.wazuh": "Wazuh 接続", "settings.hosts": "対象ホスト", "settings.keys": "SSH 鍵", "settings.users": "ユーザー",
  "common.test": "接続テスト", "common.save": "保存", "common.delete": "削除", "common.add": "追加", "common.cancel": "キャンセル", "common.ok": "OK", "common.loading": "読み込み中…", "common.error": "エラー",
};
const en: Record<string, string> = {
  "nav.dashboard": "Dashboard", "nav.alerts": "Alerts", "nav.sidekick": "Sidekick", "nav.approvals": "Approvals", "nav.settings": "Settings", "nav.audit": "Audit log",
  "login.title": "Sign in to MamorAI", "login.email": "Email", "login.password": "Password", "login.submit": "Sign in", "login.failed": "Invalid email or password",
  "pw.title": "First login: please change your password", "pw.current": "Current password", "pw.next": "New password (12+ chars)", "pw.submit": "Change",
  "dash.last24h": "Last 24 hours", "dash.critical": "Critical", "dash.high": "High", "dash.medium": "Medium", "dash.low": "Low", "dash.topRules": "Top rules", "dash.agents": "Agents", "dash.noWazuh": "No Wazuh instance registered. Add one in Settings.",
  "settings.wazuh": "Wazuh connections", "settings.hosts": "Target hosts", "settings.keys": "SSH keys", "settings.users": "Users",
  "common.test": "Test connection", "common.save": "Save", "common.delete": "Delete", "common.add": "Add", "common.cancel": "Cancel", "common.ok": "OK", "common.loading": "Loading…", "common.error": "Error",
};
let dict = ja;
export function setLocale(l: string) { dict = l === "en" ? en : ja; }
export function t(k: string): string { return dict[k] ?? k; }
