// EDR-114 pkg_candidates: 「このホストで、このパッケージの修正版を入れられるか」をコードで決める。
// LLM に dnf / apt の出力を読ませて判断させると、Amazon Linux 2023 のリリース固定（dnf check-update は今の
// リリースしか見ない）を見落として「修正版はまだない」と誤判定する（sidekick/33, EDR-110）。
// ここでは読み取り専用のコマンドだけを 1 回の SSH で流し、結果を構造化して判定まで返す。
import { cmpVer, normalizeVersion } from "./versionCheck.js";

export type PkgVerdict =
  | "up_to_date"          // 入っている版が修正版以上
  | "update_in_release"   // 今のリリース（今のリポジトリ設定）のままで修正版が入る
  | "needs_release_upgrade" // AL2023: 新しいリリースに修正版がある → dnf upgrade --releasever=<release>
  | "not_available"       // どのリリース / リポジトリにも修正版がない
  | "not_installed"
  | "unknown";

export interface PkgCandidatesResult {
  host: string;
  os: { id: string; version_id: string; pretty: string; release: string | null; family: "amzn" | "rhel" | "debian" | "other" };
  package: string;
  packages: { name: string; installed: string | null; current_release_candidate: string | null; latest_release_candidate: string | null }[];
  fixed_version: string | null;
  newest_release: string | null;
  verdict: PkgVerdict;
  plan_hint: string;
  long_running: boolean;
  memory_mb: { total: number; available: number; swap_used: number } | null;
  package_manager_busy: string[];
  summary: string;
  raw_errors?: string;
}

const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

/** The read-only script. Every line of output is "KEY=value" so parsing does not depend on locale or dnf version. */
export function buildScript(pkg: string): string {
  if (!SAFE_NAME.test(pkg)) throw new Error(`invalid package name: ${pkg}`);
  const P = pkg;
  return [
    `. /etc/os-release 2>/dev/null; echo "OS=$ID|$VERSION_ID|$PRETTY_NAME"`,
    `free -m 2>/dev/null | awk '/^Mem:/{print "MEM="$2"|"$7} /^Swap:/{print "SWAP="$3}'`,
    `pgrep -a -x 'dnf|yum|rpm|apt|apt-get|dpkg|unattended-upgr|packagekitd' 2>/dev/null | grep -v -e unattended-upgrade-shutdown -e 'packagekitd$' | head -5 | sed 's/^/BUSY=/'`,
    `if command -v rpm >/dev/null 2>&1; then`,
    `  echo "REL=$(rpm -q --qf '%{VERSION}' system-release 2>/dev/null | grep -v 'not installed')"`,
    // the installed packages that belong to this product: exact name, versioned stream (php8.3), and its sub-packages
    `  NAMES=$( (rpm -q --qf '%{NAME}\\n' ${P} 2>/dev/null | grep -v 'not installed'; rpm -qa --qf '%{NAME}\\n' | grep -E '^${P.replace(/[.+]/g, "\\$&")}([0-9.]*)(-(common|fpm|cli))?$') | sort -u | head -6)`,
    `  [ -z "$NAMES" ] && NAMES=${P}`,
    `  for n in $NAMES; do echo "INST=$n|$(rpm -q --qf '%{VERSION}-%{RELEASE}' $n 2>/dev/null | grep -v 'not installed')"; done`,
    `  if command -v dnf >/dev/null 2>&1; then`,
    `    dnf -q repoquery --latest-limit=1 --qf 'CUR=%{name}|%{version}-%{release}' $NAMES 2>/dev/null | grep '^CUR='`,
    `    if [ "$ID" = "amzn" ]; then`,
    `      dnf check-release-update 2>&1 | grep -oE 'Version [0-9]{4}\\.[0-9]+\\.[0-9]+' | awk '{print "NEWREL="$2}' | tail -1`,
    `      dnf -q --releasever=latest repoquery --latest-limit=1 --qf 'LATEST=%{name}|%{version}-%{release}' $NAMES 2>/dev/null | grep '^LATEST='`,
    `    fi`,
    `  fi`,
    `elif command -v dpkg-query >/dev/null 2>&1; then`,
    `  NAMES=$( (dpkg-query -W -f='\${Package}\\n' ${P} 2>/dev/null; dpkg-query -W -f='\${Package}\\n' 2>/dev/null | grep -E '^${P.replace(/[.+]/g, "\\$&")}([0-9.]*)(-(common|fpm|cli))?$') | sort -u | head -6)`,
    `  [ -z "$NAMES" ] && NAMES=${P}`,
    // apt-cache reads the local lists; refreshing them (apt-get update) is a write and is the agent's call
    `  for n in $NAMES; do echo "INST=$n|$(dpkg-query -W -f='\${Version}' $n 2>/dev/null)"; apt-cache policy $n 2>/dev/null | awk -v n=$n '/Candidate:/{print "CUR="n"|"$2}'; done`,
    `  echo "LISTS_AGE_H=$(( ( $(date +%s) - $(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0) ) / 3600 ))"`,
    `fi`,
    `true`,
  ].join("\n");
}

function upstream(v: string | null): string { return v ? normalizeVersion(v.replace(/^\d+:/, "")) : ""; }

export function parse(host: string, pkg: string, stdout: string, fixed: string | null, stderr = ""): PkgCandidatesResult {
  const lines = stdout.split("\n").map((l) => l.trim()).filter(Boolean);
  const get = (k: string) => lines.filter((l) => l.startsWith(k + "=")).map((l) => l.slice(k.length + 1));
  const [id = "", version_id = "", pretty = ""] = (get("OS")[0] ?? "").split("|");
  const family = id === "amzn" ? "amzn" : /^(rhel|centos|rocky|almalinux|fedora|ol)$/.test(id) ? "rhel" : /^(debian|ubuntu|raspbian)$/.test(id) ? "debian" : "other";
  const release = get("REL")[0] || null;
  const mem = get("MEM")[0]?.split("|").map(Number);
  const swap = Number(get("SWAP")[0] ?? 0);
  const map = new Map<string, PkgCandidatesResult["packages"][number]>();
  const ent = (n: string) => { if (!map.has(n)) map.set(n, { name: n, installed: null, current_release_candidate: null, latest_release_candidate: null }); return map.get(n)!; };
  for (const v of get("INST")) { const [n, ver] = v.split("|"); ent(n).installed = ver || null; }
  for (const v of get("CUR")) { const [n, ver] = v.split("|"); if (ver && ver !== "(none)") ent(n).current_release_candidate = ver; }
  for (const v of get("LATEST")) { const [n, ver] = v.split("|"); if (ver) ent(n).latest_release_candidate = ver; }
  const packages = [...map.values()];
  const newestRel = get("NEWREL")[0] || null;
  const busy = get("BUSY");
  const main = packages.find((p) => p.installed) ?? packages[0];
  const inst = upstream(main?.installed ?? null), cur = upstream(main?.current_release_candidate ?? null), lat = upstream(main?.latest_release_candidate ?? null);
  const fx = fixed ? normalizeVersion(fixed) : "";
  const ge = (a: string, b: string) => !!a && !!b && cmpVer(a, b) >= 0;
  // without a known fixed version, "the newest the host can get" is the target
  const target = fx || [cur, lat].filter(Boolean).sort(cmpVer).pop() || "";
  let verdict: PkgVerdict = "unknown";
  if (!main || !main.installed) verdict = "not_installed";
  else if (target && ge(inst, target) && (!lat || ge(inst, lat) || fx)) verdict = "up_to_date";
  else if (target && ge(cur, target) && cmpVer(cur, inst) > 0) verdict = "update_in_release";
  else if (family === "amzn" && target && ge(lat, target) && cmpVer(lat, inst) > 0) verdict = "needs_release_upgrade";
  else if (fx && !ge(cur, fx) && !ge(lat, fx)) verdict = "not_available";
  else if (!target) verdict = "unknown";
  const longRunning = !!mem && mem[0] < 1024;
  const names = packages.filter((p) => p.installed).map((p) => p.name).join(" ") || pkg;
  const hint: Record<PkgVerdict, string> = {
    up_to_date: `入っている版（${inst}）は${fx ? `修正版 ${fx}` : "入手できる最新"}以上。更新は不要。`,
    update_in_release: family === "debian" ? `今のリポジトリで ${cur} が入る: apt-get install --only-upgrade ${names}（long: true）→ 設定テスト → サービス再起動。` : `今のリリースで ${cur} が入る: dnf upgrade -y ${names}（long: true）→ 設定テスト → サービス再起動。`,
    needs_release_upgrade: `今のリリース（${release ?? "?"}）には無く、新しいリリースに ${lat} がある。AL2023 はリリース固定なので dnf check-update では見えない。直し方: dnf upgrade --releasever=${newestRel ?? "latest"} -y（OS 全体の更新・long: true。カーネルが変わるので再起動はメンテ枠で人と相談）。`,
    not_available: `修正版 ${fx} はまだどのリリース / リポジトリにも無い。告知の緩和策を提案し、schedule_task で 1 日ごとに pkg_candidates を再確認する。ソースビルド・外部リポジトリは使わない。`,
    not_installed: `${pkg} は入っていない。製品名ではなくパッケージ名（例: php8.3, httpd, openssl-libs）で調べ直すか、このホストは対象外。`,
    unknown: fx ? "候補版を取れなかった（ネットワーク / リポジトリの状態を確認）。結論を出さない。" : "修正版が分からない。version_check または告知で修正版を確かめてから fixed_version を渡して呼び直す。",
  };
  const r: PkgCandidatesResult = {
    host, os: { id, version_id, pretty, release, family }, package: pkg, packages, fixed_version: fx || null, newest_release: newestRel,
    verdict, plan_hint: hint[verdict], long_running: longRunning,
    memory_mb: mem ? { total: mem[0], available: mem[1], swap_used: swap } : null, package_manager_busy: busy,
    summary: `${host}: ${main?.name ?? pkg} 入っている版 ${main?.installed ?? "なし"} / 今のリリースの候補 ${main?.current_release_candidate ?? "-"}${family === "amzn" ? ` / 最新リリース${newestRel ? ` ${newestRel}` : ""}の候補 ${main?.latest_release_candidate ?? "-"}` : ""} → ${verdict}`,
  };
  if (busy.length) r.plan_hint = `パッケージ管理が実行中（${busy.join(", ")}）。終わるまで変更を始めない（kill しない）。 ` + r.plan_hint;
  if (longRunning && verdict !== "up_to_date") r.plan_hint += ` RAM ${mem![0]}MB のホスト: パッケージ処理は 10〜30 分かかることがある。`;
  if (stderr.trim()) r.raw_errors = stderr.slice(0, 1500);
  return r;
}
