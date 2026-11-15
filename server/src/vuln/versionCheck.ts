// EDR-81 version_check: ランタイム / ミドルウェア / OS の「サポート状況（EOL）・同系統の最新版・その版より後に出た
// セキュリティリリース・Wazuh が検出している CVE」を、LLM の知識ではなく公式データで決定的に判定する。
// 外部取得は ALLOWED_HOSTS のみ（汎用 web fetch にはしない＝プロンプトインジェクション対策）。
import { fetch as ufetch } from "undici";

export type Verdict = "eol" | "outdated" | "latest" | "unknown";

export interface VersionCheckResult {
  product: string;
  version: string;
  cycle: string | null;
  verdict: Verdict;
  confidence: "確認済み" | "未確認";
  do_not_conclude_safe: boolean;
  is_eol: boolean | null;
  eol_from: string | null;
  today: string;
  eol_status: string | null; // 「2026-04-30 に終了済み（175 日経過）」/「2027-04-30 まで（あと 190 日）」— LLM に日付計算をさせない
  latest_in_cycle: string | null;
  supported_cycles: { cycle: string; latest: string | null; eol_from: string | null }[];
  security_releases_since: { version: string; date: string }[];
  wazuh: null | { agent: string; packages: string[]; total: number; by_severity: Record<string, number>; top_cves: { cve: string; severity: string; package: string; version: string }[]; note?: string };
  summary: string;
  evidence: string[];
  error?: string;
}

interface Searcher { search(index: string, body: Record<string, unknown>, size?: number): Promise<any> }

const ALLOWED_HOSTS = new Set(["endoflife.date", "nodejs.org"]);
const TTL_MS = 6 * 60 * 60 * 1000;
const cache = new Map<string, { at: number; data: unknown }>();

/** よくある呼び名 → endoflife.date の製品 ID */
const ALIASES: Record<string, string> = {
  node: "nodejs", "node.js": "nodejs", nodejs: "nodejs",
  python3: "python", py: "python",
  postgres: "postgresql", pg: "postgresql",
  "amazon linux": "amazon-linux", amzn: "amazon-linux", al2023: "amazon-linux", al2: "amazon-linux",
  httpd: "apache-http-server", apache: "apache-http-server", apache2: "apache-http-server",
  "windows server": "windows-server", golang: "go", "mysql-server": "mysql",
};

/** Wazuh の package.name で探す名前 */
const PACKAGES: Record<string, string[]> = {
  nodejs: ["nodejs", "node"],
  python: ["python3", "python"],
  openssl: ["openssl", "libssl3", "libssl3t64", "libssl1.1"],
  postgresql: ["postgresql"],
  "apache-http-server": ["apache2", "httpd"],
  nginx: ["nginx", "nginx-core"],
  php: ["php"],
  openssh: ["openssh-server", "openssh-client", "openssh"],
};

export function normalizeProduct(p: string): string {
  const s = String(p || "").toLowerCase().trim();
  return ALIASES[s] ?? s;
}

export function normalizeVersion(v: string): string {
  const m = String(v || "").trim().replace(/^v/i, "").match(/^\d+(?:\.\d+){0,3}/);
  return m ? m[0] : "";
}

export function cmpVer(a: string, b: string): number {
  const pa = a.split(".").map((x) => parseInt(x, 10) || 0), pb = b.split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] ?? 0) - (pb[i] ?? 0); if (d) return d; }
  return 0;
}

/** 最長一致でサイクルを選ぶ（20 / 3.12 / 3.0 / 24.04 など） */
export function matchCycle<T extends { name: string }>(releases: T[], version: string): T | undefined {
  return releases
    .filter((r) => version === String(r.name) || version.startsWith(`${r.name}.`))
    .sort((a, b) => String(b.name).length - String(a.name).length)[0];
}

const dateStr = (x: unknown): string | null => (typeof x === "string" && /^\d{4}-\d{2}-\d{2}/.test(x) ? x.slice(0, 10) : null);
const today = () => new Date().toISOString().slice(0, 10);

async function getJson(url: string): Promise<any> {
  const u = new URL(url);
  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname)) throw new Error(`host not allowed: ${u.hostname}`);
  const hit = cache.get(url);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.data;
  const res = await ufetch(url, { headers: { "User-Agent": "edr-console/version-check", Accept: "application/json" }, signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`${u.hostname}${u.pathname} -> HTTP ${res.status}`);
  const data = await res.json();
  cache.set(url, { at: Date.now(), data });
  return data;
}

async function wazuhVulns(ix: Searcher, agent: string, product: string): Promise<VersionCheckResult["wazuh"]> {
  const pkgs = PACKAGES[product] ?? [product];
  const body = {
    query: { bool: {
      filter: [{ term: { "agent.name": agent } }],
      should: [{ terms: { "package.name": pkgs } }, ...pkgs.map((p) => ({ prefix: { "package.name": p } }))],
      minimum_should_match: 1,
    } },
    aggs: { sev: { terms: { field: "vulnerability.severity", size: 10 } } },
    sort: [{ "vulnerability.score.base": { order: "desc", unmapped_type: "float" } }],
    _source: ["vulnerability.id", "vulnerability.severity", "package.name", "package.version"],
  };
  const r = await ix.search("wazuh-states-vulnerabilities-*", body, 15);
  const total = typeof r?.hits?.total === "object" ? r.hits.total.value : Number(r?.hits?.total ?? 0);
  const by_severity: Record<string, number> = {};
  for (const b of r?.aggregations?.sev?.buckets ?? []) by_severity[b.key] = b.doc_count;
  const top_cves = (r?.hits?.hits ?? []).map((h: any) => ({ cve: h._source?.vulnerability?.id, severity: h._source?.vulnerability?.severity, package: h._source?.package?.name, version: h._source?.package?.version }));
  return { agent, packages: pkgs, total, by_severity, top_cves, note: total === 0 ? "Wazuh はこのパッケージの CVE を検出していない。サードパーティのリポジトリ（NodeSource 等）や手動導入のものは Wazuh が照合できないことがあるため、0 件は安全の根拠にならない" : undefined };
}

export async function versionCheck(args: { product: string; version: string; agent?: string }, ix?: Searcher | null): Promise<VersionCheckResult> {
  const product = normalizeProduct(args.product);
  const version = normalizeVersion(args.version);
  const out: VersionCheckResult = {
    product, version, cycle: null, verdict: "unknown", confidence: "未確認", do_not_conclude_safe: true,
    is_eol: null, eol_from: null, today: today(), eol_status: null, latest_in_cycle: null, supported_cycles: [], security_releases_since: [], wazuh: null, summary: "", evidence: [],
  };
  if (!/^[a-z0-9][a-z0-9.\-]{0,40}$/.test(product) || !version) {
    return { ...out, error: "invalid product or version", summary: "製品名または版が不正なため判定できない（未確認）。実機で版を取得してから呼び直すこと" };
  }

  // Wazuh（任意）: 失敗しても判定は続ける
  if (args.agent && ix) {
    try { out.wazuh = await wazuhVulns(ix, String(args.agent), product); } catch (e: any) { out.wazuh = { agent: String(args.agent), packages: [], total: 0, by_severity: {}, top_cves: [], note: `Wazuh 照会に失敗: ${e?.message ?? e}` }; }
  }

  // 1) endoflife.date
  let releases: any[] = [];
  try {
    const j = await getJson(`https://endoflife.date/api/v1/products/${encodeURIComponent(product)}`);
    releases = j?.result?.releases ?? [];
  } catch (e: any) {
    return { ...out, error: String(e?.message ?? e), summary: `${product} のサポート情報を取得できなかった（未確認）。product は endoflife.date の ID（nodejs, python, openssl, nginx, php, postgresql, ubuntu, debian, amazon-linux 等）。結論を出さないこと` };
  }
  out.evidence.push(`https://endoflife.date/${product}`);
  out.supported_cycles = releases
    .filter((r) => r.isEol !== true && r.isMaintained !== false && (dateStr(r.eolFrom) ?? "9999") > today())
    .slice(0, 6)
    .map((r) => ({ cycle: String(r.name), latest: r.latest?.name ?? null, eol_from: dateStr(r.eolFrom) }));

  const rel = matchCycle(releases.map((r) => ({ ...r, name: String(r.name) })), version);
  if (!rel) return { ...out, summary: `${product} ${version} に対応するサイクルが endoflife.date に無い（未確認）。結論を出さないこと` };

  out.cycle = String(rel.name);
  out.eol_from = dateStr(rel.eolFrom);
  out.is_eol = rel.isEol === true || (out.eol_from ? out.eol_from <= today() : false);
  out.latest_in_cycle = rel.latest?.name ?? null;
  if (out.eol_from) {
    const days = Math.round((Date.parse(out.eol_from) - Date.parse(out.today)) / 86_400_000);
    out.eol_status = days <= 0 ? `${out.eol_from} に終了済み（${-days} 日経過）` : `${out.eol_from} まで（あと ${days} 日）`;
  }
  if (rel.latest?.link) out.evidence.push(String(rel.latest.link));

  // 2) Node.js: この版の後に出たセキュリティリリース（全系統）
  if (product === "nodejs") {
    try {
      const dist: any[] = await getJson("https://nodejs.org/dist/index.json");
      const cur = dist.find((d) => String(d.version).replace(/^v/, "") === version);
      if (cur?.date) out.security_releases_since = dist.filter((d) => d.security === true && String(d.date) > String(cur.date)).map((d) => ({ version: String(d.version), date: String(d.date) })).slice(0, 20);
      out.evidence.push("https://nodejs.org/en/blog/vulnerability");
    } catch { /* EOL 判定だけで返す */ }
  }

  // 3) 判定
  const sup = out.supported_cycles.map((c) => `${c.cycle}系（最新 ${c.latest ?? "?"}、サポート終了 ${c.eol_from ?? "未定"}）`).join(" / ");
  const sec = out.security_releases_since.length ? `この版の後に出たセキュリティリリースが ${out.security_releases_since.length} 件（直近 ${out.security_releases_since[0].version} ${out.security_releases_since[0].date}）。` : "";
  const wz = out.wazuh && out.wazuh.total > 0 ? `Wazuh は ${out.wazuh.agent} でこのパッケージの CVE を ${out.wazuh.total} 件検出。` : "";
  if (out.is_eol) {
    out.verdict = "eol";
    out.summary = `${product} ${version} は ${out.cycle} 系で、サポートは${out.eol_status ?? "既に終了"}（EOL）。公式の修正はもう出ないため「リポジトリに更新が無い」は安全の根拠にならない。${sec}${wz}サポート中の系統へ更新が必要: ${sup}`;
  } else if (out.latest_in_cycle && cmpVer(version, normalizeVersion(out.latest_in_cycle)) < 0) {
    out.verdict = "outdated";
    out.summary = `${product} ${version} はサポート中（${out.cycle} 系、サポート終了 ${out.eol_from ?? "未定"}）だが、同系統の最新は ${out.latest_in_cycle}。更新が必要。${sec}${wz}`;
  } else {
    out.verdict = "latest";
    out.do_not_conclude_safe = !!(out.wazuh && out.wazuh.total > 0);
    out.summary = `${product} ${version} はサポート中の ${out.cycle} 系の最新版（サポート終了 ${out.eol_from ?? "未定"}）。${wz}`;
  }
  out.confidence = "確認済み";
  return out;
}

// ---------------------------------------------------------------------------------------------
// 発動条件: 人間の最新の発言が脆弱性 / 版 / パッチの話題のときだけ、system prompt に VULN_GUIDE を足す

const VULN_RE = /脆弱性|ぜいじゃく|CVE|EOL|サポート(終了|切れ|期限)|セキュリティ(修正|パッチ|アップデート|リリース|更新)|パッチ|アップデート|アップグレード|バージョン|最新(版|か|です|なの)|古い(版|バージョン)|更新(版|が必要|した方|すべき)|(?<![\d.])v?\d+\.\d+\.\d+(?![\d.])|vulnerab|\bpatch|outdated|end[- ]of[- ]life|upgrade|security (fix|release|update)/i;

export function isVulnQuestion(text: string | null | undefined): boolean {
  return !!text && VULN_RE.test(text);
}

export const VULN_GUIDE = `## Vulnerability / version question (auto-injected for this question)
The human's latest message is about vulnerabilities, versions, patches or support status. For THIS question follow these rules — they override your habits:
1. Get the exact installed version from the host first (ssh_exec, read-only: node -v, python3 --version, openssl version, nginx -v, dpkg -l <pkg>, rpm -q <pkg>, cat /etc/os-release). Never assume a version.
2. Call version_check(product, version, agent) for every runtime / middleware / OS involved (pass agent = the Wazuh agent name so Wazuh's CVE findings are included). Your own knowledge of release dates, latest versions and CVEs is OUTDATED — never use it to decide that a version is safe or current.
3. "The package repository has no newer version" / "apt has no update" is NOT evidence of being up to date: an EOL line simply receives no more updates.
4. verdict=eol or outdated (or do_not_conclude_safe=true) → never conclude 対応不要 / 安全. Propose upgrading to a supported line in propose_next_actions (commands + rollback; production → maintenance window; cloud VM → cloud_snapshot first) and say what depends on it (e.g. Haraka on Node.js: npm rebuild, restart, verify SMTP).
5. verdict=unknown or the tool failed → say 未確認 and do not conclude either way.
6. Dates: use eol_status as written (it is computed against today); never compute remaining support time yourself. An EOL line is already unsupported — do not write 'before EOL'.
7. Mark each conclusion 確認済み / 推定 / 未確認 and cite the evidence URLs returned by version_check. Wazuh showing 0 CVEs for a package is not proof of safety (third-party repos are often not matched).
8. (EDR-113) Before planning a package change call pkg_candidates(host, package) and base the plan on its verdict. On Amazon Linux 2023 the OS release is pinned: "dnf check-update shows nothing" only means the CURRENT release has nothing — newer releases may already ship the fix (then the plan is dnf upgrade --releasever=<release>).
9. Version numbers compare numerically (8.3.15 < 8.3.33). Never install a version lower than the one installed and never call it the fixed version; distributions do not renumber upstream versions (only the -release suffix differs).
10. Never build from source, add third-party repositories (EPEL/Remi on AL2023) or kill dnf/yum/rpm/apt/dpkg to "speed things up". Package transactions can take 20+ minutes on small hosts; mark them long: true in apply_change and let them finish.
11. If the human pointed to an advisory URL, the versions in its "Fixed in" are the truth; quote them.`;
