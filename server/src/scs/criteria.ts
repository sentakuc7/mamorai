/**
 * EDR-174（SCS P1-2）: 評価基準マスタ。
 * 本文は IPA の配布物（SCS-400 ★3・★4 要求事項・評価基準、Excel）を MamorAI が取り込み時にダウンロードして DB に入れる。
 * リポジトリには IPA の本文を同梱しない（公開リポジトリでの再配布を避ける）。ここに置くのは MamorAI 側の対応付けだけ。
 * 件数（Ver.1.1）: 評価基準 153（★3 81 / ★4 72）、要求事項 43（★3 を含むもの 26）— 2026-11-09 に IPA の Excel で確認。
 */
import JSZip from "jszip";
import type { Ctx } from "../api/context.js";

export const IPA_CRITERIA_URL = "https://www.ipa.go.jp/security/scs/rcu1hd0000007a2i-att/SCS-400-criteria-v1.1.xlsx";
export const EXPECTED: Record<string, { total: number; star3: number; star4: number; requirements: number }> = { "Ver.1.1": { total: 153, star3: 81, star4: 72, requirements: 43 } };

/** MamorAI での扱い（指示書 §2）。ここに無い評価基準は C（対象外）。feature は画面に出す説明 */
export const MAPPING: Record<string, { mode: "A" | "B"; feature: string }> = {
  // ★3
  "3-1-1-1": { mode: "A", feature: "資産台帳（PC の製造元・OS・台数）" },
  "3-1-1-2": { mode: "A", feature: "資産台帳（サーバ・ハイパーバイザ）" },
  "3-1-1-3": { mode: "B", feature: "パッチ適用ルール（14日 SLA の設定）を文書として出力" },
  "3-1-1-4": { mode: "A", feature: "脆弱性台帳の SLA 遵守率（年次点検）" },
  "3-1-2-1": { mode: "B", feature: "資産台帳の手入力（ネットワーク）" },
  "3-1-2-2": { mode: "B", feature: "資産台帳の手入力（NW 機器の製造元・モデル・保守事業者）" },
  "4-1-1-3": { mode: "A", feature: "長期未ログオンのアカウント検知" },
  "4-1-2-5": { mode: "A", feature: "ローカル管理者の棚卸し" },
  "4-1-2-6": { mode: "A", feature: "長期未ログオンのアカウント検知" },
  "4-1-4-1": { mode: "A", feature: "SCA（ログオン試行の制限）" },
  "4-1-4-2": { mode: "A", feature: "SCA（PIN・パスワードの長さ）" },
  "4-4-1-1": { mode: "A", feature: "許可ソフト一覧との突き合わせ" },
  "4-4-1-2": { mode: "A", feature: "SCA（外部媒体の自動実行の無効化）" },
  "4-4-1-3": { mode: "B", feature: "設定変更の検知と承認記録" },
  "4-4-4-1": { mode: "A", feature: "サポート切れ（EOL）の検知" },
  "4-4-4-2": { mode: "A", feature: "脆弱性台帳＋14日 SLA" },
  "4-4-5-1": { mode: "A", feature: "マルウェア対策ソフトの導入状況" },
  "4-4-5-3": { mode: "A", feature: "定義ファイルの更新日の監視" },
  "5-1-1-1": { mode: "A", feature: "Wazuh の検知・自動対処の稼働状況" },
  "5-1-1-2": { mode: "A", feature: "AI トリアージと判断記録" },
  "5-1-1-3": { mode: "A", feature: "速報レポートの作成・通知" },
  "6-1-1-5": { mode: "A", feature: "インシデント報告のテンプレート" },
  // ★4
  "1-2-2-1": { mode: "A", feature: "脅威情報フィード（KEV / IPA / JPCERT）" },
  "1-2-2-2": { mode: "A", feature: "Wazuh の相関ルール＋AI 分析" },
  "3-1-1-5": { mode: "B", feature: "資産台帳の手入力（スマートデバイス）" },
  "3-1-1-6": { mode: "A", feature: "SCA 結果のスナップショット" },
  "3-1-1-7": { mode: "B", feature: "資産台帳の年次点検" },
  "3-1-2-3": { mode: "B", feature: "ネットワーク図の添付と点検記録" },
  "3-1-2-4": { mode: "B", feature: "ネットワーク図の年次点検" },
  "3-2-1-1": { mode: "B", feature: "脆弱性管理手順書の出力" },
  "3-2-1-2": { mode: "B", feature: "脆弱性管理手順書の出力" },
  "3-2-1-3": { mode: "B", feature: "脆弱性管理手順書の出力" },
  "3-2-1-4": { mode: "A", feature: "脆弱性台帳（残存状況）" },
  "3-2-1-5": { mode: "A", feature: "月次点検レポート（脆弱性）" },
  "4-1-7-6": { mode: "A", feature: "重要サーバの認証ログ集計" },
  "4-4-1-4": { mode: "A", feature: "SCA（不要なサービス・プロトコル）" },
  "4-4-1-5": { mode: "A", feature: "SCA（デフォルトユーザ ID の停止）" },
  "4-4-2-1": { mode: "A", feature: "サポート切れ（EOL）の検知と更改計画" },
  "4-4-3-1": { mode: "A", feature: "ログ保管 180 日のチェック" },
  "4-4-3-2": { mode: "B", feature: "MamorAI 自身の MFA" },
  "4-4-3-3": { mode: "A", feature: "認証ログの月次レポート" },
  "4-4-4-3": { mode: "B", feature: "境界機器台帳と JVN / NVD の突き合わせ" },
  "4-5-1-8": { mode: "A", feature: "SCA（ソフトウェア FW の有効化）" },
  "5-1-2-1": { mode: "A", feature: "許可ソフト一覧" },
  "5-1-2-2": { mode: "A", feature: "許可ソフト一覧の年次点検" },
  "5-1-2-3": { mode: "A", feature: "Defender のリアルタイム保護の状態" },
  "5-2-1-1": { mode: "A", feature: "インシデントレベルの対応付け" },
  "5-2-1-2": { mode: "A", feature: "アラートのレベル判定" },
};

export interface CriteriaRow { criteria_no: string; source_version: string; requirement_no: string; level: string; title: string; body: string; nist_function: string | null; mamorai_mode: "A" | "B" | "C"; mamorai_feature: string | null; annual_check: boolean }

// ---- xlsx（jszip で sharedStrings と sheet1 を読むだけの最小パーサ）----
const unxml = (s: string) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#10;/g, "\n").replace(/&#13;/g, "").replace(/&amp;/g, "&");
function colIndex(ref: string): number { const l = ref.match(/^[A-Z]+/)![0]; let n = 0; for (const c of l) n = n * 26 + (c.charCodeAt(0) - 64); return n - 1; }
export async function readSheet(buf: Buffer | Uint8Array): Promise<(string | null)[][]> {
  const zip = await JSZip.loadAsync(buf);
  const ssx = (await zip.file("xl/sharedStrings.xml")?.async("string")) ?? "";
  // <rPh>（ふりがな）は本文ではないので除く
  const shared = [...ssx.matchAll(/<si>([\s\S]*?)<\/si>/g)].map((m) => unxml([...m[1].replace(/<rPh[\s\S]*?<\/rPh>/g, "").matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map((t) => t[1]).join("")));
  const sheetName = Object.keys(zip.files).filter((f) => /^xl\/worksheets\/sheet\d+\.xml$/.test(f)).sort()[0];
  const sx = await zip.file(sheetName)!.async("string");
  const rows: (string | null)[][] = [];
  for (const r of sx.matchAll(/<row[^>]*>([\s\S]*?)<\/row>/g)) {
    const row: (string | null)[] = [];
    for (const c of r[1].matchAll(/<c r="([A-Z]+\d+)"([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const i = colIndex(c[1]); const attrs = c[2]; const inner = c[3] ?? "";
      const v = inner.match(/<v>([\s\S]*?)<\/v>/)?.[1]; const is = inner.match(/<is>([\s\S]*?)<\/is>/)?.[1];
      let val: string | null = null;
      if (/t="s"/.test(attrs) && v !== undefined) val = shared[Number(v)] ?? null;
      else if (is) val = unxml([...is.matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map((t) => t[1]).join(""));
      else if (v !== undefined) val = unxml(v);
      row[i] = val;
    }
    rows.push(row);
  }
  return rows;
}

/** SCS-400 の Excel → 評価基準の行。列: 大分類No, 大分類, 中分類No, 中分類, 要求事項No, ★3, ★4, 要求事項名, 要求事項, ★3/★4, 評価基準No, 評価基準, NIST CSF */
export function parseCriteria(rows: (string | null)[][]): { version: string; items: CriteriaRow[] } {
  const title = rows.flat().find((x) => x && /要求事項・評価基準\s*\(?（?Ver\.?\s*\d/.test(x)) ?? "";
  const version = title.match(/Ver\.?\s*(\d+\.\d+)/)?.[1] ? `Ver.${title.match(/Ver\.?\s*(\d+\.\d+)/)![1]}` : "unknown";
  const head = rows.findIndex((r) => r.includes("評価基準No.") || r.some((c) => c === "評価基準No."));
  if (head < 0) throw new Error("見出し行（評価基準No.）が見つかりません。Excel の様式が変わった可能性があります");
  const h = rows[head]; const ix = (name: string) => h.findIndex((c) => c === name);
  const col = { req: ix("要求事項No."), reqName: ix("要求事項名"), level: ix("★3/★4"), no: ix("評価基準No."), body: ix("評価基準"), nist: h.findIndex((c) => !!c && /NIST/.test(c)) };
  if (Object.values(col).some((i) => i < 0)) throw new Error(`列が見つかりません: ${JSON.stringify(col)}`);
  const raw = rows.slice(head + 1).filter((r) => r[col.no] && /^\d+-\d+-\d+-\d+$/.test(String(r[col.no]).trim()));
  // 年次点検の対象（1-4-1-1 の本文に列挙される No.）
  const annualBody = raw.find((r) => String(r[col.no]).trim() === "1-4-1-1")?.[col.body] ?? "";
  const annual = new Set([...annualBody.matchAll(/(\d+-\d+-\d+-\d+)/g)].map((m) => m[1]));
  const items: CriteriaRow[] = raw.map((r) => {
    const no = String(r[col.no]).trim(); const m = MAPPING[no];
    return { criteria_no: no, source_version: version, requirement_no: String(r[col.req] ?? "").trim(), level: String(r[col.level] ?? "").trim(), title: String(r[col.reqName] ?? "").trim(), body: String(r[col.body] ?? "").trim(), nist_function: r[col.nist] ? String(r[col.nist]).trim() : null, mamorai_mode: m?.mode ?? "C", mamorai_feature: m?.feature ?? null, annual_check: annual.has(no) };
  });
  return { version, items };
}

export async function importCriteria(ctx: Ctx, url = IPA_CRITERIA_URL): Promise<{ version: string; total: number; star3: number; star4: number; requirements: number; expected: boolean | null }> {
  const r = await fetch(url, { signal: AbortSignal.timeout(60_000), headers: { "User-Agent": "MamorAI-SCS" } });
  if (!r.ok) throw new Error(`IPA からダウンロードできません（HTTP ${r.status}）`);
  const { version, items } = parseCriteria(await readSheet(Buffer.from(await r.arrayBuffer())));
  const star3 = items.filter((i) => i.level === "★3").length, star4 = items.filter((i) => i.level === "★4").length;
  const requirements = new Set(items.map((i) => i.requirement_no)).size;
  const exp = EXPECTED[version];
  const expected = exp ? exp.total === items.length && exp.star3 === star3 && exp.star4 === star4 && exp.requirements === requirements : null;
  if (exp && !expected) throw new Error(`件数が合いません（${version}: 評価基準 ${items.length}・★3 ${star3}・★4 ${star4}・要求事項 ${requirements}）。取り込みを中止しました`);
  await ctx.db.transaction(async (trx) => {
    await trx("scs_criteria").where({ source_version: version }).delete();
    for (let i = 0; i < items.length; i += 50) await trx("scs_criteria").insert(items.slice(i, i + 50));
  });
  await ctx.db("app_flags").where({ key: "scs_criteria_version" }).delete();
  await ctx.db("app_flags").insert({ key: "scs_criteria_version", value: version });
  return { version, total: items.length, star3, star4, requirements, expected };
}

/** 使っている版（最後に取り込んだもの） */
export async function currentVersion(ctx: Ctx): Promise<string | null> {
  return (await ctx.db("app_flags").where({ key: "scs_criteria_version" }).first())?.value ?? null;
}
