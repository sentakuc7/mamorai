import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import knex from "knex";
import path from "node:path";
import { readSheet, parseCriteria, MAPPING } from "./criteria.js";
import { eolOf, evaluateAll } from "./evaluate.js";

/** IPA の Excel と同じ形（共有文字列＋ふりがな rPh）の小さな xlsx を作る */
async function xlsx(rows: (string | null)[][]): Promise<Buffer> {
  const strings: string[] = []; const si = (s: string) => { let i = strings.indexOf(s); if (i < 0) { strings.push(s); i = strings.length - 1; } return i; };
  const col = (i: number) => String.fromCharCode(65 + i);
  const sheet = rows.map((r, ri) => `<row r="${ri + 1}">${r.map((c, ci) => (c == null ? "" : `<c r="${col(ci)}${ri + 1}" t="s"><v>${si(c)}</v></c>`)).join("")}</row>`).join("");
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const zip = new JSZip();
  zip.file("xl/sharedStrings.xml", `<sst>${strings.map((s) => `<si><r><t>${esc(s)}</t></r><rPh sb="0" eb="1"><t>フリガナ</t></rPh></si>`).join("")}</sst>`);
  zip.file("xl/worksheets/sheet1.xml", `<worksheet><sheetData>${sheet}</sheetData></worksheet>`);
  return zip.generateAsync({ type: "nodebuffer" });
}
const H = [null, "大分類No.", "大分類", "中分類No.", "中分類", "要求事項No.", "★3", "★4", "要求事項名", "要求事項", "★3/★4", "評価基準No.", "評価基準", "NIST CSFにおける機能"];
const row = (no: string, lv: string, body: string) => [null, no[0], "x", no.slice(0, 3), "y", no.slice(0, 5), "〇", "〇", "要求事項名" + no.slice(0, 5), "本文", lv, no, body, "識別"];

describe("EDR-174 評価基準マスタの取り込み", () => {
  it("見出し行を探し、ふりがなを除き、年次点検の対象を拾う", async () => {
    const buf = await xlsx([["サプライチェーン強化に向けたセキュリティ対策評価制度 ★3・★4 要求事項・評価基準 (Ver.1.1)"], [], H,
      row("1-4-1-1", "★3", "年次で点検する（3-1-1-1、4-4-4-2 を含む）"), row("3-1-1-1", "★3", "PC の台帳"), row("4-4-4-2", "★3", "14 日以内に適用"), row("9-9-9-9", "★4", "対応付けなし"),
      [null, "注記", null, null, null, null, null, null, null, null, null, "※補足", "番号ではない行"]]);
    const { version, items } = parseCriteria(await readSheet(buf));
    expect(version).toBe("Ver.1.1");
    expect(items.map((i) => i.criteria_no)).toEqual(["1-4-1-1", "3-1-1-1", "4-4-4-2", "9-9-9-9"]);
    expect(items[1]).toMatchObject({ requirement_no: "3-1-1", level: "★3", title: "要求事項名3-1-1", body: "PC の台帳", nist_function: "識別", mamorai_mode: "A", annual_check: true });
    expect(items[1].body).not.toContain("フリガナ");
    expect(items[3]).toMatchObject({ mamorai_mode: "C", mamorai_feature: null, annual_check: false });
  });
  it("様式が変わったら止める", async () => {
    await expect(async () => parseCriteria(await readSheet(await xlsx([["表題"], ["列名が違う"]])))).rejects.toThrow(/見出し行/);
  });
  it("対応付けの番号は全部 4 階層", () => {
    for (const k of Object.keys(MAPPING)) expect(k).toMatch(/^\d+-\d+-\d+-\d+$/);
  });
});

describe("EDR-174 サポート期限（4-4-4-1）", () => {
  it("OS 名と版から期限を引く", () => {
    expect(eolOf("Microsoft Windows Server 2012 R2 Standard", "6.3.9600")).toMatchObject({ label: "Windows Server 2012 / 2012 R2", expired: true });
    expect(eolOf("Microsoft Windows 11 Pro", "10.0.26100.6899")).toMatchObject({ end: "2026-10-13" });
    expect(eolOf("Microsoft Windows 11 Enterprise", "10.0.26100.1")).toMatchObject({ end: "2027-10-12" });
    expect(eolOf("Microsoft Windows 10 Enterprise LTSC 2021", "10.0.19044.1")).toMatchObject({ end: "2027-01-12" });
    expect(eolOf("Microsoft Windows 10 Pro", "10.0.19045.1")).toMatchObject({ expired: true });
    expect(eolOf("Ubuntu", "22.04.5 LTS (Jammy Jellyfish)")).toMatchObject({ end: "2027-06-01" });
    expect(eolOf("Amazon Linux", "2023")).toMatchObject({ label: "Amazon Linux 2023" });
    expect(eolOf("Amazon Linux", "2")).toMatchObject({ label: "Amazon Linux 2" });
    expect(eolOf("FreeBSD", "14.1")).toBeNull();
  });
});

describe("EDR-174 評価（根拠の無い適合を出さない）", () => {
  it("データが無いときは要対応・未接続", async () => {
    const db = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
    await db.migrate.latest({ directory: path.resolve("src/db/migrations"), loadExtensions: [".ts"] });
    const ev = await evaluateAll({ db } as any);
    expect(ev["3-1-1-1"].state).toBe("要対応");
    expect(ev["4-4-4-2"].state).toBe("未接続");
    expect(ev["1-2-2-1"].state).toBe("未接続");
    expect(ev["5-1-1-1"].state).toBe("要対応");
    await db("scs_assets").insert({ source: "manual", name: "pc1", category: "pc", manufacturer: "FUJITSU", os_name: "Microsoft Windows 11 Pro", os_version: "10.0.26200.1" });
    const ev2 = await evaluateAll({ db } as any);
    expect(ev2["3-1-1-1"].state).toBe("適合");
    expect(ev2["4-4-4-1"].state).toBe("適合");
    await db.destroy();
  });
});
