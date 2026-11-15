import type { Knex } from "knex";
/**
 * EDR-173（SCS P1-1）: SCS評価制度★3・★4 の証跡用テーブル。
 *
 * 方針（2026-11-09 決定）: 脆弱性は「重ね書き方式」。
 *   - 脆弱性そのものの正は Wazuh indexer（wazuh-states-vulnerabilities-*）。MamorAI は全件をコピーしない。
 *   - MamorAI が持つのは、14日 SLA の候補（Critical / High / 深刻度不明 / CVSS 7.0 以上、境界機器は全件）について
 *     判定結果・期限・状態・計画・緩和策・起点日の根拠・解消日と、その変更履歴だけ。
 *   - Medium / Low（P3）は台帳に行を作らず、画面では indexer から直接表示する。人が状態を付けた時点で行を作る。
 *   - 取り込みのたびに last_seen_at を更新し、前回あって今回無い行を「適用済」（resolved_at）にする。
 * 文言（状態・緩和策の種類）は SCS-410 / 解説書の用語に合わせて日本語のまま保存する（帳票にそのまま出すため）。
 */
export async function up(db: Knex): Promise<void> {
  // ---- 評価基準マスタ（IPA Excel「要求事項・評価基準」から取り込む。版ごとに保持）----
  await db.schema.createTable("scs_criteria", (t) => {
    t.string("criteria_no", 16).notNullable();        // '4-4-4-2'
    t.string("source_version", 16).notNullable();     // 'Ver.1.1'
    t.string("requirement_no", 16).notNullable();     // '4-4-4'
    t.string("level", 4).notNullable();               // ★3 | ★4
    t.text("title").notNullable();
    t.text("body").notNullable();
    t.string("nist_function", 32);
    t.string("mamorai_mode", 1).notNullable();        // A（自動証跡）| B（半自動）| C（対象外）
    t.text("mamorai_feature");                        // 対応する MamorAI 機能（画面に出す説明）
    t.boolean("annual_check").notNullable().defaultTo(false); // 1-4-1-1 で年次点検の対象に挙がっているか
    t.primary(["criteria_no", "source_version"]);
  });

  // ---- 資産台帳（Wazuh のエージェント＋手入力の機器）----
  await db.schema.createTable("scs_assets", (t) => {
    t.increments("id").primary();
    t.string("source", 8).notNullable();              // wazuh | manual
    t.integer("host_id").references("id").inTable("hosts").onDelete("SET NULL"); // MamorAI のホスト（あれば）
    t.integer("wazuh_instance_id");
    t.string("agent_id", 16);
    t.string("name", 255).notNullable();
    t.string("category", 16).notNullable();           // pc | server | hypervisor | smart_device | network_device | other
    t.string("category_source", 8).notNullable().defaultTo("auto"); // auto（OS から判定）| manual（画面で上書き）
    t.string("manufacturer", 255);
    t.string("model", 255);
    t.string("serial", 128);
    t.string("os_name", 255);
    t.string("os_version", 128);
    t.string("firmware", 128);                        // 境界機器・NW 機器のファームウェア版
    t.timestamp("firmware_checked_at", { useTz: true }); // Sophos XG は XML API で自動取得した日時
    t.string("location", 255);
    t.text("purpose");
    t.string("maintainer", 255);                      // 保守事業者（3-1-2-2）
    t.boolean("is_boundary").notNullable().defaultTo(false); // インターネットとの境界にある機器（4-4-4-2 / 4-4-4-3）
    t.boolean("important_system").notNullable().defaultTo(false); // 重要システムの機器（★4: 3-1-1-6 / 4-1-7-6）
    t.text("cpe");                                    // JVN / NVD 照合用（カンマ区切りで複数可）
    t.integer("open_ports");                          // 公開ポート数（★4 技術検証の候補選定）
    t.boolean("in_scope").notNullable().defaultTo(true);
    t.text("out_of_scope_reason");
    t.timestamp("first_seen_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.timestamp("last_seen_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.timestamp("removed_at", { useTz: true });       // Wazuh から消えた日（台帳には残す。年次点検の差分に使う）
    t.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.unique(["wazuh_instance_id", "agent_id"]);
    t.index(["category"]);
  });

  // ---- 脆弱性台帳（重ね書き: SLA 候補と、人が状態を付けた行だけ）----
  await db.schema.createTable("scs_vulns", (t) => {
    t.increments("id").primary();
    t.integer("asset_id").notNullable().references("id").inTable("scs_assets").onDelete("CASCADE");
    t.string("cve_id", 32).notNullable();
    t.string("package_name", 255).notNullable();      // 端末×パッケージ×CVE で 1 行（版は下の列。更新で変わる）
    t.string("package_version", 128);
    // 判定（取り込みのたびに再計算。manual のものは上書きしない）
    t.string("target_class", 24).notNullable().defaultTo("undetermined"); // pc_os | pc_browser | pc_office | server_os | server_middleware | smart_os | smart_app | boundary_fw | other | undetermined
    t.string("target_class_source", 8).notNullable().defaultTo("auto");  // auto（辞書）| manual（画面で決めた）
    t.string("severity_vendor", 16);                  // Critical | High | Medium | Low | -（不明）
    t.decimal("cvss_base", 3, 1);
    t.string("cvss_version", 8);
    t.boolean("sla_target").notNullable().defaultTo(false); // 4-4-4-2 の14日対象
    t.boolean("exploited").notNullable().defaultTo(false);  // KEV / IPA / JPCERT に掲載
    t.string("priority", 2).notNullable().defaultTo("P3");  // P0 | P1 | P2 | P3
    t.timestamp("published_at", { useTz: true });
    t.timestamp("detected_at", { useTz: true }).notNullable();
    t.timestamp("fix_released_at", { useTz: true });  // 期限の起点（アップデートのリリース日）
    t.string("fix_released_source", 8).notNullable().defaultTo("auto"); // auto（published/detected の早い方）| manual
    t.text("fix_released_basis");                     // 起点日の根拠（ベンダー告知 URL など）
    t.timestamp("due_at", { useTz: true });
    // 人が決めること（SCS-410 の用語）
    t.string("status", 16).notNullable().defaultTo("未対応"); // 未対応 | 計画中 | 緩和策適用中 | 適用済 | 対象外
    t.timestamp("plan_due_at", { useTz: true });      // P1 の期限延長・計画中の予定日
    t.text("plan_reason");
    t.string("mitigation_type", 24);                  // 機能の無効化 | ベンダー回避策 | ネットワークからの分離 | 監視・遮断の強化 | その他
    t.text("mitigation_note");
    t.text("exclusion_reason");
    t.integer("approval_id");                         // パッチ適用を依頼した承認カード（既存の承認キュー）
    // indexer との突き合わせ
    t.timestamp("last_seen_at", { useTz: true }).notNullable().defaultTo(db.fn.now()); // 最後に indexer にあった時刻
    t.timestamp("resolved_at", { useTz: true });      // indexer から消えた（= 適用済になった）時刻
    t.timestamp("created_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.unique(["asset_id", "cve_id", "package_name"]);
    t.index(["status", "priority"]);
    t.index(["cve_id"]);
    t.index(["due_at"]);
  });

  // ---- 状態変更の履歴（解説書の「対応履歴」。自動の変更も system として残す）----
  await db.schema.createTable("scs_vuln_history", (t) => {
    t.increments("id").primary();
    t.integer("vuln_id").notNullable().references("id").inTable("scs_vulns").onDelete("CASCADE");
    t.timestamp("changed_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.string("changed_by", 64).notNullable();         // ユーザー名 | system（取り込み・自動解消）
    t.string("field", 32).notNullable().defaultTo("status"); // status | priority | due_at | target_class | fix_released_at ...
    t.text("from_value");
    t.text("to_value");
    t.text("note");
    t.index(["vuln_id"]);
  });

  // ---- 脅威情報（CVE 単位の悪用・緊急フラグ）と取り込み履歴（1-2-2-1 の証跡）----
  await db.schema.createTable("scs_threat_intel", (t) => {
    t.increments("id").primary();
    t.string("cve_id", 32).notNullable();
    t.string("source", 16).notNullable();             // CISA_KEV | IPA_ALERT | JPCERT_AT | EUVD
    t.date("listed_at");
    t.text("url");
    t.text("title");
    t.timestamp("fetched_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.unique(["cve_id", "source"]);
  });
  await db.schema.createTable("scs_feed_runs", (t) => {
    t.increments("id").primary();
    t.string("source", 16).notNullable();
    t.timestamp("started_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
    t.boolean("ok").notNullable();
    t.integer("fetched").notNullable().defaultTo(0);  // 取り込んだ CVE の件数
    t.integer("added").notNullable().defaultTo(0);    // 新しく増えた件数
    t.text("error");
  });

  // ---- 許可ソフトマスタ（P2 で使う。器だけ先に作る）----
  await db.schema.createTable("scs_software_policy", (t) => {
    t.increments("id").primary();
    t.string("name_pattern", 255).notNullable().unique();
    t.string("decision", 8).notNullable();            // 許可 | 禁止 | 未判定
    t.text("note");
    t.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(db.fn.now());
  });

  // ---- 点検記録（年次・月次の点検すべて）----
  await db.schema.createTable("scs_inspections", (t) => {
    t.increments("id").primary();
    t.string("criteria_no", 16).notNullable();        // '3-1-1-7' | '3-2-1-5' | '4-4-3-3' ...
    t.string("period_label", 32).notNullable();       // '2026-11' | '2026年度'
    t.timestamp("generated_at", { useTz: true });     // レポートを自動生成した日時
    t.timestamp("inspected_at", { useTz: true });     // 点検者が「確認済」を押した日時（未確認なら null）
    t.string("inspected_by", 64);
    t.string("result", 8);                            // 問題なし | 是正あり | 未完了
    t.text("summary");
    t.text("snapshot");                               // 点検時点の集計（JSON）。あとから数字が変わっても証跡が残る
    t.integer("attachment_id");                       // PDF などを既存の attachments に保存した場合
    t.unique(["criteria_no", "period_label"]);
  });
}

export async function down(db: Knex): Promise<void> {
  for (const t of ["scs_inspections", "scs_software_policy", "scs_feed_runs", "scs_threat_intel", "scs_vuln_history", "scs_vulns", "scs_assets", "scs_criteria"]) await db.schema.dropTableIfExists(t);
}
