import type { Knex } from "knex";
/** Binary session files (pptx) are stored base64-encoded. */
export async function up(db: Knex): Promise<void> { await db.schema.alterTable("attachments", (t) => { t.string("encoding", 8).notNullable().defaultTo("utf8"); }); }
export async function down(db: Knex): Promise<void> { await db.schema.alterTable("attachments", (t) => { t.dropColumn("encoding"); }); }
