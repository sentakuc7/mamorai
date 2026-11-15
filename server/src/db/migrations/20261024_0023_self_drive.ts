import type { Knex } from "knex";
/** EDR-94: how many automatic fix-and-retry attempts the approver granted for this change. */
export async function up(db: Knex): Promise<void> { await db.schema.alterTable("approvals", (t) => { t.integer("self_drive_max"); }); }
export async function down(db: Knex): Promise<void> { await db.schema.alterTable("approvals", (t) => { t.dropColumn("self_drive_max"); }); }
