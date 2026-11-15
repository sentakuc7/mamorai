import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import knex, { type Knex } from "knex";
import type { AppConfig } from "../config/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));

export type DB = Knex;

export function createDb(cfg: AppConfig): DB {
  if (cfg.DB_DRIVER === "postgres") {
    return knex({
      client: "pg",
      connection: cfg.DATABASE_URL,
      pool: { min: 1, max: 8 },
      migrations: { directory: path.join(here, "migrations"), loadExtensions: [".js", ".ts"] },
    });
  }
  fs.mkdirSync(path.dirname(cfg.DB_PATH!), { recursive: true });
  const db = knex({
    client: "better-sqlite3",
    connection: { filename: cfg.DB_PATH! },
    useNullAsDefault: true,
    pool: {
      min: 1,
      max: 1,
      afterCreate: (conn: any, done: (err: Error | null, conn: any) => void) => {
        conn.pragma("journal_mode = WAL");
        conn.pragma("foreign_keys = ON");
        conn.pragma("busy_timeout = 5000");
        done(null, conn);
      },
    },
    migrations: { directory: path.join(here, "migrations"), loadExtensions: [".js", ".ts"] },
  });
  return db;
}

export async function migrate(db: DB): Promise<void> {
  await db.migrate.latest();
}

/** JSON column helper: sqlite stores text, pg stores jsonb. */
export function j(v: unknown): string {
  return JSON.stringify(v ?? null);
}
export function pj<T = any>(v: unknown): T {
  if (v == null) return null as T;
  if (typeof v === "string") {
    try { return JSON.parse(v) as T; } catch { return v as T; }
  }
  return v as T;
}
