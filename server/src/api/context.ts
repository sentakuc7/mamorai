import type { AppConfig } from "../config/index.js";
import type { DB } from "../db/index.js";
import { SecretBox } from "../crypto/index.js";
import { Audit } from "../audit/index.js";
import { AuthService } from "../auth/index.js";
import { IndexerClient, ManagerApiClient, type WazuhConn } from "../wazuh/index.js";
import type pino from "pino";
import type { AgentRuntime } from "../runtime/index.js";
import type { Sentinel } from "../sentinel/index.js";
import type { Scheduler } from "../scheduler/index.js";

export interface Ctx {
  cfg: AppConfig;
  db: DB;
  box: SecretBox;
  audit: Audit;
  auth: AuthService;
  log: pino.Logger;
  version: string;
  runtime?: AgentRuntime;
  sentinel?: Sentinel;
  scheduler?: Scheduler;
  hostScanner?: import("../hosts/scan.js").HostScanner;
}

export async function wazuhConn(ctx: Ctx, id: number): Promise<{ row: any; conn: WazuhConn }> {
  const row = await ctx.db("wazuh_instances").where({ id }).first();
  if (!row) throw Object.assign(new Error("wazuh instance not found"), { status: 404 });
  const conn: WazuhConn = {
    indexerUrl: row.indexer_url, indexerUser: row.indexer_user, indexerPassword: ctx.box.decrypt(row.indexer_secret_enc),
    apiUrl: row.api_url, apiUser: row.api_user, apiPassword: row.api_secret_enc ? ctx.box.decrypt(row.api_secret_enc) : null,
    caPem: row.ca_pem, tlsVerify: !!row.tls_verify, apiTlsVerify: !!row.api_tls_verify,
  };
  return { row, conn };
}

export async function indexer(ctx: Ctx, id: number): Promise<IndexerClient> {
  const { conn } = await wazuhConn(ctx, id);
  return new IndexerClient(conn);
}
export async function managerApi(ctx: Ctx, id: number): Promise<ManagerApiClient> {
  const { conn } = await wazuhConn(ctx, id);
  return new ManagerApiClient(conn);
}

export function publicWazuh(row: any) {
  return {
    id: row.id, name: row.name, indexer_url: row.indexer_url, indexer_user: row.indexer_user,
    api_url: row.api_url, api_user: row.api_user, has_ca: !!row.ca_pem, tls_verify: !!row.tls_verify, api_tls_verify: !!row.api_tls_verify,
    archives_enabled: !!row.archives_enabled, notes: row.notes, created_at: row.created_at, updated_at: row.updated_at,
  };
}
