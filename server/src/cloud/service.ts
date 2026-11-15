/** クラウド管理のサービス層: プロバイダの復元・台帳同期・ホスト突合・操作実行（承認後に decide() から呼ばれる）。 */
import type { Knex } from "knex";
import type { SecretBox } from "../crypto/index.js";
import { j, pj } from "../db/index.js";
import { buildProvider, type CloudProvider, type Instance, type OpResult, type PowerOp } from "./index.js";

export function providerFor(box: SecretBox, row: any): CloudProvider {
  const secret = row.secret_enc ? JSON.parse(box.decrypt(row.secret_enc)) : {};
  return buildProvider(row.kind, pj(row.config) ?? {}, secret);
}

export function pubProvider(row: any, counts?: Record<number, number>) {
  const cfg = pj<any>(row.config) ?? {};
  return { id: row.id, kind: row.kind, name: row.name, config: cfg, capability: row.capability, status: row.status, last_error: row.last_error, last_sync_at: row.last_sync_at, created_at: row.created_at, has_secret: !!row.secret_enc, instances: counts?.[row.id] ?? 0 };
}
export function pubInstance(row: any, provider?: any) {
  return { ...row, tags: pj(row.tags) ?? {}, raw: pj(row.raw) ?? {}, provider_kind: provider?.kind, provider_name: provider?.name };
}

/** 台帳同期: プロバイダから一覧を取り、cloud_instances を upsert。消えたものは削除。ホスト/エージェントとの突合も行う。 */
export async function syncProvider(db: Knex, box: SecretBox, providerId: number, agents: { name: string; ip: string | null }[] = []): Promise<{ count: number; linked: number }> {
  const row = await db("cloud_providers").where({ id: providerId }).first();
  if (!row) throw Object.assign(new Error("provider not found"), { status: 404 });
  let list: Instance[];
  try { list = await providerFor(box, row).list(); }
  catch (e: any) { await db("cloud_providers").where({ id: providerId }).update({ status: "error", last_error: String(e.message).slice(0, 500), updated_at: db.fn.now() }); throw e; }
  const hosts = await db("hosts").select("id", "name", "address", "agent_id");
  const seen: string[] = []; let linked = 0;
  for (const i of list) {
    const key = `${i.service}:${i.external_id}`; seen.push(key);
    const ips = [i.public_ip, i.private_ip].filter(Boolean) as string[];
    const host = hosts.find((h: any) => ips.includes(h.address) || h.name.toLowerCase() === i.name.toLowerCase());
    const agent = agents.find((a) => (a.ip && ips.includes(a.ip)) || a.name.toLowerCase() === i.name.toLowerCase());
    if (host || agent) linked++;
    const data = { service: i.service, external_id: i.external_id, name: i.name, state: i.state, public_ip: i.public_ip, private_ip: i.private_ip, region: i.region, zone: i.zone, machine_type: i.machine_type, os: i.os, tags: j(i.tags), raw: j(i.raw), seen_at: db.fn.now() };
    const ex = await db("cloud_instances").where({ provider_id: providerId, service: i.service, external_id: i.external_id }).first();
    if (ex) await db("cloud_instances").where({ id: ex.id }).update({ ...data, host_id: ex.host_id ?? host?.id ?? null, agent_name: ex.agent_name ?? agent?.name ?? null });
    else await db("cloud_instances").insert({ provider_id: providerId, ...data, host_id: host?.id ?? null, agent_name: agent?.name ?? null });
  }
  const all = await db("cloud_instances").where({ provider_id: providerId });
  for (const r of all) if (!seen.includes(`${r.service}:${r.external_id}`)) await db("cloud_instances").where({ id: r.id }).delete();
  await db("cloud_providers").where({ id: providerId }).update({ status: "ok", last_error: null, last_sync_at: db.fn.now(), updated_at: db.fn.now() });
  return { count: list.length, linked };
}

export interface CloudAction { provider_id: number; instance_id: number; op: "snapshot" | "power" | "isolate"; params?: { name?: string; power?: PowerOp; allow_cidrs?: string[] } }

/** 承認済みクラウド操作の実行 */
export async function executeCloudAction(db: Knex, box: SecretBox, action: CloudAction): Promise<OpResult & { instance: string }> {
  const row = await db("cloud_providers").where({ id: action.provider_id }).first();
  const inst = await db("cloud_instances").where({ id: action.instance_id, provider_id: action.provider_id }).first();
  if (!row || !inst) throw new Error("provider or instance not found");
  const cap = row.capability as string;
  if (cap === "inventory") throw new Error("このプロバイダは台帳のみ（capability=inventory）です");
  if (action.op === "isolate" && cap !== "isolate") throw new Error("このプロバイダでは隔離が許可されていません（capability=isolate が必要）");
  const p = providerFor(box, row);
  const i: Instance = { service: inst.service, external_id: inst.external_id, name: inst.name, state: inst.state, public_ip: inst.public_ip, private_ip: inst.private_ip, region: inst.region, zone: inst.zone, machine_type: inst.machine_type, os: inst.os, tags: pj(inst.tags) ?? {}, raw: pj(inst.raw) ?? {} };
  let r: OpResult;
  if (action.op === "snapshot") r = await p.snapshot(i, action.params?.name ?? `edr-${i.name}-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "")}`);
  else if (action.op === "power") r = await p.power(i, action.params?.power ?? "reboot");
  else r = await p.isolate(i, action.params?.allow_cidrs ?? []);
  return { ...r, instance: `${row.name} / ${i.name}` };
}

export const OP_JA: Record<string, string> = { snapshot: "スナップショットを作成", power: "電源操作", isolate: "ネットワーク隔離" };
export function describeAction(a: CloudAction, providerName: string, instName: string): string {
  if (a.op === "snapshot") return `${providerName}: ${instName} のスナップショットを作成（${a.params?.name ?? "自動命名"}）`;
  if (a.op === "power") return `${providerName}: ${instName} を ${({ start: "起動", stop: "停止", reboot: "再起動" } as any)[a.params?.power ?? "reboot"]}`;
  return `${providerName}: ${instName} をネットワーク隔離（許可: ${(a.params?.allow_cidrs ?? []).join(", ") || "なし"}）`;
}
