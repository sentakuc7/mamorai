/**
 * EDR-121 S1: import Wazuh agents as hosts.
 *  - an agent that no host points at (hosts.agent_id) becomes an "agent_only" host (no SSH; Wazuh data + active response)
 *  - every host with an agent gets its agent state copied (status, last keep-alive, OS, version) for the list view
 * Never deletes hosts: a removed agent only shows up as "never_connected / removed" in the list.
 */
import type { Ctx } from "../api/context.js";
import { managerApi } from "../api/context.js";

export function osFamily(platform?: string | null, name?: string | null): string {
  const p = `${platform ?? ""} ${name ?? ""}`.toLowerCase();
  if (p.includes("windows")) return "windows";
  if (p.includes("darwin") || p.includes("macos")) return "darwin";
  if (p.trim()) return "linux";
  return "other";
}

const toTs = (v?: string | null) => { if (!v) return null; const d = new Date(v); return isNaN(d.getTime()) || d.getFullYear() > 9000 ? null : d; };

export async function syncAgents(ctx: Ctx): Promise<{ created: string[]; updated: number; instance: number | null }> {
  const { db } = ctx;
  const created: string[] = []; let updated = 0;
  const instances = await db("wazuh_instances").orderBy("id");
  let ignore: string[] = []; try { ignore = JSON.parse((await db("app_flags").where({ key: "host_sync_ignore" }).first())?.value ?? "[]"); } catch { ignore = []; }
  for (const wi of instances) {
    if (!wi.api_url) continue;
    let agents: any[];
    try { agents = await (await managerApi(ctx, wi.id)).agents(); }
    catch (e: any) { ctx.log.warn({ err: e.message, wazuh: wi.id }, "agent sync: Wazuh API unavailable"); continue; }
    const hosts = await db("hosts").where((q) => q.where({ wazuh_instance_id: wi.id }).orWhereNull("wazuh_instance_id"));
    for (const a of agents) {
      const id = String(a.id ?? "");
      if (!id) continue;
      const fam = osFamily(a.os?.platform, a.os?.name);
      const state = { agent_status: String(a.status ?? "").slice(0, 24) || null, agent_last_seen: toTs(a.lastKeepAlive), agent_os: [a.os?.name, a.os?.version].filter(Boolean).join(" ").slice(0, 128) || null, agent_version: String(a.version ?? "").slice(0, 32) || null, os_family: fam, agent_groups: Array.isArray(a.group) ? JSON.stringify(a.group.map(String)) : null };
      const linked = hosts.filter((h: any) => String(h.agent_id ?? "") === id);
      if (linked.length) {
        for (const h of linked) { await db("hosts").where({ id: h.id }).update({ ...state, ...(id === "000" ? { action_locked: true } : {}), ...(h.kind === "agent_only" && a.ip ? { address: String(a.ip).slice(0, 255) } : {}) }); updated++; }
        continue;
      }
      // a host with the same name but no agent id (registered by hand before) → link it instead of creating a duplicate
      const byName = hosts.find((h: any) => !h.agent_id && String(h.name).toLowerCase() === String(a.name ?? "").toLowerCase());
      if (ignore.includes(`${wi.id}:${id}`)) continue; // deleted by an admin: do not import again
      if (byName) { await db("hosts").where({ id: byName.id }).update({ ...state, agent_id: id, wazuh_instance_id: wi.id }); updated++; continue; }
      let name = String(a.name ?? `agent-${id}`).slice(0, 120);
      if (await db("hosts").where({ name }).first()) name = `${name}-${id}`;
      await db("hosts").insert({
        name, kind: "agent_only", wazuh_instance_id: wi.id, agent_id: id, address: String(a.ip ?? "").slice(0, 255) || "-", port: 22, ssh_user: "",
        sudo_mode: "none", environment: "lab", autonomy_level: Math.min(1, ctx.cfg.AUTONOMY_DEFAULT), autonomy_max: 1, tags: JSON.stringify([fam]),
        notes: null, action_locked: id === "000", ...state,
      });
      created.push(name);
    }
  }
  if (created.length) await ctx.audit.log("system", null, "host.agents_imported", { created });
  return { created, updated, instance: instances[0]?.id ?? null };
}

// ---------------- EDR-153: the "do not import again" list (filled when an admin deletes a host that has an agent) ----------------
async function readIgnore(ctx: Ctx): Promise<string[]> {
  try { return JSON.parse((await ctx.db("app_flags").where({ key: "host_sync_ignore" }).first())?.value ?? "[]"); } catch { return []; }
}
export async function listSyncIgnore(ctx: Ctx): Promise<{ key: string; wazuh_instance_id: number; agent_id: string; name: string | null; status: string | null; deleted_at: string | null }[]> {
  const keys = await readIgnore(ctx);
  if (!keys.length) return [];
  const names = new Map<string, { name: string; status: string }>();
  for (const wi of await ctx.db("wazuh_instances").whereNotNull("api_url")) {
    try { for (const a of await (await managerApi(ctx, wi.id)).agents()) names.set(`${wi.id}:${a.id}`, { name: String(a.name ?? ""), status: String(a.status ?? "") }); } catch { /* Wazuh API unavailable */ }
  }
  const out = [];
  for (const key of keys) {
    const [wi, agent] = key.split(":");
    const del = await ctx.db("audit_log").where({ event: "host.deleted" }).where("payload", "like", `%"agent_id":"${agent}"%`).orderBy("id", "desc").first().catch(() => null);
    out.push({ key, wazuh_instance_id: Number(wi), agent_id: agent, name: names.get(key)?.name ?? null, status: names.get(key)?.status ?? null, deleted_at: del?.ts ?? null });
  }
  return out;
}
export async function unignoreAgent(ctx: Ctx, key: string): Promise<boolean> {
  const list = await readIgnore(ctx);
  if (!list.includes(key)) return false;
  await ctx.db("app_flags").where({ key: "host_sync_ignore" }).update({ value: JSON.stringify(list.filter((k) => k !== key)) });
  return true;
}
