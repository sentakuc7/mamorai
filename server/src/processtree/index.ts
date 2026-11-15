/**
 * Process tree & timeline reconstruction from Sysmon events stored in Wazuh.
 * Prefers wazuh-archives-* (all events); falls back to wazuh-alerts-*.
 */
import type { IndexerClient } from "../wazuh/index.js";
import { buildLinuxProcessTree, isLinuxFocus } from "./linux.js";
export { isLinuxFocus } from "./linux.js";

export interface ProcNode {
  guid: string; pid?: number; image: string; commandLine?: string; user?: string; parentGuid?: string; parentImage?: string;
  start?: string; end?: string; endEstimated: boolean; hashes?: string; signed?: string;
  maxLevel: number; alerts: { ruleId: string; level: number; description: string; ts: string; _id: string }[];
  events: { eid: number; ts: string; detail: string }[];
  children: ProcNode[]; depth: number; isRoot: boolean; isFocus: boolean;
  /** Linux (auditd) only — EDR-79 */
  os?: "windows" | "linux"; failed?: boolean; exitCode?: string; errno?: string; cwd?: string; ppid?: number; callerImage?: string; inferred?: boolean; hint?: string;
}
export interface ProcessTree { agentId: string; agentName?: string; index: string; focusGuid: string; root: ProcNode | null; nodes: number; truncated: boolean; window: { from: string; to: string }; os?: "windows" | "linux" }

const EV = "data.win.eventdata";
const SRC = ["timestamp", "rule.id", "rule.level", "rule.description", "agent.id", "agent.name", "data.win.system.eventID", `${EV}.processGuid`, `${EV}.parentProcessGuid`, `${EV}.processId`, `${EV}.image`, `${EV}.commandLine`, `${EV}.user`, `${EV}.parentImage`, `${EV}.utcTime`, `${EV}.targetFilename`, `${EV}.destinationIp`, `${EV}.destinationPort`, `${EV}.destinationHostname`, `${EV}.queryName`, `${EV}.targetObject`, `${EV}.details`, `${EV}.hashes`, `${EV}.signed`, `${EV}.signature`, `${EV}.imageLoaded`, `${EV}.sourceImage`, `${EV}.targetImage`];
const MAX_NODES = 400, MAX_DEPTH_DOWN = 6, MAX_UP = 10, PER_NODE_EVENTS = 60;

function ev(hit: any) { return hit.data?.win?.eventdata ?? {}; }
function eid(hit: any): number { return Number(hit.data?.win?.system?.eventID ?? 0); }
function ts(hit: any): string { return ev(hit).utcTime ? ev(hit).utcTime.replace(" ", "T") + "Z" : hit.timestamp; }
function norm(g: string | undefined): string { return (g ?? "").replace(/[{}]/g, "").toUpperCase(); }

export async function buildProcessTree(ix: IndexerClient, opts: { agentId: string; guid: string; from: string; to: string; preferArchives: boolean }): Promise<ProcessTree> {
  if (isLinuxFocus(opts.guid)) return buildLinuxProcessTree(ix, opts);
  if (opts.preferArchives) {
    const t = await buildFrom(ix, "wazuh-archives-*", opts);
    if (t.root) return t;
  }
  return buildFrom(ix, "wazuh-alerts-*", opts);
}

async function buildFrom(ix: IndexerClient, index: string, opts: { agentId: string; guid: string; from: string; to: string }): Promise<ProcessTree> {
  const focus = norm(opts.guid);
  const timeFilter = { range: { timestamp: { gte: opts.from, lte: opts.to } } };
  const base = [{ term: { "agent.id": opts.agentId } }, { term: { "data.win.system.channel": "Microsoft-Windows-Sysmon/Operational" } }, timeFilter];

  const q = async (must: any[], size: number, sort: any = [{ timestamp: { order: "asc" } }]) => {
    const r = await ix.search(index, { query: { bool: { filter: [...base, ...must] } }, sort, _source: SRC }, size);
    return (r.hits?.hits ?? []).map((h: any) => ({ _id: h._id, ...h._source }));
  };
  const guidVariants = (g: string) => [`{${g}}`, `{${g.toLowerCase()}}`, g, g.toLowerCase()];

  const nodes = new Map<string, ProcNode>();
  const mk = (guid: string): ProcNode => { let n = nodes.get(guid); if (!n) { n = { guid, image: "?", endEstimated: true, maxLevel: 0, alerts: [], events: [], children: [], depth: 0, isRoot: false, isFocus: guid === focus }; nodes.set(guid, n); } return n; };
  const applyEid1 = (n: ProcNode, h: any) => { const e = ev(h); n.image = e.image ?? n.image; n.commandLine = e.commandLine; n.user = e.user; n.parentGuid = norm(e.parentProcessGuid) || n.parentGuid; n.parentImage = e.parentImage; n.pid = e.processId ? Number(e.processId) : n.pid; n.start = ts(h); n.hashes = e.hashes; n.signed = e.signed; };
  const applyAlert = (n: ProcNode, h: any) => { const lv = Number(h.rule?.level ?? 0); if (lv >= 3 && h.rule?.id) { n.alerts.push({ ruleId: String(h.rule.id), level: lv, description: h.rule.description ?? "", ts: h.timestamp, _id: h._id }); n.maxLevel = Math.max(n.maxLevel, lv); } };

  // 1) focus process EID1 (+ any alert on it)
  let truncated = false;
  const focusHits = await q([{ terms: { [`${EV}.processGuid`]: guidVariants(focus) } }], PER_NODE_EVENTS);
  if (!focusHits.length) return { agentId: opts.agentId, index, focusGuid: focus, root: null, nodes: 0, truncated: false, window: { from: opts.from, to: opts.to } };
  const fnode = mk(focus);
  for (const h of focusHits) { if (eid(h) === 1) applyEid1(fnode, h); applyAlert(fnode, h); }

  // 2) ancestors
  let cur = fnode, up = 0;
  while (cur.parentGuid && up < MAX_UP && !nodes.has(cur.parentGuid)) {
    const ph = await q([{ terms: { [`${EV}.processGuid`]: guidVariants(cur.parentGuid) } }, { term: { "data.win.system.eventID": "1" } }], 1);
    const p = mk(cur.parentGuid);
    if (ph.length) applyEid1(p, ph[0]); else { p.image = cur.parentImage ?? "(parent not in window)"; }
    p.children.push(cur); cur = p; up++;
    if (!ph.length) break;
  }
  const root = cur; root.isRoot = true;

  // 3) descendants (BFS from focus), + siblings of focus are not expanded (keeps tree small)
  const queue: ProcNode[] = [fnode];
  let depth = 0;
  while (queue.length && nodes.size < MAX_NODES && depth < MAX_DEPTH_DOWN) {
    const level = queue.splice(0, queue.length);
    const parents = level.map((n) => n.guid);
    const kids = await q([{ terms: { [`${EV}.parentProcessGuid`]: parents.flatMap(guidVariants) } }, { term: { "data.win.system.eventID": "1" } }], 200);
    for (const h of kids) {
      const g = norm(ev(h).processGuid); if (!g || nodes.has(g)) continue;
      if (nodes.size >= MAX_NODES) { truncated = true; break; }
      const n = mk(g); applyEid1(n, h); applyAlert(n, h);
      const p = nodes.get(norm(ev(h).parentProcessGuid)); if (p) { p.children.push(n); queue.push(n); }
    }
    depth++;
  }

  // 4) activity + alerts for every node (batched by guid)
  const all = [...nodes.values()];
  for (let i = 0; i < all.length; i += 20) {
    const batch = all.slice(i, i + 20);
    const hits = await q([{ terms: { [`${EV}.processGuid`]: batch.flatMap((n) => guidVariants(n.guid)) } }, { terms: { "data.win.system.eventID": ["3", "5", "11", "12", "13", "22", "8", "10"] } }], Math.min(500, batch.length * PER_NODE_EVENTS));
    for (const h of hits) {
      const n = nodes.get(norm(ev(h).processGuid)); if (!n) continue;
      const e = ev(h), id = eid(h), t = ts(h);
      if (id === 5) { n.end = t; n.endEstimated = false; continue; }
      if (n.events.length >= PER_NODE_EVENTS) continue;
      const detail = id === 3 ? `${e.destinationIp ?? ""}:${e.destinationPort ?? ""} ${e.destinationHostname ?? ""}`.trim() : id === 11 ? e.targetFilename ?? "" : id === 22 ? e.queryName ?? "" : id === 12 || id === 13 ? `${e.targetObject ?? ""} ${e.details ?? ""}`.trim() : id === 8 || id === 10 ? `${e.sourceImage ?? ""} → ${e.targetImage ?? ""}` : "";
      n.events.push({ eid: id, ts: t, detail });
      applyAlert(n, h);
    }
    // alerts on these processes from any EID (level >= 7) if we are reading archives (alerts are also in archives)
  }
  for (const n of all) {
    n.events.sort((a, b) => a.ts.localeCompare(b.ts));
    if (!n.end) { const last = n.events[n.events.length - 1]?.ts; const lastChild = n.children.map((c) => c.end ?? c.start ?? "").sort().pop(); n.end = [last, lastChild, n.start].filter(Boolean).sort().pop(); n.endEstimated = true; }
  }
  // depth
  const walk = (n: ProcNode, d: number) => { n.depth = d; n.children.sort((a, b) => (a.start ?? "").localeCompare(b.start ?? "")); n.children.forEach((c) => walk(c, d + 1)); };
  walk(root, 0);
  return { agentId: opts.agentId, agentName: focusHits[0]?.agent?.name, index, focusGuid: focus, root, nodes: nodes.size, truncated, window: { from: opts.from, to: opts.to } };
}

/** Compact text rendering for the LLM tool. */
export function renderTreeText(t: ProcessTree): string {
  if (!t.root && t.os === "linux") return `No auditd record ${t.focusGuid} found on agent ${t.agentId} in ${t.index} within ${t.window.from}..${t.window.to}.`;
  if (!t.root) return `No Sysmon EID1 found for guid ${t.focusGuid} on agent ${t.agentId} in ${t.index} within ${t.window.from}..${t.window.to}.`;
  const lines: string[] = [`agent ${t.agentId} ${t.agentName ?? ""} · index ${t.index} · ${t.nodes} processes${t.truncated ? " (truncated)" : ""}`];
  const walk = (n: ProcNode) => {
    const pad = "  ".repeat(n.depth);
    const mark = n.isFocus ? "★ " : "";
    const al = n.alerts.length ? ` [alerts: ${n.alerts.map((a) => `${a.ruleId}/L${a.level}`).join(",")}]` : "";
    const st = n.failed ? ` FAILED-EXEC ${n.errno ?? n.exitCode ?? ""} (caller ${n.callerImage ?? "?"})` : n.inferred ? ` [no execve in range${n.hint ? `: ${n.hint}` : ""}]` : "";
    lines.push(`${pad}${mark}${n.start ?? "?"} ${n.image}${n.pid ? ` (pid ${n.pid})` : ""} user=${n.user ?? "?"}${n.cwd ? ` cwd=${n.cwd}` : ""}${st}${al}`);
    if (n.commandLine && (n.isFocus || n.alerts.length || n.depth > 0)) lines.push(`${pad}    cmd: ${n.commandLine.slice(0, 300)}`);
    const byEid: Record<number, string[]> = {};
    for (const e of n.events) (byEid[e.eid] ??= []).push(e.detail);
    for (const [k, v] of Object.entries(byEid)) { const name: Record<string, string> = { 100: "audit", 3: "net", 11: "file", 12: "reg", 13: "reg", 22: "dns", 8: "remote-thread", 10: "proc-access" }; lines.push(`${pad}    ${name[k] ?? k}(${v.length}): ${[...new Set(v)].slice(0, 8).join(" | ").slice(0, 400)}`); }
    n.children.forEach(walk);
  };
  walk(t.root);
  return lines.join("\n");
}
