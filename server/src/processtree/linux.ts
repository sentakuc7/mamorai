/**
 * Process tree reconstruction for Linux agents from auditd execve records (EDR-79).
 *
 * Sysmon gives every process a unique processGuid; auditd only gives pid / ppid, and pids are
 * reused. So a Linux node is identified by (agent, pid, the execve record that started it) and
 * every lookup is bounded in time:
 *   - parent  = the latest successful execve of `ppid` at or before the child's start
 *   - children = execve records whose ppid is the node's pid, after the node's start
 * A failed execve (success=no, e.g. exit=-2 ENOENT) becomes a leaf "failed start" node whose image
 * is the path that was attempted (PATH item 0), not the caller's exe.
 *
 * Focus id format (query param `guid`): `audit:<data.audit.id>`.
 * Node guid format: `lnx:<pid>:<audit id>` (`lnx:<pid>:?` for a parent with no execve in range).
 */
import type { IndexerClient } from "../wazuh/index.js";
import type { ProcNode, ProcessTree } from "./index.js";

const MAX_NODES = 300, MAX_UP = 10, MAX_DEPTH_DOWN = 6, PER_NODE_EVENTS = 60;
/** Users that web servers / PHP run as on common distros (and Bitnami's `daemon`). */
const WEB_USERS = new Set(["daemon", "www-data", "apache", "nginx", "http", "wwwrun", "bitnami"]);
const ERRNO: Record<string, string> = { "-2": "ENOENT（ファイルが存在しない）", "-13": "EACCES（権限がない）", "-8": "ENOEXEC（実行形式でない）", "-1": "EPERM（操作が許可されていない）", "-7": "E2BIG（引数が長すぎる）", "-20": "ENOTDIR" };
const SRC = ["timestamp", "rule.id", "rule.level", "rule.description", "agent.id", "agent.name", "full_log", "data.audit"];

export const isLinuxFocus = (guid: string) => /^audit:\d+$/i.test(guid.trim());

interface Exec {
  _id: string; auditId: string; pid: number; ppid: number; syscall: string; success: boolean; exit?: string;
  exe: string; args: string[]; target?: string; cwd?: string; user?: string; ts: string; key?: string;
  rule?: { id: string; level: number; description: string }; raw: any;
}

/** Decode an auditd hex-encoded value (used when the value contains spaces or special characters). */
function unhex(v: string): string {
  try { return Buffer.from(v, "hex").toString("utf8").replace(/\0/g, " ").trim(); } catch { return v; }
}
const isHex = (v: string) => /^(?:[0-9A-F]{2}){2,}$/.test(v);

/** Pull execve argv out of the raw record (the decoder keeps hex-encoded args undecoded). */
function parseArgs(full: string | undefined, dec: any): string[] {
  if (full) {
    const m = full.match(/type=EXECVE msg=audit\([^)]*\):\s*argc=(\d+)\s+(.*?)(?=\s*type=[A-Z_]+ msg=|\x1d|$)/s);
    if (m) {
      const out: string[] = [];
      const re = /a(\d+)(?:\[\d+\])?=("([^"]*)"|(\S+))/g;
      let x: RegExpExecArray | null;
      while ((x = re.exec(m[2]))) { const i = Number(x[1]); const val = x[3] !== undefined ? x[3] : isHex(x[4]) ? unhex(x[4]) : x[4]; out[i] = (out[i] ?? "") + val; }
      if (out.length) return out.map((s) => s ?? "");
    }
  }
  const e = dec?.execve; if (!e) return [];
  const n = Number(e.argc ?? 0) || Object.keys(e).filter((k) => /^a\d+$/.test(k)).length;
  const out: string[] = [];
  for (let i = 0; i < n; i++) { const v = e[`a${i}`]; if (v === undefined) continue; out.push(isHex(String(v)) ? unhex(String(v)) : String(v)); }
  return out;
}

export function parseExec(h: any): Exec {
  const a = h.data?.audit ?? {}; const full: string | undefined = h.full_log;
  const epoch = full?.match(/msg=audit\((\d+)\.(\d+):/);
  const ts = epoch ? new Date(Number(epoch[1]) * 1000 + Number(epoch[2])).toISOString() : new Date(h.timestamp).toISOString();
  let args = parseArgs(full, a);
  if (!args.length) { const pt = full?.match(/proctitle=([0-9A-F]+)/); if (pt) args = unhex(pt[1]).split(" "); }
  const target = full?.match(/type=PATH msg=audit\([^)]*\):\s*item=0 name="([^"]+)"/)?.[1] ?? a.file?.name;
  const user = full?.match(/\bEUID="([^"]+)"/)?.[1] ?? full?.match(/\bUID="([^"]+)"/)?.[1] ?? (a.euid !== undefined ? `uid ${a.euid}` : undefined);
  return {
    _id: h._id, auditId: String(a.id ?? ""), pid: Number(a.pid), ppid: Number(a.ppid), syscall: String(a.syscall ?? ""), success: String(a.success ?? "yes") === "yes", exit: a.exit !== undefined ? String(a.exit) : undefined,
    exe: String(a.exe ?? a.file?.name ?? "?"), args, target, cwd: a.cwd, user, ts, key: a.key,
    rule: h.rule?.id ? { id: String(h.rule.id), level: Number(h.rule.level ?? 0), description: String(h.rule.description ?? "") } : undefined, raw: h,
  };
}

const SYSCALL: Record<string, string> = { "42": "connect", "43": "accept", "49": "bind", "41": "socket", "2": "open", "257": "openat", "87": "unlink", "263": "unlinkat", "82": "rename", "90": "chmod", "268": "fchmodat", "92": "chown", "105": "setuid", "101": "ptrace", "165": "mount", "62": "kill", "56": "clone", "57": "fork", "58": "vfork" };

export async function buildLinuxProcessTree(ix: IndexerClient, opts: { agentId: string; guid: string; from: string; to: string; preferArchives: boolean }): Promise<ProcessTree> {
  if (opts.preferArchives) {
    const t = await buildFrom(ix, "wazuh-archives-*", opts);
    if (t.root) return t;
  }
  return buildFrom(ix, "wazuh-alerts-*", opts);
}

async function buildFrom(ix: IndexerClient, index: string, opts: { agentId: string; guid: string; from: string; to: string }): Promise<ProcessTree> {
  const focusAuditId = opts.guid.trim().replace(/^audit:/i, "");
  const empty = (): ProcessTree => ({ agentId: opts.agentId, index, focusGuid: `audit:${focusAuditId}`, root: null, nodes: 0, truncated: false, window: { from: opts.from, to: opts.to }, os: "linux" });
  const base = [{ term: { "agent.id": opts.agentId } }, { exists: { field: "data.audit.pid" } }];
  const q = async (must: any[], size: number, range: { gte?: string; lte?: string }, order: "asc" | "desc" = "asc"): Promise<Exec[]> => {
    const r = await ix.search(index, { query: { bool: { filter: [...base, { range: { timestamp: range } }, ...must] } }, sort: [{ timestamp: { order } }], _source: SRC }, size);
    return (r.hits?.hits ?? []).map((h: any) => parseExec({ _id: h._id, ...h._source }));
  };
  const EXECVE = { term: { "data.audit.syscall": "59" } };
  const win = { gte: opts.from, lte: opts.to };

  // 1) focus record (audit ids restart on reboot, so take the one closest to the window)
  const fh = await q([{ term: { "data.audit.id": focusAuditId } }], 10, win);
  if (!fh.length) return empty();
  const focus = fh[fh.length - 1];
  const agentName: string | undefined = focus.raw.agent?.name;

  const nodes = new Map<string, ProcNode>();
  const seen = new Set<string>(); // audit ids already placed
  const nodeOf = (e: Exec, isFocus = false): ProcNode => {
    const failed = e.syscall === "59" && !e.success;
    const guid = `lnx:${e.pid}:${e.auditId}${failed ? ":fail" : ""}`;
    let n = nodes.get(guid);
    if (n) return n;
    n = {
      guid, pid: e.pid, image: failed ? e.target ?? e.args[0] ?? "?" : e.exe, commandLine: e.args.length ? e.args.join(" ") : undefined, user: e.user,
      start: e.ts, endEstimated: true, maxLevel: 0, alerts: [], events: [], children: [], depth: 0, isRoot: false, isFocus,
      os: "linux", failed, exitCode: e.exit, errno: failed ? ERRNO[e.exit ?? ""] ?? `exit ${e.exit}` : undefined, cwd: e.cwd, ppid: e.ppid,
      callerImage: failed ? e.exe : undefined,
    };
    nodes.set(guid, n); seen.add(e.auditId);
    addAlert(n, e, isFocus ? 3 : 5);
    return n;
  };
  const addAlert = (n: ProcNode, e: Exec, minLevel: number) => {
    if (!e.rule || e.rule.level < minLevel) return;
    if (n.alerts.some((a) => a._id === e._id)) return;
    n.alerts.push({ ruleId: e.rule.id, level: e.rule.level, description: e.rule.description, ts: e.ts, _id: e._id });
    n.maxLevel = Math.max(n.maxLevel, e.rule.level);
  };

  let fnode: ProcNode;
  if (focus.syscall === "59") fnode = nodeOf(focus, true);
  else {
    // non-execve alert (connect, file write, ...): attach it to the process that was running as that pid
    const own = (await q([{ term: { "data.audit.pid": String(focus.pid) } }, EXECVE, { term: { "data.audit.success": "yes" } }], 5, { gte: `${focus.ts}||-7d`, lte: `${focus.ts}||+2m` }, "desc"))
      .filter((e) => e.ts <= focus.ts);
    fnode = own.length ? nodeOf(own[0]) : placeholder(focus.pid, focus.ppid, focus.user, focus.exe);
    fnode.isFocus = true;
    fnode.events.push({ eid: 100, ts: focus.ts, detail: `${SYSCALL[focus.syscall] ?? `syscall ${focus.syscall}`} ${focus.key ? `key=${focus.key} ` : ""}${focus.target ?? ""}`.trim() });
    addAlert(fnode, focus, 3);
  }

  function placeholder(pid: number, ppid: number | undefined, childUser?: string, exe?: string): ProcNode {
    const guid = `lnx:${pid}:?`;
    const ex = nodes.get(guid); if (ex) return ex;
    const web = childUser && WEB_USERS.has(childUser);
    const n: ProcNode = {
      guid, pid, image: exe ?? (web ? `Webサーバー（pid ${pid}）` : `pid ${pid}`), endEstimated: true, maxLevel: 0, alerts: [], events: [], children: [], depth: 0, isRoot: false, isFocus: false,
      os: "linux", inferred: true, ppid, user: childUser,
      hint: web ? `起動記録なし。子プロセスが Web 実行ユーザー（${childUser}）で動いているため Web サーバー（Apache / PHP 等）と推定` : "この期間に起動（execve）の記録がないプロセス（起動が監視開始より前、または監査対象外）",
    };
    nodes.set(guid, n);
    return n;
  }

  // 2) ancestors: latest successful execve of ppid at or before the child's start
  let cur = fnode, up = 0;
  while (up < MAX_UP && cur.ppid && cur.ppid > 1) {
    const childStart = cur.start ?? focus.raw.timestamp;
    // `timestamp` is the manager's receive time (later than the kernel time in msg=audit(...)), so
    // search a little past the child's start and keep only records whose kernel time is not later.
    const ph = (await q([{ term: { "data.audit.pid": String(cur.ppid) } }, EXECVE, { term: { "data.audit.success": "yes" } }], 5, { gte: `${childStart}||-7d`, lte: `${childStart}||+2m` }, "desc"))
      .filter((e) => e.ts <= childStart).slice(0, 1);
    const p = ph.length && !seen.has(ph[0].auditId) ? nodeOf(ph[0]) : ph.length ? [...nodes.values()].find((n) => n.guid.startsWith(`lnx:${ph[0].pid}:${ph[0].auditId}`))! : placeholder(cur.ppid, undefined, cur.user);
    p.children.push(cur); cur.parentGuid = p.guid; cur.parentImage = p.image;
    cur = p; up++;
    if (!ph.length) break;
  }
  const root = cur; root.isRoot = true;

  // 3) descendants (BFS from focus): execve records whose ppid is a node's pid, after that node started
  let truncated = false;
  let frontier: ProcNode[] = fnode.failed ? [] : [fnode];
  for (let depth = 0; frontier.length && depth < MAX_DEPTH_DOWN && nodes.size < MAX_NODES; depth++) {
    const next: ProcNode[] = [];
    const earliest = frontier.map((n) => n.start!).sort()[0];
    const kids = await q([{ terms: { "data.audit.ppid": frontier.map((n) => String(n.pid)) } }, EXECVE], 400, { gte: earliest, lte: opts.to });
    for (const k of kids) {
      if (seen.has(k.auditId)) continue;
      // the parent is the frontier node with that pid that started most recently before the child
      const p = frontier.filter((n) => n.pid === k.ppid && (n.start ?? "") <= k.ts).sort((a, b) => (b.start ?? "").localeCompare(a.start ?? ""))[0];
      if (!p) continue;
      if (nodes.size >= MAX_NODES) { truncated = true; break; }
      const n = nodeOf(k); n.parentGuid = p.guid; n.parentImage = p.image; p.children.push(n);
      if (!n.failed) next.push(n);
    }
    frontier = next;
  }

  // 4) other audit records (non-execve) made by each process → activity markers
  const live = [...nodes.values()].filter((n) => !n.failed && !n.inferred && n.start);
  for (let i = 0; i < live.length; i += 30) {
    const batch = live.slice(i, i + 30);
    const earliest = batch.map((n) => n.start!).sort()[0];
    const hits = await q([{ terms: { "data.audit.pid": batch.map((n) => String(n.pid)) } }], Math.min(500, batch.length * PER_NODE_EVENTS), { gte: earliest, lte: opts.to });
    for (const h of hits) {
      if (h.syscall === "59" || seen.has(h.auditId)) continue;
      const n = batch.filter((b) => b.pid === h.pid && (b.start ?? "") <= h.ts).sort((a, b) => (b.start ?? "").localeCompare(a.start ?? ""))[0];
      if (!n || n.events.length >= PER_NODE_EVENTS) continue;
      n.events.push({ eid: 100, ts: h.ts, detail: `${SYSCALL[h.syscall] ?? (h.syscall ? `syscall ${h.syscall}` : h.raw.data?.audit?.type ?? "audit")}${h.key ? ` key=${h.key}` : ""}${h.target ? ` ${h.target}` : ""}` });
      addAlert(n, h, 5);
    }
  }

  // 5) finish: order children, end estimates, depth
  for (const n of nodes.values()) {
    n.events.sort((a, b) => a.ts.localeCompare(b.ts));
    if (n.failed) { n.end = n.start; n.endEstimated = false; continue; }
    const last = n.events[n.events.length - 1]?.ts; const lastChild = n.children.map((c) => c.end ?? c.start ?? "").sort().pop();
    n.end = [last, lastChild, n.start].filter(Boolean).sort().pop();
  }
  const walk = (n: ProcNode, d: number) => { n.depth = d; n.children.sort((a, b) => (a.start ?? "").localeCompare(b.start ?? "")); n.children.forEach((c) => walk(c, d + 1)); };
  walk(root, 0);
  // placeholder parents have no start: show them at the earliest child time so the timeline stays sane
  for (const n of nodes.values()) if (!n.start) n.start = n.children.map((c) => c.start ?? "").filter(Boolean).sort()[0];

  return { agentId: opts.agentId, agentName, index, focusGuid: `audit:${focusAuditId}`, root, nodes: nodes.size, truncated, window: { from: opts.from, to: opts.to }, os: "linux" };
}
