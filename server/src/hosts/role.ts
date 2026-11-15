/**
 * EDR-154: server or client PC — one rule for the dashboard, the host list and the edit form.
 *  - a manual choice (node_roles, keyed by the agent / host name) wins
 *  - otherwise: agent-pack groups (laptop / desktop → client, linux-cloud / web-* → server), cloud instances, the OS name
 */
export type NodeRole = "server" | "client";
export function guessRole(o: { osName?: string | null; platform?: string | null; groups?: string[] | null; cloud?: boolean; name?: string; kind?: string | null; agentId?: string | null }): NodeRole {
  const g = (o.groups ?? []).map((x) => x.toLowerCase());
  const n = `${o.osName ?? ""} ${o.platform ?? ""}`.toLowerCase();
  if (g.includes("laptop")) return "client";
  if (g.some((x) => x === "linux-cloud" || x.startsWith("web-") || x === "servers")) return "server";
  if (o.cloud) return "server";
  if (o.kind === "managed") return "server";       // a host MamorAI reaches over SSH
  // "desktop" in the agent pack means "not a laptop" — Windows Server machines are put there too, so the OS decides first
  if (/windows server|server \d{4}/.test(n)) return "server";
  if (g.includes("desktop")) return "client";
  if (/server|linux|ubuntu|debian|centos|rhel|amazon|alma|rocky|bsd/.test(n)) return "server";
  if (/windows 1[01]|windows 7|windows 8|macos|mac os|darwin/.test(n)) return "client";
  if (/windows/.test(n)) return "server";
  return o.agentId === "000" ? "server" : "client";
}
