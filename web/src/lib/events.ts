/**
 * EDR-154: one server-sent-events stream per browser tab.
 * Browsers allow only 6 connections per host over HTTP/1.1 and every EventSource keeps one open. With a stream per
 * component (nav badges, kill switch, page, each chat) two MamorAI tabs used them all up and every other request
 * (e.g. GET /api/hosts) waited forever. Now every component subscribes to this single stream instead.
 */
type Handler = (data: any, type: string) => void;
const TYPES = ["message", "tool_call", "tool_result", "approval", "next_actions", "status", "error", "schedule"];
const subs = new Map<string, Set<Handler>>();
let es: EventSource | null = null;
let closeTimer: ReturnType<typeof setTimeout> | null = null;

function ensure() {
  if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }
  if (es) return;
  es = new EventSource("/api/sessions/0/events");
  for (const t of TYPES) es.addEventListener(t, (e: MessageEvent) => {
    let data: any = null; try { data = JSON.parse(e.data); } catch { /* ignore */ }
    for (const h of [...(subs.get(t) ?? [])]) { try { h(data, t); } catch { /* a broken handler must not stop the others */ } }
  });
}
function maybeClose() {
  if ([...subs.values()].some((s) => s.size)) return;
  closeTimer = setTimeout(() => { if (![...subs.values()].some((s) => s.size)) { es?.close(); es = null; } }, 2000);
}

/** subscribe to one or more event types; returns the unsubscribe function (use it as the useEffect cleanup) */
export function onServerEvent(types: string | string[], h: Handler, sessionId?: number | null): () => void {
  const list = Array.isArray(types) ? types : [types];
  const wrapped: Handler = sessionId ? (d, t) => { if (d?.session_id === sessionId) h(d, t); } : h;
  for (const t of list) { if (!subs.has(t)) subs.set(t, new Set()); subs.get(t)!.add(wrapped); }
  ensure();
  return () => { for (const t of list) subs.get(t)?.delete(wrapped); maybeClose(); };
}
