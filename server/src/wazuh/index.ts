import { Agent, fetch as ufetch } from "undici";

export interface WazuhConn {
  indexerUrl: string; indexerUser: string; indexerPassword: string;
  apiUrl?: string | null; apiUser?: string | null; apiPassword?: string | null;
  caPem?: string | null; tlsVerify: boolean; apiTlsVerify?: boolean;
}

function dispatcher(conn: WazuhConn, verify = conn.tlsVerify): Agent {
  return new Agent({
    connect: {
      rejectUnauthorized: verify,
      ca: conn.caPem || undefined,
    },
    connectTimeout: 10000,
  });
}

function basic(user: string, pass: string): string {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

export class IndexerClient {
  private d: Agent;
  constructor(private conn: WazuhConn) { this.d = dispatcher(conn); }

  /**
   * EDR-157: the indexer answers 429 (circuit_breaking_exception: heap nearly full) or 503 when it is busy.
   * That is temporary, so wait a little and try again (twice). If it is still busy, throw an error the screen can
   * show as is ("Wazuh の検索エンジンが混み合っています…") instead of "internal error".
   */
  async request<T = any>(method: string, path: string, body?: unknown): Promise<T> {
    const waits = [1000, 2500];
    for (let i = 0; ; i++) {
      try { return await this.requestOnce<T>(method, path, body); }
      catch (e: any) {
        if (!e?.indexerBusy) throw e;
        if (i >= waits.length) {
          const err: any = new Error("Wazuh の検索エンジン（indexer）が混み合っているため、いま結果を取得できませんでした。少し待ってから「更新」を押してください。続く場合は indexer のメモリ（jvm.options の -Xmx）を確認してください。");
          err.status = 503; err.publicMessage = err.message; err.cause = e;
          throw err;
        }
        await new Promise((r) => setTimeout(r, waits[i]));
      }
    }
  }

  private async requestOnce<T = any>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await ufetch(this.conn.indexerUrl.replace(/\/$/, "") + path, {
      method,
      dispatcher: this.d,
      headers: { Authorization: basic(this.conn.indexerUser, this.conn.indexerPassword), "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });
    const text = await res.text();
    let json: any; try { json = JSON.parse(text); } catch { json = { raw: text }; }
    if (!res.ok) {
      const err: any = new Error(`indexer ${method} ${path} -> ${res.status}: ${JSON.stringify(json).slice(0, 400)}`);
      err.indexerBusy = res.status === 429 || res.status === 503;
      throw err;
    }
    return json as T;
  }

  /** Read-only search. Guard: only alerts/archives/states indices, size capped. */
  async search(index: string, body: Record<string, unknown>, size = 50): Promise<any> {
    if (!/^wazuh-(alerts|archives|states|statistics|monitoring)-[\w.*-]*$/.test(index)) throw new Error(`index not allowed: ${index}`);
    const capped = Math.min(Math.max(0, size), 500);
    return this.request("POST", `/${encodeURIComponent(index)}/_search?size=${capped}&ignore_unavailable=true`, body);
  }

  async health(): Promise<{ status: string; indices: number; alertsToday: number; archivesEnabled: boolean }> {
    const h = await this.request("GET", "/_cluster/health");
    const cat: Array<{ index: string; "docs.count": string }> = await this.request("GET", "/_cat/indices/wazuh-alerts-*,wazuh-archives-*?format=json&h=index,docs.count");
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, ".");
    const alertsToday = cat.filter((c) => c.index.startsWith("wazuh-alerts-") && c.index.endsWith(today)).reduce((a, c) => a + Number(c["docs.count"] || 0), 0);
    const archivesEnabled = cat.some((c) => c.index.startsWith("wazuh-archives-") && c.index.endsWith(today));
    return { status: h.status, indices: cat.length, alertsToday, archivesEnabled };
  }

  /** Dashboard summary: severity buckets, top rules, top agents in a window. */
  async summary(window = "now-24h"): Promise<any> {
    const r = await this.search("wazuh-alerts-*", {
      track_total_hits: true,
      query: { range: { timestamp: { gte: window } } },
      aggs: {
        sev: { range: { field: "rule.level", ranges: [{ key: "low", from: 0, to: 7 }, { key: "medium", from: 7, to: 12 }, { key: "high", from: 12, to: 15 }, { key: "critical", from: 15 }] } },
        rules: { terms: { field: "rule.id", size: 10, order: { _count: "desc" } }, aggs: { d: { terms: { field: "rule.description", size: 1 } }, lv: { max: { field: "rule.level" } } } },
        agents: { terms: { field: "agent.name", size: 20 } },
        hist: { date_histogram: { field: "timestamp", fixed_interval: "1h", min_doc_count: 0 } },
      },
    }, 0);
    const a = r.aggregations;
    return {
      total: r.hits.total?.value ?? 0,
      severity: Object.fromEntries(a.sev.buckets.map((b: any) => [b.key, b.doc_count])),
      topRules: a.rules.buckets.map((b: any) => ({ id: b.key, count: b.doc_count, description: b.d.buckets[0]?.key ?? "", level: b.lv.value })),
      agents: a.agents.buckets.map((b: any) => ({ name: b.key, count: b.doc_count })),
      histogram: a.hist.buckets.map((b: any) => ({ t: b.key_as_string, c: b.doc_count })),
    };
  }

  /** ノード俯瞰: エージェントごとのレベル帯別件数と最新アラート時刻 */
  async perAgent(window = "now-24h"): Promise<{ name: string; id: string | null; total: number; critical: number; high: number; medium: number; low: number; last: string | null }[]> {
    const r = await this.search("wazuh-alerts-*", {
      size: 0, query: { range: { timestamp: { gte: window } } },
      aggs: { agents: { terms: { field: "agent.name", size: 200 }, aggs: { id: { terms: { field: "agent.id", size: 1 } }, sev: { range: { field: "rule.level", ranges: [{ key: "low", from: 0, to: 7 }, { key: "medium", from: 7, to: 12 }, { key: "high", from: 12, to: 15 }, { key: "critical", from: 15 }] } }, last: { max: { field: "timestamp" } } } } },
    }, 0);
    return (r.aggregations?.agents?.buckets ?? []).map((b: any) => { const sv: Record<string, number> = Object.fromEntries(b.sev.buckets.map((x: any) => [x.key, x.doc_count])); return { name: b.key, id: b.id.buckets[0]?.key ?? null, total: b.doc_count, critical: sv.critical ?? 0, high: sv.high ?? 0, medium: sv.medium ?? 0, low: sv.low ?? 0, last: b.last?.value_as_string ?? null }; });
  }

  async recentAlerts(minLevel = 12, size = 50, window = "now-24h"): Promise<any[]> {
    const r = await this.search("wazuh-alerts-*", {
      query: { bool: { filter: [{ range: { "rule.level": { gte: minLevel } } }, { range: { timestamp: { gte: window } } }] } },
      sort: [{ timestamp: { order: "desc" } }],
      _source: ["timestamp", "rule.id", "rule.level", "rule.description", "rule.groups", "rule.mitre", "agent.id", "agent.name", "agent.ip", "data.srcip", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.processGuid", "data.win.eventdata.parentProcessGuid", "data.win.eventdata.parentImage", "data.win.eventdata.parentCommandLine", "data.win.eventdata.user", "data.win.eventdata.targetFilename", "data.win.eventdata.destinationIp", "data.win.eventdata.destinationPort", "data.win.eventdata.hashes", "data.win.system.eventID", "data.srcuser", "data.dstuser", "data.url", "data.id", "data.protocol", "data.vulnerability", "full_log"],
    }, size);
    return r.hits.hits.map((h: any) => ({ _id: h._id, _index: h._index, ...h._source }));
  }
}

export class ManagerApiClient {
  private d: Agent;
  private token: { value: string; exp: number } | null = null;
  constructor(private conn: WazuhConn) { this.d = dispatcher(conn, conn.apiTlsVerify ?? false); }

  private async auth(): Promise<string> {
    if (this.token && this.token.exp > Date.now() + 30_000) return this.token.value;
    if (!this.conn.apiUrl || !this.conn.apiUser || !this.conn.apiPassword) throw new Error("Wazuh API not configured");
    const res = await ufetch(this.conn.apiUrl.replace(/\/$/, "") + "/security/user/authenticate?raw=true", {
      method: "POST", dispatcher: this.d,
      headers: { Authorization: basic(this.conn.apiUser, this.conn.apiPassword) },
      signal: AbortSignal.timeout(15000),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`wazuh api auth -> ${res.status}: ${text.slice(0, 200)}`);
    this.token = { value: text.trim(), exp: Date.now() + 14 * 60 * 1000 };
    return this.token.value;
  }

  /** GET only (read-only role). */
  async get<T = any>(path: string): Promise<T> {
    if (!path.startsWith("/")) path = "/" + path;
    const tok = await this.auth();
    const res = await ufetch(this.conn.apiUrl!.replace(/\/$/, "") + path, {
      method: "GET", dispatcher: this.d, headers: { Authorization: `Bearer ${tok}` }, signal: AbortSignal.timeout(30000),
    });
    const json: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`wazuh api GET ${path} -> ${res.status}: ${JSON.stringify(json).slice(0, 300)}`);
    return json as T;
  }

  /**
   * EDR-121: write call used ONLY for active responses, with a dedicated API user that holds
   * nothing but `active-response:command` (WAZUH_AR_USER). The read-only console user never writes.
   */
  async put<T = any>(path: string, body: unknown): Promise<T> {
    if (!path.startsWith("/active-response")) throw new Error("only /active-response may be written");
    const tok = await this.auth();
    const res = await ufetch(this.conn.apiUrl!.replace(/\/$/, "") + path, {
      method: "PUT", dispatcher: this.d, headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000),
    });
    const json: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`wazuh api PUT ${path} -> ${res.status}: ${JSON.stringify(json).slice(0, 300)}`);
    return json as T;
  }

  async info(): Promise<{ version: string; hostname: string }> {
    const r = await this.get("/");
    return { version: r.data?.api_version ?? "?", hostname: r.data?.hostname ?? "?" };
  }

  async agents(): Promise<any[]> {
    const r = await this.get("/agents?limit=500&select=id,name,ip,status,os.name,os.platform,os.version,version,lastKeepAlive,group");
    return r.data?.affected_items ?? [];
  }
}
