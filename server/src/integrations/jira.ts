import { fetch as ufetch } from "undici";
import type { AppConfig } from "../config/index.js";

export class JiraClient {
  constructor(private cfg: AppConfig) {}
  get enabled() { return !!(this.cfg.JIRA_BASE_URL && this.cfg.JIRA_EMAIL && this.cfg.JIRA_API_TOKEN); }
  private auth() { return "Basic " + Buffer.from(`${this.cfg.JIRA_EMAIL}:${this.cfg.JIRA_API_TOKEN}`).toString("base64"); }
  private adf(text: string) {
    // minimal ADF: one paragraph per line, code fences preserved as codeBlock
    const content: any[] = []; let code: string[] | null = null;
    for (const line of text.split("\n")) {
      if (line.startsWith("```")) { if (code) { content.push({ type: "codeBlock", content: [{ type: "text", text: code.join("\n") || " " }] }); code = null; } else code = []; continue; }
      if (code) { code.push(line); continue; }
      content.push({ type: "paragraph", content: line ? [{ type: "text", text: line }] : [] });
    }
    if (code) content.push({ type: "codeBlock", content: [{ type: "text", text: code.join("\n") || " " }] });
    return { type: "doc", version: 1, content };
  }
  private async req(method: string, path: string, body?: unknown) {
    const res = await ufetch(`${this.cfg.JIRA_BASE_URL!.replace(/\/$/, "")}/rest/api/3${path}`, { method, headers: { Authorization: this.auth(), "Content-Type": "application/json", Accept: "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000) });
    const json: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`jira ${method} ${path} -> ${res.status}: ${JSON.stringify(json).slice(0, 300)}`);
    return json;
  }
  async comment(issueKey: string, text: string): Promise<{ id: string }> {
    const r = await this.req("POST", `/issue/${encodeURIComponent(issueKey)}/comment`, { body: this.adf(text) });
    return { id: r.id };
  }
  async create(summary: string, text: string): Promise<{ key: string }> {
    const r = await this.req("POST", `/issue`, { fields: { project: { key: this.cfg.JIRA_PROJECT_KEY }, issuetype: { name: "Task" }, summary: summary.slice(0, 250), description: this.adf(text) } });
    return { key: r.key };
  }
}
