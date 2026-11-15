/**
 * EDR-142: "what happens to THIS host if I press Contain?" — explained by the AI from the latest host scan.
 *  - input: the same evidence-checked facts the host card uses (user names pseudonymized, secrets redacted)
 *  - output: JSON (summary, what keeps working, what stops and who is affected, checks before / after, diagram data)
 *  - the diagram is drawn by the web UI from the JSON (the AI never produces markup)
 *  - cached per scan in host_ai_notes; "regenerate" makes a new one
 */
import { z } from "zod";
import type { Ctx } from "../api/context.js";
import { llmInput, parseLooseJson } from "./interpret.js";
import { getPseudonymize } from "./scan.js";
import { platformOf } from "./actions.js";
import { pj } from "../db/index.js";

const str = z.preprocess((v) => (v == null ? "" : String(v)), z.string());
const txt = z.string().trim().min(1);
/** the AI sometimes answers a list of sentences as objects ({sign, why}) or as one string — flatten to strings */
const flat = (v: unknown): unknown => (typeof v === "string" ? v.split(/\n+|(?<=。)/).map((x) => x.replace(/^\s*[-*•]\s*/, "")) : Array.isArray(v) ? v.map((x) => (x && typeof x === "object" ? Object.values(x).filter((y) => typeof y === "string").join(" — ") : x)) : v);
const lines = (max: number) => z.preprocess(flat, list(txt, max));
const list = <T extends z.ZodTypeAny>(item: T, max: number) => z.preprocess((v) => (Array.isArray(v) ? v.filter((x) => item.safeParse(x).success).slice(0, max) : []), z.array(item));
const sev = z.preprocess((v) => { const s = String(v ?? "").toLowerCase(); return ["high", "critical"].includes(s) ? "high" : s === "low" ? "low" : "medium"; }, z.enum(["high", "medium", "low"]));
const group = z.preprocess((v) => { const s = String(v ?? "").toLowerCase(); return ["internet", "lan", "inbound", "users", "other"].includes(s) ? s : "other"; }, z.enum(["internet", "lan", "inbound", "users", "other"]));
export const impactSchema = z.object({
  summary: str,
  use_now_if: lines(6),
  avoid_if: lines(4),
  keeps: list(z.object({ name: z.string().min(1), why: str }), 6),
  stops: list(z.object({ name: z.string().min(1), impact: str, who: str, severity: sev, group }), 12),
  before: lines(6),
  during: lines(6),
  restore: lines(6),
});
export type ContainImpact = z.infer<typeof impactSchema>;

/** what Contain keeps open, per platform (mirrors actions.ts linuxScript / mamorai-ar.ps1 isolate) */
function keepsFor(platform: string): string {
  if (platform === "windows_ar") return "Windows: outbound TCP 1514/1515 to the Wazuh manager addresses; the Tailscale daemon if installed (so a laptop outside the office still reaches the manager); optionally DNS and domain controllers when the admin ticks them. Everything else in and out is blocked by Windows Firewall (local rules are disabled temporarily, GPO rules stay). Released only by a human from MamorAI.";
  if (platform === "linux_ssh") return "Linux: SSH from MamorAI's address (so it can be released remotely) and TCP 1514/1515 to the Wazuh manager; loopback stays. Everything else in and out is dropped by nftables / iptables. Released only by a human from MamorAI.";
  return "This host cannot be contained from MamorAI yet (no SSH and no Windows add-on).";
}

const SYSTEM = `You explain to the security team of a small organization, in Japanese, what will happen to ONE computer if they press "インターネット通信遮断（Contain）" (network isolation).
Rules:
- Use only the FACTS. Do not invent services, users or connections. Be concrete: name the services, ports, programs and (pseudonymized) users from the facts.
- User names are pseudonyms (U01 …). Use them as they are.
- Readers are not experts: short sentences, no jargon without a word of explanation.
- Output ONLY one JSON object with these keys:
  summary: 2-4 sentences: what this computer is and what Contain does to it in practice.
  use_now_if: signs (for THIS computer) that mean "press it now" (e.g. ransomware-like file changes, unknown remote-control tool, connections to suspicious addresses).
  avoid_if: cases where pressing it would do more harm than good for THIS computer (e.g. it is a server many people depend on — use a narrower block instead).
  keeps: what keeps working [{name, why}] (based on the CONTAIN BEHAVIOUR below).
  stops: what stops [{name, impact, who, severity: high|medium|low, group: internet|lan|inbound|users|other}] — the user's internet, VPN/remote tools, file sharing / services other machines use, logged-in users, updates, cloud sync …
  before: checks to do before pressing (who to tell, what to save, whether a remote user will be cut off).
  during: what to do while it is contained (investigate with MamorAI, collect evidence, do not reboot unless needed …).
  restore: how and when to release it and what to check after.
Lists (use_now_if, avoid_if, before, during, restore) are JSON arrays of SHORT strings — one point per item, 3-5 items. Keep every text field under 140 characters.`;

export async function getImpact(ctx: Ctx, host: any): Promise<{ note: any | null; scan_id: number | null; stale: boolean }> {
  const scan = await ctx.db("host_scans").where({ host_id: host.id, status: "done" }).orderBy("id", "desc").first();
  const note = await ctx.db("host_ai_notes").where({ host_id: host.id, kind: "contain_impact" }).orderBy("id", "desc").first();
  return { note: note ? { ...note, content: pj(note.content) } : null, scan_id: scan?.id ?? null, stale: !!note && !!scan && note.scan_id !== scan.id };
}

export async function generateImpact(ctx: Ctx, host: any, userId: number | null): Promise<any> {
  const provider = ctx.runtime?.llmProvider;
  if (!provider) throw Object.assign(new Error("AI（LLM）が設定されていません"), { status: 409 });
  const scan = await ctx.db("host_scans").where({ host_id: host.id, status: "done" }).orderBy("id", "desc").first();
  if (!scan) throw Object.assign(new Error("先に「ホストを AI でスキャン」を実行してください（影響の説明はスキャン結果をもとに作ります）"), { status: 409 });
  const facts = pj<any>(scan.facts); const profile = pj<any>(scan.profile) ?? {};
  const { text, map } = llmInput(facts, await getPseudonymize(ctx));
  const platform = platformOf(host);
  const ctxText = JSON.stringify({ host: { name: host.name, environment: host.environment, kind: host.kind, os: facts?.system?.os ?? host.os_family, groups: host.agent_groups ?? undefined }, card_summary: profile.summary ?? null, role_tags: profile.role_tags ?? [] });
  const ask = (extra: string, maxTokens: number) => provider.chat([{ role: "system", content: SYSTEM + extra }, { role: "user", content: `CONTAIN BEHAVIOUR:\n${keepsFor(platform)}\n\nHOST:\n${ctxText}\n\nFACTS:\n${text}` }], [], { maxTokens, temperature: 0 });
  let res = await ask("", 5000); let usage = { ...res.usage };
  let parsed = parseLooseJson(String(res.message.content ?? ""));
  if (!parsed) { res = await ask("\nIMPORTANT: your previous answer was cut off. Use at most 6 stops and keep texts short.", 7000); usage = { input: usage.input + res.usage.input, output: usage.output + res.usage.output }; parsed = parseLooseJson(String(res.message.content ?? "")); }
  if (!parsed) throw new Error(`the AI returned broken JSON (finish: ${res.finish})`);
  const p = impactSchema.parse(parsed);
  if (!p.use_now_if.length && !p.before.length) ctx.log.warn({ keys: Object.keys(parsed ?? {}), sample: JSON.stringify(parsed).slice(0, 800) }, "contain impact: guidance lists came back empty");
  const restore = (s: string) => s.replace(/\bU\d{2}\b/g, (ps) => map.get(ps) ?? ps);
  const deep = (v: any): any => typeof v === "string" ? restore(v) : Array.isArray(v) ? v.map(deep) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, deep(x)])) : v;
  const content = { ...deep(p), platform, keeps_behaviour: keepsFor(platform) };
  const [id] = await ctx.db("host_ai_notes").insert({ host_id: host.id, kind: "contain_impact", scan_id: scan.id, content: JSON.stringify(content), model: res.model, tokens: usage.input + usage.output, requested_by: userId })
    .returning("id").then((x: any) => [typeof x[0] === "object" ? x[0].id : x[0]]);
  // keep the last 5 per host
  const old = await ctx.db("host_ai_notes").where({ host_id: host.id, kind: "contain_impact" }).orderBy("id", "desc").offset(5).select("id");
  if (old.length) await ctx.db("host_ai_notes").whereIn("id", old.map((o: any) => o.id)).delete();
  await ctx.audit.log(userId ? "user" : "system", userId, "host.contain_impact_generated", { host: host.name, scan_id: scan.id, model: res.model, tokens: usage.input + usage.output });
  return (await ctx.db("host_ai_notes").where({ id }).first());
}
