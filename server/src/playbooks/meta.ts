/**
 * Structured playbook model. The UI edits `PlaybookMeta`; the investigation agent reads the markdown that
 * `renderMarkdown` generates from it. Legacy markdown-only playbooks are split into sections by `parseMarkdown`.
 */
import { z } from "zod";

export const procedureSchema = z.object({ title: z.string().min(1).max(200), steps: z.array(z.string().max(2000)).default([]) });
export const fixSchema = z.object({
  title: z.string().min(1).max(200),
  when: z.string().max(2000).default(""),
  commands: z.array(z.string().max(2000)).default([]),
  rollback: z.array(z.string().max(2000)).default([]),
  approval: z.enum(["always", "auto_low_risk", "never"]).default("always"),
  note: z.string().max(2000).default(""),
});
export const precedentSchema = z.object({ date: z.string().max(32).default(""), summary: z.string().max(2000), ref: z.string().max(200).default("") });
export const extraSchema = z.object({ title: z.string().max(200), items: z.array(z.string().max(4000)).default([]) });

export const playbookMetaSchema = z.object({
  purpose: z.string().max(4000).default(""),
  targets: z.array(z.string().max(128)).default([]),
  environment: z.enum(["lab", "staging", "production", "mixed"]).nullable().default(null),
  record_to: z.string().max(200).default(""),
  tags: z.array(z.string().max(64)).default([]),
  facts: z.array(z.string().max(2000)).default([]),
  prohibitions: z.array(z.string().max(2000)).default([]),
  procedures: z.array(procedureSchema).default([]),
  fixes: z.array(fixSchema).default([]),
  precedents: z.array(precedentSchema).default([]),
  extra: z.array(extraSchema).default([]),
});
export type PlaybookMeta = z.infer<typeof playbookMetaSchema>;

export function emptyMeta(): PlaybookMeta { return playbookMetaSchema.parse({}); }

const APPROVAL_JA: Record<string, string> = { always: "常に人の承認が必要", auto_low_risk: "低リスクなら自動実行可（L2 以上）", never: "AI からは実行しない（提案のみ）" };

/** Markdown for the agent's system prompt. Deterministic; no secrets are added. */
export function renderMarkdown(name: string, m: PlaybookMeta): string {
  const out: string[] = [`# ${name}`];
  const head: string[] = [];
  if (m.purpose) head.push(m.purpose.trim());
  if (m.targets.length) head.push(`対象: ${m.targets.join(", ")}`);
  if (m.environment) head.push(`環境区分: ${m.environment}`);
  if (m.tags.length) head.push(`タグ: ${m.tags.join(", ")}`);
  if (head.length) out.push(head.join("\n"));
  if (m.facts.length) out.push(`## 環境の事実\n${m.facts.map((x) => `- ${x}`).join("\n")}`);
  if (m.prohibitions.length) out.push(`## 禁止事項（絶対に提案・実行しない）\n${m.prohibitions.map((x) => `- ${x}`).join("\n")}`);
  for (const p of m.procedures) out.push(`## 調査手順: ${p.title}\n${p.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}`);
  if (m.fixes.length) out.push(`## 定型の対処\n` + m.fixes.map((f) => {
    const lines = [`### ${f.title}`];
    if (f.when) lines.push(`条件: ${f.when}`);
    if (f.commands.length) lines.push("コマンド:\n```\n" + f.commands.join("\n") + "\n```");
    if (f.rollback.length) lines.push("戻し方:\n```\n" + f.rollback.join("\n") + "\n```");
    lines.push(`承認: ${APPROVAL_JA[f.approval] ?? f.approval}`);
    if (f.note) lines.push(f.note);
    return lines.join("\n");
  }).join("\n\n"));
  if (m.precedents.length) out.push(`## 過去の前例\n${m.precedents.map((p) => `- ${[p.date, p.summary, p.ref].filter(Boolean).join(" — ")}`).join("\n")}`);
  for (const e of m.extra) if (e.title || e.items.length) out.push(`## ${e.title || "補足"}\n${e.items.map((x) => `- ${x}`).join("\n")}`);
  if (m.record_to) out.push(`## 記録先\n${m.record_to}`);
  return out.join("\n\n") + "\n";
}

/** Heuristic split of a legacy markdown playbook into the structured model (headings → fields by keyword). */
export function parseMarkdown(md: string): PlaybookMeta {
  const m = emptyMeta();
  const lines = md.replace(/\r/g, "").split("\n");
  type Sec = { title: string; body: string[] };
  const secs: Sec[] = [];
  let cur: Sec = { title: "", body: [] };
  let title = "";
  for (const l of lines) {
    const h1 = l.match(/^#\s+(.+)/); const h = l.match(/^#{2,4}\s+(.+)/);
    if (h1 && !title) { title = h1[1].trim(); continue; }
    if (h) { if (cur.title || cur.body.some((x) => x.trim())) secs.push(cur); cur = { title: h[1].trim(), body: [] }; continue; }
    cur.body.push(l);
  }
  if (cur.title || cur.body.some((x) => x.trim())) secs.push(cur);
  const items = (body: string[]) => {
    const out: string[] = []; let inCode = false; let code: string[] = [];
    for (const l of body) {
      if (/^```/.test(l)) { if (inCode) { out.push(code.join("\n")); code = []; } inCode = !inCode; continue; }
      if (inCode) { code.push(l); continue; }
      const b = l.match(/^\s*(?:[-*•]|\d+[.)])\s+(.*)/);
      if (b) out.push(b[1].trim());
      else if (l.trim() && !/^\|/.test(l)) { if (out.length && !/[。.!?）)]$/.test(out[out.length - 1]) && /^\s{2,}/.test(l)) out[out.length - 1] += " " + l.trim(); else out.push(l.trim()); }
      else if (/^\|/.test(l) && !/^\|\s*-/.test(l)) out.push(l.replace(/^\||\|$/g, "").split("|").map((c) => c.trim()).filter(Boolean).join(" / "));
    }
    return out.filter(Boolean);
  };
  for (const s of secs) {
    const t = s.title.toLowerCase();
    if (!s.title) { // preamble: prose → purpose, bullets/tables → facts
      const prose = s.body.filter((x) => x.trim() && !/^\s*(?:[-*•]|\d+[.)]|\|)/.test(x)).map((x) => x.trim());
      m.purpose = prose.join("\n"); m.facts.push(...items(s.body.filter((x) => /^\s*(?:[-*•]|\d+[.)]|\|)/.test(x))));
      continue;
    }
    if (/目的|対象|scope|purpose|overview|概要/.test(t)) { m.purpose = [m.purpose, ...items(s.body)].filter(Boolean).join("\n"); continue; }
    if (/禁止|never|do not|don't|must not|prohibit|guardrail|hard rules|rules|やってはいけない|触らない/.test(t)) { m.prohibitions.push(...items(s.body)); continue; }
    if (/事実|環境|facts|environment|inventory|構成|hosts|known|what runs|runs there|stack|benign|patterns|event ids|network|access/.test(t)) { m.facts.push(...items(s.body)); continue; }
    if (/手順|procedure|investigat|triage|how to|調査|確認|query|querying|useful reads|reads|checks/.test(t)) { m.procedures.push({ title: s.title, steps: items(s.body) }); continue; }
    if (/対処|fix|remediat|routine|action|response|対応|operations|ops/.test(t)) { for (const it of items(s.body)) m.fixes.push({ title: it.slice(0, 200), when: "", commands: [], rollback: [], approval: "always", note: it.length > 200 ? it : "" }); continue; }
    if (/前例|precedent|history|incident|past|履歴|実績/.test(t)) { for (const it of items(s.body)) { const d = it.match(/^(\d{4}-\d{2}-\d{2})\s*[:：—-]?\s*(.*)/); m.precedents.push({ date: d?.[1] ?? "", summary: d?.[2] ?? it, ref: (it.match(/\b[A-Z][A-Z0-9]+-\d+\b/) ?? [""])[0] }); } continue; }
    if (/記録|record|jira|logging|where to/.test(t)) { m.record_to = items(s.body).join("; "); continue; }
    m.extra.push({ title: s.title, items: items(s.body) });
  }
  const refs = md.match(/\b(EDR|CAM|OPS)-\d+\b/g);
  if (!m.record_to && refs?.length) m.record_to = [...new Set(refs)].slice(0, 5).join(", ");
  if (/production|本番/.test(md) && /lab|ラボ|検証/.test(md)) m.environment = "mixed"; else if (/production|本番/.test(md)) m.environment = "production"; else if (/\blab\b|ラボ/.test(md)) m.environment = "lab";
  return m;
}

/** Normalise untrusted input (LLM / UI) into a valid meta or throw a zod error. */
export function coerceMeta(input: unknown): PlaybookMeta {
  const r = playbookMetaSchema.safeParse(input ?? {});
  if (!r.success) throw Object.assign(new Error("meta: " + r.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join(", ")), { status: 400 });
  return r.data;
}
