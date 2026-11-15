/**
 * EDR-155: AI suggestions for the host settings (役割メモ / タグ / 使い方), from the latest AI host scan.
 * Rules (agreed with the user):
 *  - only for fields a person has not filled in or decided: notes empty, tags still the automatic [os], environment never decided
 *  - "反映する" or "このままでいい" decides the field; it is not suggested again …
 *  - … unless the scan says the PURPOSE changed (purpose_key differs from the one it was decided for) → suggested once more, marked "changed"
 *  - never written automatically (environment changes how strict approvals are); no notifications
 */
import type { Ctx } from "../api/context.js";

export type Field = "notes" | "tags" | "environment";
export interface Suggestion { field: Field; value: any; current: any; reason: string; changed: boolean; purpose_key: string }
type Decision = { state: "applied" | "dismissed" | "manual"; purpose_key: string | null; at: string };
type Decisions = Partial<Record<Field, Decision>>;

const pj = <T>(v: any): T | null => { if (v == null) return null; if (typeof v !== "string") return v as T; try { return JSON.parse(v) as T; } catch { return null; } };
export const decisionsOf = (h: any): Decisions => pj<Decisions>(h.ai_decisions) ?? {};
const autoTags = (h: any) => [String(h.os_family ?? "")].filter(Boolean);
const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.map((y) => y.toLowerCase()).includes(x.toLowerCase()));

export async function latestProfile(ctx: Ctx, hostId: number): Promise<{ scan_id: number; profile: any } | null> {
  const s = await ctx.db("host_scans").where({ host_id: hostId, status: "done" }).whereNotNull("profile").orderBy("id", "desc").first();
  const p = s ? pj<any>(s.profile) : null;
  return s && p?.suggest ? { scan_id: s.id, profile: p } : null;
}

export function suggestionsFor(h: any, profile: any): Suggestion[] {
  const sg = profile?.suggest; if (!sg) return [];
  const pk = String(sg.purpose_key || "other");
  const dec = decisionsOf(h);
  const out: Suggestion[] = [];
  const open = (f: Field, filled: boolean) => {
    const d = dec[f];
    if (!d) return filled ? null : { changed: false };                    // not decided: only when the field is still empty / automatic
    if (d.purpose_key && pk !== "other" && d.purpose_key !== pk) return { changed: true }; // the purpose changed since it was decided
    return null;
  };
  const tags: string[] = pj<string[]>(h.tags) ?? [];
  let o = open("notes", !!String(h.notes ?? "").trim());
  if (o && sg.notes && sg.notes !== h.notes) out.push({ field: "notes", value: String(sg.notes).slice(0, 200), current: h.notes ?? "", reason: profile.usage?.primary_use || "", changed: o.changed, purpose_key: pk });
  o = open("tags", !sameSet(tags, autoTags(h)) && tags.length > 0);
  if (o && sg.tags?.length && !sameSet(sg.tags, tags)) out.push({ field: "tags", value: [...new Set([...tags, ...sg.tags.map((t: string) => t.toLowerCase())])].slice(0, 8), current: tags, reason: (profile.role_tags ?? []).join(", "), changed: o.changed, purpose_key: pk });
  if (sg.use !== "unknown") {
    const want = sg.use === "business" ? "production" : "lab";
    o = open("environment", false);
    if (o && want !== h.environment) out.push({ field: "environment", value: want, current: h.environment, reason: sg.use_reason || "", changed: o.changed, purpose_key: pk });
  }
  return out;
}

export async function decide(ctx: Ctx, h: any, field: Field, state: Decision["state"], purposeKey: string | null): Promise<void> {
  const dec = decisionsOf(h);
  dec[field] = { state, purpose_key: purposeKey, at: new Date().toISOString() };
  await ctx.db("hosts").where({ id: h.id }).update({ ai_decisions: JSON.stringify(dec) });
}
