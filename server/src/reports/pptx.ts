/**
 * Server-side PowerPoint generation for the agent's `write_pptx` tool.
 * The LLM supplies structured slides; this module applies one consistent design (16:9, light executive theme,
 * native editable charts/tables via pptxgenjs) so every deck looks the same regardless of the model.
 */
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const PptxGenJS = require("pptxgenjs");

export interface ChartSpec { type: "bar" | "column" | "pie" | "doughnut" | "line"; categories: string[]; series: { name: string; values: number[] }[]; unit?: string }
export interface Slide {
  layout: "title" | "kpi" | "bullets" | "chart" | "table" | "two_column" | "chart_bullets" | "closing";
  title?: string; subtitle?: string;
  bullets?: string[]; right_bullets?: string[];
  kpis?: { label: string; value: string; tone?: "neutral" | "good" | "warn" | "bad" }[];
  chart?: ChartSpec;
  table?: { headers: string[]; rows: (string | number)[][] };
  notes?: string; takeaway?: string;
}
export interface DeckSpec { title: string; subtitle?: string; author?: string; date?: string; slides: Slide[] }

const C = { bg: "FFFFFF", ink: "1E293B", muted: "64748B", line: "E2E8F0", accent: "0F766E", accent2: "14B8A6", good: "15803D", warn: "B45309", bad: "B91C1C", panel: "F8FAFC" };
const PALETTE = ["0F766E", "F59E0B", "3B82F6", "EF4444", "8B5CF6", "10B981", "F97316", "64748B"];
const FONT = "Noto Sans JP";
const W = 13.333, H = 7.5, M = 0.6;

function header(s: any, title?: string, subtitle?: string) {
  s.addShape("rect", { x: 0, y: 0, w: W, h: 0.12, fill: { color: C.accent } });
  if (title) s.addText(title, { x: M, y: 0.35, w: W - 2 * M, h: 0.7, fontFace: FONT, fontSize: 26, bold: true, color: C.ink });
  if (subtitle) s.addText(subtitle, { x: M, y: 1.0, w: W - 2 * M, h: 0.4, fontFace: FONT, fontSize: 13, color: C.muted });
}
function footer(s: any, deck: DeckSpec, n: number, total: number) {
  s.addShape("line", { x: M, y: H - 0.55, w: W - 2 * M, h: 0, line: { color: C.line, width: 0.75 } });
  s.addText(`${deck.title}${deck.date ? " · " + deck.date : ""}`, { x: M, y: H - 0.5, w: W - 3, h: 0.35, fontFace: FONT, fontSize: 9, color: C.muted });
  s.addText(`${n} / ${total}`, { x: W - M - 1.5, y: H - 0.5, w: 1.5, h: 0.35, fontFace: FONT, fontSize: 9, color: C.muted, align: "right" });
}
function takeaway(s: any, text?: string) {
  if (!text) return;
  s.addShape("rect", { x: M, y: H - 1.35, w: W - 2 * M, h: 0.6, fill: { color: "ECFDF5" }, line: { color: C.accent2, width: 0.75 }, rectRadius: 0.08 });
  s.addText([{ text: "要点  ", options: { bold: true, color: C.accent } }, { text, options: { color: C.ink } }], { x: M + 0.2, y: H - 1.35, w: W - 2 * M - 0.4, h: 0.6, fontFace: FONT, fontSize: 12, valign: "middle" });
}
function bullets(s: any, items: string[], x: number, y: number, w: number, h: number, size = 14) {
  if (!items?.length) return;
  s.addText(items.map((t) => ({ text: t, options: { bullet: { code: "25A0" }, breakLine: true } })), { x, y, w, h, fontFace: FONT, fontSize: size, color: C.ink, valign: "top", paraSpaceAfter: 6 });
}
function chart(s: any, c: ChartSpec, x: number, y: number, w: number, h: number) {
  const typeMap: Record<string, string> = { bar: "bar", column: "bar", pie: "pie", doughnut: "doughnut", line: "line" };
  const data = c.type === "pie" || c.type === "doughnut" ? [{ name: c.series[0]?.name ?? "", labels: c.categories, values: c.series[0]?.values ?? [] }] : c.series.map((se) => ({ name: se.name, labels: c.categories, values: se.values }));
  const opts: any = {
    x, y, w, h, chartColors: PALETTE, dataLabelFontFace: FONT, dataLabelFontSize: 10, dataLabelColor: C.ink,
    catAxisLabelFontFace: FONT, catAxisLabelFontSize: 10, catAxisLabelColor: C.muted, valAxisLabelFontFace: FONT, valAxisLabelFontSize: 10, valAxisLabelColor: C.muted,
    valGridLine: { color: C.line, style: "solid", size: 0.5 }, catGridLine: { style: "none" },
    showLegend: c.series.length > 1 || c.type === "pie" || c.type === "doughnut", legendPos: "b", legendFontFace: FONT, legendFontSize: 10, legendColor: C.ink,
    showValue: true, barDir: c.type === "bar" ? "bar" : "col", barGapWidthPct: 60, lineSize: 2, lineDataSymbolSize: 6,
  };
  if (c.type === "pie" || c.type === "doughnut") { opts.showPercent = true; opts.showValue = false; opts.dataLabelPosition = "bestFit"; if (c.type === "doughnut") opts.holeSize = 55; }
  if (c.unit) opts.valAxisTitle = c.unit, opts.showValAxisTitle = true, opts.valAxisTitleFontFace = FONT, opts.valAxisTitleFontSize = 10, opts.valAxisTitleColor = C.muted;
  s.addChart(typeMap[c.type] ?? "bar", data, opts);
}
function table(s: any, t: { headers: string[]; rows: (string | number)[][] }, x: number, y: number, w: number) {
  const head = t.headers.map((h) => ({ text: String(h), options: { bold: true, color: "FFFFFF", fill: { color: C.accent }, fontFace: FONT, fontSize: 11 } }));
  const body = t.rows.slice(0, 14).map((r, i) => r.map((c) => ({ text: String(c ?? ""), options: { fontFace: FONT, fontSize: 10.5, color: C.ink, fill: { color: i % 2 ? C.panel : "FFFFFF" } } })));
  s.addTable([head, ...body], { x, y, w, colW: Array(t.headers.length).fill(w / t.headers.length), border: { type: "solid", color: C.line, pt: 0.5 }, autoPage: false, rowH: 0.34 });
}
function kpis(s: any, items: { label: string; value: string; tone?: string }[], y: number) {
  const n = Math.min(items.length, 4); const gap = 0.3; const w = (W - 2 * M - gap * (n - 1)) / n;
  items.slice(0, 4).forEach((k, i) => {
    const x = M + i * (w + gap); const tone = k.tone === "good" ? C.good : k.tone === "warn" ? C.warn : k.tone === "bad" ? C.bad : C.accent;
    s.addShape("rect", { x, y, w, h: 1.7, fill: { color: C.panel }, line: { color: C.line, width: 0.75 }, rectRadius: 0.1 });
    s.addShape("rect", { x, y, w: 0.09, h: 1.7, fill: { color: tone } });
    s.addText(k.value, { x: x + 0.2, y: y + 0.2, w: w - 0.4, h: 0.9, fontFace: FONT, fontSize: 34, bold: true, color: tone, valign: "middle" });
    s.addText(k.label, { x: x + 0.2, y: y + 1.1, w: w - 0.4, h: 0.45, fontFace: FONT, fontSize: 12, color: C.muted });
  });
}

export async function buildPptx(deck: DeckSpec): Promise<Buffer> {
  const pptx = new PptxGenJS();
  pptx.layout = "LAYOUT_WIDE"; // 13.333 x 7.5
  pptx.title = deck.title; if (deck.author) pptx.author = deck.author;
  const slides = deck.slides.length ? deck.slides : [{ layout: "bullets", title: deck.title, bullets: ["(内容なし)"] } as Slide];
  const total = slides.length + 1;
  // title slide
  {
    const s = pptx.addSlide(); s.background = { color: C.bg };
    s.addShape("rect", { x: 0, y: 0, w: 0.35, h: H, fill: { color: C.accent } });
    s.addText(deck.title, { x: 1.0, y: 2.3, w: W - 2, h: 1.4, fontFace: FONT, fontSize: 36, bold: true, color: C.ink, valign: "bottom" });
    if (deck.subtitle) s.addText(deck.subtitle, { x: 1.0, y: 3.8, w: W - 2, h: 0.7, fontFace: FONT, fontSize: 16, color: C.muted });
    s.addText([deck.date, deck.author].filter(Boolean).join(" · ") || new Date().toISOString().slice(0, 10), { x: 1.0, y: H - 1.3, w: W - 2, h: 0.4, fontFace: FONT, fontSize: 11, color: C.muted });
  }
  slides.forEach((sl, i) => {
    const s = pptx.addSlide(); s.background = { color: C.bg };
    const n = i + 2; const top = sl.subtitle ? 1.55 : 1.25; const bodyH = H - top - (sl.takeaway ? 1.6 : 0.8);
    if (sl.layout === "closing") {
      s.addShape("rect", { x: 0, y: 0, w: W, h: H, fill: { color: C.accent } });
      s.addText(sl.title ?? "まとめ", { x: 1, y: 1.2, w: W - 2, h: 0.9, fontFace: FONT, fontSize: 30, bold: true, color: "FFFFFF" });
      s.addText((sl.bullets ?? []).map((t) => ({ text: t, options: { bullet: { code: "25A0" }, breakLine: true } })), { x: 1, y: 2.3, w: W - 2, h: H - 3.2, fontFace: FONT, fontSize: 16, color: "FFFFFF", valign: "top", paraSpaceAfter: 8 });
      if (sl.notes) s.addNotes(sl.notes); return;
    }
    header(s, sl.title, sl.subtitle); footer(s, deck, n, total);
    switch (sl.layout) {
      case "title": s.addText(sl.bullets?.join("\n") ?? "", { x: M, y: top + 0.5, w: W - 2 * M, h: bodyH - 0.5, fontFace: FONT, fontSize: 18, color: C.ink, valign: "top" }); break;
      case "kpi": if (sl.kpis?.length) kpis(s, sl.kpis, top + 0.1); bullets(s, sl.bullets ?? [], M, top + 2.1, W - 2 * M, bodyH - 2.1, 13); break;
      case "bullets": bullets(s, sl.bullets ?? [], M, top, W - 2 * M, bodyH, 16); break;
      case "two_column": bullets(s, sl.bullets ?? [], M, top, (W - 2 * M) / 2 - 0.2, bodyH, 14); bullets(s, sl.right_bullets ?? [], W / 2 + 0.2, top, (W - 2 * M) / 2 - 0.2, bodyH, 14); break;
      case "chart": if (sl.chart) chart(s, sl.chart, M, top, W - 2 * M, bodyH); break;
      case "chart_bullets": if (sl.chart) chart(s, sl.chart, M, top, (W - 2 * M) * 0.58, bodyH); bullets(s, sl.bullets ?? [], M + (W - 2 * M) * 0.62, top, (W - 2 * M) * 0.38, bodyH, 13); break;
      case "table": if (sl.table) table(s, sl.table, M, top, W - 2 * M); break;
      default: bullets(s, sl.bullets ?? [], M, top, W - 2 * M, bodyH, 16);
    }
    takeaway(s, sl.takeaway);
    if (sl.notes) s.addNotes(sl.notes);
  });
  const out = await pptx.write({ outputType: "nodebuffer" });
  return Buffer.from(out as ArrayBuffer);
}
