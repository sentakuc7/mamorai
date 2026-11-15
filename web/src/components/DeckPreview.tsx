import { useEffect, useRef, useState } from "react";

/** Browser preview of a write_pptx deck, rendered from the same structured spec the server used (same design, not a pixel copy). */
export interface DeckSpec { title: string; subtitle?: string; author?: string; date?: string; slides: SlideSpec[] }
export interface SlideSpec { layout: string; title?: string; subtitle?: string; bullets?: string[]; right_bullets?: string[]; kpis?: { label: string; value: string; tone?: string }[]; chart?: { type: string; categories: string[]; series: { name: string; values: number[] }[]; unit?: string }; table?: { headers: string[]; rows: (string | number)[][] }; takeaway?: string; notes?: string }

const PALETTE = ["#0F766E", "#F59E0B", "#3B82F6", "#EF4444", "#8B5CF6", "#10B981", "#F97316", "#64748B"];
const TONE: Record<string, string> = { good: "#15803D", warn: "#B45309", bad: "#B91C1C", neutral: "#0F766E" };
const W = 1280, H = 720;

function Chart({ c, w, h }: { c: NonNullable<SlideSpec["chart"]>; w: number; h: number }) {
  const cats = c.categories ?? []; const series = c.series ?? [];
  if (c.type === "pie" || c.type === "doughnut") {
    const vals = series[0]?.values ?? []; const total = vals.reduce((a, b) => a + b, 0) || 1;
    const r = Math.min(w, h) / 2 - 20, cx = r + 20, cy = h / 2; let ang = -Math.PI / 2;
    const arcs = vals.map((v, i) => { const a0 = ang, a1 = ang + (v / total) * 2 * Math.PI; ang = a1; const big = a1 - a0 > Math.PI ? 1 : 0; const p = (a: number) => [cx + r * Math.cos(a), cy + r * Math.sin(a)]; const [x0, y0] = p(a0), [x1, y1] = p(a1); return <path key={i} d={`M${cx},${cy} L${x0},${y0} A${r},${r} 0 ${big} 1 ${x1},${y1} Z`} fill={PALETTE[i % PALETTE.length]} stroke="#fff" strokeWidth={2} />; });
    return <svg width={w} height={h}>{arcs}{c.type === "doughnut" && <circle cx={cx} cy={cy} r={r * 0.55} fill="#fff" />}
      {cats.map((l, i) => <g key={i} transform={`translate(${cx + r + 40},${h / 2 - cats.length * 11 + i * 22})`}><rect width={12} height={12} fill={PALETTE[i % PALETTE.length]} /><text x={18} y={11} fontSize={13} fill="#1E293B">{l} {total ? Math.round(((vals[i] ?? 0) / total) * 100) : 0}%</text></g>)}</svg>;
  }
  const pad = { l: 50, r: 20, t: 20, b: 40 }; const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
  const max = Math.max(1, ...series.flatMap((s) => s.values)); const ticks = 4;
  const horizontal = c.type === "bar";
  return (
    <svg width={w} height={h} fontSize={12} fill="#64748B">
      {Array.from({ length: ticks + 1 }, (_, i) => { const v = (max / ticks) * i; const y = pad.t + ih - (v / max) * ih; return horizontal ? null : <g key={i}><line x1={pad.l} x2={pad.l + iw} y1={y} y2={y} stroke="#E2E8F0" /><text x={pad.l - 6} y={y + 4} textAnchor="end">{Math.round(v)}</text></g>; })}
      {c.type === "line" ? series.map((s, si) => {
        const pts = s.values.map((v, i) => [pad.l + (cats.length > 1 ? (i / (cats.length - 1)) * iw : iw / 2), pad.t + ih - (v / max) * ih]);
        return <g key={si}><polyline points={pts.map((p) => p.join(",")).join(" ")} fill="none" stroke={PALETTE[si % PALETTE.length]} strokeWidth={2.5} />{pts.map((p, i) => <g key={i}><circle cx={p[0]} cy={p[1]} r={4} fill={PALETTE[si % PALETTE.length]} /><text x={p[0]} y={p[1] - 8} textAnchor="middle" fill="#1E293B">{s.values[i]}</text></g>)}</g>;
      }) : horizontal ? cats.map((cat, i) => { const bh = ih / cats.length; return series.map((s, si) => { const bw = (s.values[i] / max) * iw; const y = pad.t + i * bh + (bh / (series.length + 1)) * (si + 0.5); const hh = bh / (series.length + 1); return <g key={`${i}-${si}`}><rect x={pad.l} y={y} width={bw} height={hh} fill={PALETTE[si % PALETTE.length]} rx={2} /><text x={pad.l + bw + 6} y={y + hh / 2 + 4} fill="#1E293B">{s.values[i]}</text></g>; }); })
        : cats.map((cat, i) => { const gw = iw / cats.length; const bw = (gw * 0.6) / series.length; return series.map((s, si) => { const bh = (s.values[i] / max) * ih; const x = pad.l + i * gw + gw * 0.2 + si * bw; return <g key={`${i}-${si}`}><rect x={x} y={pad.t + ih - bh} width={bw - 2} height={bh} fill={PALETTE[si % PALETTE.length]} rx={2} /><text x={x + bw / 2} y={pad.t + ih - bh - 6} textAnchor="middle" fill="#1E293B">{s.values[i]}</text></g>; }); })}
      {cats.map((cat, i) => horizontal ? <text key={i} x={pad.l - 6} y={pad.t + (i + 0.5) * (ih / cats.length) + 4} textAnchor="end">{cat}</text> : <text key={i} x={pad.l + (c.type === "line" ? (cats.length > 1 ? (i / (cats.length - 1)) * iw : iw / 2) : (i + 0.5) * (iw / cats.length))} y={pad.t + ih + 18} textAnchor="middle">{cat}</text>)}
      {series.length > 1 && series.map((s, si) => <g key={si} transform={`translate(${pad.l + si * 140},${h - 12})`}><rect width={12} height={12} y={-10} fill={PALETTE[si % PALETTE.length]} /><text x={16} fill="#1E293B">{s.name}</text></g>)}
    </svg>
  );
}

function Bullets({ items, size = 22 }: { items?: string[]; size?: number }) {
  return <ul className="space-y-2">{(items ?? []).map((t, i) => <li key={i} className="flex gap-3 text-slate-800" style={{ fontSize: size }}><span className="mt-[0.45em] inline-block h-2.5 w-2.5 shrink-0 bg-teal-700" />{t}</li>)}</ul>;
}

function Slide({ deck, s, n, total }: { deck: DeckSpec; s: SlideSpec | null; n: number; total: number }) {
  const font = { fontFamily: "'Noto Sans JP', sans-serif" };
  if (!s) return ( // cover
    <div className="relative h-full w-full bg-white" style={font}><div className="absolute inset-y-0 left-0 w-9 bg-teal-700" />
      <div className="absolute left-24 right-24 top-56"><div className="text-5xl font-bold text-slate-800">{deck.title}</div>{deck.subtitle && <div className="mt-6 text-2xl text-slate-500">{deck.subtitle}</div>}</div>
      <div className="absolute bottom-24 left-24 text-base text-slate-500">{[deck.date, deck.author].filter(Boolean).join(" · ")}</div></div>);
  if (s.layout === "closing") return (
    <div className="h-full w-full bg-teal-700 p-24 text-white" style={font}><div className="text-4xl font-bold">{s.title ?? "まとめ"}</div><div className="mt-10"><ul className="space-y-4">{(s.bullets ?? []).map((t, i) => <li key={i} className="flex gap-3 text-2xl"><span className="mt-2 inline-block h-3 w-3 shrink-0 bg-white" />{t}</li>)}</ul></div></div>);
  const bodyTop = s.subtitle ? 150 : 120; const bodyH = H - bodyTop - (s.takeaway ? 160 : 80);
  return (
    <div className="relative h-full w-full bg-white" style={font}>
      <div className="absolute inset-x-0 top-0 h-3 bg-teal-700" />
      <div className="absolute left-14 right-14 top-8 text-4xl font-bold text-slate-800">{s.title}</div>
      {s.subtitle && <div className="absolute left-14 right-14 top-24 text-lg text-slate-500">{s.subtitle}</div>}
      <div className="absolute left-14 right-14" style={{ top: bodyTop, height: bodyH }}>
        {s.layout === "kpi" && <><div className="grid gap-6" style={{ gridTemplateColumns: `repeat(${Math.min(4, s.kpis?.length ?? 1)}, 1fr)` }}>{(s.kpis ?? []).slice(0, 4).map((k, i) => <div key={i} className="relative rounded-lg border border-slate-200 bg-slate-50 p-5" style={{ height: 160 }}><div className="absolute inset-y-0 left-0 w-2 rounded-l-lg" style={{ background: TONE[k.tone ?? "neutral"] }} /><div className="text-5xl font-bold" style={{ color: TONE[k.tone ?? "neutral"] }}>{k.value}</div><div className="mt-3 text-base text-slate-500">{k.label}</div></div>)}</div><div className="mt-8"><Bullets items={s.bullets} size={18} /></div></>}
        {(s.layout === "bullets" || s.layout === "title") && <Bullets items={s.bullets} />}
        {s.layout === "two_column" && <div className="grid grid-cols-2 gap-10"><Bullets items={s.bullets} size={19} /><Bullets items={s.right_bullets} size={19} /></div>}
        {s.layout === "chart" && s.chart && <Chart c={s.chart} w={W - 112} h={bodyH} />}
        {s.layout === "chart_bullets" && <div className="flex gap-8">{s.chart && <Chart c={s.chart} w={(W - 112) * 0.58} h={bodyH} />}<div className="flex-1"><Bullets items={s.bullets} size={18} /></div></div>}
        {s.layout === "table" && s.table && <table className="w-full border-collapse text-base"><thead><tr>{s.table.headers.map((h, i) => <th key={i} className="border border-slate-200 bg-teal-700 px-3 py-2 text-left font-semibold text-white">{h}</th>)}</tr></thead><tbody>{s.table.rows.slice(0, 14).map((r, i) => <tr key={i} className={i % 2 ? "bg-slate-50" : "bg-white"}>{r.map((c, k) => <td key={k} className="border border-slate-200 px-3 py-1.5 text-slate-800">{String(c ?? "")}</td>)}</tr>)}</tbody></table>}
      </div>
      {s.takeaway && <div className="absolute left-14 right-14 flex items-center gap-3 rounded-md border border-teal-400 bg-emerald-50 px-5 text-lg text-slate-800" style={{ bottom: 86, height: 58 }}><span className="font-bold text-teal-700">要点</span>{s.takeaway}</div>}
      <div className="absolute inset-x-14 flex justify-between border-t border-slate-200 pt-2 text-sm text-slate-500" style={{ bottom: 28 }}><span>{deck.title}{deck.date ? " · " + deck.date : ""}</span><span>{n} / {total}</span></div>
    </div>
  );
}

export default function DeckPreview({ deck }: { deck: DeckSpec }) {
  const [i, setI] = useState(0); const wrap = useRef<HTMLDivElement>(null); const [scale, setScale] = useState(0.5);
  const pages: (SlideSpec | null)[] = [null, ...(deck.slides ?? [])]; const total = pages.length;
  useEffect(() => { const el = wrap.current; if (!el) return; const ro = new ResizeObserver(() => setScale(el.clientWidth / W)); ro.observe(el); setScale(el.clientWidth / W); return () => ro.disconnect(); }, []);
  const cur = pages[i];
  return (
    <div className="space-y-2">
      <div ref={wrap} className="relative w-full overflow-hidden rounded border border-slate-500/60 bg-white" style={{ height: H * scale }}>
        <div style={{ width: W, height: H, transform: `scale(${scale})`, transformOrigin: "top left" }}><Slide deck={deck} s={cur} n={i + 1} total={total} /></div>
      </div>
      <div className="flex items-center gap-2 text-xs text-slate-300">
        <button className="btn-secondary px-2 py-0.5 text-xs" disabled={i === 0} onClick={() => setI(i - 1)}>‹ 前</button>
        <span>{i + 1} / {total}{cur?.title ? ` · ${cur.title}` : " · 表紙"}</span>
        <button className="btn-secondary px-2 py-0.5 text-xs" disabled={i === total - 1} onClick={() => setI(i + 1)}>次 ›</button>
        <div className="ml-auto flex gap-1 overflow-x-auto">{pages.map((p, k) => <button key={k} title={p?.title ?? "表紙"} onClick={() => setI(k)} className={`h-2 w-6 rounded-sm ${k === i ? "bg-teal-400" : "bg-slate-700 hover:bg-slate-600"}`} />)}</div>
      </div>
      {cur?.notes && <div className="rounded bg-slate-700/50 p-2 text-[11px] text-slate-400">ノート: {cur.notes}</div>}
      <div className="text-[10px] text-slate-500">※ 構成データからの簡易プレビューです。実際の PowerPoint ではグラフ・表が編集可能なオブジェクトになります。</div>
    </div>
  );
}
