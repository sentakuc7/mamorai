/**
 * EDR-142: "ポンチ絵" — small explanatory diagrams drawn from JSON (the AI never writes SVG itself).
 *  - layout "contain": host in the middle, what keeps working on the left (green), what stops on the right (red, behind a wall)
 *  - layout "flow": boxes and arrows (steps, cause → effect, who talks to whom)
 * Used by the Contain help page and by SessionChat for ```diagram fences.
 */
import { useId } from "react";

export type Tone = "good" | "bad" | "warn" | "info" | "neutral";
export type Severity = "high" | "medium" | "low";
export type ContainSpec = { layout: "contain"; title?: string; host?: string; keeps?: (string | { label: string })[]; stops?: ({ label: string; severity?: Severity; group?: string } | string)[]; note?: string };
export type FlowSpec = { layout: "flow"; title?: string; nodes: { id: string; label: string; tone?: Tone; sub?: string }[]; edges?: { from: string; to: string; label?: string; dashed?: boolean }[]; note?: string };
export type DiagramSpec = ContainSpec | FlowSpec;

const TONE: Record<Tone, { fill: string; stroke: string; text: string }> = {
  good: { fill: "#0E2A22", stroke: "#2FBF8F", text: "#C9F5E4" },
  bad: { fill: "#2E1218", stroke: "#F0566E", text: "#FFD3DA" },
  warn: { fill: "#2D2410", stroke: "#F2B33D", text: "#FCE9C2" },
  info: { fill: "#132245", stroke: "#5B7CF5", text: "#D6E0FF" },
  neutral: { fill: "#1A2234", stroke: "#64748B", text: "#E2E8F0" },
};
const SEV: Record<Severity, string> = { high: "#F0566E", medium: "#F2B33D", low: "#94A3B8" };
const SEV_JA: Record<Severity, string> = { high: "影響大", medium: "影響中", low: "影響小" };
const GROUP_JA: Record<string, string> = { internet: "インターネット", lan: "社内 LAN・共有", inbound: "この端末へのアクセス", users: "利用者", other: "その他" };

/** split a label into lines; full-width chars count 2, others 1 */
export function wrapLabel(s: string, maxUnits = 22, maxLines = 3): string[] {
  const out: string[] = []; let cur = ""; let units = 0;
  for (const ch of Array.from(String(s ?? ""))) {
    const u = /[\u0000-ÿ｡-ﾟ]/.test(ch) ? 1 : 2;
    if (units + u > maxUnits) {
      // prefer breaking after a space / separator in the last few characters, so words and numbers stay together
      const chars = Array.from(cur); let cut = -1;
      for (let k = chars.length - 1; k >= Math.max(1, chars.length - 10); k--) { if (/[\s・、。,/）)]/.test(chars[k]) || /[（(]/.test(chars[k])) { cut = /[（(]/.test(chars[k]) ? k : k + 1; break; } }
      if (cut > 0) { out.push(chars.slice(0, cut).join("").trimEnd()); cur = chars.slice(cut).join("").trimStart(); units = Array.from(cur).reduce((n, c) => n + (/[\u0000-\u00ff\uff61-\uff9f]/.test(c) ? 1 : 2), 0); }
      else { out.push(cur); cur = ""; units = 0; }
    }
    cur += ch; units += u;
  }
  if (cur) out.push(cur);
  if (out.length > maxLines) { const cut = out.slice(0, maxLines); cut[maxLines - 1] = cut[maxLines - 1].slice(0, -1) + "…"; return cut; }
  return out.length ? out : [""];
}

/** parse ```diagram JSON (tolerant of trailing commas); null when it is not a usable diagram */
export function parseDiagram(src: string): DiagramSpec | null {
  let t = src.trim();
  try {
    t = t.replace(/,\s*([}\]])/g, "$1");
    const v = JSON.parse(t);
    if (v?.layout === "contain" && (Array.isArray(v.keeps) || Array.isArray(v.stops))) return v;
    if (v?.layout === "flow" && Array.isArray(v.nodes) && v.nodes.length) return { ...v, nodes: v.nodes.filter((n: any) => n && n.id != null).slice(0, 12).map((n: any) => ({ ...n, id: String(n.id), label: String(n.label ?? n.id) })) };
  } catch { /* fallthrough */ }
  return null;
}

function Box({ x, y, w, h, tone, lines, sub, rx = 10 }: { x: number; y: number; w: number; h: number; tone: Tone; lines: string[]; sub?: string; rx?: number }) {
  const c = TONE[tone];
  const lh = 15; const total = lines.length * lh + (sub ? 13 : 0);
  const y0 = y + h / 2 - total / 2 + 11;
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={rx} fill={c.fill} stroke={c.stroke} strokeWidth={1.5} />
      {lines.map((l, i) => <text key={i} x={x + w / 2} y={y0 + i * lh} textAnchor="middle" fontSize={12.5} fill={c.text}>{l}</text>)}
      {sub && <text x={x + w / 2} y={y0 + lines.length * lh} textAnchor="middle" fontSize={10.5} fill="#94A3B8">{sub}</text>}
    </g>
  );
}

function PcIcon({ cx, cy, tone }: { cx: number; cy: number; tone: Tone }) {
  const c = TONE[tone];
  return (
    <g>
      <rect x={cx - 26} y={cy - 20} width={52} height={34} rx={4} fill="#0B1220" stroke={c.stroke} strokeWidth={2} />
      <rect x={cx - 20} y={cy - 14} width={40} height={22} rx={2} fill={c.fill} />
      <rect x={cx - 8} y={cy + 14} width={16} height={6} fill={c.stroke} />
      <rect x={cx - 18} y={cy + 20} width={36} height={4} rx={2} fill={c.stroke} />
    </g>
  );
}

function ContainDiagram({ spec, mid }: { spec: ContainSpec; mid: string }) {
  const keeps = (spec.keeps ?? []).map((k) => (typeof k === "string" ? k : k?.label)).filter(Boolean).slice(0, 6) as string[];
  const stopsRaw = (spec.stops ?? []).map((s) => (typeof s === "string" ? { label: s } : s)).filter((s) => s?.label).slice(0, 10) as { label: string; severity?: Severity; group?: string }[];
  // group the stops (keeps AI order inside a group)
  const order: string[] = []; const byGroup = new Map<string, typeof stopsRaw>();
  for (const s of stopsRaw) { const g = s.group && GROUP_JA[s.group] ? s.group : ""; if (!byGroup.has(g)) { byGroup.set(g, []); order.push(g); } byGroup.get(g)!.push(s); }
  const W = 720; const top = spec.title ? 44 : 16;
  const boxH = 44, gap = 10, ghead = 18;
  const rows: any[] = []; let yy = top + 22;
  for (const g of order) { if (g && order.length > 1) { rows.push({ kind: "head", g, y: yy }); yy += ghead; } for (const s of byGroup.get(g)!) { rows.push({ kind: "stop", s, y: yy }); yy += boxH + gap; } }
  const rightH = yy - top; const leftH = 22 + keeps.length * (boxH + gap);
  const H = Math.max(rightH, leftH, 190) + top + (spec.note ? 40 : 14);
  const hostCx = 360, hostCy = top + Math.max(rightH, leftH, 190) / 2 + 6;
  const lx = 16, lw = 190, rx = 500, rw = 204, wallX = 452;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={spec.title ?? "通信遮断の影響図"} style={{ maxWidth: W }}>
      <defs>
        <marker id={`${mid}-ag`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#2FBF8F" /></marker>
        <pattern id={`${mid}-brick`} width="16" height="12" patternUnits="userSpaceOnUse"><rect width="16" height="12" fill="#3A1A20" /><path d="M0 6H16M8 0V6M0 6V12M16 6V12" stroke="#F0566E" strokeWidth="1" opacity=".7" /></pattern>
      </defs>
      {spec.title && <text x={16} y={26} fontSize={15} fontWeight={700} fill="#F1F5F9">{spec.title}</text>}
      <text x={lx} y={top + 12} fontSize={11.5} fill="#2FBF8F" fontWeight={700}>✓ 残る通信</text>
      <text x={rx} y={top + 12} fontSize={11.5} fill="#F0566E" fontWeight={700}>✕ 止まる通信</text>
      {/* the wall */}
      <rect x={wallX - 9} y={top + 18} width={18} height={Math.max(rightH, leftH, 190) - 14} rx={3} fill={`url(#${mid}-brick)`} stroke="#F0566E" strokeWidth={1} />
      <text x={wallX} y={top + Math.max(rightH, leftH, 190) + 16} textAnchor="middle" fontSize={10.5} fill="#F0566E">遮断（Contain）</text>
      {/* keeps */}
      {keeps.map((k, i) => { const y = top + 22 + i * (boxH + gap); return (
        <g key={`k${i}`}>
          <path d={`M${lx + lw} ${y + boxH / 2} C ${lx + lw + 60} ${y + boxH / 2}, ${hostCx - 110} ${hostCy}, ${hostCx - 58} ${hostCy}`} fill="none" stroke="#2FBF8F" strokeWidth={1.6} markerEnd={`url(#${mid}-ag)`} markerStart={`url(#${mid}-ag)`} />
          <Box x={lx} y={y} w={lw} h={boxH} tone="good" lines={wrapLabel(k, 26, 2)} />
        </g>); })}
      {!keeps.length && <text x={lx} y={top + 44} fontSize={12} fill="#94A3B8">（なし）</text>}
      {/* host */}
      <Box x={hostCx - 56} y={hostCy - 52} w={112} h={104} tone="info" lines={[""]} rx={14} />
      <PcIcon cx={hostCx} cy={hostCy - 12} tone="info" />
      {wrapLabel(spec.host ?? "この端末", 16, 2).map((l, i) => <text key={i} x={hostCx} y={hostCy + 30 + i * 14} textAnchor="middle" fontSize={12} fontWeight={700} fill="#D6E0FF">{l}</text>)}
      {/* stops */}
      {rows.map((r: any, i: number) => r.kind === "head"
        ? <text key={`h${i}`} x={rx} y={r.y + 12} fontSize={10.5} fill="#94A3B8">{GROUP_JA[r.g]}</text>
        : (
          <g key={`s${i}`}>
            <path d={`M${hostCx + 56} ${hostCy} C ${wallX - 30} ${hostCy}, ${wallX - 30} ${r.y + boxH / 2}, ${wallX - 10} ${r.y + boxH / 2}`} fill="none" stroke="#F0566E" strokeWidth={1.4} strokeDasharray="5 4" opacity={0.8} />
            <path d={`M${wallX + 10} ${r.y + boxH / 2} H ${rx}`} stroke="#F0566E" strokeWidth={1.4} strokeDasharray="5 4" opacity={0.5} />
            <g transform={`translate(${wallX + 26} ${r.y + boxH / 2})`}><circle r={8} fill="#2E1218" stroke="#F0566E" /><path d="M-4 -4L4 4M4 -4L-4 4" stroke="#F0566E" strokeWidth={2} /></g>
            <Box x={rx} y={r.y} w={rw} h={boxH} tone="bad" lines={wrapLabel(r.s.label, 26, 2)} />
            {r.s.severity && <g><rect x={rx + rw - 44} y={r.y - 7} width={44} height={14} rx={7} fill={SEV[r.s.severity as Severity] ?? SEV.low} /><text x={rx + rw - 22} y={r.y + 3.5} textAnchor="middle" fontSize={9} fontWeight={700} fill="#0B1220">{SEV_JA[r.s.severity as Severity] ?? ""}</text></g>}
          </g>))}
      {!stopsRaw.length && <text x={rx} y={top + 44} fontSize={12} fill="#94A3B8">（なし）</text>}
      {spec.note && wrapLabel(spec.note, 110, 2).map((l, i) => <text key={i} x={16} y={H - 26 + i * 14} fontSize={11.5} fill="#CBD5E1">{l}</text>)}
    </svg>
  );
}

function FlowDiagram({ spec, mid }: { spec: FlowSpec; mid: string }) {
  const nodes = spec.nodes.slice(0, 12);
  const cols = Math.min(4, nodes.length); const bw = 150, bh = 58, gx = 40, gy = 46;
  const W = Math.max(cols * bw + (cols - 1) * gx + 32, 360); const top = spec.title ? 44 : 16;
  const pos = new Map<string, { x: number; y: number; row: number; col: number }>();
  nodes.forEach((n, i) => { const row = Math.floor(i / cols); const colRaw = i % cols; const col = row % 2 ? cols - 1 - colRaw : colRaw; pos.set(n.id, { x: 16 + col * (bw + gx), y: top + row * (bh + gy), row, col }); });
  const rowsN = Math.ceil(nodes.length / cols);
  const H = top + rowsN * bh + (rowsN - 1) * gy + (spec.note ? 44 : 16);
  const edges = (spec.edges ?? (nodes.slice(1).map((n, i) => ({ from: nodes[i].id, to: n.id })) as FlowSpec["edges"]))!.filter((e) => pos.has(String(e.from)) && pos.has(String(e.to))).slice(0, 16);
  const anchor = (a: { x: number; y: number }, b: { x: number; y: number }) => {
    const ac = { x: a.x + bw / 2, y: a.y + bh / 2 }, bc = { x: b.x + bw / 2, y: b.y + bh / 2 };
    const dx = bc.x - ac.x, dy = bc.y - ac.y;
    if (Math.abs(dy) < 4) return { s: { x: ac.x + Math.sign(dx) * bw / 2, y: ac.y }, e: { x: bc.x - Math.sign(dx) * bw / 2, y: bc.y } };
    return { s: { x: ac.x, y: ac.y + Math.sign(dy) * bh / 2 }, e: { x: bc.x, y: bc.y - Math.sign(dy) * bh / 2 } };
  };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={spec.title ?? "説明図"} style={{ maxWidth: W }}>
      <defs><marker id={`${mid}-a`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#94A3B8" /></marker></defs>
      {spec.title && <text x={16} y={26} fontSize={15} fontWeight={700} fill="#F1F5F9">{spec.title}</text>}
      {edges.map((e, i) => {
        const a = pos.get(String(e.from))!, b = pos.get(String(e.to))!; const { s, e: t } = anchor(a, b);
        const straight = Math.abs(s.y - t.y) < 4 || Math.abs(s.x - t.x) < 4;
        const d = straight ? `M${s.x} ${s.y} L${t.x} ${t.y}` : `M${s.x} ${s.y} C ${s.x} ${(s.y + t.y) / 2}, ${t.x} ${(s.y + t.y) / 2}, ${t.x} ${t.y}`;
        return (
          <g key={i}>
            <path d={d} fill="none" stroke="#94A3B8" strokeWidth={1.6} strokeDasharray={e.dashed ? "5 4" : undefined} markerEnd={`url(#${mid}-a)`} />
          </g>
        );
      })}
      {nodes.map((n) => { const p = pos.get(n.id)!; return <Box key={n.id} x={p.x} y={p.y} w={bw} h={bh} tone={(TONE as any)[n.tone ?? ""] ? (n.tone as Tone) : "neutral"} lines={wrapLabel(n.label, 20, n.sub ? 2 : 3)} sub={n.sub ? wrapLabel(n.sub, 22, 1)[0] : undefined} />; })}
      {edges.map((e, i) => { if (!e.label) return null; const { s, e: t } = anchor(pos.get(String(e.from))!, pos.get(String(e.to))!); const horiz = Math.abs(s.y - t.y) < 4; const mx = (s.x + t.x) / 2, my = horiz ? s.y - 10 : (s.y + t.y) / 2;
        return <g key={`l${i}`}>{wrapLabel(e.label, 16, 2).map((l, k) => <text key={k} x={mx} y={my + k * 12} textAnchor="middle" fontSize={10.5} fontWeight={600} fill="#E2E8F0" stroke="#0B1220" strokeWidth={4} paintOrder="stroke">{l}</text>)}</g>; })}
      {spec.note && wrapLabel(spec.note, Math.floor(W / 7), 2).map((l, i) => <text key={i} x={16} y={H - 26 + i * 14} fontSize={11.5} fill="#CBD5E1">{l}</text>)}
    </svg>
  );
}

export default function Diagram({ spec, className = "" }: { spec: DiagramSpec; className?: string }) {
  const mid = useId().replace(/[^a-zA-Z0-9]/g, "");
  return (
    <figure className={`my-2 overflow-x-auto rounded-xl border border-[#24314D] bg-[#0B1220] p-2 ${className}`}>
      {spec.layout === "contain" ? <ContainDiagram spec={spec} mid={mid} /> : <FlowDiagram spec={spec} mid={mid} />}
    </figure>
  );
}
