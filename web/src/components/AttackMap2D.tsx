import { useEffect, useMemo, useState } from "react";
import { feature } from "topojson-client";

/** 攻撃可視化の 2D フォールバック（EDR-73）: WebGL が使えない端末や、印刷・スクショ用。等距円筒図法の SVG に国の塗りと曲線アークを描く。 */

export interface Country2D { name: string; iso2: string | null; name_ja: string; lat: number | null; lon: number | null; total: number; by_kind: Record<string, number>; blocked: number; targets: { host: string; n: number }[] }
export interface Site2D { site_id: number; name: string; lat: number; lon: number }

const W = 1000, H = 500;
const X = (lon: number) => ((lon + 180) / 360) * W;
const Y = (lat: number) => ((90 - lat) / 180) * H;
const KIND_COLOR: Record<string, string> = { ssh: "#f43f5e", web: "#fb923c", vpn: "#facc15", smtp: "#facc15", rdp: "#f43f5e", fw: "#a78bfa", blocked: "#2dd4bf" };

export default function AttackMap2D({ countries, sites, defaultSiteId, agentSite, onHover, onClick, labels = 8 }: { countries: Country2D[]; sites: Site2D[]; defaultSiteId: number; agentSite: Record<string, number>; onHover?: (c: Country2D | null, x: number, y: number) => void; onClick?: (c: Country2D) => void; labels?: number }) {
  const [paths, setPaths] = useState<{ d: string; jp: boolean }[]>([]);
  useEffect(() => {
    fetch("/countries-110m.json").then((r) => r.json()).then((topo) => {
      const fc: any = feature(topo, topo.objects.countries); const out: { d: string; jp: boolean }[] = [];
      for (const f of fc.features) {
        if (f.id === "010") continue;
        const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
        const d = polys.map((poly: any) => poly.map((ring: [number, number][]) => ring.map(([lon, lat], i) => `${i ? "L" : "M"}${X(lon).toFixed(1)},${Y(lat).toFixed(1)}`).join("") + "Z").join("")).join("");
        out.push({ d, jp: f.id === "392" });
      }
      setPaths(out);
    }).catch(() => {});
  }, []);
  const siteById = useMemo(() => new Map(sites.map((s) => [s.site_id, s])), [sites]);
  const rows = useMemo(() => countries.filter((c) => c.lat != null && c.lon != null && (c.total > 0 || c.blocked > 0)), [countries]);
  const max = Math.max(1, ...rows.map((c) => c.total));
  const arcs = useMemo(() => rows.flatMap((c, i) => {
    if (c.total <= 0) return [];
    const w = Math.log10(1 + c.total) / Math.log10(1 + max);
    const kind = Object.entries(c.by_kind).sort((x, y) => y[1] - x[1])[0]?.[0] ?? "web";
    const perSite = new Map<number, number>();
    for (const t of c.targets) { const sid = agentSite[t.host] ?? defaultSiteId; perSite.set(sid, (perSite.get(sid) ?? 0) + t.n); }
    if (!perSite.size) perSite.set(defaultSiteId, c.total);
    return [...perSite.keys()].map((sid) => {
      const st = siteById.get(sid) ?? sites[0]; if (!st) return null;
      const x1 = X(c.lon!), y1 = Y(c.lat!), x2 = X(st.lon), y2 = Y(st.lat); const mx = (x1 + x2) / 2, my = Math.min(y1, y2) - Math.min(120, Math.hypot(x2 - x1, y2 - y1) * .35);
      return { key: `${c.name}-${sid}`, d: `M${x1},${y1} Q${mx},${my} ${x2},${y2}`, color: KIND_COLOR[kind] ?? "#94a3b8", w, i };
    }).filter(Boolean) as { key: string; d: string; color: string; w: number; i: number }[];
  }), [rows, sites, agentSite, defaultSiteId, max]);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" style={{ background: "#050a14" }} preserveAspectRatio="xMidYMid meet">
      <defs><style>{`@keyframes dash { to { stroke-dashoffset: -60; } } .arc { stroke-dasharray: 8 52; animation: dash 1.6s linear infinite; } .pulse { animation: pulse 1.6s ease-in-out infinite; transform-origin: center; transform-box: fill-box; } @keyframes pulse { 0%,100% { opacity: .9; transform: scale(1);} 50% { opacity: .4; transform: scale(1.5);} }`}</style></defs>
      {Array.from({ length: 13 }, (_, i) => <line key={"v" + i} x1={(i * W) / 12} x2={(i * W) / 12} y1={0} y2={H} stroke="#0b1c24" strokeWidth={1} />)}
      {Array.from({ length: 7 }, (_, i) => <line key={"h" + i} x1={0} x2={W} y1={(i * H) / 6} y2={(i * H) / 6} stroke="#0b1c24" strokeWidth={1} />)}
      {paths.map((p, i) => <path key={i} d={p.d} fill={p.jp ? "#3A56F0" : "#111A2E"} fillOpacity={p.jp ? .75 : .9} stroke="#3A56F0" strokeWidth={.6} />)}
      {arcs.map((a) => <g key={a.key}><path d={a.d} fill="none" stroke={a.color} strokeWidth={.8 + a.w * 2.2} strokeOpacity={.25 + a.w * .4} /><path className="arc" d={a.d} fill="none" stroke={a.color} strokeWidth={1.2 + a.w * 2.6} strokeLinecap="round" /></g>)}
      {sites.map((s) => <g key={s.site_id}><circle className="pulse" cx={X(s.lon)} cy={Y(s.lat)} r={9} fill="none" stroke="#8EA2FF" strokeWidth={2} /><circle cx={X(s.lon)} cy={Y(s.lat)} r={3.5} fill="#8EA2FF" /><text x={X(s.lon) + 12} y={Y(s.lat) - 10} fill="#8EA2FF" fontSize={13} fontWeight={700}>◎ {s.name}</text></g>)}
      {rows.map((c, i) => { const w = Math.log10(1 + c.total) / Math.log10(1 + max); const kind = Object.entries(c.by_kind).sort((x, y) => y[1] - x[1])[0]?.[0] ?? "blocked"; const color = c.total > 0 ? KIND_COLOR[kind] ?? "#94a3b8" : "#2dd4bf";
        return <g key={c.name} style={{ cursor: "pointer" }} onMouseMove={(e) => { const r = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect(); onHover?.(c, e.clientX - r.left, e.clientY - r.top); }} onMouseLeave={() => onHover?.(null, 0, 0)} onClick={() => onClick?.(c)}>
          <circle cx={X(c.lon!)} cy={Y(c.lat!)} r={8 + w * 6} fill={color} fillOpacity={.12} /><circle cx={X(c.lon!)} cy={Y(c.lat!)} r={2.5 + w * 4} fill={color} />
          {i < labels && c.total > 0 && <text x={X(c.lon!) + 8 + w * 5} y={Y(c.lat!) - 6} fill="#e2e8f0" fontSize={12} fontWeight={600} style={{ paintOrder: "stroke", stroke: "#050a14", strokeWidth: 3 }}>{c.name_ja} {c.total.toLocaleString()}</text>}
        </g>; })}
    </svg>
  );
}
