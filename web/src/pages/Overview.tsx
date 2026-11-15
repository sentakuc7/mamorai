import { useContext, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import * as THREE from "three";
import { feature } from "topojson-client";
import { api, fmtTs } from "../lib/api";
import { useMode } from "../lib/mode";
import { UserCtx } from "../main";
import OverviewWizard, { type Setup } from "../components/OverviewWizard";
import AttackMap2D from "../components/AttackMap2D";
import "flag-icons/css/flag-icons.min.css";
import { Ico, I } from "../components/Icon";

/** 攻撃可視化 Overview（EDR-70 / EDR-72）: 国別の攻撃通信を 3D 世界地図にアークで描く。データは /api/wazuh/:id/attack-map。 */

interface Country { name: string; iso2: string | null; name_ja: string; lat: number | null; lon: number | null; total: number; by_kind: Record<string, number>; blocked: number; top_ips: { ip: string; n: number }[]; targets: { host: string; n: number }[]; rules: { id: string; n: number }[] }
interface Recent { ts: string; country: string | null; iso2: string | null; ip: string; dst: string; kind: string; color: string; rule_id: string; what_ja: string; level: number }
interface Site { site_id: number; name: string; lat: number; lon: number; kind: string; total: number; hosts: string[] }
interface Data { sites?: Site[]; agent_site?: Record<string, number>; default_site_id?: number; demo?: boolean; window: string; generated_at: string; profiles: { id: string; name: string; kind: string; color: string; role: string; total: number; error?: string }[]; kpi: { total: number; countries: number; targets: number; blocked: number; internal: number; cdn_unknown: number; no_geo: number }; countries: Country[]; targets: { host: string; total: number; by_kind: Record<string, number> }[]; recent: Recent[]; timeline: { t: string; n: number; by_kind: Record<string, number> }[] }

const KIND_COLOR: Record<string, string> = { ssh: "#f43f5e", web: "#fb923c", vpn: "#facc15", smtp: "#facc15", rdp: "#f43f5e", fw: "#a78bfa", blocked: "#2dd4bf" };
const KIND_JA: Record<string, string> = { ssh: "SSH 総当たり", web: "Web スキャン・探索", vpn: "VPN 認証失敗", smtp: "SMTP 認証失敗", rdp: "RDP / ログオン失敗", fw: "FW 拒否", blocked: "遮断済み" };
const Flag = ({ iso2, className = "" }: { iso2: string | null; className?: string }) => (iso2 ? <span className={`fi fi-${iso2.toLowerCase()} rounded-sm ${className}`} style={{ fontSize: "1em", lineHeight: 1 }} /> : <span className={`inline-block rounded-sm bg-slate-700 ${className}`} style={{ width: "1.33em", height: "1em" }} />);
const webglOk = (() => { try { const c = document.createElement("canvas"); return !!(c.getContext("webgl2") || c.getContext("webgl")); } catch { return false; } })();
export const maskIp = (ip: string) => ip.includes(":") ? ip.split(":").slice(0, 3).join(":") + ":xxxx" : ip.split(".").slice(0, 2).join(".") + ".xx.xx";
const ago = (iso: string) => { const s = (Date.now() - new Date(iso).getTime()) / 1000; return s < 60 ? "たった今" : s < 3600 ? `${Math.floor(s / 60)} 分前` : s < 86400 ? `${Math.floor(s / 3600)} 時間前` : `${Math.floor(s / 86400)} 日前`; };
const fmtN = (n: number) => n.toLocaleString();

// --- 3D scene ----------------------------------------------------------------------------------------------
const W = 420, H = 210; // map plane size (x: lon, z: -lat)
const DEFAULT_SITE: Site = { site_id: 0, name: "自拠点（東京）", lat: 35.7, lon: 139.7, kind: "home", total: 0, hosts: [] };
const P = (lon: number, lat: number) => new THREE.Vector3(lon * W / 360, 0, -lat * H / 180);

class Scene3D {
  renderer: THREE.WebGLRenderer; scene = new THREE.Scene(); camera: THREE.PerspectiveCamera;
  group = new THREE.Group(); dyn = new THREE.Group(); particles: { m: THREE.Mesh; curve: THREE.QuadraticBezierCurve3; t: number; speed: number; once?: boolean }[] = [];
  rings: THREE.Mesh[] = []; raf = 0; t = 0; rotate = false; pick: { mesh: THREE.Mesh; country: Country }[] = []; raycaster = new THREE.Raycaster(); hovered: Country | null = null; onHover?: (c: Country | null, x: number, y: number) => void; onClick?: (c: Country) => void; disposed = false; mapReady = false;
  constructor(public canvas: HTMLCanvasElement) {
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(2, window.devicePixelRatio));
    this.scene.fog = new THREE.Fog(0x0A0F1C, 420, 900);
    this.camera = new THREE.PerspectiveCamera(38, 1, 1, 2000);
    this.camera.position.set(120, 210, 300); this.camera.lookAt(70, 0, -30);
    this.scene.add(this.group); this.scene.add(this.dyn);
    const grid = new THREE.GridHelper(W * 1.15, 28, 0x1B2A6B, 0x111A2E); grid.position.y = -0.5; this.group.add(grid);
    this.resize();
    canvas.addEventListener("mousemove", (e) => this.mouse(e, false)); canvas.addEventListener("click", (e) => this.mouse(e, true));
    this.loop();
  }
  resize() { const w = this.canvas.clientWidth || 800, h = this.canvas.clientHeight || 500; this.renderer.setSize(w, h, false); this.camera.aspect = w / h; this.camera.updateProjectionMatrix(); }
  async loadMap() {
    const topo = await fetch("/countries-110m.json").then((r) => r.json());
    const countries: any = feature(topo, topo.objects.countries);
    const lineMat = new THREE.LineBasicMaterial({ color: 0x3A56F0, transparent: true, opacity: .85 });
    const fillMat = new THREE.MeshBasicMaterial({ color: 0x111A2E, transparent: true, opacity: .9, side: THREE.DoubleSide });
    const jpMat = new THREE.MeshBasicMaterial({ color: 0x3A56F0, transparent: true, opacity: .75, side: THREE.DoubleSide });
    for (const f of countries.features) {
      if (f.id === "010") continue; // 南極
      const isJP = f.id === "392";
      const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
      for (const poly of polys) {
        // 日付変更線（±180°）をまたぐ輪郭は経度を連続化して、地図を横切る線にならないようにする
      const raw = poly[0] as [number, number][];
      const ring: [number, number][] = []; let off = 0;
      raw.forEach(([lon, lat], k) => { if (k > 0) { const d = lon - raw[k - 1][0]; if (d > 180) off -= 360; else if (d < -180) off += 360; } ring.push([lon + off, lat]); });
        this.group.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(ring.map(([lon, lat]) => P(lon, lat))), lineMat));
        try { const shape = new THREE.Shape(ring.map(([lon, lat]) => new THREE.Vector2(lon * W / 360, lat * H / 180))); const g = new THREE.ShapeGeometry(shape); g.rotateX(-Math.PI / 2); const m = new THREE.Mesh(g, isJP ? jpMat : fillMat); m.position.y = isJP ? .1 : -.2; this.group.add(m); } catch { /* degenerate polygon */ }
      }
    }
    this.mapReady = true;
  }
  label(text: string, color = "#e2e8f0", scale = 40): THREE.Sprite {
    const cv = document.createElement("canvas"); cv.width = 512; cv.height = 64; const cx = cv.getContext("2d")!;
    cx.font = "bold 28px 'Noto Sans JP', 'Segoe UI', sans-serif"; cx.fillStyle = color; cx.shadowColor = "#000"; cx.shadowBlur = 6; cx.fillText(text, 8, 42);
    const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(cv), transparent: true, depthTest: false })); sp.scale.set(scale * 2, scale / 4 * 2 / 4 * 2, 1); sp.scale.set(scale, scale / 8, 1); return sp;
  }
  sitesOf(d: Data): Site[] { return d.sites?.length ? d.sites : [DEFAULT_SITE]; }
  /** rebuild targets / arcs / columns / particles from data */
  setData(d: Data, maxLabels = 8) {
    for (const p of this.particles) { this.dyn.remove(p.m); (p.m.geometry as any).dispose?.(); } this.particles = []; this.pick = []; this.rings = [];
    while (this.dyn.children.length) { const c = this.dyn.children[0] as any; this.dyn.remove(c); c.geometry?.dispose?.(); c.material?.map?.dispose?.(); c.material?.dispose?.(); }
    // targets (sites)
    const sites = this.sitesOf(d); const siteById = new Map(sites.map((s) => [s.site_id, s]));
    const defId = d.default_site_id ?? sites[0].site_id;
    for (const st of sites) {
      const tgt = P(st.lon, st.lat);
      const ring = new THREE.Mesh(new THREE.RingGeometry(4, 5.2, 48), new THREE.MeshBasicMaterial({ color: 0x8EA2FF, transparent: true, opacity: .9, side: THREE.DoubleSide }));
      ring.rotation.x = -Math.PI / 2; ring.position.copy(tgt).add(new THREE.Vector3(0, .3, 0)); this.dyn.add(ring); this.rings.push(ring);
      const beacon = new THREE.Mesh(new THREE.CylinderGeometry(.6, .6, 70, 8), new THREE.MeshBasicMaterial({ color: 0x8EA2FF, transparent: true, opacity: .35 })); beacon.position.copy(tgt).add(new THREE.Vector3(0, 35, 0)); this.dyn.add(beacon);
      const tl = this.label(`◎ ${st.name}`, "#B9C6FF", 70); tl.position.copy(tgt).add(new THREE.Vector3(-30, 78, 0)); this.dyn.add(tl);
    }
    const siteForHost = (h: string) => siteById.get(d.agent_site?.[h] ?? defId) ?? siteById.get(defId) ?? sites[0];
    const rows = d.countries.filter((c) => c.lat != null && c.lon != null && (c.total > 0 || c.blocked > 0));
    const max = Math.max(1, ...rows.map((c) => c.total));
    rows.forEach((c, i) => {
      const w = Math.log10(1 + c.total) / Math.log10(1 + max); // 0..1
      const a = P(c.lon!, c.lat!);
      const mainKind = Object.entries(c.by_kind).sort((x, y) => y[1] - x[1])[0]?.[0] ?? "blocked";
      const color = new THREE.Color(KIND_COLOR[mainKind] ?? "#94a3b8");
      if (c.total > 0) {
        // one arc per target site, weighted by how many hits went to hosts of that site
        const perSite = new Map<number, number>();
        for (const t of c.targets) { const st = siteForHost(t.host); perSite.set(st.site_id, (perSite.get(st.site_id) ?? 0) + t.n); }
        if (!perSite.size) perSite.set(defId, c.total);
        const sum = [...perSite.values()].reduce((x, y) => x + y, 0) || 1;
        for (const [sid, n] of perSite) {
          const st = siteById.get(sid) ?? sites[0]; const tgt = P(st.lon, st.lat); const share = n / sum;
          const dist = a.distanceTo(tgt); const mid = a.clone().lerp(tgt, .5); mid.y = Math.min(150, 40 + dist * .4);
          const curve = new THREE.QuadraticBezierCurve3(a, mid, tgt);
          const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(80)), new THREE.LineBasicMaterial({ color, transparent: true, opacity: (.2 + w * .5) * (0.4 + 0.6 * share) })); this.dyn.add(line);
          const np = Math.max(1, Math.round((1 + w * 4) * share));
          for (let k = 0; k < np; k++) { const m = new THREE.Mesh(new THREE.SphereGeometry(1 + w * .9, 8, 8), new THREE.MeshBasicMaterial({ color })); this.dyn.add(m); this.particles.push({ m, curve, t: k / np, speed: .002 + w * .004 }); }
        }
      }
      const hgt = 4 + w * 42;
      const col = new THREE.Mesh(new THREE.CylinderGeometry(.6, .6, hgt, 6), new THREE.MeshBasicMaterial({ color: c.total > 0 ? color : 0x2dd4bf, transparent: true, opacity: .55 })); col.position.copy(a).add(new THREE.Vector3(0, hgt / 2, 0)); this.dyn.add(col);
      const dot = new THREE.Mesh(new THREE.SphereGeometry(1.4 + w * 1.8, 12, 12), new THREE.MeshBasicMaterial({ color: c.total > 0 ? color : 0x2dd4bf })); dot.position.copy(a).add(new THREE.Vector3(0, .8, 0)); this.dyn.add(dot);
      // invisible, larger pick target
      const pk = new THREE.Mesh(new THREE.SphereGeometry(6 + w * 3, 8, 8), new THREE.MeshBasicMaterial({ visible: false })); pk.position.copy(dot.position); this.dyn.add(pk); this.pick.push({ mesh: pk, country: c });
      if (i < maxLabels && c.total > 0) { const sp = this.label(c.name_ja); sp.position.copy(a).add(new THREE.Vector3(14, hgt + 6, 0)); this.dyn.add(sp); }
    });
  }
  /** one-shot particle for a live event */
  burst(c: Country, d: Data) {
    if (c.lat == null || c.lon == null) return;
    const sites = this.sitesOf(d); const st = sites.find((x) => x.site_id === (d.default_site_id ?? sites[0].site_id)) ?? sites[0];
    const a = P(c.lon, c.lat), tgt = P(st.lon, st.lat); const dist = a.distanceTo(tgt); const mid = a.clone().lerp(tgt, .5); mid.y = Math.min(150, 40 + dist * .4);
    const curve = new THREE.QuadraticBezierCurve3(a, mid, tgt);
    const m = new THREE.Mesh(new THREE.SphereGeometry(2.4, 10, 10), new THREE.MeshBasicMaterial({ color: 0xffffff })); this.dyn.add(m); this.particles.push({ m, curve, t: 0, speed: .012, once: true });
  }
  mouse(e: MouseEvent, click: boolean) {
    const r = this.canvas.getBoundingClientRect(); const v = new THREE.Vector2(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
    this.raycaster.setFromCamera(v, this.camera);
    const hit = this.raycaster.intersectObjects(this.pick.map((p) => p.mesh), false)[0];
    const c = hit ? this.pick.find((p) => p.mesh === hit.object)?.country ?? null : null;
    if (click) { if (c) this.onClick?.(c); return; }
    if (c !== this.hovered) { this.hovered = c; this.canvas.style.cursor = c ? "pointer" : "default"; }
    this.onHover?.(c, e.clientX - r.left, e.clientY - r.top);
  }
  loop = () => {
    if (this.disposed) return;
    this.raf = requestAnimationFrame(this.loop);
    if (document.hidden) return;
    this.t++;
    for (let i = this.particles.length - 1; i >= 0; i--) { const p = this.particles[i]; p.t += p.speed; if (p.t >= 1) { if (p.once) { this.dyn.remove(p.m); this.particles.splice(i, 1); continue; } p.t -= 1; } p.m.position.copy(p.curve.getPoint(p.t)); const sc = p.t > .92 ? Math.max(.05, (1 - p.t) / .08) : 1; p.m.scale.set(sc, sc, sc); }
    const k = 1 + .25 * Math.sin(this.t / 12); for (const ring of this.rings) { ring.scale.set(k, k, 1); (ring.material as THREE.MeshBasicMaterial).opacity = .9 - .3 * Math.sin(this.t / 12); }
    if (this.rotate) { const ang = this.t * .0012; this.camera.position.set(70 + 330 * Math.sin(ang), 210, -30 + 330 * Math.cos(ang)); this.camera.lookAt(70, 0, -30); }
    this.renderer.render(this.scene, this.camera);
  };
  dispose() { this.disposed = true; cancelAnimationFrame(this.raf); this.renderer.dispose(); }
}

// --- page ---------------------------------------------------------------------------------------------------
export default function Overview() {
  const { mode } = useMode(); const { user } = useContext(UserCtx); const nav = useNavigate();
  const [wz, setWz] = useState<{ id: number; name: string }[]>([]); const [sel, setSel] = useState<number | null>(null);
  const [window_, setWindow] = useState<"24h" | "7d">("24h"); const [live, setLive] = useState(true); const [rotate, setRotate] = useState(false); const [mask, setMask] = useState(true);
  const [data, setData] = useState<Data | null>(null); const [err, setErr] = useState(""); const [loading, setLoading] = useState(false);
  const [hover, setHover] = useState<{ c: Country; x: number; y: number } | null>(null); const [picked, setPicked] = useState<Country | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null); const sceneRef = useRef<Scene3D | null>(null); const lastSeen = useRef<string>("");
  const [setup, setSetup] = useState<Setup | null>(null); const [wizard, setWizard] = useState(false); const [demo, setDemo] = useState(false);
  const [view2d, setView2d] = useState(!webglOk);
  const [replay, setReplay] = useState<{ frames: { t: string; total: number; countries: Record<string, number>; kinds: Record<string, number> }[]; interval: string } | null>(null); const [frame, setFrame] = useState(-1); const [playing, setPlaying] = useState(false);
  const [sp] = useSearchParams(); const highlight = sp.get("country");
  const showIp = mode === "detail" && !mask;
  const ip = (s: string) => (showIp ? s : maskIp(s));

  useEffect(() => { api.get<{ items: any[] }>("/wazuh").then((r) => { setWz(r.items); if (r.items[0]) setSel(r.items[0].id); }); }, []);
  useEffect(() => {
    if (!canvasRef.current) return; const sc = new Scene3D(canvasRef.current); sceneRef.current = sc;
    sc.onHover = (c, x, y) => setHover(c ? { c, x, y } : null); sc.onClick = (c) => setPicked(c);
    sc.loadMap().then(() => { if (data) sc.setData(data); }).catch((e) => setErr("地図データの読み込みに失敗: " + e.message));
    const ro = new ResizeObserver(() => sc.resize()); ro.observe(canvasRef.current);
    return () => { ro.disconnect(); sc.dispose(); sceneRef.current = null; };
  }, []);
  useEffect(() => { if (sceneRef.current) sceneRef.current.rotate = rotate; }, [rotate]);

  const loadSetup = async () => { if (sel == null) return; const st = await api.get<Setup>(`/overview/setup?wazuh=${sel}`); setSetup(st); return st; };
  useEffect(() => {
    // 初回: 診断して、描けない状態で未完了ならウィザードを出す
    if (sel == null) return;
    loadSetup().then((st) => { if (!st) return; if (st.state.demo && st.readiness.level === "empty") setDemo(true); if (!st.state.completed && !st.state.skipped && (st.readiness.level === "empty" || st.readiness.level === "partial")) setWizard(true); }).catch(() => {});
  }, [sel]);
  const load = async (quiet = false) => {
    if (sel == null) return; if (!quiet) setLoading(true); setErr("");
    try {
      const d = demo ? { ...(await api.get<Data>(`/wazuh/${sel}/attack-map/demo?window=${window_}`)), demo: true } : await api.get<Data>(`/wazuh/${sel}/attack-map?window=${window_}`);
      setData(d);
      void d;
      // live: burst for events newer than the last seen
      if (quiet && lastSeen.current && sceneRef.current) for (const ev of d.recent) { if (ev.ts > lastSeen.current) { const c = d.countries.find((x) => x.name_ja === ev.country || x.iso2 === ev.iso2); if (c) sceneRef.current.burst(c, d); } }
      if (d.recent[0]) lastSeen.current = d.recent[0].ts;
    } catch (e: any) { setErr(e.message); } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, [sel, window_, demo]);
  useEffect(() => { if (!live) return; const id = setInterval(() => { if (!document.hidden) load(true); }, 30_000); return () => clearInterval(id); }, [live, sel, window_]);


  // 表示用データ: 拠点名のマスク / リプレイ中のフレーム適用
  const viewData = useMemo<Data | null>(() => {
    if (!data) return null;
    let d: Data = data;
    if (replay && frame >= 0 && replay.frames[frame]) {
      const f = replay.frames[frame];
      d = { ...d, kpi: { ...d.kpi, total: f.total }, countries: d.countries.map((c) => { const n = f.countries[c.name] ?? 0; const k = c.total ? n / c.total : 0; return { ...c, total: n, blocked: Math.round(c.blocked * k), by_kind: Object.fromEntries(Object.entries(c.by_kind).map(([kk, v]) => [kk, Math.round(v * k)])) }; }).filter((c) => c.total > 0).sort((a, b) => b.total - a.total) };
    }
    if (!showIp && d.sites) d = { ...d, sites: d.sites.map((s, i) => ({ ...s, name: s.site_id === 0 ? s.name : `拠点 ${i + 1}`, hosts: s.hosts })) };
    return d;
  }, [data, replay, frame, showIp]);
  useEffect(() => { if (viewData && sceneRef.current?.mapReady && !view2d) sceneRef.current.setData(viewData); }, [viewData, view2d]);
  // リプレイ再生
  useEffect(() => { if (!playing || !replay) return; const id = setInterval(() => setFrame((f) => { const n = f + 1; if (n >= replay.frames.length) { setPlaying(false); return f; } return n; }), 700); return () => clearInterval(id); }, [playing, replay]);
  const startReplay = async () => { if (sel == null) return; setErr(""); try { const r = await api.get<{ frames: any[]; interval: string }>(`/wazuh/${sel}/attack-map/replay?window=${window_ === "24h" ? "24h" : "7d"}`); setReplay(r); setFrame(0); setPlaying(true); setLive(false); } catch (e: any) { setErr(e.message); } };
  const stopReplay = () => { setPlaying(false); setReplay(null); setFrame(-1); };
  useEffect(() => { if (highlight && data) { const c = data.countries.find((x) => x.name === highlight || x.name_ja === highlight || x.iso2 === highlight); if (c) setPicked(c); } }, [highlight, data?.generated_at]);
  const top = useMemo(() => (viewData?.countries ?? []).filter((c) => c.total > 0).slice(0, 8), [viewData]);
  const maxTop = Math.max(1, ...top.map((c) => c.total));
  const kinds = useMemo(() => { const m: Record<string, number> = {}; for (const c of data?.countries ?? []) for (const [k, v] of Object.entries(c.by_kind)) m[k] = (m[k] ?? 0) + v; return Object.entries(m).sort((a, b) => b[1] - a[1]); }, [data]);
  const total = viewData?.kpi.total ?? 0;
  const blockedRate = data && data.kpi.total ? Math.min(100, Math.round((data.kpi.blocked / data.kpi.total) * 100)) : null;
  const noData = data && data.kpi.total === 0 && data.kpi.blocked === 0;

  return (
    <div className="relative -m-6 h-screen overflow-hidden bg-[#0A0F1C]" style={{ minHeight: 560 }}>
      <canvas ref={canvasRef} className={`absolute inset-0 h-full w-full ${view2d ? "invisible" : ""}`} />
      {view2d && viewData && <div className="absolute inset-0 flex items-center justify-center p-4 pt-24 pb-16 pr-[330px]"><AttackMap2D countries={viewData.countries} sites={viewData.sites?.length ? viewData.sites : [{ site_id: 0, name: "自拠点（東京）", lat: 35.7, lon: 139.7 }]} defaultSiteId={viewData.default_site_id ?? 0} agentSite={viewData.agent_site ?? {}} onHover={(c, x, y) => setHover(c ? { c: c as Country, x: x + 16, y: y + 96 } : null)} onClick={(c) => setPicked(c as Country)} /></div>}
      {/* title */}
      <div className="pointer-events-none absolute left-5 top-4">
        <h1 className="flex items-center gap-2 text-[26px] font-bold text-slate-100"><Ico d={I.globe} size={22} />攻撃可視化 <span className="text-teal-300">Overview</span></h1>
        <div className="mt-0.5 text-[11px] text-slate-500">{wz.find((w) => w.id === sel)?.name} · 直近 {window_ === "24h" ? "24 時間" : "7 日"}の外部からの攻撃通信を国別に集計 · {loading ? "更新中…" : data ? `更新 ${fmtTs(data.generated_at).slice(11)}` : ""}{live && " · ライブ"}{replay && <span className="ml-2 rounded bg-teal-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-teal-300">リプレイ {replay.frames[frame] ? fmtTs(replay.frames[frame].t).slice(0, 16) : ""}</span>}{demo && <span className="ml-2 rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300">デモデータ（実際の通信ではありません）</span>}</div>
      </div>
      {/* KPI */}
      {data && <div className="pointer-events-none absolute left-5 top-[68px] flex flex-wrap gap-2">
        {[["攻撃通信", fmtN(total), "text-rose-300"], ["送信元の国", fmtN(data.kpi.countries), "text-slate-100"], ["狙われたホスト", fmtN(data.kpi.targets), "text-slate-100"], ["遮断（fail2ban / FW）", fmtN(data.kpi.blocked) + (blockedRate != null ? ` · ${blockedRate}%` : ""), "text-teal-300"]].map(([l, v, cls]) => (
          <div key={l} className="min-w-[140px] rounded-xl border border-slate-700 bg-[#0E1526]/80 px-4 py-2.5 backdrop-blur-md"><div className="text-[10px] text-slate-500">{l}</div><div className={`font-display text-2xl font-semibold tabular-nums ${cls}`}>{v}</div></div>
        ))}
        {(data.kpi.cdn_unknown > 0 || data.kpi.internal > 0) && <div className="min-w-[140px] rounded-xl border border-slate-700 bg-[#0E1526]/80 px-4 py-2.5 backdrop-blur-md" title="CDN（Cloudflare 等）のエッジ IP や内部アドレスからのものは真の送信元が分からないため地図には描きません"><div className="text-[10px] text-slate-500">地図に出せない通信</div><div className="text-sm font-semibold text-slate-300">CDN 経由 {fmtN(data.kpi.cdn_unknown)} · 内部 {fmtN(data.kpi.internal)}{data.kpi.no_geo > 0 && ` · 国不明 ${fmtN(data.kpi.no_geo)}`}</div></div>}
      </div>}
      {/* right panel */}
      <div className="absolute right-5 top-4 w-[300px] rounded-xl border border-teal-500/25 bg-[#0E1526]/75 p-3 backdrop-blur">
        <div className="mb-1 flex items-center justify-between"><h2 className="text-[11px] font-semibold tracking-widest text-slate-400">{picked ? <><Flag iso2={picked.iso2} /> {picked.name_ja}</> : "送信元の国 TOP"}</h2>{picked && <button className="text-[11px] text-slate-400 hover:text-slate-200" onClick={() => setPicked(null)}>× 一覧へ</button>}</div>
        {!picked && top.map((c) => (
          <button key={c.name} className="flex w-full items-center gap-2 border-t border-slate-700 py-1 text-left text-[13px] first:border-t-0 hover:bg-slate-700" onClick={() => setPicked(c)}>
            <span className="w-6 text-[15px]"><Flag iso2={c.iso2} /></span><span className="w-[84px] truncate text-slate-200">{c.name_ja}</span>
            <span className="h-1.5 flex-1 overflow-hidden rounded bg-slate-900/50"><i className="block h-full rounded" style={{ width: `${(c.total / maxTop) * 100}%`, background: "linear-gradient(90deg,#f43f5e,#fb923c)" }} /></span>
            <span className="w-12 text-right tabular-nums text-slate-100">{fmtN(c.total)}</span>
          </button>
        ))}
        {!picked && !top.length && <div className="py-3 text-center text-xs text-slate-500">{loading ? "読み込み中…" : "この期間の攻撃通信はありません"}</div>}
        {!picked && kinds.length > 0 && <div className="mt-2 border-t border-slate-700 pt-2 text-[11px] text-slate-400">種類: {kinds.map(([k, v]) => <span key={k} className="mr-2"><i className="mr-1 inline-block h-2 w-2 rounded-sm align-middle" style={{ background: KIND_COLOR[k] }} />{KIND_JA[k] ?? k} {total ? Math.round((v / total) * 100) : 0}%</span>)}</div>}
        {picked && (
          <div className="space-y-2 text-xs">
            <div className="flex items-baseline gap-2"><span className="text-2xl font-bold text-rose-300">{fmtN(picked.total)}</span><span className="text-slate-400">件</span>{picked.blocked > 0 && <span className="ml-auto text-teal-300">遮断 {fmtN(picked.blocked)}</span>}</div>
            <div><div className="label">種類</div>{Object.entries(picked.by_kind).sort((a, b) => b[1] - a[1]).map(([k, v]) => <div key={k} className="flex items-center gap-2 py-0.5"><i className="h-2 w-2 rounded-sm" style={{ background: KIND_COLOR[k] }} /><span className="flex-1 text-slate-300">{KIND_JA[k] ?? k}</span><span className="tabular-nums text-slate-100">{fmtN(v)}</span></div>)}</div>
            <div><div className="label">狙われたホスト</div>{picked.targets.slice(0, 6).map((t) => <div key={t.host} className="flex justify-between py-0.5"><span className="font-mono text-slate-300">{t.host}</span><span className="tabular-nums text-slate-100">{fmtN(t.n)}</span></div>)}</div>
            <div><div className="label">送信元 IP 上位{!showIp && <span className="ml-1 text-slate-500">（マスク中）</span>}</div>{picked.top_ips.map((x) => <div key={x.ip} className="flex justify-between py-0.5 font-mono"><span className="text-slate-300">{ip(x.ip)}</span><span className="tabular-nums text-slate-100">{fmtN(x.n)}</span></div>)}</div>
            {mode === "detail" && <div><div className="label">ルール</div>{picked.rules.map((r) => <div key={r.id} className="flex justify-between py-0.5"><span className="font-mono text-slate-400">{r.id}</span><span className="tabular-nums text-slate-100">{fmtN(r.n)}</span></div>)}</div>}
            <div className="flex gap-2 pt-1">
              <button className="btn-secondary px-3 py-1.5 text-xs" onClick={() => nav(`/alerts?q=${encodeURIComponent(picked.name)}`)}>アラート一覧で見る</button>
              {user && <button className="btn-primary px-3 py-1.5 text-xs" onClick={() => nav("/sidekick", { state: { prefill: `攻撃可視化で ${picked.name_ja} からの攻撃通信が ${picked.total} 件（直近 ${window_}）。種類: ${Object.entries(picked.by_kind).map(([k, v]) => `${KIND_JA[k] ?? k} ${v}`).join("、")}。狙われたホスト: ${picked.targets.slice(0, 3).map((t) => t.host).join("、")}。送信元の傾向と、遮断・抑止の要否を調査して` } })}><Ico d={I.ai} size={14} className="" />AI に調査させる</button>}
            </div>
          </div>
        )}
      </div>
      {/* hover tooltip */}
      {hover && !picked && <div className="pointer-events-none absolute z-10 rounded-lg border border-slate-600 bg-[#0E1526]/90 px-3 py-2 text-xs shadow-xl" style={{ left: hover.x + 14, top: hover.y + 14 }}>
        <div className="font-semibold text-slate-100"><Flag iso2={hover.c.iso2} /> {hover.c.name_ja} <span className="text-rose-300">{fmtN(hover.c.total)} 件</span>{hover.c.blocked > 0 && <span className="ml-2 text-teal-300">遮断 {fmtN(hover.c.blocked)}</span>}</div>
        <div className="mt-0.5 text-slate-400">{Object.entries(hover.c.by_kind).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${KIND_JA[k] ?? k} ${fmtN(v)}`).join(" · ")}</div>
        <div className="text-slate-500">狙われたホスト: {hover.c.targets.slice(0, 3).map((t) => t.host).join("、")}</div>
        <div className="mt-0.5 text-[10px] text-slate-500">クリックで詳細</div>
      </div>}
      {/* controls */}
      <div className="absolute bottom-12 right-5 flex items-center gap-1 text-[11px]">
        <select className="input w-auto py-0.5 text-[11px]" value={sel ?? ""} onChange={(e) => setSel(Number(e.target.value))}>{wz.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select>
        {(["24h", "7d"] as const).map((w) => <button key={w} className={`rounded-lg border px-2.5 py-1 ${window_ === w ? "border-teal-400 bg-teal-500/15 text-teal-200" : "border-slate-600 text-slate-400 hover:text-slate-200"}`} onClick={() => setWindow(w)}>{w}</button>)}
        <button className={`rounded-lg border px-2.5 py-1 ${live ? "border-teal-400 bg-teal-500/15 text-teal-200" : "border-slate-600 text-slate-400"}`} onClick={() => setLive(!live)} title="30 秒ごとに更新し、新しい通信を光らせます">● ライブ</button>
        <button className={`rounded-lg border px-2.5 py-1 ${rotate ? "border-teal-400 bg-teal-500/15 text-teal-200" : "border-slate-600 text-slate-400"}`} onClick={() => setRotate(!rotate)} disabled={view2d}>回転</button>
        <button className={`rounded-lg border px-2.5 py-1 ${view2d ? "border-teal-400 bg-teal-500/15 text-teal-200" : "border-slate-600 text-slate-400"}`} onClick={() => setView2d(!view2d)} title={webglOk ? "3D と 2D を切り替えます" : "この端末では WebGL が使えないため 2D 表示です"}>2D 地図</button>
        {!replay ? <button className="rounded-md border border-slate-600 px-2 py-0.5 text-slate-400 hover:text-slate-200" onClick={startReplay} title="過去の推移を早回しで再生します">▶ リプレイ</button>
          : <span className="flex items-center gap-1 rounded-md border border-teal-400 px-2 py-0.5 text-teal-300"><button onClick={() => setPlaying(!playing)}>{playing ? "❚❚" : "▶"}</button><input type="range" min={0} max={Math.max(0, replay.frames.length - 1)} value={Math.max(0, frame)} onChange={(e) => { setPlaying(false); setFrame(Number(e.target.value)); }} className="w-28" /><span className="w-[7.5rem] text-[10px]">{replay.frames[frame] ? fmtTs(replay.frames[frame].t).slice(5, 16) : ""} · {replay.interval}</span><button onClick={stopReplay} title="リプレイを終了">✕</button></span>}
        {mode === "detail" && <button className={`rounded-lg border px-2.5 py-1 ${mask ? "border-teal-400 bg-teal-500/15 text-teal-200" : "border-slate-600 text-slate-400"}`} onClick={() => setMask(!mask)} title="送信元 IP を伏せます（公開用）">IP マスク</button>}
        <button className="rounded-md border border-slate-600 px-2 py-0.5 text-slate-400 hover:text-slate-200" onClick={() => load()}>↻</button>
        {demo && <button className="rounded-md border border-amber-500 px-2 py-0.5 text-amber-300" onClick={async () => { setDemo(false); if (user?.role === "admin" && setup) await api.put("/overview/setup", { wazuh_instance_id: setup.wazuh_instance_id, demo: false }); }}>デモを終了</button>}
        <button className="rounded-md border border-slate-600 px-2 py-0.5 text-slate-400 hover:text-slate-200" title="セットアップ・ウィザード（取り込み・拠点）" onClick={async () => { await loadSetup(); setWizard(true); }}><span className="inline-flex items-center gap-1"><Ico d={I.gear} size={13} className="" />セットアップ</span></button>
      </div>
      {/* legend */}
      <div className="pointer-events-none absolute bottom-12 left-5 flex flex-wrap gap-3 text-[11px] text-slate-500">
        {Object.entries(KIND_JA).map(([k, l]) => <span key={k}><i className="mr-1 inline-block h-[3px] w-4 rounded align-middle" style={{ background: KIND_COLOR[k] }} />{l}</span>)}
      </div>
      {/* ticker */}
      <div className="pointer-events-none absolute bottom-3 left-5 right-5 flex gap-5 overflow-hidden whitespace-nowrap text-[11px] text-slate-400">
        {(data?.recent ?? []).slice(0, 4).map((ev, i) => <span key={i}><span className="text-slate-500">{fmtTs(ev.ts).slice(11)}</span> <b style={{ color: ev.color }}><Flag iso2={ev.iso2} /> {ip(ev.ip)}</b> → {ev.dst} : {ev.what_ja}{ev.kind === "blocked" && " → 遮断"}</span>)}
        {!data?.recent.length && <span>直近のイベントはありません</span>}
      </div>
      {err && <div className="absolute left-5 top-[120px] rounded-md border border-rose-700/50 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{err}</div>}
      {setup && wizard && <OverviewWizard setup={setup} onReload={async () => { await loadSetup(); await load(true); }} onClose={() => { setWizard(false); loadSetup().catch(() => {}); }} onDemo={async () => { setDemo(true); setWizard(false); if (user?.role === "admin") await api.put("/overview/setup", { wazuh_instance_id: setup.wazuh_instance_id, demo: true }); }} />}
      {noData && !loading && !wizard && <div className="absolute left-1/2 top-1/2 w-[520px] -translate-x-1/2 -translate-y-1/2 rounded-xl border border-slate-600 bg-[#0E1526]/90 p-5 text-sm text-slate-300 backdrop-blur">
        <div className="mb-1 text-base font-semibold text-slate-100">まだ攻撃通信のデータがありません</div>
        <p className="text-xs text-slate-400">外部に公開しているサーバー（Web / SSH / VPN / メール）のログが Wazuh に入ると、ここに国別の攻撃通信が描かれます。送信元 IP（data.srcip）と Wazuh 標準の GeoLocation が付いたアラートが対象です。</p>
        <button className="btn-primary mt-3 px-3 py-1 text-sm" onClick={async () => { await loadSetup(); setWizard(true); }}>セットアップ・ウィザードを開く</button>
      </div>}
      {data?.profiles.some((p) => p.error) && mode === "detail" && <div className="absolute left-5 top-[120px] text-[10px] text-amber-300">一部の集計でエラー: {data.profiles.filter((p) => p.error).map((p) => `${p.name}: ${p.error}`).join(" / ")}</div>}
    </div>
  );
}
