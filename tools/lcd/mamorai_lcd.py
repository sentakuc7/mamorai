# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""
mamorai_lcd.py — MamorAI attack map on a 3.5" USB sub-monitor (Turing Smart Screen 3.5" Rev A)

Shows the MamorAI "Attack map" (Overview) on a cheap 480x320 USB LCD:
  - clock / connection status
  - KPI: attack events, source countries, targeted hosts, blocked (+ rate)
  - 2D world map with animated arcs from source countries to your sites
    (port of web/src/components/AttackMap2D.tsx; same data as GET /api/wazuh/{id}/attack-map)

Requirements
  - Turing Smart Screen 3.5" (Rev A, USB VID 1A86 / PID 5722)
  - https://github.com/mathoudebine/turing-smart-screen-python (used as the serial driver)
  - MamorAI console reachable from this PC and an API token (viewer role is enough)

Usage
  python mamorai_lcd.py                       run on the LCD (resident)
  python mamorai_lcd.py --demo                fictional sample data on the LCD
  python mamorai_lcd.py --demo --preview a.gif  render a 2-second animation without the LCD
  python mamorai_lcd.py --preview a.png       render one frame from live data without the LCD
  python mamorai_lcd.py --list-ports          show serial ports (to check the LCD is detected)

Config: config.json next to this file (see config.example.json).
Token : environment variable MAMORAI_TOKEN (never put it in config.json).
"""

import argparse
import datetime as dt
import json
import logging
import logging.handlers
import math
import os
import signal
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))

# ============================== config ==============================
DEFAULTS = {
    "mamorai_url": "",                 # e.g. "https://mamorai.example:8444"
    "wazuh_id": None,                  # null = first Wazuh instance (same as the dashboard default)
    "window": "now-24h",               # now-24h / now-7d / now-30d
    "verify_tls": False,               # the console usually has a self-signed certificate
    "ca_file": "",                     # PEM to verify the console certificate (recommended)
    "refresh_seconds": 60,
    "com_port": "auto",                # "auto" = find VID 1A86 / PID 5722, or e.g. "COM3" / "/dev/ttyACM0"
    "brightness": 40,                  # 0-100
    "reverse": False,                  # true if the image is upside down
    "fps": 8,                          # target frames per second (Rev A transfer speed caps it)
    "labels": 4,                       # country labels on the map (top N)
    "turing_lib": "",                  # path to the turing-smart-screen-python clone ("" = this folder or its parents)
    "font": "",                        # TTF/TTC with Japanese glyphs ("" = auto: Meiryo / Noto CJK)
    "font_bold": "",
    "lang": "ja",                      # ja / en (labels)
}
CFG = dict(DEFAULTS)

NATIVE_W, NATIVE_H = 320, 480
USB_VID, USB_PID = 0x1A86, 0x5722
WORLD_JSON = os.path.join(HERE, "countries-110m.json")
LOG_PATH = os.path.join(HERE, "mamorai_lcd.log")

BG = (10, 12, 16)
LINE = (55, 60, 70)
FG = (232, 232, 232)
SUB = (150, 155, 165)
DIM = (95, 100, 110)
ACCENT = (0, 200, 255)
OK = (70, 200, 110)
NG = (255, 70, 70)
KPI_ATTACK = (253, 164, 175)
KPI_BLOCK = (94, 234, 212)

# map colours (brighter than the browser version: cheap LCD panels have low contrast)
MAP_BG = (6, 12, 26)
MAP_GRID = (20, 36, 56)
MAP_LAND = (92, 116, 160)
MAP_COAST = (185, 205, 245)
MAP_HOME_LAND = (110, 150, 255)       # country of the default site (Japan by default)
MAP_HOME_COAST = (230, 238, 255)
SITE_COLOR = (170, 185, 255)
KIND_COLOR = {"ssh": (244, 63, 94), "web": (251, 146, 60), "vpn": (250, 204, 21), "smtp": (250, 204, 21),
              "rdp": (244, 63, 94), "fw": (167, 139, 250), "blocked": (45, 212, 191)}
HOME_COUNTRY_ID = "392"               # ISO 3166 numeric id highlighted on the map (392 = Japan)

TXT = {
    "ja": {"title": "攻撃可視化", "attack": "攻撃", "countries": "国", "targets": "対象", "blocked": "遮断",
           "fail": "取得失敗", "unset": "未設定", "loading": "読み込み中…", "site": "自拠点", "week": "月火水木金土日"},
    "en": {"title": "Attack map", "attack": "Attacks", "countries": "Countries", "targets": "Hosts", "blocked": "Blocked",
           "fail": "fetch failed", "unset": "not configured", "loading": "loading…", "site": "Home", "week": "MTWTFSS"},
}
# ===================================================================

log = logging.getLogger("mamorai_lcd")
running = True
DEMO = False


def t(key):
    return TXT.get(CFG["lang"], TXT["en"]).get(key, key)


def load_config(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        unknown = set(user) - set(DEFAULTS)
        if unknown:
            log.warning("unknown config keys ignored: %s", ", ".join(sorted(unknown)))
        CFG.update({k: v for k, v in user.items() if k in DEFAULTS})
    if os.environ.get("MAMORAI_URL"):
        CFG["mamorai_url"] = os.environ["MAMORAI_URL"]


def setup_logging():
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.handlers.RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if sys.stdout is not None:      # None under pythonw
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        log.addHandler(sh)


# ------------------------------------------------------------------ fonts
FONT_REG = [r"C:\Windows\Fonts\meiryo.ttc", r"C:\Windows\Fonts\YuGothM.ttc", r"C:\Windows\Fonts\msgothic.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc"]
FONT_BOLD = [r"C:\Windows\Fonts\meiryob.ttc", r"C:\Windows\Fonts\YuGothB.ttc", r"C:\Windows\Fonts\msgothic.ttc",
             "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc", "/usr/share/fonts/noto-cjk/NotoSansCJK-Bold.ttc",
             "/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc"]
_font_cache = {}


def _pick(user, cands):
    for p in ([user] if user else []) + cands:
        if p and os.path.exists(p):
            return p
    raise FileNotFoundError("no font with Japanese glyphs found; set \"font\" in config.json")


def font(size, bold=False):
    key = (size, bold)
    if key not in _font_cache:
        path = _pick(CFG["font_bold"], FONT_BOLD) if bold else _pick(CFG["font"], FONT_REG)
        _font_cache[key] = ImageFont.truetype(path, size)
    return _font_cache[key]


def fmt_n(n):
    return f"{int(n):,}"


# ------------------------------------------------------------------ data
class Source:
    """Last good value + status. A failed fetch keeps the previous value (drawn greyed out)."""

    def __init__(self, name, interval):
        self.name, self.interval = name, interval
        self.data, self.ok, self.updated, self.next_at = None, False, None, 0.0

    def due(self):
        return time.time() >= self.next_at

    def run(self, fn):
        self.next_at = time.time() + self.interval
        try:
            self.data, self.ok, self.updated = fn(), True, dt.datetime.now()
        except Exception as e:
            self.ok = False
            log.warning("%s fetch failed: %s: %s", self.name, type(e).__name__, e)


def configured():
    return bool(CFG["mamorai_url"] and os.environ.get("MAMORAI_TOKEN"))


def _tls():
    if CFG["ca_file"]:
        return ssl.create_default_context(cafile=CFG["ca_file"])
    ctx = ssl.create_default_context()
    if not CFG["verify_tls"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def api_get(path, raw=False):
    if not configured():
        raise RuntimeError("mamorai_url / MAMORAI_TOKEN not set")
    url = CFG["mamorai_url"].rstrip("/") + ("" if raw else "/api") + path
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "mamorai-lcd/1.0",
                                               "Authorization": "Bearer " + os.environ["MAMORAI_TOKEN"]})
    with urllib.request.urlopen(req, timeout=10, context=_tls()) as r:
        return json.loads(r.read().decode("utf-8"))


_wazuh_id = None


def fetch_attack():
    global _wazuh_id
    wid = CFG["wazuh_id"] or _wazuh_id
    if wid is None:
        items = api_get("/wazuh").get("items") or []
        if not items:
            raise RuntimeError("no Wazuh instance registered in MamorAI")
        wid = _wazuh_id = items[0]["id"]
    d = api_get(f"/wazuh/{wid}/attack-map?window={urllib.parse.quote(CFG['window'])}")
    d["_key"] = d.get("generated_at") or str(time.time())
    return d


def demo_data():
    """Fictional sample data (for screenshots / testing without a console)."""
    def c(name, ja, lat, lon, total, kind, blocked=0):
        return {"name": name, "name_ja": ja, "iso2": None, "lat": lat, "lon": lon, "total": total,
                "by_kind": {kind: total}, "blocked": blocked, "targets": [{"host": "demo-web", "n": total}]}
    return {
        "_key": "demo",
        "kpi": {"total": 1873, "countries": 14, "targets": 3, "blocked": 702},
        "countries": [c("China", "中国", 35, 103, 812, "ssh", 300), c("United States", "米国", 39, -98, 420, "web", 120),
                      c("Russia", "ロシア", 60, 90, 266, "ssh", 140), c("Netherlands", "オランダ", 52.1, 5.3, 141, "web", 60),
                      c("Brazil", "ブラジル", -10, -52, 88, "rdp", 30), c("Vietnam", "ベトナム", 16, 107, 64, "vpn", 20),
                      c("Germany", "ドイツ", 51, 10, 41, "fw", 20), c("India", "インド", 21, 78, 27, "smtp", 12)],
        "sites": [{"site_id": 0, "name": "Tokyo", "lat": 35.7, "lon": 139.7}],
        "agent_site": {}, "default_site_id": 0,
    }


# ------------------------------------------------------------------ world map (TopoJSON)
def _topo_polygons(topo):
    tf = topo.get("transform")
    sx, sy = tf["scale"] if tf else (1, 1)
    tx, ty = tf["translate"] if tf else (0, 0)
    arcs = []
    for arc in topo["arcs"]:
        x = y = 0
        pts = []
        for p in arc:
            if tf:
                x += p[0]
                y += p[1]
                pts.append((x * sx + tx, y * sy + ty))
            else:
                pts.append((p[0], p[1]))
        arcs.append(pts)

    def ring(idx):
        out = []
        for i in idx:
            pts = arcs[i] if i >= 0 else arcs[~i][::-1]
            out.extend(pts if not out else pts[1:])
        return out

    res = []
    for g in topo["objects"]["countries"]["geometries"]:
        polys = [g["arcs"]] if g.get("type") == "Polygon" else g["arcs"] if g.get("type") == "MultiPolygon" else []
        res.append((str(g.get("id")), [ring(r) for poly in polys for r in poly]))
    return res


_world = None


def load_world():
    """countries-110m.json (world-atlas): local copy, else fetched once from the MamorAI console."""
    global _world
    if _world is not None:
        return _world
    topo = None
    try:
        if os.path.exists(WORLD_JSON):
            with open(WORLD_JSON, encoding="utf-8") as f:
                topo = json.load(f)
        elif configured():
            topo = api_get("/countries-110m.json", raw=True)
            with open(WORLD_JSON, "w", encoding="utf-8") as f:
                json.dump(topo, f)
    except Exception as e:
        log.warning("world map load failed: %s", e)
    _world = _topo_polygons(topo) if topo else []
    return _world


# ------------------------------------------------------------------ render
W, H = 480, 320
HEADER_H = 40
KPI_Y0, KPI_Y1 = 40, 86
MAP_Y = 86
MAP_W, MAP_H = W, H - MAP_Y            # 480 x 234
LAT_TOP, LAT_BOT = 82.0, -58.0
REGIONS = [(0, 0, W, HEADER_H), (0, KPI_Y0, W, KPI_Y1)]   # hashed, sent whole when changed
MAP_BOX = (0, MAP_Y, W, H)                                # tile-diffed every frame


def proj(lon, lat, ss=1):
    return (lon + 180.0) / 360.0 * MAP_W * ss, (LAT_TOP - lat) / (LAT_TOP - LAT_BOT) * MAP_H * ss


def _main_kind(c, default):
    bk = c.get("by_kind") or {}
    return max(bk.items(), key=lambda kv: kv[1])[0] if bk else default


class AttackScene:
    """Static layer (map, arc trails, country dots, labels) is rebuilt only when the data changes;
    each frame only adds the flowing dashes and the pulsing site marker."""

    SS = 2
    DASH, GAP, PERIOD = 8.0, 22.0, 1.6

    def __init__(self):
        self.key, self.base, self.arcs, self.sites = None, None, [], []

    def build(self, data):
        key = (data or {}).get("_key")
        if key == self.key and self.base is not None:
            return
        self.key = key
        ss = self.SS
        img = Image.new("RGB", (MAP_W * ss, MAP_H * ss), MAP_BG)
        ov = Image.new("RGBA", img.size, (0, 0, 0, 0))
        d, do = ImageDraw.Draw(img), ImageDraw.Draw(ov)
        for i in range(13):
            x = i * MAP_W * ss / 12
            d.line([x, 0, x, MAP_H * ss], fill=MAP_GRID, width=1)
        for i in range(7):
            y = i * MAP_H * ss / 6
            d.line([0, y, MAP_W * ss, y], fill=MAP_GRID, width=1)
        for cid, rings in load_world():
            if cid == "010":                       # Antarctica
                continue
            home = cid == HOME_COUNTRY_ID
            for r in rings:
                if len(r) < 3:
                    continue
                pts = [proj(lon, lat, ss) for lon, lat in r]
                if max(p[0] for p in pts) - min(p[0] for p in pts) > MAP_W * ss * 0.9:   # crosses the antimeridian
                    continue
                d.polygon(pts, fill=MAP_HOME_LAND if home else MAP_LAND)
                d.line(pts + [pts[0]], fill=MAP_HOME_COAST if home else MAP_COAST, width=2 if home else 1)

        data = data or {}
        rows = [c for c in (data.get("countries") or [])
                if c.get("lat") is not None and c.get("lon") is not None and (c.get("total", 0) > 0 or c.get("blocked", 0) > 0)]
        sites = data.get("sites") or [{"site_id": 0, "name": t("site"), "lat": 35.7, "lon": 139.7}]
        site_by = {s["site_id"]: s for s in sites}
        def_id = data.get("default_site_id", sites[0]["site_id"])
        agent_site = data.get("agent_site") or {}
        mx_total = max([1] + [c.get("total", 0) for c in rows])
        arcs = []
        for c in rows:
            if c.get("total", 0) <= 0:
                continue
            w = math.log10(1 + c["total"]) / math.log10(1 + mx_total)
            col = KIND_COLOR.get(_main_kind(c, "web"), (148, 163, 184))
            per_site = {}
            for tg in c.get("targets") or []:
                sid = agent_site.get(tg.get("host"), def_id)
                per_site[sid] = per_site.get(sid, 0) + tg.get("n", 0)
            for sid in per_site or {def_id: c["total"]}:
                st = site_by.get(sid, sites[0])
                x1, y1 = proj(c["lon"], c["lat"])
                x2, y2 = proj(st["lon"], st["lat"])
                mx, my = (x1 + x2) / 2, min(y1, y2) - min(80, math.hypot(x2 - x1, y2 - y1) * 0.35)
                pts = [((1 - k) ** 2 * x1 + 2 * (1 - k) * k * mx + k * k * x2,
                        (1 - k) ** 2 * y1 + 2 * (1 - k) * k * my + k * k * y2) for k in (i / 48 for i in range(49))]
                cum = [0.0]
                for a, b in zip(pts, pts[1:]):
                    cum.append(cum[-1] + math.hypot(b[0] - a[0], b[1] - a[1]))
                arcs.append((pts, cum, cum[-1], col, max(2, round(1.5 + w * 2.5))))
                do.line([(x * ss, y * ss) for x, y in pts], fill=col + (int(255 * (0.3 + w * 0.35)),),
                        width=max(1, round((0.9 + w * 1.8) * ss)))
        for c in rows:
            w = math.log10(1 + c.get("total", 0)) / math.log10(1 + mx_total)
            col = KIND_COLOR.get(_main_kind(c, "blocked"), (148, 163, 184)) if c.get("total", 0) > 0 else KIND_COLOR["blocked"]
            x, y = proj(c["lon"], c["lat"], ss)
            r1, r2 = (6 + w * 6) * ss, (2 + w * 3) * ss
            do.ellipse([x - r1, y - r1, x + r1, y + r1], fill=col + (50,))
            do.ellipse([x - r2, y - r2, x + r2, y + r2], fill=col + (255,))
        for s in sites:
            x, y = proj(s["lon"], s["lat"], ss)
            do.ellipse([x - 3 * ss, y - 3 * ss, x + 3 * ss, y + 3 * ss], fill=SITE_COLOR + (255,))
        img = Image.alpha_composite(img.convert("RGBA"), ov).convert("RGB").resize((MAP_W, MAP_H), Image.LANCZOS)

        d = ImageDraw.Draw(img)
        fl = font(12, True)
        name_key = "name_ja" if CFG["lang"] == "ja" else "name"
        for c in sorted([c for c in rows if c.get("total", 0) > 0], key=lambda c: -c["total"])[:CFG["labels"]]:
            x, y = proj(c["lon"], c["lat"])
            txt = f"{c.get(name_key) or c.get('name')} {fmt_n(c['total'])}"
            tw = d.textlength(txt, font=fl)
            lx = min(x + 8, MAP_W - 4 - tw)
            # keep labels off the site marker: flip to the left of the dot if they would cover it
            if any(lx - 12 <= proj(s["lon"], s["lat"])[0] <= lx + tw + 12 and abs(proj(s["lon"], s["lat"])[1] - (y - 10)) < 26 for s in sites):
                lx = max(4, x - 8 - tw)
            d.text((lx, max(0, y - 18)), txt, font=fl, fill=(240, 244, 250), stroke_width=2, stroke_fill=MAP_BG)
        for s in sites:
            x, y = proj(s["lon"], s["lat"])
            name = "◎ " + str(s.get("name", ""))
            d.text((min(x + 9, MAP_W - 4 - d.textlength(name, font=fl)), y + 5), name, font=fl,
                   fill=SITE_COLOR, stroke_width=2, stroke_fill=MAP_BG)
        self.base, self.arcs, self.sites = img, arcs, sites

    @staticmethod
    def _seg(pts, cum, a, b):
        out = []
        for i in range(len(pts) - 1):
            l0, l1 = cum[i], cum[i + 1]
            if l1 < a or l0 > b:
                continue

            def lerp(s):
                k = 0 if l1 == l0 else (s - l0) / (l1 - l0)
                return pts[i][0] + (pts[i + 1][0] - pts[i][0]) * k, pts[i][1] + (pts[i + 1][1] - pts[i][1]) * k
            p0, p1 = lerp(max(a, l0)), lerp(min(b, l1))
            if not out:
                out.append(p0)
            out.append(p1)
        return out

    def frame(self, now_s):
        img = self.base.copy()
        d = ImageDraw.Draw(img)
        period = self.DASH + self.GAP
        phase = (now_s % self.PERIOD) / self.PERIOD * period
        for pts, cum, total, col, width in self.arcs:
            s = phase - period
            while s < total:
                a, b = max(0.0, s), min(total, s + self.DASH)
                if b > a:
                    seg = self._seg(pts, cum, a, b)
                    if len(seg) >= 2:
                        d.line(seg, fill=col, width=width, joint="curve")
                s += period
        k = 0.5 + 0.5 * math.sin(now_s / self.PERIOD * 2 * math.pi)
        for s in self.sites:
            x, y = proj(s["lon"], s["lat"])
            r = 6 + 4 * k
            col = tuple(int(SITE_COLOR[i] * (1 - 0.5 * k) + MAP_BG[i] * 0.5 * k) for i in range(3))
            d.ellipse([x - r, y - r, x + r, y + r], outline=col, width=2)
        return img


SCENE = AttackScene()


def draw_header(d, now, src):
    wk = t("week")[now.weekday()]
    d.text((10, 8), f"{now.month}/{now.day}({wk})", font=font(18), fill=SUB)
    d.text((104, 0), now.strftime("%H:%M"), font=font(30, True), fill=ACCENT)
    f = font(15, True)
    title = t("title")
    x = W - 10 - d.textlength(title, font=f)
    d.text((x, 10), title, font=f, fill=FG)
    col = DIM if not (DEMO or configured()) else (OK if src.ok else NG)
    r = 5
    d.ellipse([x - 18 - r, 19 - r, x - 18 + r, 19 + r], fill=col)
    d.line([0, HEADER_H - 1, W, HEADER_H - 1], fill=LINE, width=1)


def draw_kpi(d, src):
    v = (src.data or {}).get("kpi") or {}
    if not v:
        msg = t("unset") if not (DEMO or configured()) else (t("fail") if not src.ok else t("loading"))
        d.text((12, KPI_Y0 + 12), msg, font=font(16), fill=NG if msg == t("fail") else SUB)
        return
    stale = not src.ok
    total, blocked = v.get("total", 0), v.get("blocked", 0)
    rate = f"{min(100, round(blocked / total * 100))}%" if total else ""
    cells = [(t("attack"), fmt_n(total), KPI_ATTACK, ""), (t("countries"), fmt_n(v.get("countries", 0)), FG, ""),
             (t("targets"), fmt_n(v.get("targets", 0)), FG, ""), (t("blocked"), fmt_n(blocked), KPI_BLOCK, rate)]
    cw = W / 4
    for i, (label, num, col, extra) in enumerate(cells):
        x0 = i * cw + 10
        d.text((x0, KPI_Y0 + 3), label, font=font(12), fill=SUB)
        d.text((x0, KPI_Y0 + 17), num, font=font(22, True), fill=DIM if stale else col)
        if extra:
            d.text((x0 + d.textlength(num, font=font(22, True)) + 5, KPI_Y0 + 26), extra, font=font(12),
                   fill=DIM if stale else col)
    if stale:
        f = font(11)
        d.text((W - 8 - d.textlength(t("fail"), font=f), KPI_Y0 + 3), t("fail"), font=f, fill=NG)


def render(src, now_s=None, now=None):
    now = now or dt.datetime.now()
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    draw_header(d, now, src)
    draw_kpi(d, src)
    SCENE.build(src.data)
    img.paste(SCENE.frame(time.time() if now_s is None else now_s), (0, MAP_Y))
    return img


# ------------------------------------------------------------------ LCD
def add_turing_lib():
    cands = [CFG["turing_lib"]] if CFG["turing_lib"] else []
    p = HERE
    for _ in range(4):
        cands.append(p)
        p = os.path.dirname(p)
    for c in cands:
        if c and os.path.exists(os.path.join(c, "library", "lcd", "lcd_comm_rev_a.py")):
            if c not in sys.path:
                sys.path.insert(0, c)
            return c
    raise RuntimeError("turing-smart-screen-python not found: clone it and set \"turing_lib\" in config.json")


def find_port():
    if CFG["com_port"] and CFG["com_port"].lower() != "auto":
        return CFG["com_port"]
    from serial.tools import list_ports
    for p in list_ports.comports():
        if p.vid == USB_VID and p.pid == USB_PID:
            return p.device
    raise RuntimeError("LCD not found (USB 1A86:5722). Check the cable or set \"com_port\".")


class Lcd:
    TILE_W, TILE_H = 48, 26

    def __init__(self):
        self.lcd = None
        self.reset_cache()

    def reset_cache(self):
        self.last = [None] * len(REGIONS)
        self.last_map = None

    def open(self):
        add_turing_lib()
        from library.lcd.lcd_comm import Orientation
        from library.lcd.lcd_comm_rev_a import LcdCommRevA
        err = None
        for attempt in range(1, 4):
            try:
                port = find_port()
                lcd = LcdCommRevA(com_port=port, display_width=NATIVE_W, display_height=NATIVE_H)
                lcd.Reset()
                lcd.InitializeComm()
                lcd.SetBrightness(level=int(CFG["brightness"]))
                lcd.SetOrientation(orientation=Orientation.REVERSE_LANDSCAPE if CFG["reverse"] else Orientation.LANDSCAPE)
                self.lcd = lcd
                self.reset_cache()
                log.info("LCD ready on %s (%dx%d)", port, lcd.get_width(), lcd.get_height())
                return
            except Exception as e:
                err = e
                log.warning("LCD init failed %d/3: %s", attempt, e)
                self.close()
                time.sleep(5)
        raise err

    def close(self):
        if self.lcd is not None:
            try:
                self.lcd.closeSerial()
            except Exception:
                pass
        self.lcd = None

    def show(self, img):
        for i, box in enumerate(REGIONS):
            part = img.crop(box)
            b = part.tobytes()
            if b != self.last[i]:
                self.lcd.DisplayPILImage(part, box[0], box[1])
                self.last[i] = b
        # map: compare with the last frame tile by tile, send only changed runs of tiles
        x0, y0, x1, y1 = MAP_BOX
        part = img.crop(MAP_BOX)
        cur = part.tobytes()
        if self.last_map is None:
            self.lcd.DisplayPILImage(part, x0, y0)
            self.last_map = cur
            return
        prev, bw, bh = self.last_map, x1 - x0, y1 - y0
        rb = bw * 3
        for ty in range(0, bh, self.TILE_H):
            th = min(self.TILE_H, bh - ty)
            run = None
            for tx in range(0, bw + self.TILE_W, self.TILE_W):
                changed = False
                if tx < bw:
                    tw = min(self.TILE_W, bw - tx)
                    for yy in range(ty, ty + th):
                        o = yy * rb + tx * 3
                        if cur[o:o + tw * 3] != prev[o:o + tw * 3]:
                            changed = True
                            break
                if changed and run is None:
                    run = tx
                elif not changed and run is not None:
                    self.lcd.DisplayPILImage(part.crop((run, ty, min(tx, bw), ty + th)), x0 + run, y0 + ty)
                    run = None
        self.last_map = cur


# ------------------------------------------------------------------ main
def on_signal(sig, frame):
    global running
    running = False


def main():
    global DEMO, running
    ap = argparse.ArgumentParser(description="MamorAI attack map on a Turing Smart Screen 3.5\" (Rev A)")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--preview", metavar="FILE", help="render to PNG (or a 2-second .gif) without the LCD and exit")
    ap.add_argument("--demo", action="store_true", help="use fictional sample data")
    ap.add_argument("--once", action="store_true", help="draw one frame on the LCD and exit")
    ap.add_argument("--list-ports", action="store_true", help="list serial ports and exit")
    args = ap.parse_args()
    setup_logging()
    load_config(args.config)
    DEMO = args.demo

    if args.list_ports:
        from serial.tools import list_ports
        for p in list_ports.comports():
            mark = "  <- LCD" if (p.vid, p.pid) == (USB_VID, USB_PID) else ""
            print(f"{p.device}\t{p.vid and hex(p.vid)}:{p.pid and hex(p.pid)}\t{p.description}{mark}")
        return 0

    src = Source("attack-map", int(CFG["refresh_seconds"]))
    fetch = demo_data if DEMO else fetch_attack
    src.run(fetch)

    if args.preview:
        if args.preview.lower().endswith(".gif"):
            frames = [render(src, now_s=i / 10) for i in range(20)]
            frames[0].save(args.preview, save_all=True, append_images=frames[1:], duration=100, loop=0)
        else:
            render(src, now_s=0.4).save(args.preview)
        log.info("preview written: %s", args.preview)
        return 0

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    def worker():                          # fetching never blocks the animation loop
        while running:
            if src.due():
                src.run(fetch)
            time.sleep(0.5)
    threading.Thread(target=worker, daemon=True).start()

    lcd = Lcd()
    frame_s = 1.0 / max(1, int(CFG["fps"]))
    while running:
        try:
            if lcd.lcd is None:
                lcd.open()
            t0 = time.time()
            lcd.show(render(src))
            if args.once:
                break
            end = t0 + frame_s
            while running and time.time() < end:
                time.sleep(min(0.05, max(0.0, end - time.time())))
        except Exception as e:
            log.error("LCD/render error: %s -> re-init in 5 s", e)
            lcd.close()
            time.sleep(5)
    lcd.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
