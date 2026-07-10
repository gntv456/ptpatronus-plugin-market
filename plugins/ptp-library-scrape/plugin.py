"""媒体库刮削 — 调用宿主 /media/search 复用 TMDB/豆瓣源，写 movie.nfo/tvshow.nfo + 海报。"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PLUGIN_TOKEN = os.environ.get("PTP_PLUGIN_TOKEN", "")
HOST_URL = os.environ.get("PTP_HOST_URL", "")
HOST_TOKEN = os.environ.get("PTP_HOST_TOKEN", "")
DEFAULT_EXT = ".mp4,.mkv,.avi,.ts,.mov,.wmv,.flv,.m4v,.rmvb,.mpg,.mpeg,.webm"
UA = "PTPatronusPlugin/1.0 (library-scrape)"


def host_call(path, body):
    if not HOST_URL or not HOST_TOKEN:
        return None
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        HOST_URL.rstrip("/") + path, data=data,
        headers={"Authorization": f"Bearer {HOST_TOKEN}", "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            return json.loads(res.read().decode("utf-8") or "{}")
    except Exception:
        return None


def log(level, event, message, data=None):
    host_call("/log", {"level": level, "event": event, "message": message, "data": data or {}})


def notice(title, body, level="info"):
    host_call("/notice", {"title": title, "body": body, "level": level})


# ---------------- host media API ----------------

def host_media_search(keyword, year=0):
    if not HOST_URL or not HOST_TOKEN:
        return []
    box = {}

    def _w():
        try:
            data = json.dumps({"keyword": keyword, "year": year}).encode("utf-8")
            req = urllib.request.Request(HOST_URL.rstrip("/") + "/media/search", data=data,
                                         headers={"Authorization": f"Bearer {HOST_TOKEN}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as res:
                box["data"] = res.read().decode("utf-8")
        except Exception as exc:
            box["error"] = exc

    t = threading.Thread(target=_w, daemon=True)
    t.start()
    t.join(25)
    if t.is_alive() or "error" in box:
        return []
    try:
        return (json.loads(box.get("data") or "{}") or {}).get("results") or []
    except Exception:
        return []


def fetch_bytes(url, deadline=30):
    box = {}

    def _w():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=deadline) as res:
                box["data"] = res.read()
        except Exception as exc:
            box["error"] = exc

    t = threading.Thread(target=_w, daemon=True)
    t.start()
    t.join(deadline)
    if t.is_alive() or "error" in box:
        return b""
    return box.get("data") or b""


# ---------------- name cleaning ----------------

BRACKET_RE = re.compile(r"【.*?】|\[.*?\]|\(.*?\)|（.*?）|「.*?」")
NOISE_RE = re.compile(r"(S\d{1,2}E?\d{0,3}|[Ee][Pp]?\d{1,3}|\d{3,4}[pP]|[48][Kk]|HEVC|H\.?26[45]|h264|AVC|10bit|X264|[Xx]26[45]|AAC|FLAC|WEB-DL|BluRay|BDRip)", re.I)
SEP_RE = re.compile(r"[._]+")


def clean_name(raw):
    s = BRACKET_RE.sub(" ", str(raw or ""))
    s = NOISE_RE.sub(" ", s)
    s = SEP_RE.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip(" -—")


def pick_match(name, items):
    if not items:
        return None
    target = name.lower()
    best, best_score = items[0], -1
    for it in items:
        title = str(it.get("title") or "").lower()
        score = 100 if target and target == title else (50 if target and (target in title or title in target) else (10 if title else 0))
        if score > best_score:
            best, best_score = it, score
    return best


# ---------------- NFO ----------------

def write_nfo(dest, hit, is_tv):
    root = ET.Element("tvshow" if is_tv else "movie")
    ET.SubElement(root, "title").text = str(hit.get("title") or "")
    if hit.get("original_title"):
        ET.SubElement(root, "originaltitle").text = str(hit.get("original_title"))
    ET.SubElement(root, "sorttitle").text = str(hit.get("title") or "")
    if hit.get("overview"):
        ET.SubElement(root, "plot").text = str(hit.get("overview"))
    if hit.get("year"):
        ET.SubElement(root, "year").text = str(hit.get("year"))
    if hit.get("release_date"):
        ET.SubElement(root, "premiered").text = str(hit.get("release_date"))
    for g in hit.get("genres") or []:
        ET.SubElement(root, "genre").text = str(g)
    ET.SubElement(root, "studio").text = str(hit.get("source") or "PTPatronus")
    rating = float(hit.get("rating") or 0)
    if rating > 0:
        ratings = ET.SubElement(root, "ratings")
        r = ET.SubElement(ratings, "rating", {"name": str(hit.get("source") or "ptp"), "max": "10", "default": "true"})
        ET.SubElement(r, "value").text = str(rating)
    if hit.get("source_id"):
        uid = ET.SubElement(root, "uniqueid", {"type": str(hit.get("source") or "ptp"), "default": "true"})
        uid.text = str(hit.get("source_id"))
    if is_tv:
        ET.SubElement(root, "season").text = "1"
    try:
        ET.indent(root, space="  ")
    except Exception:
        pass
    ET.ElementTree(root).write(os.path.join(dest, "tvshow.nfo" if is_tv else "movie.nfo"),
                               encoding="utf-8", xml_declaration=True)


def save_image(url, dest):
    if not url:
        return False
    data = fetch_bytes(url)
    if not data:
        return False
    with open(dest, "wb") as f:
        f.write(data)
    return True


# ---------------- scan ----------------

def parse_exts(value):
    parts = [p.strip().lower() for p in str(value or DEFAULT_EXT).split(",") if p.strip()]
    return [p if p.startswith(".") else f".{p}" for p in parts]


def parse_path(line):
    """返回 (dir, force_type)；后缀 #TV/#MOVIE 强制类型。"""
    line = line.strip()
    force = ""
    upper = line.upper()
    for tag, t in (("#TV", "tv"), ("#MOVIE", "movie")):
        if upper.endswith(tag):
            force = t
            line = line[: -len(tag)].strip()
            break
    return line, force


def list_media(folder, exts):
    out = []
    for dirpath, _dirs, files in os.walk(folder):
        for name in files:
            if Path(name).suffix.lower() in exts:
                out.append(Path(dirpath) / name)
    return out


def scrape_dir(folder, force_type, cfg, exts):
    media = list_media(folder, exts)
    if not media:
        return {"status": "skip", "reason": "no media"}
    name = clean_name(Path(folder).name) or clean_name(media[0].stem)
    if not name:
        return {"status": "skip", "reason": "empty name"}

    hits = host_media_search(name)
    hit = pick_match(name, hits)
    if not hit:
        return {"status": "miss", "name": name}

    is_tv = force_type == "tv" or (force_type != "movie" and str(hit.get("type") or "").lower() in ("tv", "series"))
    nfo_name = "tvshow.nfo" if is_tv else "movie.nfo"
    mode = str(cfg.get("mode") or "skip")
    if os.path.exists(os.path.join(folder, nfo_name)) and mode != "force":
        return {"status": "exists", "name": name}

    write_nfo(folder, hit, is_tv)
    saved_poster = save_image(hit.get("poster_url"), os.path.join(folder, "poster.jpg"))
    saved_fanart = save_image(hit.get("backdrop_url"), os.path.join(folder, "fanart.jpg"))
    return {"status": "ok", "name": name, "title": hit.get("title"), "is_tv": is_tv,
            "poster": saved_poster, "fanart": saved_fanart}


def do_scrape(cfg):
    lines = [l for l in str(cfg.get("scraper_paths") or "").splitlines() if l.strip()]
    excludes = [e.strip() for e in str(cfg.get("exclude_paths") or "").splitlines() if e.strip()]
    exts = parse_exts(cfg.get("media_ext"))
    if not lines:
        raise ValueError("scraper_paths 未配置")
    ok = miss = exists = skipped = 0
    errors = []
    for raw in lines:
        root_path, force = parse_path(raw)
        if not os.path.isdir(root_path):
            errors.append(f"not a dir: {root_path}")
            continue
        for dirpath, _dirs, _files in os.walk(root_path):
            if any(ex and ex in dirpath for ex in excludes):
                continue
            media = list_media(dirpath, exts)
            if not media:
                continue
            try:
                r = scrape_dir(dirpath, force, cfg, exts)
                st = r.get("status")
                if st == "ok":
                    ok += 1
                elif st == "miss":
                    miss += 1
                elif st == "exists":
                    exists += 1
                else:
                    skipped += 1
            except Exception as exc:
                errors.append(f"{dirpath}: {exc}")
            _worker_status.update({"ok": ok, "miss": miss, "exists": exists, "errors": len(errors)})
    return {"ok": ok, "miss": miss, "exists": exists, "skipped": skipped, "errors": errors}


_worker_lock = threading.Lock()
_worker_thread = None
_worker_status = {"running": False, "done": False, "ok": 0, "miss": 0, "errors": 0}


def _scrape_worker(cfg):
    global _worker_thread
    _worker_status.update({"running": True, "done": False, "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "ok": 0, "miss": 0, "exists": 0, "errors": 0, "error": None})
    try:
        result = do_scrape(cfg)
        _worker_status.update({"running": False, "done": True, "finished_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        notice("媒体库刮削", f"完成：补齐 {result['ok']}，未匹配 {result['miss']}，已存在 {result['exists']}，失败 {len(result['errors'])}。", "info")
    except Exception as exc:
        _worker_status.update({"running": False, "done": True, "error": str(exc)})
        log("error", "library.scrape.fatal", str(exc))
        notice("媒体库刮削", f"扫描失败：{exc}", "warning")
    finally:
        with _worker_lock:
            _worker_thread = None


def start_scrape(cfg):
    global _worker_thread
    with _worker_lock:
        if _worker_thread and _worker_thread.is_alive():
            return {"started": False, "already_running": True, "status": dict(_worker_status)}
        _worker_thread = threading.Thread(target=_scrape_worker, args=(cfg,), daemon=True)
        _worker_thread.start()
        return {"started": True, "status": dict(_worker_status)}


def handle_action(action, inp, cfg, host):
    if action == "search_one":
        name = clean_name(inp.get("name") or "")
        if not name:
            raise ValueError("input.name is required")
        return {"name": name, "results": host_media_search(name)[:10]}
    if action == "scrape":
        return start_scrape(cfg)
    if action == "status":
        return dict(_worker_status)
    raise ValueError(f"unknown action: {action}")


def handle_event(event_type, data, cfg):
    return None


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

    def _auth(self):
        return not PLUGIN_TOKEN or self.headers.get("Authorization") == f"Bearer {PLUGIN_TOKEN}"

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            self._json(401, {"error": "unauthorized"})
            return
        payload = self._body()
        if self.path == "/action":
            try:
                output = handle_action(payload.get("action"), payload.get("input") or {},
                                        payload.get("config") or {}, payload.get("host") or {})
                self._json(200, {"ok": True, "output": output})
            except Exception as exc:
                log("error", "action.error", str(exc))
                self._json(200, {"ok": False, "error": str(exc)})
            return
        if self.path == "/event":
            self._json(200, {"ok": True})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, *args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("PTP_PLUGIN_PORT", "19090"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
