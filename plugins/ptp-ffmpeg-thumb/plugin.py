"""FFmpeg缩略图 — 为缺少缩略图的视频用 ffmpeg 截取一帧生成 <文件名>-thumb.jpg。"""
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PLUGIN_TOKEN = os.environ.get("PTP_PLUGIN_TOKEN", "")
HOST_URL = os.environ.get("PTP_HOST_URL", "")
HOST_TOKEN = os.environ.get("PTP_HOST_TOKEN", "")

DEFAULT_EXT = ".mp4,.mkv,.avi,.ts,.mov,.wmv,.flv,.m4v,.rmvb,.mpg,.mpeg,.webm"


def host_call(path, body):
    if not HOST_URL or not HOST_TOKEN:
        return None
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        HOST_URL.rstrip("/") + path,
        data=data,
        headers={"Authorization": f"Bearer {HOST_TOKEN}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            raw = res.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except Exception:
        return None


def log(level, event, message, data=None):
    host_call("/log", {"level": level, "event": event, "message": message, "data": data or {}})


def notice(title, body, level="info"):
    host_call("/notice", {"title": title, "body": body, "level": level})


def split_lines(value):
    return [line.strip() for line in str(value or "").splitlines() if line.strip()]


def parse_exts(value):
    parts = [p.strip().lower() for p in str(value or DEFAULT_EXT).split(",") if p.strip()]
    return [p if p.startswith(".") else f".{p}" for p in parts]


def is_excluded(path, excludes):
    p = str(path)
    return any(ex and ex in p for ex in excludes)


def iter_media(root, exts, excludes):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if Path(name).suffix.lower() in exts:
                video = Path(dirpath) / name
                if not is_excluded(video, excludes):
                    yield video


def make_thumb(video, timeline, overwrite):
    out = video.with_name(f"{video.stem}-thumb.jpg")
    if out.exists() and not overwrite:
        return "skipped"
    cmd = ["ffmpeg", "-y", "-ss", str(timeline or "00:03:01"), "-i", str(video),
           "-frames:v", "1", "-q:v", "3", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"ffmpeg exit {proc.returncode}: {proc.stderr[-300:]}")
    return "generated"


def do_scan(cfg):
    roots = split_lines(cfg.get("scan_paths"))
    excludes = split_lines(cfg.get("exclude_paths"))
    timeline = str(cfg.get("timeline") or "00:03:01").strip()
    overwrite = bool(cfg.get("overwrite"))
    exts = parse_exts(cfg.get("media_ext"))
    if not roots:
        raise ValueError("scan_paths 未配置")

    scanned = generated = skipped = 0
    errors = []
    for root in roots:
        if not os.path.isdir(root):
            errors.append(f"not a dir: {root}")
            continue
        for video in iter_media(root, exts, excludes):
            scanned += 1
            try:
                result = make_thumb(video, timeline, overwrite)
                if result == "generated":
                    generated += 1
                else:
                    skipped += 1
            except Exception as exc:
                errors.append(f"{video}: {exc}")
                log("error", "ffmpeg.thumb.error", str(exc), {"file": str(video)})
            _worker_status.update({"scanned": scanned, "generated": generated,
                                   "skipped": skipped, "errors": len(errors)})
    return {"scanned": scanned, "generated": generated, "skipped": skipped, "errors": errors}


_worker_lock = threading.Lock()
_worker_thread = None
_worker_status = {"running": False, "done": False, "scanned": 0, "generated": 0, "errors": 0}


def _scan_worker(cfg):
    global _worker_thread
    _worker_status.update({"running": True, "done": False, "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "scanned": 0, "generated": 0, "skipped": 0, "errors": 0, "error": None})
    try:
        result = do_scan(cfg)
        _worker_status.update({"running": False, "done": True,
                               "finished_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        notice("FFmpeg缩略图",
               f"扫描 {result['scanned']} 个视频，生成 {result['generated']}，失败 {len(result['errors'])}。",
               "warning" if result["errors"] else "info")
    except Exception as exc:
        _worker_status.update({"running": False, "done": True, "error": str(exc)})
        log("error", "ffmpeg.scan.fatal", str(exc))
        notice("FFmpeg缩略图", f"扫描失败：{exc}", "warning")
    finally:
        with _worker_lock:
            _worker_thread = None


def start_scan(cfg):
    global _worker_thread
    with _worker_lock:
        if _worker_thread and _worker_thread.is_alive():
            return {"started": False, "already_running": True, "status": dict(_worker_status)}
        _worker_thread = threading.Thread(target=_scan_worker, args=(cfg,), daemon=True)
        _worker_thread.start()
        return {"started": True, "status": dict(_worker_status)}


def handle_action(action, inp, cfg, host):
    if action == "scan":
        return start_scan(cfg)
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
                output = handle_action(
                    payload.get("action"),
                    payload.get("input") or {},
                    payload.get("config") or {},
                    payload.get("host") or {},
                )
                self._json(200, {"ok": True, "output": output})
            except Exception as exc:
                log("error", "action.error", str(exc))
                self._json(200, {"ok": False, "error": str(exc)})
            return
        if self.path == "/event":
            try:
                handle_event(payload.get("type"), payload.get("data") or {}, payload.get("config") or {})
            except Exception as exc:
                log("error", "event.error", str(exc))
            self._json(200, {"ok": True})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, *args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("PTP_PLUGIN_PORT", "19090"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
