"""AI字幕生成 — faster-whisper 转录视频生成 .srt，可选 OpenAI 兼容接口翻译。

外部 HTTP 运行时（runtime=external-http）：启动 ThreadingHTTPServer，
暴露 /health 与 /action，宿主用 PluginToken 鉴权调用。转录为 CPU/GPU 密集任务，
后台线程执行，进度经 /action status 查询。

依赖：pip install -r requirements.txt（faster-whisper）。首次使用下载模型到 ~/.cache。
翻译走 OpenAI 兼容 /v1/chat/completions（标准库 urllib，无需额外依赖）。
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PLUGIN_TOKEN = os.environ.get("PTP_PLUGIN_TOKEN", "")
HOST_URL = os.environ.get("PTP_HOST_URL", "")
HOST_TOKEN = os.environ.get("PTP_HOST_TOKEN", "")

DEFAULT_EXT = ".mp4,.mkv,.avi,.ts,.mov,.wmv,.flv,.m4v"

# 全局运行状态（后台转录线程写，status 读；单任务串行，简化并发）
_state = {"running": False, "current": "", "done": 0, "total": 0, "errors": 0, "last": ""}
_state_lock = threading.Lock()
# whisper 模型缓存（按 model 名惰性加载，避免进程启动即占显存）
_models = {}
_models_lock = threading.Lock()


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


def kv_get(key):
    r = host_call("/kv/get", {"key": key})
    if isinstance(r, dict):
        return r.get("value", "")
    return ""


def kv_set(key, value):
    host_call("/kv/set", {"key": key, "value": value})


def split_lines(value):
    return [line.strip() for line in str(value or "").splitlines() if line.strip()]


def parse_exts(value):
    parts = [p.strip().lower() for p in str(value or DEFAULT_EXT).split(",") if p.strip()]
    return [p if p.startswith(".") else f".{p}" for p in parts]


def iter_media(roots, exts):
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if Path(name).suffix.lower() in exts:
                    yield Path(dirpath) / name


def fmt_ts(sec):
    """秒 → SRT 时间戳 HH:MM:SS,mmm"""
    ms = int(round(sec * 1000))
    h, ms = divmod(ms, 3600000)
    m, ms = divmod(ms, 60000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def get_model(name, device):
    """惰性加载 whisper 模型（按 name 缓存）。faster-whisper 未装时抛清晰错误。"""
    with _models_lock:
        key = f"{name}|{device}"
        if key in _models:
            return _models[key]
        try:
            from faster_whisper import WhisperModel
        except ImportError as e:
            raise RuntimeError("faster-whisper 未安装，请在插件目录执行 pip install -r requirements.txt") from e
        compute = "default"
        dev = device
        if device == "auto":
            try:
                import torch  # noqa: F401
                dev = "cuda"
            except Exception:
                dev = "cpu"
        model = WhisperModel(name, device=dev, compute_type=compute)
        _models[key] = model
        return model


def transcribe_to_srt(video, model, language):
    """转录单个视频 → 返回 SRT 文本。language=auto 时让 whisper 自动检测。"""
    lang = None if (not language or language == "auto") else language
    segments, info = model.transcribe(str(video), language=lang, vad_filter=True, beam_size=5)
    lines = []
    for i, seg in enumerate(segments, 1):
        text = seg.text.strip()
        if not text:
            continue
        lines.append(f"{i}\n{fmt_ts(seg.start)} --> {fmt_ts(seg.end)}\n{text}\n")
    return "".join(lines), (info.language if info else "und")


def translate_lines(srt_text, cfg):
    """用 OpenAI 兼容接口翻译 SRT 文本。返回译文 SRT；失败抛异常（调用方决定是否保留原文）。"""
    base = cfg.get("openai_base_url", "").rstrip("/")
    key = cfg.get("openai_api_key", "")
    model = cfg.get("openai_model", "gpt-4o-mini") or "gpt-4o-mini"
    target = cfg.get("target_lang", "中文") or "中文"
    bilingual = str(cfg.get("bilingual", "false")).lower() in ("1", "true", "yes", "on")
    if not base or not key:
        raise RuntimeError("翻译启用但未配置 openai_base_url / openai_api_key")
    output_mode = "双语：每行译文后跟原文（译文\\n原文）。" if bilingual else "仅译文。"
    prompt = (
        f"你是专业字幕翻译。把下面 SRT 字幕翻译为「{target}」，保持序号与时间轴完全不变，"
        f"只输出翻译后的 SRT。{output_mode}"
    )
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": srt_text},
        ],
        "temperature": 0.2,
    }).encode("utf-8")
    req = urllib.request.Request(
        base + "/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as res:
        data = json.loads(res.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"].strip()


def process_video(video, cfg):
    """转录单个视频并写同名 .srt（可选翻译）。返回输出路径。"""
    model = get_model(cfg.get("model", "small") or "small", cfg.get("device", "auto") or "auto")
    srt, detected = transcribe_to_srt(video, model, cfg.get("language", "auto"))
    out = video.with_suffix(".srt")
    if str(cfg.get("translate_enabled", "false")).lower() in ("1", "true", "yes", "on"):
        try:
            translated = translate_lines(srt, cfg)
            if translated:
                srt = translated
        except Exception as e:
            log("warn", "translate_failed", f"翻译失败，保留原文：{e}", {"video": str(video)})
    out.write_text(srt, encoding="utf-8")
    return out, detected


def run_scan(cfg):
    """后台扫描：为缺少 .srt 的视频逐个转录。"""
    with _state_lock:
        if _state["running"]:
            return
        _state["running"] = True
        _state["done"] = 0
        _state["errors"] = 0
        _state["current"] = ""

    def worker():
        try:
            roots = split_lines(cfg.get("scan_paths", ""))
            exts = parse_exts(cfg.get("media_ext", DEFAULT_EXT))
            videos = [v for v in iter_media(roots, exts) if not v.with_suffix(".srt").exists()]
            with _state_lock:
                _state["total"] = len(videos)
            log("info", "scan_start", f"待转录 {len(videos)} 个视频")
            for v in videos:
                with _state_lock:
                    _state["current"] = v.name
                try:
                    out, lang = process_video(v, cfg)
                    with _state_lock:
                        _state["done"] += 1
                        _state["last"] = f"{v.name} ({lang})"
                    log("info", "transcribed", str(out))
                except Exception as e:
                    with _state_lock:
                        _state["errors"] += 1
                    log("error", "transcribe_failed", f"{v}: {e}")
            notice("AI字幕扫描完成", f"成功 {_state['done']}，失败 {_state['errors']}")
        finally:
            with _state_lock:
                _state["running"] = False
                _state["current"] = ""

    threading.Thread(target=worker, daemon=True).start()


def run_transcribe(path, cfg):
    """后台转录单个视频。"""
    with _state_lock:
        if _state["running"]:
            return False, "已有任务运行中"
        _state["running"] = True
        _state["total"] = 1
        _state["done"] = 0
        _state["errors"] = 0
        _state["current"] = Path(path).name

    def worker():
        try:
            out, lang = process_video(Path(path), cfg)
            with _state_lock:
                _state["done"] = 1
                _state["last"] = f"{Path(path).name} ({lang})"
            notice("AI字幕生成完成", str(out))
        except Exception as e:
            with _state_lock:
                _state["errors"] += 1
            log("error", "transcribe_failed", f"{path}: {e}")
            notice("AI字幕生成失败", f"{path}: {e}", "warning")
        finally:
            with _state_lock:
                _state["running"] = False
                _state["current"] = ""

    threading.Thread(target=worker, daemon=True).start()
    return True, "已开始转录"


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _check(self):
        tok = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if PLUGIN_TOKEN and tok != PLUGIN_TOKEN:
            self._json(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True, "name": "ptp-ai-subtitle"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._check():
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        payload = {}
        if length:
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                payload = {}
        action = (payload.get("action") or "").strip()
        cfg = payload.get("config") or {}
        if self.path == "/action":
            if action == "status":
                with _state_lock:
                    self._json(200, {"ok": True, "state": dict(_state)})
            elif action == "scan":
                run_scan(cfg)
                self._json(200, {"ok": True, "message": "扫描已启动"})
            elif action == "transcribe":
                path = (payload.get("path") or "").strip()
                if not path or not os.path.isfile(path):
                    self._json(400, {"error": "path 必填且须为存在的文件"})
                    return
                ok, msg = run_transcribe(path, cfg)
                self._json(200 if ok else 409, {"ok": ok, "message": msg})
            else:
                self._json(400, {"error": f"unknown action: {action}"})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, *args):
        pass  # 静默默认访问日志


def main():
    port = int(os.environ.get("PORT", "0") or "0")
    if not port:
        # 宿主未指定端口则自动选一个并写 KV 供宿主读取（与 ffmpeg-thumb 范式一致）
        port = 0
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if port == 0:
        port = srv.server_address[1]
        kv_set("__listen_port", str(port))
    log("info", "started", f"ptp-ai-subtitle listening on 127.0.0.1:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
