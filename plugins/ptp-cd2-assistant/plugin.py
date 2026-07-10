"""CloudDrive2助手 — 定时检查 CD2 实例健康 + 仪表盘。依赖 clouddrive 包（安装时自动 pip 装）。

注意：clouddrive 是第三方 gRPC 客户端，以下调用按其公开 API 编写；各操作均 try/except，
单个实例/方法失败不影响整体，返回结构里带 error 字段。真机联调时按实际返回校准字段名。
"""
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLUGIN_TOKEN = os.environ.get("PTP_PLUGIN_TOKEN", "")
HOST_URL = os.environ.get("PTP_HOST_URL", "")
HOST_TOKEN = os.environ.get("PTP_HOST_TOKEN", "")


def host_call(path, body):
    if not HOST_URL or not HOST_TOKEN:
        return None
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(HOST_URL.rstrip("/") + path, data=data,
                                 headers={"Authorization": f"Bearer {HOST_TOKEN}", "Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return json.loads(res.read().decode("utf-8") or "{}")
    except Exception:
        return None


def log(level, event, message, data=None):
    host_call("/log", {"level": level, "event": event, "message": message, "data": data or {}})


def notice(title, body, level="info"):
    host_call("/notice", {"title": title, "body": body, "level": level})


# ---------------- clouddrive (lazy import: 插件即使依赖未装也能 /health) ----------------

def _import_cd2():
    try:
        from clouddrive import CloudDriveClient  # type: ignore
        from clouddrive.proto import CloudDrive_pb2  # type: ignore
        return CloudDriveClient, CloudDrive_pb2
    except Exception as exc:
        raise RuntimeError(f"clouddrive 包未安装或不可用：{exc}")


def parse_confs(text):
    out = []
    for line in str(text or "").splitlines():
        parts = [p.strip() for p in line.split("#")]
        if len(parts) >= 4 and parts[0] and parts[1]:
            out.append({"name": parts[0], "url": parts[1], "user": parts[2], "password": parts[3]})
    return out


def connect(conf):
    CloudDriveClient, _pb = _import_cd2()
    client = CloudDriveClient(conf["url"])
    client.login(conf["user"], conf["password"])
    return client


def safe(label, fn):
    try:
        return fn()
    except Exception as exc:
        return {"error": f"{label}: {exc}"}


def gather_info(conf):
    """单实例指标。每步独立 try/except，单点失败不拖垮整体。"""
    info = {"name": conf["name"], "url": conf["url"]}
    try:
        client = connect(conf)
    except Exception as exc:
        info["error"] = f"connect: {exc}"
        return info

    def running():
        r = client.GetRunningInfo()
        return {"cpu": getattr(r, "cpuUsage", None), "mem": getattr(r, "memoryUsage", None),
                "uptime": getattr(r, "upTime", None), "handles": getattr(r, "fileHandleCount", None)}

    def tasks():
        c = client.GetAllTasksCount()
        return {"upload_tasks": getattr(c, "uploadTaskCount", None),
                "download_tasks": getattr(c, "downloadTaskCount", None)}

    def space():
        # 取根目录空间信息（取第一个挂载点）
        roots = client.fs.listdir("/") or []
        if not roots:
            return {}
        first = "/" + (roots[0].name if hasattr(roots[0], "name") else str(roots[0]))
        s = client.GetSpaceInfo(first)
        return {"total": getattr(s, "totalSpace", None), "used": getattr(s, "usedSpace", None)}

    info["running"] = safe("running", running)
    info["tasks"] = safe("tasks", tasks)
    info["space"] = safe("space", space)
    info["status"] = "ok" if all(isinstance(info[k], dict) and "error" not in info[k] for k in ("running", "tasks")) else "degraded"
    return info


def detect_issues(conf, keyword):
    """返回该实例的问题列表（上传错误关键字 / 账号失效）。"""
    issues = []
    try:
        client = connect(conf)
        uploads = client.upload_tasklist.list(page=0, page_size=10) or []
        for t in uploads:
            err = str(getattr(t, "errorMessage", "") or getattr(t, "result", "") or "")
            if keyword and keyword in err:
                issues.append(f"上传任务异常：{err[:80]}")
        # listdir 探测 cookie 是否失效
        try:
            client.fs.listdir("/")
        except Exception as exc:
            issues.append(f"疑似账号失效（listdir 失败）：{exc}")
    except Exception as exc:
        issues.append(f"检查失败：{exc}")
    return issues


# ---------------- actions ----------------

def action_info(cfg):
    return {"instances": [gather_info(c) for c in parse_confs(cfg.get("cd2_confs"))]}


def action_restart(inp, cfg):
    target = str(inp.get("name") or "").strip()
    done, errors = [], []
    for c in parse_confs(cfg.get("cd2_confs")):
        if target and c["name"] != target:
            continue
        try:
            client = connect(c)
            client.RestartService()
            done.append(c["name"])
        except Exception as exc:
            errors.append(f"{c['name']}: {exc}")
    return {"restarted": done, "errors": errors}


def action_add_offline(inp, cfg):
    name = str(inp.get("name") or "").strip()
    urls = inp.get("urls") or []
    folder = str(inp.get("folder") or "").strip() or "/"
    if not urls:
        raise ValueError("input.urls is required")
    for c in parse_confs(cfg.get("cd2_confs")):
        if name and c["name"] != name:
            continue
        try:
            CloudDriveClient, pb = _import_cd2()
            client = connect(c)
            client.AddOfflineFiles(pb.AddOfflineFileRequest(urls=list(urls), toFolder=folder))
            return {"ok": True, "instance": c["name"], "count": len(urls)}
        except Exception as exc:
            return {"ok": False, "error": f"{c.get('name')}: {exc}"}
    return {"ok": False, "error": "instance not found"}


def do_check(cfg):
    keyword = str(cfg.get("keyword") or "账号异常").strip()
    notify_on = bool(cfg.get("notify"))
    all_issues, checked = [], 0
    for c in parse_confs(cfg.get("cd2_confs")):
        checked += 1
        issues = detect_issues(c, keyword)
        if issues:
            all_issues.append({"name": c["name"], "issues": issues})
            if notify_on:
                notice("CloudDrive2助手", f"{c['name']}：{'; '.join(issues[:2])}", "warning")
        _worker_status.update({"checked": checked, "issues": len(all_issues)})
    return {"checked": checked, "instances_with_issues": len(all_issues), "details": all_issues}


_worker_lock = threading.Lock()
_worker_thread = None
_worker_status = {"running": False, "done": False, "checked": 0, "issues": 0}


def _check_worker(cfg):
    global _worker_thread
    _worker_status.update({"running": True, "done": False, "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "checked": 0, "issues": 0, "error": None})
    try:
        result = do_check(cfg)
        _worker_status.update({"running": False, "done": True,
                               "finished_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        notice("CloudDrive2助手", f"检查完成：{result['checked']} 个实例，{result['instances_with_issues']} 个有异常。", "info")
    except Exception as exc:
        _worker_status.update({"running": False, "done": True, "error": str(exc)})
        log("error", "cd2.check.fatal", str(exc))
    finally:
        with _worker_lock:
            _worker_thread = None


def start_check(cfg):
    global _worker_thread
    with _worker_lock:
        if _worker_thread and _worker_thread.is_alive():
            return {"started": False, "already_running": True, "status": dict(_worker_status)}
        _worker_thread = threading.Thread(target=_check_worker, args=(cfg,), daemon=True)
        _worker_thread.start()
        return {"started": True, "status": dict(_worker_status)}


def handle_action(action, inp, cfg, host):
    if action == "check":
        return start_check(cfg)
    if action == "status":
        return dict(_worker_status)
    if action == "info":
        return action_info(cfg)
    if action == "restart":
        return action_restart(inp, cfg)
    if action == "add_offline":
        return action_add_offline(inp, cfg)
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
