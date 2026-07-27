# -*- coding: utf-8 -*-
import json, os, re, time, socket, ipaddress, hashlib, base64, subprocess, urllib.request, urllib.error, urllib.parse, hmac, struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone, timedelta
from pathlib import Path
from email.utils import parsedate_to_datetime

PLUGIN_TOKEN = os.environ.get("PTP_PLUGIN_TOKEN", "")
HOST_URL = os.environ.get("PTP_HOST_URL", "")
HOST_TOKEN = os.environ.get("PTP_HOST_TOKEN", "")
PLUGIN_ID = os.environ.get("PTP_PLUGIN_ID", "")

def host_call(path, body=None, method="POST"):
    if not HOST_URL or not HOST_TOKEN: return None
    data=None; headers={"Authorization": f"Bearer {HOST_TOKEN}"}
    if body is not None:
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"); headers["Content-Type"]="application/json"
    req=urllib.request.Request(HOST_URL.rstrip("/")+path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            raw=res.read().decode("utf-8"); return json.loads(raw) if raw else {}
    except Exception:
        return None
def log(level, event, message, data=None): host_call("/log", {"level":level,"event":event,"message":message,"data":data or {}})
def notice(title, body, level="info"): host_call("/notice", {"title":title,"body":body,"level":level})
def publish_event(etype, data=None): host_call("/events", {"type":etype,"data":data or {}})
def kv_get(key):
    r=host_call("/kv/get",{"key":key}) or {}; return r.get("value","")
def kv_set(key, value): host_call("/kv/set",{"key":key,"value":value})
def as_bool(v, default=False):
    if v is None: return default
    if isinstance(v,bool): return v
    return str(v).strip().lower() in ("1","true","yes","on","y")
def as_int(v, default=0):
    try: return int(v)
    except Exception: return default
def split_multi(raw):
    return [p.strip() for p in re.split(r"[\n,;]+", str(raw or "")) if p.strip()]
def http_json(url, method="GET", headers=None, data=None, timeout=10, form=None):
    body=None; hdrs=dict(headers or {}); hdrs.setdefault("User-Agent","PTPatronus-Plugin/1.0")
    if form is not None:
        body=urllib.parse.urlencode(form).encode(); hdrs["Content-Type"]="application/x-www-form-urlencoded"; method="POST"
    elif data is not None:
        body=json.dumps(data).encode(); hdrs["Content-Type"]="application/json"
    req=urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
    with urllib.request.urlopen(req, timeout=timeout) as res:
        raw=res.read().decode("utf-8","replace"); return json.loads(raw) if raw.strip().startswith(("{","[")) else {"raw":raw}

class Handler(BaseHTTPRequestHandler):
    def _json(self,s,p):
        raw=json.dumps(p, ensure_ascii=False).encode(); self.send_response(s); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def _body(self):
        n=int(self.headers.get("Content-Length","0") or "0"); return json.loads(self.rfile.read(n).decode()) if n else {}
    def _auth(self): return (not PLUGIN_TOKEN) or self.headers.get("Authorization")==f"Bearer {PLUGIN_TOKEN}"
    def do_GET(self):
        self._json(200,{"ok":True,"plugin":PLUGIN_ID or "plugin"}) if self.path=="/health" else self._json(404,{"error":"not found"})
    def do_POST(self):
        if not self._auth(): self._json(401,{"error":"unauthorized"}); return
        payload=self._body()
        if self.path=="/action":
            try: self._json(200,{"ok":True,"output":handle_action(payload.get("action"), payload.get("input") or {}, payload.get("config") or {}, payload.get("host") or {})})
            except Exception as e: log("error","action.error",str(e),{"action":payload.get("action")}); self._json(200,{"ok":False,"error":str(e)})
            return
        if self.path=="/event":
            try: handle_event(payload.get("type") or payload.get("event") or "", payload.get("data") or {}, payload.get("config") or {}); self._json(200,{"ok":True})
            except Exception as e: log("error","event.error",str(e)); self._json(200,{"ok":False,"error":str(e)})
            return
        self._json(404,{"error":"not found"})
    def log_message(self,*a): return


def _is_private_host(host):
    try:
        infos=socket.getaddrinfo(host, None)
        for info in infos:
            ip=ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved: return True
    except Exception:
        return False
    return False
def handle_event(event_type, data, cfg):
    return
def handle_action(action, inp, cfg, host):
    if action!="probe": raise ValueError("unknown action")
    raw_url=str(inp.get("url") or "").strip()
    if not raw_url: raise ValueError("URL 不能为空")
    u=urllib.parse.urlparse(raw_url)
    if u.scheme not in ("http","https") or not u.hostname: raise ValueError("仅支持有效 HTTP/HTTPS URL")
    if not as_bool(cfg.get("allow_private_network"), False) and _is_private_host(u.hostname):
        raise ValueError("默认禁止探测内网/回环地址，可在配置中允许")
    method=str(inp.get("method") or "GET").upper()
    headers={}
    for line in str(cfg.get("default_headers") or "").splitlines():
        if ":" in line:
            k,v=line.split(":",1); headers[k.strip()]=v.strip()
    for line in str(inp.get("headers") or "").splitlines():
        if ":" in line:
            k,v=line.split(":",1); headers[k.strip()]=v.strip()
    body=str(inp.get("body") or "").encode() if method=="POST" and inp.get("body") is not None else None
    timeout=as_int(cfg.get("timeout_seconds"),10) or 10
    follow=as_bool(cfg.get("follow_redirects"), True)
    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    opener=urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedir)
    req=urllib.request.Request(raw_url, data=body, headers=headers, method=method)
    started=time.time(); status=0; resp_headers={}; raw=b""; final=raw_url; err=None
    try:
        with opener.open(req, timeout=timeout) as res:
            status=getattr(res,"status",200); resp_headers=dict(res.headers.items()); raw=res.read(); final=res.geturl()
    except urllib.error.HTTPError as e:
        status=e.code; resp_headers=dict(e.headers.items()) if e.headers else {}; raw=e.read() if e.fp else b""; err=str(e)
    except Exception as e:
        err=str(e)
    maxb=as_int(cfg.get("max_body_bytes"),2048) or 2048
    snippet=raw[:maxb].decode("utf-8","replace")
    expected=as_int(inp.get("expected_status"),200)
    ok=(err is None) and (status==expected if expected else status>0)
    out={"ok":ok,"status":status,"elapsed_ms":int((time.time()-started)*1000),"url":final,"expected_status":expected,"headers":resp_headers,"body_snippet":snippet,"error":err}
    log("info" if ok else "warning","http-probe", f"probe {raw_url} -> {status}", {"ok":ok,"elapsed_ms":out["elapsed_ms"]})
    return out


if __name__ == "__main__":
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PTP_PLUGIN_PORT","19090"))), Handler).serve_forever()
