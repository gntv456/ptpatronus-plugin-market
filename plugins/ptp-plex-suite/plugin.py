# -*- coding: utf-8 -*-
import json, os, re, time, threading, socket, ipaddress, hashlib, base64, subprocess, urllib.request, urllib.error, urllib.parse, hmac, struct
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



def handle_event(event_type, data, cfg):
    return
def _plex(cfg, path):
    base=str(cfg.get("base_url") or "").rstrip("/")
    token=str(cfg.get("token") or "")
    if not base or not token: raise ValueError("需要 base_url 与 token")
    url=base+path+("&" if "?" in path else "?")+"X-Plex-Token="+urllib.parse.quote(token)
    req=urllib.request.Request(url, headers={"Accept":"application/json","User-Agent":"PTPatronus-Plex/1.0"})
    with urllib.request.urlopen(req, timeout=20) as res:
        raw=res.read().decode("utf-8","replace")
        return json.loads(raw) if raw else {}
def handle_action(action, inp, cfg, host):
    if action=="status":
        data=_plex(cfg, "/identity")
        return {"ok":True,"identity":data}
    if action=="libraries":
        data=_plex(cfg, "/library/sections")
        dirs=((data.get("MediaContainer") or {}).get("Directory")) or []
        libs=[{"key":d.get("key"),"title":d.get("title"),"type":d.get("type")} for d in dirs]
        return {"libraries":libs}
    if action=="apply":
        libs=handle_action("libraries", {}, cfg, host).get("libraries") or []
        refreshed=[]
        if as_bool(cfg.get("refresh_on_apply"), True):
            for lib in libs:
                key=lib.get("key")
                if not key: continue
                try:
                    _plex(cfg, f"/library/sections/{key}/refresh")
                    refreshed.append(key)
                except Exception as e:
                    refreshed.append({"key":key,"error":str(e)})
        notice("Plex 套件", f"已处理 {len(libs)} 个库", "info")
        return {"libraries":len(libs),"refreshed":refreshed}
    raise ValueError("unknown action")


if __name__ == "__main__":
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PTP_PLUGIN_PORT","19090"))), Handler).serve_forever()
