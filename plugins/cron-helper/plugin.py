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



def handle_event(event_type, data, cfg):
    return
def _parse_field(field, min_v, max_v):
    vals=set()
    for part in str(field).split(","):
        part=part.strip()
        if part=="*":
            vals.update(range(min_v, max_v+1)); continue
        step=1
        if "/" in part:
            part, step_s = part.split("/",1); step=int(step_s)
        if part=="*":
            vals.update(range(min_v, max_v+1, step)); continue
        if "-" in part:
            a,b=part.split("-",1); a=int(a); b=int(b)
            vals.update(range(a, b+1, step)); continue
        vals.add(int(part))
    return sorted(v for v in vals if min_v <= v <= max_v)
def _next_runs(expr, count, loc_offset_hours=8):
    parts=expr.split()
    if len(parts)!=5: raise ValueError("需要标准 5 段 cron: m h dom mon dow")
    minutes=_parse_field(parts[0],0,59); hours=_parse_field(parts[1],0,23)
    doms=_parse_field(parts[2],1,31); months=_parse_field(parts[3],1,12); dows=_parse_field(parts[4],0,6)
    # naive UTC+offset search
    now=datetime.now(timezone.utc)+timedelta(hours=loc_offset_hours)
    t=now.replace(second=0, microsecond=0)+timedelta(minutes=1)
    out=[]; guard=0
    while len(out)<count and guard<400000:
        guard+=1
        if t.month in months and t.day in doms and t.hour in hours and t.minute in minutes and ((t.weekday()+1)%7) in dows:
            out.append(t.strftime("%Y-%m-%d %H:%M:%S"))
            t+=timedelta(minutes=1); continue
        t+=timedelta(minutes=1)
    return out
def handle_action(action, inp, cfg, host):
    if action!="next_runs": raise ValueError("unknown action")
    expr=str(inp.get("expression") or "").strip()
    if not expr: raise ValueError("Cron 表达式不能为空")
    count=min(20, max(1, as_int(inp.get("count"),5) or 5))
    tz=str(inp.get("timezone") or "Asia/Shanghai")
    # fixed offset map common
    off=8 if "Shanghai" in tz or "Beijing" in tz or tz=="CST" else 0
    runs=_next_runs(expr, count, off)
    log("info","cron-helper","cron next runs calculated",{"expression":expr,"count":count})
    return {"expression":expr,"timezone":tz,"next_runs":runs}


if __name__ == "__main__":
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PTP_PLUGIN_PORT","19090"))), Handler).serve_forever()
