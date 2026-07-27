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



MIWIFI_KEY="a2ffa5c9be07488bbb04a3a47d3c5f6a"
_sessions={}
def _base(cfg):
    u=str(cfg.get("router_url") or "http://192.168.31.1").strip().rstrip("/")
    if not re.match(r"^https?://", u, re.I): u="http://"+u
    return u
def _login(cfg):
    base=_base(cfg); password=str(cfg.get("password") or ""); timeout=as_int(cfg.get("timeout_seconds"),10) or 10
    if not password: raise ValueError("未配置登录密码")
    init=http_json(base+"/cgi-bin/luci/api/xqsystem/init_info", timeout=timeout)
    device_id=str(init.get("deviceId") or init.get("id") or "0"*16)
    import random
    nonce=f"0_{device_id}_{int(time.time())}_{random.randint(1000,9999)}"
    acc=hashlib.sha1((password+MIWIFI_KEY).encode()).hexdigest()
    pwd=hashlib.sha1((nonce+acc).encode()).hexdigest()
    data=http_json(base+"/cgi-bin/luci/api/xqsystem/login", headers={}, timeout=timeout)
    # login via query
    q=urllib.parse.urlencode({"username":"admin","password":pwd,"logtype":2,"nonce":nonce})
    data=http_json(base+"/cgi-bin/luci/api/xqsystem/login?"+q, timeout=timeout)
    if data.get("code") not in (0,"0"): raise RuntimeError(f"登录失败: {data}")
    stok=data.get("token") or data.get("stok")
    if not stok: raise RuntimeError("无 stok")
    _sessions[base]=stok; return base, stok, timeout
def _api(base, stok, path, params=None, timeout=10):
    url=f"{base}/cgi-bin/luci/;stok={stok}{path}"
    if params: url += ("&" if "?" in url else "?")+urllib.parse.urlencode(params)
    return http_json(url, timeout=timeout)
def handle_event(event_type, data, cfg):
    return
def handle_action(action, inp, cfg, host):
    base, stok, timeout=_login(cfg)
    if action=="status":
        st=_api(base, stok, "/api/misystem/status", timeout=timeout)
        devs=_api(base, stok, "/api/misystem/devicelist", timeout=timeout)
        return {"status":st, "devices": (devs.get("list") if isinstance(devs,dict) else devs)}
    if action=="port_list":
        return _api(base, stok, "/api/xqnetwork/portforward", timeout=timeout)
    if action=="port_add":
        params={"name":inp.get("name") or "ptp","protocol":inp.get("proto") or inp.get("protocol") or "tcp","ip":inp.get("ip"),"sport":inp.get("sport"),"dport":inp.get("dport")}
        return _api(base, stok, "/api/xqnetwork/add_redirect", params=params, timeout=timeout)
    if action=="port_delete":
        port=inp.get("port") or inp.get("sport")
        raw=_api(base, stok, "/api/xqnetwork/portforward", timeout=timeout)
        rules=raw.get("list") if isinstance(raw,dict) else raw
        target=None
        for r in rules or []:
            if str(r.get("sport") or r.get("src_port"))==str(port): target=r; break
        if not target: raise ValueError("未找到端口映射")
        params={"fwid": target.get("fwid") or target.get("id"), "name": target.get("name"), "sport": port}
        params={k:v for k,v in params.items() if v is not None}
        try: return _api(base, stok, "/api/xqnetwork/delete_redirect", params=params, timeout=timeout)
        except Exception: return _api(base, stok, "/api/xqnetwork/remove_redirect", params=params, timeout=timeout)
    if action=="quick_toggle":
        name=str(cfg.get("quick_name") or "ptp-quick"); sport=as_int(cfg.get("quick_sport"),8000)
        raw=_api(base, stok, "/api/xqnetwork/portforward", timeout=timeout)
        rules=raw.get("list") if isinstance(raw,dict) else raw
        exist=None
        for r in rules or []:
            if str(r.get("name"))==name or str(r.get("sport"))==str(sport): exist=r; break
        if exist:
            return handle_action("port_delete", {"port": exist.get("sport") or sport}, cfg, host)
        return handle_action("port_add", {"name":name,"proto":cfg.get("quick_proto") or "tcp","sport":sport,"ip":cfg.get("quick_ip"),"dport":cfg.get("quick_dport") or sport}, cfg, host)
    raise ValueError("unknown action")


if __name__ == "__main__":
    from http.server import ThreadingHTTPServer
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PTP_PLUGIN_PORT","19090"))), Handler).serve_forever()
