# -*- coding: utf-8 -*-
"""小米路由器助手 — 通过 Luci Web API 连接并配置小米/红米路由器。

兼容经典后台 (/cgi-bin/luci/;stok=.../api/...)。
各 API 多路径回退；单点失败不拖垮整体。
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence

PLUGIN_TOKEN = os.environ.get("PTP_PLUGIN_TOKEN", "")
HOST_URL = os.environ.get("PTP_HOST_URL", "")
HOST_TOKEN = os.environ.get("PTP_HOST_TOKEN", "")
MIWIFI_KEY = "a2ffa5c9be07488bbb04a3a47d3c5f6a"

# 机型档案：hardware 字段（init_info.hardware）-> 展示与能力提示
# AX9000 公开 hardware 多为 ra81
MODEL_PROFILES = {
    "ra81": {
        "model": "Xiaomi AX9000",
        "bands": ["2.4G", "5G-1", "5G-2"],
        "wifi_index_map": {1: "2.4G", 2: "5G-1", 3: "5G-2", 4: "访客"},
        "notes": "三频 AX9000；经典 Luci API；端口映射走 xqnetwork redirect",
        "series": "ax",
    },
    "ra70": {
        "model": "Xiaomi AX1800 / 类似 AX 系列",
        "bands": ["2.4G", "5G"],
        "wifi_index_map": {1: "2.4G", 2: "5G", 3: "访客"},
        "series": "ax",
    },
    "ra80": {
        "model": "Xiaomi AX6000",
        "bands": ["2.4G", "5G"],
        "wifi_index_map": {1: "2.4G", 2: "5G", 3: "访客"},
        "series": "ax",
    },
    "ra82": {
        "model": "Redmi AX6000",
        "bands": ["2.4G", "5G"],
        "wifi_index_map": {1: "2.4G", 2: "5G", 3: "访客"},
        "series": "ax",
    },
}


def detect_profile(hardware: str, rom: str = "", raw_init: dict | None = None) -> dict:
    hw = str(hardware or "").strip().lower()
    rom_s = str(rom or "").lower()
    init = raw_init or {}
    # direct hardware match
    if hw in MODEL_PROFILES:
        prof = dict(MODEL_PROFILES[hw])
        prof["hardware"] = hw
        return prof
    # fuzzy
    blob = " ".join([
        hw,
        str(init.get("hardware") or ""),
        str(init.get("model") or ""),
        str(init.get("routername") or ""),
        rom_s,
    ]).lower()
    if "ax9000" in blob or "ra81" in blob:
        prof = dict(MODEL_PROFILES["ra81"])
        prof["hardware"] = hw or "ra81"
        return prof
    if "ax6000" in blob or hw in ("ra80", "ra82"):
        key = hw if hw in MODEL_PROFILES else "ra80"
        prof = dict(MODEL_PROFILES[key])
        prof["hardware"] = hw or key
        return prof
    # generic AX tri/dual
    if "ax" in blob:
        return {
            "model": f"Xiaomi AX series ({hw or 'unknown'})",
            "hardware": hw,
            "bands": ["2.4G", "5G"],
            "wifi_index_map": {1: "2.4G", 2: "5G", 3: "访客"},
            "series": "ax",
            "notes": "通用 AX 档案",
        }
    return {
        "model": hw or "Xiaomi Router",
        "hardware": hw,
        "bands": ["2.4G", "5G"],
        "wifi_index_map": {1: "2.4G", 2: "5G", 3: "访客"},
        "series": "classic",
    }


_session_lock = threading.Lock()
_sessions: Dict[str, Dict[str, Any]] = {}
_watch_prev: Dict[str, bool] = {}
_watch_lock = threading.Lock()


def host_call(path: str, body: dict):
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


def log(level: str, event: str, message: str, data=None):
    host_call("/log", {"level": level, "event": event, "message": message, "data": data or {}})


def notice(title: str, body: str, level: str = "info"):
    host_call("/notice", {"title": title, "body": body, "level": level})


def _as_bool(v, default=False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y")


def _as_int(v, default=0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def normalize_base(url: str) -> str:
    u = (url or "").strip().rstrip("/")
    if not u:
        return "http://192.168.31.1"
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u.rstrip("/")


def normalize_mac(mac: str) -> str:
    m = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(m) != 12:
        return (mac or "").strip().lower()
    return ":".join(m[i:i + 2] for i in range(0, 12, 2)).lower()


def parse_extra_routers(text: str) -> List[dict]:
    out = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [x.strip() for x in line.split("#")]
        if len(parts) >= 3 and parts[0] and parts[1]:
            out.append({
                "name": parts[0],
                "base_url": normalize_base(parts[1]),
                "password": parts[2],
                "username": parts[3] if len(parts) >= 4 and parts[3] else "admin",
            })
    return out


def primary_router(cfg: dict) -> dict:
    return {
        "name": "主路由",
        "base_url": normalize_base(cfg.get("base_url") or "http://192.168.31.1"),
        "username": (cfg.get("username") or "admin").strip() or "admin",
        "password": cfg.get("password") or "",
    }


def all_routers(cfg: dict) -> List[dict]:
    items = [primary_router(cfg)]
    seen = {items[0]["base_url"]}
    for ex in parse_extra_routers(cfg.get("extra_routers") or ""):
        if ex["base_url"] not in seen:
            items.append(ex)
            seen.add(ex["base_url"])
    return items


def pick_router(cfg: dict, inp: dict) -> dict:
    name = (inp or {}).get("name")
    if name:
        for r in all_routers(cfg):
            if r["name"] == name:
                return r
    return primary_router(cfg)


def password_fp(password: str) -> str:
    return hashlib.sha256((password or "").encode("utf-8")).hexdigest()[:16]


class MiWifiError(RuntimeError):
    def __init__(self, message: str, code=None, payload=None):
        super().__init__(message)
        self.code = code
        self.payload = payload


def http_json(url: str, *, method: str = "GET", params=None, form=None, timeout: float = 8.0, headers=None):
    full = url
    data = None
    req_headers = {"User-Agent": "PTPatronus-miwifi/0.2.2", "Accept": "application/json,text/plain,*/*"}
    if headers:
        req_headers.update(headers)
    if params:
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        full = url + ("&" if "?" in url else "?") + q
    if form is not None:
        data = urllib.parse.urlencode({k: v for k, v in form.items() if v is not None}).encode("utf-8")
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        method = method or "POST"
    req = urllib.request.Request(full, data=data, headers=req_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            raw = res.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise MiWifiError(f"HTTP {exc.code}: {raw[:200]}", code=exc.code) from exc
    except Exception as exc:
        raise MiWifiError(f"请求失败: {exc}") from exc
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw[0] in "{[":
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    m = re.search(r"(\{.*\}|\[.*\])", raw, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    raise MiWifiError(f"无法解析响应: {raw[:180]}")


class MiWifiClient:
    def __init__(self, base_url: str, password: str, username: str = "admin", timeout: float = 8.0):
        self.base_url = normalize_base(base_url)
        self.password = password or ""
        self.username = username or "admin"
        self.timeout = float(timeout or 8)
        self.stok = ""
        self.device_id = ""
        self.hardware = ""
        self.rom = ""
        self.profile = detect_profile("", "")

    def _api(self, path: str) -> str:
        path = path if path.startswith("/") else "/" + path
        if not self.stok:
            raise MiWifiError("未登录")
        return f"{self.base_url}/cgi-bin/luci/;stok={self.stok}{path}"

    def request(self, path: str, *, method: str = "GET", params=None, form=None, retry_login: bool = True):
        url = self._api(path)
        try:
            data = http_json(url, method=method, params=params, form=form, timeout=self.timeout)
        except MiWifiError as exc:
            if retry_login and (exc.code in (401, 403) or "stok" in str(exc).lower()):
                self.login(force=True)
                return self.request(path, method=method, params=params, form=form, retry_login=False)
            raise
        if isinstance(data, dict):
            code = data.get("code")
            if code not in (None, 0, "0"):
                if retry_login and str(code) in ("401", "403", "1501", "1502"):
                    self.login(force=True)
                    return self.request(path, method=method, params=params, form=form, retry_login=False)
                msg = data.get("msg") or data.get("message") or f"路由器返回 code={code}"
                raise MiWifiError(str(msg), code=code, payload=data)
        return data

    def try_paths(self, paths: Sequence[str], *, method: str = "GET", params=None, form=None):
        errors = []
        for path in paths:
            try:
                return self.request(path, method=method, params=params, form=form)
            except Exception as exc:
                errors.append(f"{method} {path}: {exc}")
        # also try POST form for write-like calls
        if method.upper() == "GET" and (params or form):
            body = form if form is not None else params
            for path in paths:
                try:
                    return self.request(path, method="POST", form=body)
                except Exception as exc:
                    errors.append(f"POST {path}: {exc}")
        raise MiWifiError("接口不可用: " + "; ".join(errors[:6]))

    def init_info(self) -> dict:
        url = f"{self.base_url}/cgi-bin/luci/api/xqsystem/init_info"
        data = http_json(url, timeout=self.timeout)
        if not isinstance(data, dict):
            raise MiWifiError("init_info 响应异常")
        self.device_id = str(data.get("deviceId") or data.get("id") or self.device_id or "")
        self.hardware = str(data.get("hardware") or data.get("model") or self.hardware or "")
        self.rom = str(data.get("romversion") or data.get("version") or self.rom or "")
        if not self.device_id:
            self.device_id = self._scrape_device_id()
        self.profile = detect_profile(self.hardware, self.rom, data)
        return data

    def _scrape_device_id(self) -> str:
        try:
            req = urllib.request.Request(self.base_url + "/", headers={"User-Agent": "PTPatronus-miwifi/0.2.2"})
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                html = res.read().decode("utf-8", errors="replace")
            for pat in (
                r"deviceId\s*[:=]\s*['\"]([0-9a-fA-F]+)['\"]",
                r'name="deviceId"\s+value="([^"]+)"',
                r"deviceId=([0-9a-fA-F]+)",
            ):
                m = re.search(pat, html)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return ""

    def login(self, force: bool = False) -> dict:
        if not self.password:
            raise MiWifiError("未配置管理密码")
        fp = password_fp(self.password)
        with _session_lock:
            cached = _sessions.get(self.base_url)
            if (
                not force and cached and cached.get("password_fp") == fp and cached.get("stok")
                and (time.time() - float(cached.get("ts") or 0)) < 3600
            ):
                self.stok = cached["stok"]
                self.device_id = cached.get("device_id") or self.device_id
                return {"code": 0, "stok": self.stok, "cached": True}
        info = self.init_info()
        device_id = self.device_id or str(info.get("deviceId") or "") or ("0" * 16)
        nonce = f"0_{device_id}_{int(time.time())}_{random.randint(1000, 9999)}"
        account_str = hashlib.sha1((self.password + MIWIFI_KEY).encode("utf-8")).hexdigest()
        password_hash = hashlib.sha1((nonce + account_str).encode("utf-8")).hexdigest()
        data = http_json(
            f"{self.base_url}/cgi-bin/luci/api/xqsystem/login",
            params={"username": self.username, "password": password_hash, "logtype": 2, "nonce": nonce},
            timeout=self.timeout,
        )
        if not isinstance(data, dict):
            raise MiWifiError("登录响应异常")
        if data.get("code") not in (0, "0"):
            msg = data.get("msg") or data.get("message") or "登录失败"
            raise MiWifiError(f"登录失败: {msg}", code=data.get("code"), payload=data)
        stok = data.get("token") or data.get("stok") or ""
        if not stok:
            raise MiWifiError("登录成功但未返回 stok", payload=data)
        self.stok = str(stok)
        with _session_lock:
            _sessions[self.base_url] = {"stok": self.stok, "device_id": device_id, "password_fp": fp, "ts": time.time()}
        return {"code": 0, "stok": self.stok, "deviceId": device_id, "cached": False}

    def ensure_login(self):
        if not self.stok:
            self.login()

    # ---- APIs ----
    def status(self) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/misystem/status", "/api/xqsystem/status", "/api/misystem/new_status"])

    def device_list(self) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/misystem/devicelist", "/api/xqsystem/device_list", "/api/misystem/device_list"])

    def wifi_detail_all(self) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/xqnetwork/wifi_detail_all", "/api/xqnetwork/wifi_detail", "/api/misystem/wifi_detail"])

    def set_wifi(self, params: dict) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/xqnetwork/set_wifi", "/api/xqnetwork/wifi_set"], params=params)

    def wan_info(self) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/xqnetwork/wan_info", "/api/misystem/wan_info", "/api/xqsystem/wan_info"])

    def lan_info(self) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqnetwork/lan_info", "/api/xqnetwork/lan_dhcp", "/api/misystem/lan_info",
            "/api/xqsystem/lan_wan", "/api/xqnetwork/dhcp_info",
        ])

    def dhcp_set(self, params: dict) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqnetwork/set_lan_dhcp", "/api/xqnetwork/set_dhcp", "/api/xqnetwork/dhcp_set",
            "/api/misystem/set_lan_dhcp",
        ], params=params)

    def dns_info(self) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqnetwork/dns_info", "/api/xqsystem/dns_info", "/api/xqnetwork/wan_dns",
            "/api/misystem/dns_info",
        ])

    def dns_set(self, params: dict) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqnetwork/set_dns", "/api/xqsystem/set_dns", "/api/xqnetwork/set_wan_dns",
            "/api/misystem/set_dns",
        ], params=params)

    def mac_filter_info(self) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/xqnetwork/wifi_macfilter_info", "/api/xqnetwork/macfilter_info"])

    def set_mac_filter(self, params: dict) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/xqnetwork/set_wifi_macfilter", "/api/xqnetwork/set_macfilter"], params=params)

    def set_device_authority(self, mac: str, authority: dict) -> dict:
        self.ensure_login()
        params = {"mac": normalize_mac(mac)}
        for k in ("wan", "lan", "admin", "pridisk"):
            if k in authority and authority[k] is not None:
                params[k] = _as_int(authority[k])
        return self.try_paths([
            "/api/xqsystem/set_device_authority", "/api/misystem/set_device_authority",
            "/api/xqsystem/device_list_set",
        ], params=params)

    def set_device_nickname(self, mac: str, nickname: str) -> dict:
        self.ensure_login()
        params = {"mac": normalize_mac(mac), "name": nickname, "nickname": nickname}
        return self.try_paths([
            "/api/xqsystem/set_device_nickname", "/api/misystem/set_device_nickname",
            "/api/xqsystem/mod_device_name", "/api/misystem/mod_device",
        ], params=params)

    def set_mac_limit(self, mac: str, maxdownload: int, maxupload: int) -> dict:
        self.ensure_login()
        params = {
            "mac": normalize_mac(mac),
            "maxdownload": _as_int(maxdownload, 0),
            "maxupload": _as_int(maxupload, 0),
            "download": _as_int(maxdownload, 0),
            "upload": _as_int(maxupload, 0),
        }
        return self.try_paths([
            "/api/misystem/set_mac_limit", "/api/xqsystem/set_mac_limit",
            "/api/misystem/qos_mac_limit", "/api/xqsystem/qos_mac_limit",
        ], params=params)

    def mesh_info(self) -> dict:
        """AX/Mesh 拓扑与子节点（AX9000 常见）。"""
        self.ensure_login()
        return self.try_paths([
            "/api/misystem/topo",
            "/api/xqsystem/multi_ap_list",
            "/api/xqsystem/slave_list",
            "/api/misystem/slave_list",
            "/api/xqsystem/mesh_info",
            "/api/misystem/mesh_info",
        ])

    def wifi_txpwr_channels(self) -> dict:
        """信道/功率辅助信息（部分 AX 固件提供）。"""
        self.ensure_login()
        return self.try_paths([
            "/api/xqnetwork/wifi_txpwr_channels",
            "/api/xqnetwork/wifi_channel_list",
            "/api/xqnetwork/wifi_diag",
        ])

    def portforward_list(self) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqnetwork/portforward",
            "/api/xqnetwork/portforward_list",
            "/api/xqnetwork/redirect_list",
            "/api/misystem/portforward",
            "/api/xqsystem/portforward",
        ])

    def _proto_value(self, protocol):
        p = str(protocol or "tcp").strip().lower()
        mapping = {
            "tcp": "tcp",
            "udp": "udp",
            "both": "tcp+udp",
            "tcp+udp": "tcp+udp",
            "tcpudp": "tcp+udp",
            "1": "tcp",
            "2": "udp",
            "3": "tcp+udp",
        }
        return mapping.get(p, p or "tcp")

    def _proto_code(self, protocol):
        p = self._proto_value(protocol)
        return {"tcp": 1, "udp": 2, "tcp+udp": 3}.get(p, 1)

    def portforward_add(self, rule: dict) -> dict:
        self.ensure_login()
        name = str(rule.get("name") or "ptp").strip() or "ptp"
        ip = rule.get("ip") or rule.get("dest_ip") or rule.get("lan_ip")
        sport = rule.get("sport") or rule.get("src_port") or rule.get("external_port") or rule.get("wan_port")
        dport = rule.get("dport") or rule.get("dest_port") or rule.get("internal_port") or rule.get("lan_port") or sport
        if not ip:
            raise MiWifiError("端口映射需要目标 IP（input.ip）")
        if sport is None or str(sport).strip() == "":
            raise MiWifiError("端口映射需要外部端口（input.sport / external_port）")
        protocol = self._proto_value(rule.get("protocol") or rule.get("proto") or "tcp")
        enable = 1 if rule.get("enable") is None else _as_int(rule.get("enable"), 1)
        params = {
            "name": name,
            "protocol": protocol,
            "proto": self._proto_code(protocol),
            "ip": ip,
            "sport": sport,
            "dport": dport,
            "fstatus": enable,
            "status": enable,
        }
        if rule.get("sport_end") is not None:
            params["sport"] = f"{sport}-{rule.get('sport_end')}"
        if rule.get("dport_end") is not None:
            params["dport"] = f"{dport}-{rule.get('dport_end')}"
        return self.try_paths([
            "/api/xqnetwork/add_redirect",
            "/api/xqnetwork/portforward_add",
            "/api/xqnetwork/add_portforward",
            "/api/misystem/add_redirect",
            "/api/xqnetwork/portforward",
        ], params=params)

    def portforward_delete(self, rule: dict) -> dict:
        self.ensure_login()
        params = {}
        for k in ("fwid", "id", "name", "ip", "sport", "dport", "protocol", "proto"):
            if rule.get(k) is not None and rule.get(k) != "":
                params[k] = rule[k]
        if "src_port" in rule and "sport" not in params:
            params["sport"] = rule["src_port"]
        if "dest_port" in rule and "dport" not in params:
            params["dport"] = rule["dest_port"]
        if not params:
            raise MiWifiError("删除端口映射需要 fwid/name/ip+sport 等标识")
        return self.try_paths([
            "/api/xqnetwork/delete_redirect",
            "/api/xqnetwork/remove_redirect",
            "/api/xqnetwork/del_redirect",
            "/api/xqnetwork/portforward_delete",
            "/api/misystem/delete_redirect",
        ], params=params)

    def portforward_toggle(self, rule: dict) -> dict:
        self.ensure_login()
        params = {}
        for k in ("fwid", "id", "name", "ip", "sport", "dport"):
            if rule.get(k) is not None and rule.get(k) != "":
                params[k] = rule[k]
        if rule.get("enable") is None and rule.get("fstatus") is None:
            raise MiWifiError("需要 input.enable=0/1")
        enable = _as_int(rule.get("enable") if rule.get("enable") is not None else rule.get("fstatus"), 1)
        params["fstatus"] = enable
        params["status"] = enable
        return self.try_paths([
            "/api/xqnetwork/redirect_status",
            "/api/xqnetwork/set_redirect",
            "/api/xqnetwork/mod_redirect",
            "/api/xqnetwork/portforward_set",
            "/api/misystem/set_redirect",
        ], params=params)

    def time_info(self) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqsystem/sys_time", "/api/misystem/sys_time", "/api/xqsystem/get_time",
            "/api/misystem/time",
        ])

    def time_set(self, params: dict) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqsystem/set_sys_time", "/api/xqsystem/set_time", "/api/misystem/set_sys_time",
            "/api/xqsystem/sys_time",
        ], params=params)

    def netdetect(self) -> dict:
        self.ensure_login()
        return self.try_paths([
            "/api/xqnetdetect/netspeed", "/api/misystem/netdetect", "/api/xqsystem/netdetect",
            "/api/misystem/bandwidth_test", "/api/xqsystem/fac_info",
        ])

    def reboot(self) -> dict:
        self.ensure_login()
        try:
            return self.request("/api/xqsystem/reboot", params={"client": "web"})
        except Exception:
            return self.try_paths(["/api/xqsystem/reboot", "/api/misystem/reboot"])

    def router_name_get(self) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/xqsystem/router_name", "/api/misystem/router_name"])

    def router_name_set(self, name: str) -> dict:
        self.ensure_login()
        return self.try_paths(["/api/xqsystem/set_router_name", "/api/misystem/set_router_name"], params={"name": name})


def client_from_router(router: dict, cfg: dict) -> MiWifiClient:
    return MiWifiClient(
        base_url=router["base_url"],
        password=router.get("password") or "",
        username=router.get("username") or "admin",
        timeout=_as_int(cfg.get("timeout"), 8) or 8,
    )

def summarize_status(raw):
    mem = raw.get("mem") or {}
    cpu = raw.get("cpu") or {}
    wan = raw.get("wan") or {}
    count = raw.get("count") or {}
    hardware = raw.get("hardware") or {}
    temp = raw.get("temperature") or raw.get("temp") or hardware.get("temperature")
    load = cpu.get("load")
    cpu_load = load[0] if isinstance(load, list) and load else (cpu.get("load") or cpu.get("core"))
    wan_info = wan.get("info") if isinstance(wan.get("info"), dict) else {}
    return {
        "uptime": raw.get("upTime") or raw.get("uptime"),
        "cpu_load": cpu_load,
        "cpu_cores": cpu.get("core"),
        "cpu_hz": cpu.get("hz"),
        "mem_usage": mem.get("usage"),
        "mem_total": mem.get("total"),
        "online": count.get("online"),
        "all_devices": count.get("all"),
        "temperature": temp,
        "wan_name": wan.get("name") or wan.get("devname"),
        "wan_ip": wan_info.get("ip") if wan_info else wan.get("ip"),
        "hardware": hardware.get("mac") or hardware.get("platform"),
        "raw": raw,
    }


def summarize_devices(raw, online_only=False):
    items = raw.get("list") or raw.get("devices") or raw.get("dev") or []
    out = []
    for d in items:
        if not isinstance(d, dict):
            continue
        online = d.get("online")
        is_online = online in (1, "1", True, "true", "online")
        if online_only and not is_online:
            continue
        stats = d.get("statistics") or {}
        auth = d.get("authority") or {}
        out.append({
            "name": d.get("name") or d.get("dname") or d.get("hostname") or "",
            "mac": normalize_mac(str(d.get("mac") or "")),
            "ip": d.get("ip") or "",
            "online": is_online,
            "type": d.get("type") or d.get("dtype"),
            "company": d.get("company") or d.get("org") or "",
            "upspeed": stats.get("upspeed") or d.get("upspeed"),
            "downspeed": stats.get("downspeed") or d.get("downspeed"),
            "online_time": d.get("online_time") or d.get("onlineTime"),
            "authority": {"wan": auth.get("wan"), "lan": auth.get("lan"), "admin": auth.get("admin"), "pridisk": auth.get("pridisk")},
            "raw": d,
        })
    out.sort(key=lambda x: (not x["online"], x["name"] or x["mac"]))
    return out


def summarize_wifi(raw, profile=None):
    info = raw.get("info") if isinstance(raw.get("info"), list) else (raw.get("list") or [])
    index_map = (profile or {}).get("wifi_index_map") or {1: "2.4G", 2: "5G", 3: "访客"}
    out = []
    if isinstance(info, list):
        for idx, w in enumerate(info, 1):
            if not isinstance(w, dict):
                continue
            status = w.get("status") if isinstance(w.get("status"), dict) else w
            on = status.get("up") if "up" in status else status.get("on")
            if on is None:
                on = w.get("on")
            index = w.get("wifiIndex") or w.get("index") or idx
            try:
                index_i = int(index)
            except Exception:
                index_i = idx
            band = (
                w.get("band")
                or status.get("band")
                or index_map.get(index_i)
                or index_map.get(str(index_i))
                or f"#{index}"
            )
            # AX9000 / tri-band heuristics from ifname
            ifname = str(w.get("ifname") or status.get("ifname") or "")
            if not w.get("band") and ifname:
                if "wl2" in ifname or "5g1" in ifname.lower():
                    band = "5G-1"
                elif "wl1" in ifname or ifname.endswith("5g") or "5g2" in ifname.lower():
                    # keep map preferred; only override vague labels
                    if band in ("5G", f"#{index}"):
                        band = "5G"
                elif "wl0" in ifname or "2g" in ifname.lower():
                    band = "2.4G"
            out.append({
                "index": index,
                "band": band,
                "ifname": w.get("ifname") or status.get("ifname"),
                "ssid": status.get("ssid") or w.get("ssid"),
                "password": status.get("password") or status.get("pwd") or w.get("password"),
                "on": on,
                "channel": status.get("channel") or w.get("channel"),
                "bandwidth": status.get("bandwidth") or w.get("bandwidth"),
                "encryption": status.get("encryption") or w.get("encryption"),
                "hidden": status.get("hidden") or w.get("hidden"),
                "mode": status.get("mode") or w.get("mode"),
                "txpwr": status.get("txpwr") or w.get("txpwr"),
                "raw": w,
            })
    return out


def summarize_lan(raw):
    info = raw.get("info") if isinstance(raw.get("info"), dict) else raw
    dhcp = info.get("dhcp") if isinstance(info.get("dhcp"), dict) else (raw.get("dhcp") or {})
    return {
        "ip": info.get("ip") or info.get("lanIp") or info.get("ipv4") or raw.get("ip"),
        "mask": info.get("mask") or info.get("netmask"),
        "dhcp_enabled": dhcp.get("enabled") if "enabled" in dhcp else info.get("dhcpEnabled") or raw.get("dhcpEnabled"),
        "start": dhcp.get("start") or info.get("start") or raw.get("start"),
        "end": dhcp.get("end") or info.get("end") or raw.get("end"),
        "leasetime": dhcp.get("leasetime") or info.get("leasetime") or raw.get("leasetime"),
        "gateway": info.get("gateway") or raw.get("gateway"),
        "raw": raw,
    }


def summarize_port_rules(raw):
    """Normalize heterogeneous port-forward payloads into a stable list."""
    if raw is None:
        return []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = (
            raw.get("list")
            or raw.get("rules")
            or raw.get("redirect")
            or raw.get("redirects")
            or raw.get("portforward")
            or raw.get("data")
            or []
        )
        if isinstance(items, dict):
            # some firmwares nest again
            items = items.get("list") or items.get("rules") or []
    else:
        items = []
    out = []
    for i, r in enumerate(items):
        if not isinstance(r, dict):
            continue
        proto = r.get("protocol") or r.get("proto") or r.get("type") or ""
        if str(proto) in ("1", "tcp"):
            proto = "tcp"
        elif str(proto) in ("2", "udp"):
            proto = "udp"
        elif str(proto) in ("3", "tcp+udp", "both"):
            proto = "tcp+udp"
        enable = r.get("fstatus")
        if enable is None:
            enable = r.get("status")
        if enable is None:
            enable = r.get("enable")
        if enable is None:
            enabled = True
        else:
            enabled = str(enable).strip().lower() not in ("0", "false", "off", "disable", "disabled")
        out.append({
            "fwid": r.get("fwid") or r.get("id") or r.get("uid") or i,
            "name": r.get("name") or r.get("desc") or r.get("comment") or "",
            "ip": r.get("ip") or r.get("destip") or r.get("dest_ip") or r.get("lan_ip") or "",
            "sport": r.get("sport") or r.get("src_port") or r.get("external_port") or r.get("from") or "",
            "dport": r.get("dport") or r.get("dest_port") or r.get("internal_port") or r.get("to") or "",
            "protocol": proto,
            "enable": enabled,
            "raw": r,
        })
    return out


def _watch_devices(cfg, router, devices):
    if not _as_bool(cfg.get("notify_offline"), False):
        return
    watch = [normalize_mac(x) for x in str(cfg.get("watch_macs") or "").splitlines() if x.strip()]
    online_map = {d["mac"]: d["online"] for d in devices if d.get("mac")}
    with _watch_lock:
        for mac in watch:
            now_online = bool(online_map.get(mac, False))
            prev = _watch_prev.get(mac)
            _watch_prev[mac] = now_online
            if prev is True and not now_online:
                notice("小米路由：设备离线", f"{mac} 已离线（{router['name']}）", level="warning")
                log("warning", "miwifi.device_offline", f"{mac} offline", {"mac": mac, "router": router["name"]})
            elif prev is False and now_online:
                notice("小米路由：设备上线", f"{mac} 已上线（{router['name']}）", level="info")


def action_ping(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    info = c.init_info()
    login = c.login(force=True)
    prof = c.profile or detect_profile(c.hardware, c.rom, info)
    return {
        "ok": True,
        "router": router["name"],
        "base_url": router["base_url"],
        "hardware": c.hardware or info.get("hardware"),
        "rom": c.rom or info.get("romversion"),
        "deviceId": c.device_id,
        "model": prof.get("model"),
        "profile": {
            "model": prof.get("model"),
            "hardware": prof.get("hardware"),
            "bands": prof.get("bands"),
            "wifi_index_map": prof.get("wifi_index_map"),
            "series": prof.get("series"),
            "notes": prof.get("notes"),
        },
        "login_cached": bool(login.get("cached")),
        "init": {k: info.get(k) for k in ("hardware", "romversion", "countrycode", "routername", "id", "deviceId") if k in info},
        "ax9000": (str(prof.get("hardware") or "").lower() == "ra81") or ("AX9000" in str(prof.get("model") or "")),
    }


def action_status(cfg, inp):
    results = []
    targets = all_routers(cfg)
    if inp.get("name"):
        targets = [r for r in targets if r["name"] == inp["name"]] or targets[:1]
    for r in targets:
        item = {"name": r["name"], "base_url": r["base_url"]}
        try:
            c = client_from_router(r, cfg)
            item.update(summarize_status(c.status()))
            item["status"] = "ok"
        except Exception as exc:
            item["status"] = "error"
            item["error"] = str(exc)
        results.append(item)
    return {"routers": results}


def action_devices(cfg, inp):
    online_only = _as_bool(inp.get("online_only"), False)
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    all_devs = summarize_devices(c.device_list(), online_only=False)
    _watch_devices(cfg, router, all_devs)
    devices = [d for d in all_devs if d["online"]] if online_only else all_devs
    return {
        "router": router["name"],
        "base_url": router["base_url"],
        "count": len(devices),
        "online": sum(1 for d in devices if d["online"]),
        "devices": devices,
    }


def action_device_rename(cfg, inp):
    mac = inp.get("mac")
    nickname = inp.get("nickname") or inp.get("new_name") or inp.get("device_name")
    if not mac or not nickname:
        raise ValueError("需要 input.mac 与 input.nickname")
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    raw = c.set_device_nickname(str(mac), str(nickname))
    return {"ok": True, "mac": normalize_mac(str(mac)), "nickname": str(nickname), "result": raw}


def action_device_limit(cfg, inp):
    mac = inp.get("mac")
    if not mac:
        raise ValueError("需要 input.mac")
    down = _as_int(inp.get("maxdownload") if inp.get("maxdownload") is not None else inp.get("download"), 0)
    up = _as_int(inp.get("maxupload") if inp.get("maxupload") is not None else inp.get("upload"), 0)
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    raw = c.set_mac_limit(str(mac), down, up)
    return {"ok": True, "mac": normalize_mac(str(mac)), "maxdownload": down, "maxupload": up, "result": raw}


def action_wifi_info(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    raw = c.wifi_detail_all()
    prof = c.profile or detect_profile(c.hardware, c.rom)
    return {"router": router["name"], "model": prof.get("model"), "profile": prof, "wifi": summarize_wifi(raw, prof)}


def action_wifi_set(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    wifi_index = _as_int(inp.get("wifi_index") or inp.get("index") or 1, 1)
    params = {"wifiIndex": wifi_index}
    mapping = {
        "ssid": "ssid", "password": "pwd", "pwd": "pwd", "on": "on", "channel": "channel",
        "bandwidth": "bandwidth", "encryption": "encryption", "hidden": "hidden", "txpwr": "txpwr", "mode": "mode",
    }
    for src, dst in mapping.items():
        if src in inp and inp[src] is not None and inp[src] != "":
            params[dst] = inp[src]
    if "on" in params:
        params["on"] = _as_int(params["on"], 1)
    if "hidden" in params:
        params["hidden"] = _as_int(params["hidden"], 0)
    raw = c.set_wifi(params)
    log("info", "miwifi.wifi_set", "wifi updated", {"index": wifi_index, "ssid": params.get("ssid")})
    return {"ok": True, "params": params, "result": raw}

def action_wan_info(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    raw = c.wan_info()
    info = raw.get("info") if isinstance(raw.get("info"), dict) else raw
    summary = {
        "type": info.get("type") or raw.get("type") or info.get("details") or info.get("wanType"),
        "ip": info.get("ip") or info.get("ipv4"),
        "mask": info.get("mask"),
        "gateway": info.get("gateway") or info.get("gw"),
        "dns": info.get("dns") or info.get("dns1"),
        "uptime": info.get("uptime") or info.get("upTime"),
        "link": info.get("link") or info.get("status"),
    }
    return {"router": router["name"], "wan": summary, "raw": raw}


def action_lan_info(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    return {"router": router["name"], "lan": summarize_lan(c.lan_info())}


def action_dhcp_set(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    params = {}
    for k in ("start", "end", "leasetime", "lan_ip", "ip", "netmask", "mask", "enable", "dhcpEnabled"):
        if inp.get(k) is not None and inp.get(k) != "":
            params[k] = inp[k]
    if not params:
        raise ValueError("请至少提供 start/end/leasetime/lan_ip 等 DHCP 字段")
    return {"ok": True, "params": params, "result": c.dhcp_set(params)}


def action_dns_info(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    try:
        raw = c.dns_info()
    except Exception:
        wan = c.wan_info()
        info = wan.get("info") if isinstance(wan.get("info"), dict) else wan
        raw = {"dns1": info.get("dns") or info.get("dns1"), "dns2": info.get("dns2"), "source": "wan_info", "raw": wan}
    return {"router": router["name"], "dns": raw}


def action_dns_set(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    params = {}
    for k in ("dns1", "dns2", "mode", "dnsmode", "dns"):
        if inp.get(k) is not None and inp.get(k) != "":
            params[k] = inp[k]
    if "dns" in params and "dns1" not in params:
        params["dns1"] = params["dns"]
    if not params:
        raise ValueError("请提供 dns1/dns2")
    return {"ok": True, "params": params, "result": c.dns_set(params)}


def action_mac_filter_info(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    return {"router": router["name"], "filter": c.mac_filter_info()}


def action_mac_filter_set(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    params = {}
    if inp.get("model") is not None:
        params["model"] = _as_int(inp.get("model"))
    if inp.get("mac"):
        params["mac"] = normalize_mac(str(inp.get("mac")))
    if inp.get("option") is not None:
        params["option"] = _as_int(inp.get("option"))
    if inp.get("wlan_macfilter") is not None:
        params["wlan_macfilter"] = _as_int(inp.get("wlan_macfilter"))
    if inp.get("name"):
        params["name"] = inp.get("name")
    return {"ok": True, "params": params, "result": c.set_mac_filter(params)}


def action_device_authority(cfg, inp):
    mac = inp.get("mac")
    if not mac:
        raise ValueError("input.mac 必填")
    auth = {"wan": inp.get("wan"), "lan": inp.get("lan"), "admin": inp.get("admin"), "pridisk": inp.get("pridisk")}
    if _as_bool(inp.get("kick"), False):
        auth["wan"] = 0
    if _as_bool(inp.get("allow"), False):
        auth["wan"] = 1
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    raw = c.set_device_authority(str(mac), auth)
    return {"ok": True, "mac": normalize_mac(str(mac)), "authority": auth, "result": raw}


def action_port_forward(cfg, inp):
    op = str((inp.get("op") or "list")).strip().lower()
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    if op in ("list", "ls", "get"):
        raw = c.portforward_list()
        rules = summarize_port_rules(raw)
        return {
            "router": router["name"],
            "base_url": router["base_url"],
            "count": len(rules),
            "rules": rules,
            "raw": raw,
        }
    if op in ("add", "create", "set"):
        # required field checks happen inside client too
        raw = c.portforward_add(inp)
        log("info", "miwifi.port_forward.add", "port mapping added", {
            "name": inp.get("name"),
            "ip": inp.get("ip") or inp.get("dest_ip"),
            "sport": inp.get("sport") or inp.get("external_port"),
            "dport": inp.get("dport") or inp.get("internal_port"),
        })
        # return refreshed list best-effort
        try:
            rules = summarize_port_rules(c.portforward_list())
        except Exception:
            rules = []
        return {"ok": True, "op": "add", "result": raw, "rules": rules}
    if op in ("delete", "del", "remove"):
        raw = c.portforward_delete(inp)
        log("info", "miwifi.port_forward.delete", "port mapping deleted", {
            "fwid": inp.get("fwid") or inp.get("id"),
            "name": inp.get("name"),
        })
        try:
            rules = summarize_port_rules(c.portforward_list())
        except Exception:
            rules = []
        return {"ok": True, "op": "delete", "result": raw, "rules": rules}
    if op in ("enable", "disable", "toggle"):
        if op == "enable":
            inp = dict(inp)
            inp["enable"] = 1
        elif op == "disable":
            inp = dict(inp)
            inp["enable"] = 0
        raw = c.portforward_toggle(inp)
        try:
            rules = summarize_port_rules(c.portforward_list())
        except Exception:
            rules = []
        return {"ok": True, "op": op, "result": raw, "rules": rules}
    raise ValueError("input.op 应为 list|add|delete|enable|disable")



def action_time_info(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    return {"router": router["name"], "time": c.time_info()}


def action_time_set(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    params = {}
    for k in ("timezone", "timeZone", "ntp", "server", "time", "date", "hour", "minute", "second", "year", "month", "day"):
        if inp.get(k) is not None and inp.get(k) != "":
            params[k] = inp[k]
    if not params:
        raise ValueError("请提供 timezone / ntp / time 等字段")
    return {"ok": True, "params": params, "result": c.time_set(params)}


def action_netdetect(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    return {"router": router["name"], "detect": c.netdetect()}


def action_reboot(cfg, inp):
    if not _as_bool(inp.get("confirm"), False):
        raise ValueError("重启需 input.confirm=true，防止误触")
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    raw = c.reboot()
    with _session_lock:
        _sessions.pop(router["base_url"], None)
    notice("小米路由：已下发重启", f"{router['name']} ({router['base_url']})", level="warning")
    log("warning", "miwifi.reboot", "reboot issued", {"router": router["name"], "base_url": router["base_url"]})
    return {"ok": True, "router": router["name"], "result": raw}


def action_router_name(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    rename = inp.get("rename")
    if rename is not None and str(rename).strip() != "":
        return {"ok": True, "name": str(rename).strip(), "result": c.router_name_set(str(rename).strip())}
    return {"router": router["name"], "result": c.router_name_get()}

def action_model(cfg, inp):
    """识别机型档案（AX9000=ra81 等）。"""
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    info = c.init_info()
    c.login()
    prof = c.profile or detect_profile(c.hardware, c.rom, info)
    wifi = []
    try:
        wifi = summarize_wifi(c.wifi_detail_all(), prof)
    except Exception as exc:
        wifi = [{"error": str(exc)}]
    return {
        "router": router["name"],
        "base_url": router["base_url"],
        "hardware": c.hardware,
        "rom": c.rom,
        "deviceId": c.device_id,
        "profile": prof,
        "ax9000": (str(prof.get("hardware") or "").lower() == "ra81") or ("AX9000" in str(prof.get("model") or "")),
        "wifi": wifi,
        "tips": [
            "AX9000 为三频：wifi_index 1=2.4G, 2=5G-1, 3=5G-2",
            "端口映射 add 示例: {op:add, ip:192.168.31.20, sport:2222, dport:22, protocol:tcp}",
            "管理地址通常仍是 http://192.168.31.1",
        ],
    }


def action_mesh(cfg, inp):
    router = pick_router(cfg, inp)
    c = client_from_router(router, cfg)
    raw = c.mesh_info()
    return {"router": router["name"], "model": (c.profile or {}).get("model"), "mesh": raw}


def action_dashboard(cfg, inp):

    routers_out = []
    for r in all_routers(cfg):
        item = {"name": r["name"], "base_url": r["base_url"], "status": "ok"}
        try:
            c = client_from_router(r, cfg)
            c.login()
            item["model"] = (c.profile or {}).get("model")
            item["hardware"] = c.hardware
            item["rom"] = c.rom
            item["profile"] = {
                "model": (c.profile or {}).get("model"),
                "hardware": (c.profile or {}).get("hardware"),
                "bands": (c.profile or {}).get("bands"),
                "wifi_index_map": (c.profile or {}).get("wifi_index_map"),
                "series": (c.profile or {}).get("series"),
            }
            try:
                item["system"] = summarize_status(c.status())
            except Exception as exc:
                item["system_error"] = str(exc)
            try:
                item["devices"] = summarize_devices(c.device_list(), online_only=False)
                item["online"] = sum(1 for d in item["devices"] if d["online"])
            except Exception as exc:
                item["devices_error"] = str(exc)
                item["devices"] = []
                item["online"] = 0
            try:
                item["wifi"] = summarize_wifi(c.wifi_detail_all(), c.profile)
            except Exception as exc:
                item["wifi_error"] = str(exc)
                item["wifi"] = []
            try:
                wan_raw = c.wan_info()
                info = wan_raw.get("info") if isinstance(wan_raw.get("info"), dict) else wan_raw
                item["wan"] = {
                    "ip": info.get("ip") or info.get("ipv4"),
                    "type": info.get("type") or wan_raw.get("type"),
                    "gateway": info.get("gateway") or info.get("gw"),
                    "dns": info.get("dns") or info.get("dns1"),
                }
            except Exception as exc:
                item["wan_error"] = str(exc)
                item["wan"] = {}
            try:
                item["lan"] = summarize_lan(c.lan_info())
            except Exception as exc:
                item["lan_error"] = str(exc)
                item["lan"] = {}
            try:
                item["port_forwards"] = summarize_port_rules(c.portforward_list())
            except Exception as exc:
                item["port_forwards_error"] = str(exc)
                item["port_forwards"] = []
            try:
                item["mesh"] = c.mesh_info()
            except Exception as exc:
                item["mesh_error"] = str(exc)
                item["mesh"] = None
            errs = [k for k in ("system_error", "devices_error", "wifi_error") if item.get(k)]
            if item.get("system_error") and item.get("devices_error"):
                item["status"] = "error"
            elif errs:
                item["status"] = "degraded"
        except Exception as exc:
            item["status"] = "error"
            item["error"] = str(exc)
        routers_out.append(item)
    return {"routers": routers_out, "ts": int(time.time())}


def handle_action(action, inp, cfg, host):
    inp = inp or {}
    cfg = cfg or {}
    handlers = {
        "ping": action_ping,
        "model": action_model,
        "mesh": action_mesh,
        "status": action_status,
        "devices": action_devices,
        "device_rename": action_device_rename,
        "device_limit": action_device_limit,
        "wifi_info": action_wifi_info,
        "wifi_set": action_wifi_set,
        "wan_info": action_wan_info,
        "lan_info": action_lan_info,
        "dhcp_set": action_dhcp_set,
        "dns_info": action_dns_info,
        "dns_set": action_dns_set,
        "mac_filter_info": action_mac_filter_info,
        "mac_filter_set": action_mac_filter_set,
        "device_authority": action_device_authority,
        "port_forward": action_port_forward,
        "time_info": action_time_info,
        "time_set": action_time_set,
        "netdetect": action_netdetect,
        "reboot": action_reboot,
        "router_name": action_router_name,
        "dashboard": action_dashboard,
    }
    fn = handlers.get(action)
    if not fn:
        raise ValueError(f"unknown action: {action}")
    return fn(cfg, inp)


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
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _auth(self):
        return (not PLUGIN_TOKEN) or self.headers.get("Authorization") == f"Bearer {PLUGIN_TOKEN}"

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True, "plugin": "ptp-miwifi", "version": "0.2.2"})
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
                log("error", "miwifi.action.error", str(exc), {"action": payload.get("action")})
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
