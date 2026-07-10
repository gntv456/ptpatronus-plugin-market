#!/usr/bin/env python3
"""Developer helper for PTPatronus external plugins."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REQUIRED_MANIFEST_FIELDS = ("id", "name", "version", "runtime", "entry")
SUPPORTED_API_VERSION = "1"
SUPPORTED_HOST_CAPABILITIES = [
    "host.runtime.external-http.command",
    "host.runtime.external-http.base-url",
    "host.event.subscription",
    "host.schedule.cron",
    "host.api.config.read",
    "host.api.config.write",
    "host.api.log.write",
    "host.api.notice.write",
    "host.api.event.publish",
    "host.api.kv.read",
    "host.api.kv.write",
    "host.api.kv.delete",
    "host.api.site.read",
    "host.api.site.cookie",
    "host.ui.view",
    "host.ui.bridge",
]
PERMISSION_HOST_CAPABILITIES = {
    "config:read": ["host.api.config.read"],
    "config:write": ["host.api.config.write"],
    "log:write": ["host.api.log.write"],
    "notice:write": ["host.api.notice.write"],
    "event:publish": ["host.api.event.publish"],
    "kv:read": ["host.api.kv.read"],
    "kv:write": ["host.api.kv.write"],
    "kv:delete": ["host.api.kv.delete"],
    "site:read": ["host.api.site.read"],
    "site:cookie": ["host.api.site.cookie"],
}
PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
ED25519_FIELD = 2**255 - 19
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493


def ed25519_inv(value: int) -> int:
    return pow(value, ED25519_FIELD - 2, ED25519_FIELD)


ED25519_D = (-121665 * ed25519_inv(121666)) % ED25519_FIELD
ED25519_I = pow(2, (ED25519_FIELD - 1) // 4, ED25519_FIELD)


def ed25519_recover_x(y: int, sign: int) -> int | None:
    if y >= ED25519_FIELD:
        return None
    xx = (y * y - 1) * ed25519_inv(ED25519_D * y * y + 1) % ED25519_FIELD
    if xx == 0:
        return 0 if sign == 0 else None
    x = pow(xx, (ED25519_FIELD + 3) // 8, ED25519_FIELD)
    if (x * x - xx) % ED25519_FIELD != 0:
        x = (x * ED25519_I) % ED25519_FIELD
    if (x * x - xx) % ED25519_FIELD != 0:
        return None
    if x & 1 != sign:
        x = ED25519_FIELD - x
    return x


ED25519_BASE_Y = (4 * ed25519_inv(5)) % ED25519_FIELD
ED25519_BASE_X = ed25519_recover_x(ED25519_BASE_Y, 0)
if ED25519_BASE_X is None:
    raise RuntimeError("failed to initialize Ed25519 base point")
ED25519_BASE_POINT = (
    ED25519_BASE_X,
    ED25519_BASE_Y,
    1,
    (ED25519_BASE_X * ED25519_BASE_Y) % ED25519_FIELD,
)


def ed25519_point_add(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    a = (left[1] - left[0]) * (right[1] - right[0]) % ED25519_FIELD
    b = (left[1] + left[0]) * (right[1] + right[0]) % ED25519_FIELD
    c = 2 * left[3] * right[3] * ED25519_D % ED25519_FIELD
    d = 2 * left[2] * right[2] % ED25519_FIELD
    e = (b - a) % ED25519_FIELD
    f = (d - c) % ED25519_FIELD
    g = (d + c) % ED25519_FIELD
    h = (b + a) % ED25519_FIELD
    return (
        e * f % ED25519_FIELD,
        g * h % ED25519_FIELD,
        f * g % ED25519_FIELD,
        e * h % ED25519_FIELD,
    )


def ed25519_scalar_mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    out = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            out = ed25519_point_add(out, point)
        point = ed25519_point_add(point, point)
        scalar >>= 1
    return out


def ed25519_point_compress(point: tuple[int, int, int, int]) -> bytes:
    zinv = ed25519_inv(point[2])
    x = point[0] * zinv % ED25519_FIELD
    y = point[1] * zinv % ED25519_FIELD
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")


def ed25519_point_decompress(raw: bytes) -> tuple[int, int, int, int] | None:
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = ed25519_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % ED25519_FIELD)


def ed25519_secret_expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise SystemExit("private key seed must decode to 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def ed25519_hash_mod_order(*parts: bytes) -> int:
    digest = hashlib.sha512()
    for part in parts:
        digest.update(part)
    return int.from_bytes(digest.digest(), "little") % ED25519_ORDER


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = ed25519_secret_expand(seed)
    return ed25519_point_compress(ed25519_scalar_mul(scalar, ED25519_BASE_POINT))


def ed25519_sign(seed: bytes, payload: bytes) -> bytes:
    scalar, prefix = ed25519_secret_expand(seed)
    public_key = ed25519_point_compress(ed25519_scalar_mul(scalar, ED25519_BASE_POINT))
    nonce = ed25519_hash_mod_order(prefix, payload)
    encoded_r = ed25519_point_compress(ed25519_scalar_mul(nonce, ED25519_BASE_POINT))
    challenge = ed25519_hash_mod_order(encoded_r, public_key, payload)
    s = (nonce + challenge * scalar) % ED25519_ORDER
    return encoded_r + s.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = ed25519_point_decompress(public_key)
    point_r = ed25519_point_decompress(signature[:32])
    if point_a is None or point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= ED25519_ORDER:
        return False
    challenge = ed25519_hash_mod_order(signature[:32], public_key, payload)
    left = ed25519_scalar_mul(s, ED25519_BASE_POINT)
    right = ed25519_point_add(point_r, ed25519_scalar_mul(challenge, point_a))
    return (
        (left[0] * right[2] - right[0] * left[2]) % ED25519_FIELD == 0
        and (left[1] * right[2] - right[1] * left[2]) % ED25519_FIELD == 0
    )


def detect_app_version() -> tuple[str, bool]:
    override = os.environ.get("PTP_APP_VERSION", "").strip()
    if override:
        return override, True
    version_file = Path(__file__).resolve().parents[1] / "internal" / "version" / "version.go"
    if version_file.exists():
        match = re.search(r'Version\s*=\s*"([^"]+)"', version_file.read_text(encoding="utf-8"))
        if match:
            return match.group(1).strip(), True
    return "0.0.0", False


def current_app_version() -> str:
    return detect_app_version()[0]


def normalize_list(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def infer_manifest_host_capabilities(manifest: dict[str, Any]) -> list[str]:
    caps = list(manifest.get("host_capabilities") or [])
    entry = manifest.get("entry") if isinstance(manifest.get("entry"), dict) else {}
    if entry.get("command"):
        caps.append("host.runtime.external-http.command")
    if entry.get("base_url"):
        caps.append("host.runtime.external-http.base-url")
    if manifest.get("events"):
        caps.append("host.event.subscription")
    if manifest.get("schedule"):
        caps.append("host.schedule.cron")
    contributes = manifest.get("contributes") if isinstance(manifest.get("contributes"), dict) else {}
    if contributes.get("views"):
        caps.extend(["host.ui.view", "host.ui.bridge"])
    for permission in manifest.get("permissions", []) or []:
        caps.extend(PERMISSION_HOST_CAPABILITIES.get(str(permission).strip(), []))
    return normalize_list(caps)


def normalize_dependencies(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in manifest.get("dependencies", []) or []:
        if not isinstance(item, dict):
            continue
        dep_id = str(item.get("id") or "").strip()
        if not dep_id or dep_id in seen:
            continue
        seen.add(dep_id)
        out.append({
            "id": dep_id,
            "version": str(item.get("version") or "").strip(),
            "optional": bool(item.get("optional")),
            "reason": str(item.get("reason") or "").strip(),
        })
    return out


def compare_versions(a: str, b: str) -> int:
    sa = split_version(a)
    sb = split_version(b)
    size = max(len(sa), len(sb))
    for index in range(size):
        left = sa[index] if index < len(sa) else 0
        right = sb[index] if index < len(sb) else 0
        if left < right:
            return -1
        if left > right:
            return 1
    return 0


def split_version(value: str) -> list[int]:
    value = value.strip()
    if value.lower().startswith("v"):
        value = value[1:]
    parts = re.split(r"[.\-_+]", value)
    return [leading_int(part) for part in parts if part]


def leading_int(value: str) -> int:
    match = re.match(r"(\d+)", value or "")
    return int(match.group(1)) if match else 0


def parse_version_clause(label: str, clause: str, expr: str) -> tuple[str, str]:
    clause = clause.strip()
    if not clause:
        raise ValueError(f"invalid {label} constraint {expr!r}")
    for op in (">=", "<=", "==", ">", "<", "="):
        if clause.startswith(op):
            want = clause[len(op):].strip()
            if not want or want[:1] in "><=":
                raise ValueError(f"invalid {label} constraint {expr!r}")
            return ("=" if op == "==" else op), want
    if clause[:1].lower() != "v" and not clause[:1].isdigit():
        raise ValueError(f"invalid {label} constraint {expr!r}")
    return "=", clause


def match_version_expr(label: str, expr: str, current: str) -> bool:
    for clause in expr.split(","):
        op, want = parse_version_clause(label, clause, expr)
        cmp = compare_versions(current, want)
        if op == ">" and cmp <= 0:
            return False
        if op == ">=" and cmp < 0:
            return False
        if op == "<" and cmp >= 0:
            return False
        if op == "<=" and cmp > 0:
            return False
        if op == "=" and cmp != 0:
            return False
    return True


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value or "my-plugin"


def load_manifest(plugin_dir: Path) -> dict[str, Any]:
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.exists():
        raise SystemExit(f"plugin.json not found: {manifest_path}")
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid plugin.json: {exc}") from exc


def validate_manifest(plugin_dir: Path) -> dict[str, Any]:
    manifest = load_manifest(plugin_dir)
    errors: list[str] = []
    app_version, app_version_known = detect_app_version()
    host_capabilities = infer_manifest_host_capabilities(manifest)
    optional_host_capabilities = normalize_list(list(manifest.get("optional_host_capabilities") or []))
    dependencies = normalize_dependencies(manifest)
    for field in REQUIRED_MANIFEST_FIELDS:
        if not manifest.get(field):
            errors.append(f"missing required field: {field}")
    if manifest.get("runtime") != "external-http":
        errors.append("runtime must be external-http")
    api_version = manifest.get("api_version") or SUPPORTED_API_VERSION
    if api_version != SUPPORTED_API_VERSION:
        errors.append(f"api_version {api_version!r} is not supported; current is {SUPPORTED_API_VERSION}")
    manifest_app_version = (manifest.get("app_version") or "").strip()
    if manifest_app_version:
        try:
            if app_version_known and not match_version_expr("app_version", manifest_app_version, app_version):
                errors.append(f"app_version {manifest_app_version!r} is not satisfied by current app {app_version}")
        except ValueError as exc:
            errors.append(str(exc))
    unsupported_host_capabilities = [cap for cap in host_capabilities if cap not in SUPPORTED_HOST_CAPABILITIES]
    if unsupported_host_capabilities:
        errors.append("host_capabilities not supported by current host: " + ", ".join(unsupported_host_capabilities))
    for capability in optional_host_capabilities:
        if not capability:
            errors.append("optional_host_capabilities must not contain empty strings")
    entry = manifest.get("entry")
    if not isinstance(entry, dict):
        errors.append("entry must be an object")
    elif not entry.get("command") and not entry.get("base_url"):
        errors.append("entry.command or entry.base_url is required")
    for array_field in ("permissions", "events", "actions", "config_schema"):
        value = manifest.get(array_field, [])
        if value is not None and not isinstance(value, list):
            errors.append(f"{array_field} must be an array")
    if manifest.get("dependencies") is not None and not isinstance(manifest.get("dependencies"), list):
        errors.append("dependencies must be an array")
    if manifest.get("optional_host_capabilities") is not None and not isinstance(manifest.get("optional_host_capabilities"), list):
        errors.append("optional_host_capabilities must be an array")
    actions = {item.get("name") for item in manifest.get("actions", []) if isinstance(item, dict)}
    seen_dependencies: set[str] = set()
    for index, item in enumerate(manifest.get("dependencies", []) or []):
        if not isinstance(item, dict):
            errors.append(f"dependencies[{index}] must be an object")
            continue
        dep_id = str(item.get("id") or "").strip()
        if not dep_id:
            errors.append(f"dependencies[{index}].id is required")
            continue
        if dep_id == manifest.get("id"):
            errors.append(f"dependencies[{index}].id must not reference the plugin itself")
        if not PLUGIN_ID_RE.match(dep_id):
            errors.append(f"dependencies[{index}].id {dep_id!r} is invalid")
        if dep_id in seen_dependencies:
            errors.append(f"dependencies[{index}].id {dep_id!r} is duplicated")
        seen_dependencies.add(dep_id)
        dep_version = str(item.get("version") or "").strip()
        if dep_version:
            try:
                parse_version_clause("dependency version", dep_version, dep_version)
            except ValueError as exc:
                errors.append(f"dependencies[{index}].version: {exc}")
    for index, item in enumerate(manifest.get("schedule", []) or []):
        if not isinstance(item, dict):
            errors.append(f"schedule[{index}] must be an object")
            continue
        if item.get("action") and item["action"] not in actions:
            errors.append(f"schedule[{index}].action {item['action']!r} is not declared in actions")
    contributes = manifest.get("contributes") or {}
    if contributes and not isinstance(contributes, dict):
        errors.append("contributes must be an object")
    for index, item in enumerate((contributes.get("commands") if isinstance(contributes, dict) else []) or []):
        if not isinstance(item, dict):
            errors.append(f"contributes.commands[{index}] must be an object")
            continue
        if item.get("action") and item["action"] not in actions:
            errors.append(f"contributes.commands[{index}].action {item['action']!r} is not declared in actions")
    if errors:
        raise SystemExit("manifest validation failed:\n- " + "\n- ".join(errors))
    manifest["host_capabilities"] = host_capabilities
    manifest["optional_host_capabilities"] = optional_host_capabilities
    manifest["dependencies"] = dependencies
    return manifest


def read_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"unable to read {label}: {path}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must decode to a JSON object: {path}")
    return value


def load_package_json(plugin_dir: Path) -> dict[str, Any] | None:
    path = plugin_dir / "package.json"
    if not path.exists():
        return None
    return read_json_file(path, "package.json")


def infer_package_manager(plugin_dir: Path) -> str:
    if (plugin_dir / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (plugin_dir / "yarn.lock").exists():
        return "yarn"
    if (plugin_dir / "bun.lockb").exists() or (plugin_dir / "bun.lock").exists():
        return "bun"
    return "npm"


def infer_build_command(plugin_dir: Path) -> str:
    package_json = load_package_json(plugin_dir)
    if not package_json:
        return ""
    scripts = package_json.get("scripts")
    if not isinstance(scripts, dict):
        return ""
    build = scripts.get("build")
    if not str(build or "").strip():
        return ""
    manager = infer_package_manager(plugin_dir)
    if manager == "yarn":
        return "yarn build"
    if manager == "pnpm":
        return "pnpm run build"
    if manager == "bun":
        return "bun run build"
    return "npm run build"


def resolve_build_command(plugin_dir: Path, explicit: str, skip_build: bool) -> tuple[str, bool]:
    text = str(explicit or "").strip()
    if text:
        return text, False
    if skip_build:
        return "", False
    inferred = infer_build_command(plugin_dir)
    if inferred:
        return inferred, True
    return "", False


def current_utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_archive_ref(value: str) -> str:
    text = str(value or "").strip()
    if "://" in text:
        return text
    return text.replace("\\", "/")


def resolve_archive_ref(archive: Path, market_path: Path | None, explicit: str | None) -> str:
    explicit = str(explicit or "").strip()
    if explicit:
        return normalize_archive_ref(explicit)
    if market_path is not None:
        try:
            rel = os.path.relpath(archive, market_path.parent)
            return normalize_archive_ref(rel)
        except ValueError:
            pass
    return str(archive)


def load_key_material(source: str, field: str) -> str:
    raw = str(source or "").strip()
    if not raw:
        raise SystemExit(f"{field} is required")
    path = Path(raw)
    if path.exists():
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"unable to read {field}: {path}: {exc}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        value = parsed.get(field)
        if value is None:
            raise SystemExit(f"{field} not found in key file")
        raw = str(value).strip()
    if not raw:
        raise SystemExit(f"{field} is empty")
    return raw


def decode_base64_key(field: str, value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SystemExit(f"{field} must be base64 text") from exc


def load_private_key_seed(source: str) -> bytes:
    raw = decode_base64_key("private_key", load_key_material(source, "private_key"))
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise SystemExit("private_key must decode to 32 bytes (seed) or 64 bytes")
    return raw


def load_public_key_bytes(source: str) -> bytes:
    raw = decode_base64_key("public_key", load_key_material(source, "public_key"))
    if len(raw) != 32:
        raise SystemExit("public_key must decode to 32 bytes")
    return raw


def encode_base64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def sign_payload(private_key_source: str, payload: bytes) -> tuple[str, str]:
    seed = load_private_key_seed(private_key_source)
    public_key = ed25519_public_key(seed)
    signature = ed25519_sign(seed, payload)
    if not ed25519_verify(public_key, payload, signature):
        raise SystemExit("generated signature failed self-verification")
    return encode_base64(public_key), encode_base64(signature)


def write_key_text(path: Path, content: str, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(f"refusing to overwrite existing key file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def find_market_plugin(index: dict[str, Any], plugin_id: str) -> dict[str, Any] | None:
    plugins = index.get("plugins")
    if plugins is None:
        return None
    if not isinstance(plugins, list):
        raise SystemExit("market index plugins must be an array")
    for item in plugins:
        if isinstance(item, dict) and str(item.get("id") or "").strip() == plugin_id:
            return copy.deepcopy(item)
    return None


def publisher_args_used(args: argparse.Namespace) -> bool:
    return any([
        str(getattr(args, "publisher_id", "") or "").strip(),
        str(getattr(args, "publisher_name", "") or "").strip(),
        str(getattr(args, "publisher_website", "") or "").strip(),
        bool(getattr(args, "publisher_verified", False)),
    ])


def resolve_publisher(args: argparse.Namespace, previous: dict[str, Any] | None) -> dict[str, Any] | None:
    base = copy.deepcopy(previous) if isinstance(previous, dict) else {}
    touched = publisher_args_used(args)
    if getattr(args, "publisher_id", None):
        base["id"] = str(args.publisher_id).strip()
    if getattr(args, "publisher_name", None):
        base["name"] = str(args.publisher_name).strip()
    if getattr(args, "publisher_website", None):
        base["website"] = str(args.publisher_website).strip()
    if getattr(args, "publisher_verified", False):
        base["verified"] = True
    if not base:
        return None
    if touched and not str(base.get("name") or "").strip():
        raise SystemExit("publisher metadata requires --publisher-name")
    out: dict[str, Any] = {}
    if str(base.get("id") or "").strip():
        out["id"] = str(base["id"]).strip()
    if str(base.get("name") or "").strip():
        out["name"] = str(base["name"]).strip()
    if str(base.get("website") or "").strip():
        out["website"] = str(base["website"]).strip()
    if base.get("verified"):
        out["verified"] = True
    return out or None


def resolve_published_at(args: argparse.Namespace, previous: dict[str, Any] | None, version: str, auto_fill: bool) -> str:
    raw = str(getattr(args, "published_at", "") or "").strip()
    if raw:
        if raw.lower() in ("now", "auto"):
            return current_utc_timestamp()
        return raw
    if previous and str(previous.get("version") or "").strip() == version:
        old = str(previous.get("published_at") or "").strip()
        if old:
            return old
    return current_utc_timestamp() if auto_fill else ""


def resolve_changelog(args: argparse.Namespace, previous: dict[str, Any] | None, version: str) -> list[str]:
    values = [str(item).strip() for item in (getattr(args, "changelog", None) or []) if str(item).strip()]
    if values:
        return values
    if previous and str(previous.get("version") or "").strip() == version:
        prior = previous.get("changelog")
        if isinstance(prior, list):
            return [str(item).strip() for item in prior if str(item).strip()]
    return []


def build_market_entry(
    manifest: dict[str, Any],
    archive_ref: str,
    sha256: str,
    signature: str,
    args: argparse.Namespace,
    previous: dict[str, Any] | None,
    auto_fill_release_metadata: bool,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": manifest["id"],
        "name": manifest["name"],
        "version": manifest["version"],
        "api_version": manifest.get("api_version") or SUPPORTED_API_VERSION,
        "runtime": manifest["runtime"],
        "archive": archive_ref,
        "sha256": sha256,
    }
    for key in (
        "app_version",
        "host_capabilities",
        "optional_host_capabilities",
        "dependencies",
        "author",
        "description",
        "homepage",
        "repository",
        "license",
        "keywords",
        "permissions",
        "events",
        "actions",
        "config_schema",
        "contributes",
        "resource_access",
        "requirements",
    ):
        value = manifest.get(key)
        if value in (None, "", [], {}):
            continue
        entry[key] = copy.deepcopy(value)
    if signature:
        entry["signature"] = signature
    publisher = resolve_publisher(args, previous.get("publisher") if previous else None)
    if publisher:
        entry["publisher"] = publisher
    published_at = resolve_published_at(args, previous, manifest["version"], auto_fill_release_metadata)
    if published_at:
        entry["published_at"] = published_at
    changelog = resolve_changelog(args, previous, manifest["version"])
    if changelog:
        entry["changelog"] = changelog
    return entry


def load_market_index(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return read_json_file(path, "market index")


def write_market_index(path: Path, index: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")


def write_json_output(path: str, payload: dict[str, Any]) -> Path:
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def write_vendored_tools(plugin_dir: Path, out_dir: str) -> Path:
    tool_dir = (plugin_dir / out_dir).resolve()
    tool_dir.mkdir(parents=True, exist_ok=True)
    source_dir = Path(__file__).resolve().parent
    for name in ("pluginctl.py", "plugin-manifest.schema.json"):
        shutil.copy2(source_dir / name, tool_dir / name)
    return tool_dir


def workflow_tool_path(plugin_dir: Path, tool_file: Path) -> str:
    return Path(os.path.relpath(tool_file, plugin_dir)).as_posix()


def write_ci_workflows(plugin_dir: Path, provider: str, tool_path: str) -> list[Path]:
    targets: list[Path] = []
    github_yaml = workflow_template(tool_path, "github")
    gitea_yaml = workflow_template(tool_path, "gitea")
    if provider in ("github", "both"):
        path = plugin_dir / ".github" / "workflows" / "plugin-package.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(github_yaml, encoding="utf-8")
        targets.append(path)
    if provider in ("gitea", "both"):
        path = plugin_dir / ".gitea" / "workflows" / "plugin-package.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(gitea_yaml, encoding="utf-8")
        targets.append(path)
    return targets


def workflow_template(tool_path: str, provider: str) -> str:
    title = "Plugin Release"
    permissions = ""
    if provider == "github":
        permissions = """
permissions:
  contents: write
""".rstrip("\n")
    archive_ref_logic = ""
    if provider == "github":
        archive_ref_logic = """
          if [ -z "$archive_ref" ] && [ "${{ github.ref_type }}" = "tag" ]; then
            archive_ref="https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/$archive_name"
          fi
""".rstrip("\n")
    release_step = ""
    if provider == "github":
        release_step = """
      - name: Publish GitHub release assets
        if: github.ref_type == 'tag'
        env:
          GH_TOKEN: ${{ github.token }}
        shell: bash
        run: |
          shopt -s nullglob
          assets=(dist/plugins/*.zip dist/plugin-package.json)
          if [ -f dist/plugin-market.json ]; then
            assets+=(dist/plugin-market.json)
          fi
          if gh release view "$GITHUB_REF_NAME" >/dev/null 2>&1; then
            gh release upload "$GITHUB_REF_NAME" "${assets[@]}" --clobber
          else
            gh release create "$GITHUB_REF_NAME" "${assets[@]}" --generate-notes
          fi
""".rstrip("\n")
    upload_step = """
      - name: Upload package artifact
        uses: actions/upload-artifact@v4
        with:
          name: plugin-package
          path: |
            dist/**
          if-no-files-found: ignore
""".rstrip("\n")
    template = f"""name: {title}

{permissions}

on:
  push:
    branches: ['**']
    tags: ['v*']
  pull_request:
  workflow_dispatch:

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Setup Node
        if: ${{{{ hashFiles('package.json') != '' }}}}
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install package dependencies
        if: ${{{{ hashFiles('package.json') != '' }}}}
        shell: bash
        run: |
          if [ -f package-lock.json ]; then
            npm ci
          elif [ -f pnpm-lock.yaml ]; then
            corepack enable
            pnpm install --frozen-lockfile
          elif [ -f yarn.lock ]; then
            corepack enable
            yarn install --immutable
          elif [ -f bun.lockb ] || [ -f bun.lock ]; then
            curl -fsSL https://bun.sh/install | bash
            export PATH="$HOME/.bun/bin:$PATH"
            bun install --frozen-lockfile
          else
            npm install
          fi

      - name: Validate manifest
        run: python {tool_path} validate .

      - name: Package plugin
        shell: bash
        env:
          PTP_APP_VERSION: ${{{{ vars.PTP_APP_VERSION }}}}
          PTP_PLUGIN_CHANGELOG_FILE: ${{{{ vars.PTP_PLUGIN_CHANGELOG_FILE }}}}
          PTP_PLUGIN_MARKET_ARCHIVE_REF: ${{{{ vars.PTP_PLUGIN_MARKET_ARCHIVE_REF }}}}
          PTP_PLUGIN_MARKET_NAME: ${{{{ vars.PTP_PLUGIN_MARKET_NAME }}}}
          PTP_PLUGIN_MARKET_PRIVATE_KEY: ${{{{ secrets.PTP_PLUGIN_MARKET_PRIVATE_KEY }}}}
          PTP_PLUGIN_PUBLISHED_AT: ${{{{ vars.PTP_PLUGIN_PUBLISHED_AT }}}}
          PTP_PLUGIN_PUBLISHER_ID: ${{{{ vars.PTP_PLUGIN_PUBLISHER_ID }}}}
          PTP_PLUGIN_PUBLISHER_NAME: ${{{{ vars.PTP_PLUGIN_PUBLISHER_NAME }}}}
          PTP_PLUGIN_PUBLISHER_VERIFIED: ${{{{ vars.PTP_PLUGIN_PUBLISHER_VERIFIED }}}}
          PTP_PLUGIN_PUBLISHER_WEBSITE: ${{{{ vars.PTP_PLUGIN_PUBLISHER_WEBSITE }}}}
        run: |
          mkdir -p dist/plugins
          archive_name="$(python - <<'PY'
import json
from pathlib import Path
manifest = json.loads(Path('plugin.json').read_text(encoding='utf-8'))
print(f"{{manifest['id']}}-{{manifest['version']}}.zip")
PY
          )"

          archive_ref="${{PTP_PLUGIN_MARKET_ARCHIVE_REF:-}}"
{archive_ref_logic}

          market_output=""
          if [ -n "${{PTP_PLUGIN_MARKET_PRIVATE_KEY:-}}" ] || [ -n "${{PTP_PLUGIN_MARKET_NAME:-}}" ] || [ -n "$archive_ref" ] || [ -n "${{PTP_PLUGIN_PUBLISHER_NAME:-}}" ]; then
            market_output="dist/plugin-market.json"
          fi

          args=(package . --out-dir dist/plugins --json-out dist/plugin-package.json)
          if [ -n "${{PTP_PLUGIN_MARKET_PRIVATE_KEY:-}}" ]; then
            args+=(--private-key "$PTP_PLUGIN_MARKET_PRIVATE_KEY")
          fi
          if [ -n "$market_output" ]; then
            args+=(--market "$market_output")
          fi
          if [ -n "${{PTP_PLUGIN_MARKET_NAME:-}}" ]; then
            args+=(--market-name "$PTP_PLUGIN_MARKET_NAME")
          fi
          if [ -n "$archive_ref" ]; then
            args+=(--archive-ref "$archive_ref")
          fi
          if [ -n "${{PTP_PLUGIN_PUBLISHER_ID:-}}" ]; then
            args+=(--publisher-id "$PTP_PLUGIN_PUBLISHER_ID")
          fi
          if [ -n "${{PTP_PLUGIN_PUBLISHER_NAME:-}}" ]; then
            args+=(--publisher-name "$PTP_PLUGIN_PUBLISHER_NAME")
          fi
          if [ -n "${{PTP_PLUGIN_PUBLISHER_WEBSITE:-}}" ]; then
            args+=(--publisher-website "$PTP_PLUGIN_PUBLISHER_WEBSITE")
          fi
          if [ "${{PTP_PLUGIN_PUBLISHER_VERIFIED:-}}" = "1" ] || [ "${{PTP_PLUGIN_PUBLISHER_VERIFIED:-}}" = "true" ]; then
            args+=(--publisher-verified)
          fi
          if [ -n "${{PTP_PLUGIN_PUBLISHED_AT:-}}" ]; then
            args+=(--published-at "$PTP_PLUGIN_PUBLISHED_AT")
          fi
          if [ -n "${{PTP_PLUGIN_CHANGELOG_FILE:-}}" ] && [ -f "${{PTP_PLUGIN_CHANGELOG_FILE}}" ]; then
            while IFS= read -r line; do
              [ -n "$line" ] && args+=(--changelog "$line")
            done < "${{PTP_PLUGIN_CHANGELOG_FILE}}"
          fi
          python {tool_path} "${{args[@]}}"

{release_step}

{upload_step}
"""
    return template


def vendor_tools_cmd(args: argparse.Namespace) -> None:
    plugin_dir = Path(args.plugin_dir).resolve()
    tool_dir = write_vendored_tools(plugin_dir, args.out_dir)
    print(f"vendored tools -> {tool_dir}")


def ci_cmd(args: argparse.Namespace) -> None:
    plugin_dir = Path(args.plugin_dir).resolve()
    tool_file = plugin_dir / args.tool_path
    if args.vendor_tools:
        tool_dir = write_vendored_tools(plugin_dir, args.tool_dir)
        tool_file = tool_dir / "pluginctl.py"
    files = write_ci_workflows(plugin_dir, args.provider, workflow_tool_path(plugin_dir, tool_file))
    for path in files:
        print(f"wrote {path}")


def create_plugin(args: argparse.Namespace) -> None:
    plugin_id = slugify(args.plugin_id)
    target = Path(args.directory or plugin_id)
    if target.exists() and any(target.iterdir()):
        raise SystemExit(f"target directory is not empty: {target}")
    target.mkdir(parents=True, exist_ok=True)
    name = args.name or plugin_id.replace("-", " ").title()
    manifest = {
        "id": plugin_id,
        "name": name,
        "version": "0.1.0",
        "api_version": SUPPORTED_API_VERSION,
        "app_version": ">=0.1.0",
        "optional_host_capabilities": [],
        "dependencies": [],
        "author": args.author,
        "description": "External HTTP plugin.",
        "license": "Proprietary",
        "keywords": ["external-http", args.template],
        "runtime": "external-http",
        "entry": build_create_entry(args.template),
        "permissions": ["log:write", "kv:read", "kv:write", "event:publish"],
        "events": [{"type": "plugin.test", "description": "Test event"}],
        "actions": [{"name": "ping", "label": "Ping", "description": "Return input and update host KV."}],
        "config_schema": [{"key": "prefix", "label": "Prefix", "type": "text", "default": "pong"}],
        "contributes": {
            "commands": [{"id": f"{plugin_id}.ping", "label": "Ping", "action": "ping"}],
            "menus": [{"location": "plugins/actions", "command": f"{plugin_id}.ping"}],
        },
    }
    if args.with_view:
        manifest["contributes"]["views"] = [{
            "id": "dashboard",
            "title": name,
            "location": "plugins",
            "path": "index.html",
        }]
    (target / "plugin.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    create_template_files(target, plugin_id, args.template, args.with_view)
    tool_dir = None
    if args.vendor_tools or args.with_ci:
        tool_dir = write_vendored_tools(target, args.tool_dir)
    if args.with_ci:
        tool_file = (tool_dir or (target / args.tool_dir)) / "pluginctl.py"
        write_ci_workflows(target, args.with_ci, workflow_tool_path(target, tool_file))
    print(f"created {target}")


def build_create_entry(template: str) -> dict[str, Any]:
    if template == "typescript":
        return {
            "command": "node",
            "args": ["dist/plugin.js"],
            "health": "/health",
        }
    return {
        "command": "python",
        "args": ["plugin.py"],
        "health": "/health",
    }


def create_template_files(target: Path, plugin_id: str, template: str, with_view: bool) -> None:
    (target / ".gitignore").write_text(template_gitignore(template), encoding="utf-8")
    if template == "typescript":
        write_typescript_template(target, plugin_id, with_view)
    else:
        (target / "plugin.py").write_text(PYTHON_TEMPLATE, encoding="utf-8")
    if with_view and template != "typescript":
        web_dir = target / "web"
        web_dir.mkdir(parents=True, exist_ok=True)
        (web_dir / "index.html").write_text(VIEW_TEMPLATE, encoding="utf-8")


def template_gitignore(template: str) -> str:
    lines = ["__pycache__/", ".venv/"]
    if template == "typescript":
        lines.extend(["node_modules/", "dist/"])
    return "\n".join(lines) + "\n"


def write_typescript_template(target: Path, plugin_id: str, with_view: bool) -> None:
    scripts = {
        "build": "tsc -p tsconfig.json",
        "check": "tsc -p tsconfig.json --noEmit",
        "start": "node dist/plugin.js",
    }
    if with_view:
        scripts = {
            "build": "npm run build:server && npm run build:view",
            "build:server": "tsc -p tsconfig.json",
            "build:view": "node scripts/build-view.mjs",
            "check": "tsc -p tsconfig.json --noEmit && tsc -p tsconfig.view.json --noEmit",
            "start": "node dist/plugin.js",
        }
    (target / "package.json").write_text(json.dumps({
        "name": plugin_id,
        "version": "0.1.0",
        "private": True,
        "type": "module",
        "engines": {"node": ">=18"},
        "scripts": scripts,
        "devDependencies": {
            "@types/node": "^22.16.0",
            "typescript": "^5.8.0",
        },
    }, indent=2) + "\n", encoding="utf-8")
    (target / "tsconfig.json").write_text(TYPESCRIPT_TSCONFIG_TEMPLATE, encoding="utf-8")
    src_dir = target / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "plugin.ts").write_text(TYPESCRIPT_TEMPLATE, encoding="utf-8")
    if with_view:
        write_typescript_view_template(target)


def write_typescript_view_template(target: Path) -> None:
    (target / "tsconfig.view.json").write_text(TYPESCRIPT_VIEW_TSCONFIG_TEMPLATE, encoding="utf-8")
    scripts_dir = target / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    (scripts_dir / "build-view.mjs").write_text(TYPESCRIPT_VIEW_BUILD_SCRIPT_TEMPLATE, encoding="utf-8")
    web_src = target / "web-src"
    web_src.mkdir(parents=True, exist_ok=True)
    (web_src / "index.html").write_text(TYPESCRIPT_VIEW_INDEX_TEMPLATE, encoding="utf-8")
    (web_src / "styles.css").write_text(TYPESCRIPT_VIEW_STYLES_TEMPLATE, encoding="utf-8")
    (web_src / "main.ts").write_text(TYPESCRIPT_VIEW_MAIN_TEMPLATE, encoding="utf-8")
    (web_src / "ptpatronus.d.ts").write_text(TYPESCRIPT_VIEW_TYPES_TEMPLATE, encoding="utf-8")
    web_dir = target / "web"
    web_dir.mkdir(parents=True, exist_ok=True)
    (web_dir / "index.html").write_text(TYPESCRIPT_VIEW_INDEX_TEMPLATE, encoding="utf-8")
    (web_dir / "styles.css").write_text(TYPESCRIPT_VIEW_STYLES_TEMPLATE, encoding="utf-8")
    (web_dir / "main.js").write_text(TYPESCRIPT_VIEW_MAIN_JS_TEMPLATE, encoding="utf-8")


def should_skip(path: Path, include_node_modules: bool) -> bool:
    parts = set(path.parts)
    if "__pycache__" in parts or ".venv" in parts or ".git" in parts:
        return True
    if not include_node_modules and "node_modules" in parts:
        return True
    return False


def walk_plugin_tree(root: Path, include_node_modules: bool) -> tuple[list[Path], list[Path]]:
    dirs: list[Path] = []
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        current = Path(current_root)
        rel_root = current.relative_to(root)
        filtered_dirs = []
        for name in sorted(dirnames):
            rel = rel_root / name if str(rel_root) != "." else Path(name)
            if should_skip(rel, include_node_modules):
                continue
            filtered_dirs.append(name)
            dirs.append(rel)
        dirnames[:] = filtered_dirs
        for name in sorted(filenames):
            rel = rel_root / name if str(rel_root) != "." else Path(name)
            if should_skip(rel, include_node_modules):
                continue
            files.append(rel)
    return dirs, files


def tree_fingerprint(root: Path, include_node_modules: bool) -> str:
    digest = hashlib.sha256()
    dirs, files = walk_plugin_tree(root, include_node_modules)
    for rel in dirs:
        stat = (root / rel).stat()
        digest.update(rel.as_posix().encode("utf-8"))
        digest.update(b"\0dir\0")
        digest.update(str(stat.st_mtime_ns).encode("utf-8"))
        digest.update(b"\0")
    for rel in files:
        stat = (root / rel).stat()
        digest.update(rel.as_posix().encode("utf-8"))
        digest.update(b"\0file\0")
        digest.update(str(stat.st_size).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(stat.st_mtime_ns).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def resolve_dev_target(plugin_dir: Path, manifest: dict[str, Any], args: argparse.Namespace) -> Path:
    if args.target_dir:
        return Path(args.target_dir).resolve()
    return (Path(args.plugin_root).resolve() / manifest["id"]).resolve()


def sync_plugin_tree(plugin_dir: Path, target_dir: Path, include_node_modules: bool) -> dict[str, int]:
    target_dir.mkdir(parents=True, exist_ok=True)
    src_dirs, src_files = walk_plugin_tree(plugin_dir, include_node_modules)
    dst_dirs, dst_files = walk_plugin_tree(target_dir, include_node_modules)

    src_dir_set = {rel.as_posix() for rel in src_dirs}
    src_file_map = {rel.as_posix(): rel for rel in src_files}
    removed = 0
    added = 0
    updated = 0

    for rel in sorted(dst_files, key=lambda item: item.as_posix(), reverse=True):
        rel_key = rel.as_posix()
        if rel_key in src_file_map:
            continue
        (target_dir / rel).unlink(missing_ok=True)
        removed += 1

    for rel in sorted(dst_dirs, key=lambda item: (len(item.parts), item.as_posix()), reverse=True):
        rel_key = rel.as_posix()
        if rel_key in src_dir_set:
            continue
        shutil.rmtree(target_dir / rel, ignore_errors=True)
        removed += 1

    for rel in src_dirs:
        (target_dir / rel).mkdir(parents=True, exist_ok=True)

    for rel_key, rel in src_file_map.items():
        src_path = plugin_dir / rel
        dst_path = target_dir / rel
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        if not dst_path.exists():
            shutil.copy2(src_path, dst_path)
            added += 1
            continue
        src_stat = src_path.stat()
        dst_stat = dst_path.stat()
        if src_stat.st_size == dst_stat.st_size and src_stat.st_mtime_ns == dst_stat.st_mtime_ns:
            continue
        shutil.copy2(src_path, dst_path)
        updated += 1

    return {"added": added, "updated": updated, "removed": removed}


def format_sync_summary(stats: dict[str, int]) -> str:
    return f"added={stats['added']} updated={stats['updated']} removed={stats['removed']}"


def run_build_command(command: str, cwd: Path) -> None:
    text = str(command or "").strip()
    if not text:
        return
    try:
        subprocess.run(text, cwd=str(cwd), shell=True, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"build command failed with exit code {exc.returncode}: {text}") from exc


def defaults_from_schema(schema: list[dict[str, Any]] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in schema or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if not key:
            continue
        if "default" in item:
            out[key] = item["default"]
        elif item.get("type") == "switch":
            out[key] = False
        elif item.get("type") == "number":
            out[key] = 0
        elif item.get("type") == "multiselect":
            out[key] = []
        else:
            out[key] = ""
    return out


def parse_json_object_arg(label: str, raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = None
    if value is None:
        if str(raw).strip() in ("", "null"):
            return {}
        pairs: dict[str, Any] = {}
        for chunk in str(raw).split(","):
            item = chunk.strip()
            if not item:
                continue
            if "=" not in item:
                raise SystemExit(f"{label} must be a JSON object or key=value pairs")
            key, val = item.split("=", 1)
            key = key.strip()
            if not key:
                raise SystemExit(f"{label} contains an empty key")
            value_text = val.strip()
            try:
                pairs[key] = json.loads(value_text)
            except json.JSONDecodeError:
                pairs[key] = value_text
        if pairs:
            return pairs
        raise SystemExit(f"{label} must be a JSON object or key=value pairs")
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must decode to a JSON object")
    return value


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def random_token() -> str:
    return os.urandom(24).hex()


def replace_vars(value: str, port: int, token: str, plugin_dir: Path, plugin_id: str) -> str:
    return (
        str(value or "")
        .replace("${PORT}", str(port))
        .replace("${TOKEN}", token)
        .replace("${PLUGIN_DIR}", str(plugin_dir))
        .replace("${PLUGIN_ID}", plugin_id)
    )


def resolve_command(plugin_dir: Path, command: str) -> str:
    candidate = Path(command)
    if candidate.is_absolute():
        return str(candidate)
    local = plugin_dir / candidate
    if local.exists():
        return str(local)
    return command


def resolve_work_dir(plugin_dir: Path, work_dir: str | None) -> str:
    if not work_dir:
        return str(plugin_dir)
    path = Path(work_dir)
    if path.is_absolute():
        return str(path)
    return str((plugin_dir / path).resolve())


def build_host_context(manifest: dict[str, Any], host_url: str, host_token: str) -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "plugin_id": manifest["id"],
        "base_url": host_url,
        "token": host_token,
        "permissions": list(manifest.get("permissions") or []),
        "host_capabilities": list(SUPPORTED_HOST_CAPABILITIES),
    }


def plugin_request(base_url: str, token: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            raw = res.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"plugin request {path} failed: HTTP {exc.code} {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"plugin request {path} failed: {exc}") from exc
    return json.loads(raw) if raw else {}


def wait_for_health(base_url: str, health_path: str, timeout: float, process: subprocess.Popen[Any] | None = None) -> None:
    deadline = time.time() + max(timeout, 0.5)
    last_error = "health check did not succeed"
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"plugin process exited before healthy with code {process.returncode}")
        try:
            with urllib.request.urlopen(base_url.rstrip("/") + health_path, timeout=2) as res:
                if 200 <= res.status < 300:
                    return
                last_error = f"health returned status {res.status}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise RuntimeError(last_error)


def create_mock_host_server(bind_host: str, port: int, token: str, verbose: bool = True) -> ThreadingHTTPServer:
    kv: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def _authorized(self) -> bool:
            return self.headers.get("Authorization") == f"Bearer {token}" or self.headers.get("X-PTP-Host-Token") == token

        def _json(self, status: int, data: Any) -> None:
            raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

        def _guard(self) -> bool:
            if self.path == "/health":
                return True
            if self._authorized():
                return True
            self._json(401, {"error": "unauthorized"})
            return False

        def do_GET(self) -> None:
            if not self._guard():
                return
            if self.path == "/health":
                self._json(200, {"ok": True})
            elif self.path == "/capabilities":
                self._json(200, {
                    "api_version": SUPPORTED_API_VERSION,
                    "plugin_id": "mock-plugin",
                    "permissions": ["host:*"],
                    "host_capabilities": SUPPORTED_HOST_CAPABILITIES,
                    "endpoints": [
                        "GET /capabilities",
                        "GET /config",
                        "POST /log",
                        "POST /notice",
                        "POST /events",
                        "GET /kv/{key}",
                        "PUT /kv/{key}",
                        "DELETE /kv/{key}",
                        "GET /sites",
                    ],
                })
            elif self.path == "/config":
                self._json(200, {"config": {}})
            elif self.path.startswith("/kv/"):
                key = self.path[len("/kv/"):]
                self._json(200, {"found": key in kv, "value": kv.get(key)})
            elif self.path == "/sites":
                self._json(200, {"sites": []})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._guard():
                return
            body = self._body()
            if self.path in ("/log", "/notice", "/events", "/runtime/config"):
                if verbose:
                    print(json.dumps({"path": self.path, "body": body}, ensure_ascii=False), flush=True)
                self._json(200, {"ok": True})
            elif self.path.startswith("/kv/"):
                key = self.path[len("/kv/"):]
                kv[key] = body.get("value")
                self._json(200, {"ok": True})
            else:
                self._json(404, {"error": "not found"})

        def do_PUT(self) -> None:
            self.do_POST()

        def do_DELETE(self) -> None:
            if not self._guard():
                return
            if self.path.startswith("/kv/"):
                key = self.path[len("/kv/"):]
                kv.pop(key, None)
                self._json(200, {"ok": True})
            else:
                self._json(404, {"error": "not found"})

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return ThreadingHTTPServer((bind_host, port), Handler)


def package_plugin(args: argparse.Namespace) -> None:
    plugin_dir = Path(args.plugin_dir).resolve()
    manifest = validate_manifest(plugin_dir)
    build_command, inferred_build = resolve_build_command(plugin_dir, args.build_command, args.skip_build)
    if build_command:
        prefix = "auto-build" if inferred_build else "build"
        print(f"{prefix}: {build_command}", file=sys.stderr)
    run_build_command(build_command, plugin_dir)
    manifest = validate_manifest(plugin_dir)
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / f"{manifest['id']}-{manifest['version']}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(plugin_dir.rglob("*")):
            if path.is_dir() or should_skip(path.relative_to(plugin_dir), args.include_node_modules):
                continue
            zf.write(path, path.relative_to(plugin_dir).as_posix())
    payload = archive.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    public_key = ""
    signature = ""
    if args.private_key:
        public_key, signature = sign_payload(args.private_key, payload)

    market_path = Path(args.market).resolve() if args.market else None
    previous = find_market_plugin(load_market_index(market_path), manifest["id"]) if market_path is not None else None
    archive_ref = resolve_archive_ref(archive, market_path, args.archive_ref)
    entry = build_market_entry(
        manifest,
        archive_ref,
        digest,
        signature,
        args,
        previous,
        auto_fill_release_metadata=market_path is not None,
    )
    if market_path is not None:
        update_market_index_file(market_path, entry, str(args.market_name or ""), public_key)
        print(f"updated market index: {market_path}", file=sys.stderr)
    if args.json_out:
        write_json_output(args.json_out, entry)
    print(json.dumps(entry, indent=2))


def keygen_market(args: argparse.Namespace) -> None:
    seed = os.urandom(32)
    public_key = ed25519_public_key(seed)
    private_path = Path(args.private_key_out).resolve()
    public_path = Path(args.public_key_out).resolve()
    write_key_text(private_path, encode_base64(seed), args.force)
    write_key_text(public_path, encode_base64(public_key), args.force)
    print(json.dumps({
        "private_key_path": str(private_path),
        "public_key_path": str(public_path),
        "public_key": encode_base64(public_key),
    }, indent=2))


def sign_file(args: argparse.Namespace) -> None:
    payload_path = Path(args.file).resolve()
    if not payload_path.exists():
        raise SystemExit(f"file not found: {payload_path}")
    payload = payload_path.read_bytes()
    public_key, signature = sign_payload(args.private_key, payload)
    print(json.dumps({
        "file": str(payload_path),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "public_key": public_key,
        "signature": signature,
    }, indent=2))


def update_market_index_file(
    market_path: Path,
    entry: dict[str, Any],
    market_name: str,
    public_key: str,
) -> None:
    index = load_market_index(market_path)
    existing_public_key = str(index.get("public_key") or "").strip()
    if existing_public_key and public_key and existing_public_key != public_key:
        raise SystemExit(
            "market public_key does not match the provided signing key; rotating keys requires re-signing every market item"
        )
    final_public_key = public_key or existing_public_key
    if final_public_key and not str(entry.get("signature") or "").strip():
        raise SystemExit("signed markets require a signature for every plugin entry")

    plugins = index.get("plugins")
    if plugins is None:
        plugins = []
    if not isinstance(plugins, list):
        raise SystemExit("market index plugins must be an array")

    updated_plugins: list[dict[str, Any]] = []
    replaced = False
    for item in plugins:
        if not isinstance(item, dict):
            raise SystemExit("market index plugins must only contain objects")
        item_id = str(item.get("id") or "").strip()
        if item_id == entry["id"]:
            updated_plugins.append(copy.deepcopy(entry))
            replaced = True
            continue
        updated_plugins.append(copy.deepcopy(item))
    if not replaced:
        updated_plugins.append(copy.deepcopy(entry))
    updated_plugins.sort(key=lambda item: str(item.get("id") or "").lower())
    if final_public_key:
        unsigned = [str(item.get("id") or "").strip() for item in updated_plugins if not str(item.get("signature") or "").strip()]
        if unsigned:
            raise SystemExit(
                "signed markets require signatures for every plugin entry; unsigned entries: " + ", ".join(unsigned)
            )

    app_version, app_version_known = detect_app_version()
    index["version"] = 1
    index["api_version"] = SUPPORTED_API_VERSION
    if app_version_known:
        index["app_version"] = app_version
    elif str(index.get("app_version") or "").strip():
        index["app_version"] = str(index["app_version"]).strip()
    else:
        index.pop("app_version", None)
    index["host_capabilities"] = list(SUPPORTED_HOST_CAPABILITIES)
    index["name"] = market_name.strip() or str(index.get("name") or "").strip() or "PTPatronus Plugin Market"
    if final_public_key:
        index["public_key"] = final_public_key
    else:
        index.pop("public_key", None)
    index["plugins"] = updated_plugins
    write_market_index(market_path, index)


def validate_plugin(args: argparse.Namespace) -> None:
    manifest = validate_manifest(Path(args.plugin_dir).resolve())
    print(f"ok: {manifest['id']} v{manifest['version']}")


def dev_plugin(args: argparse.Namespace) -> None:
    plugin_dir = Path(args.plugin_dir).resolve()
    if not plugin_dir.exists():
        raise SystemExit(f"plugin directory not found: {plugin_dir}")
    manifest = validate_manifest(plugin_dir)
    build_command, inferred_build = resolve_build_command(plugin_dir, args.build_command, args.skip_build)
    if build_command:
        prefix = "auto-build" if inferred_build else "build"
        print(f"{prefix}: {build_command}")
    run_build_command(build_command, plugin_dir)
    target_dir = resolve_dev_target(plugin_dir, manifest, args)
    target_dir_before = target_dir
    in_place = target_dir == plugin_dir

    if in_place:
        print(f"validated {manifest['id']} in place: {plugin_dir}")
    else:
        stats = sync_plugin_tree(plugin_dir, target_dir, args.include_node_modules)
        print(f"synced {manifest['id']} -> {target_dir} ({format_sync_summary(stats)})")
    if args.once:
        return

    fingerprint = tree_fingerprint(plugin_dir, args.include_node_modules)
    print("watching source changes; press Ctrl+C to stop")
    try:
        while True:
            time.sleep(max(args.interval, 0.2))
            current = tree_fingerprint(plugin_dir, args.include_node_modules)
            if current == fingerprint:
                continue
            fingerprint = current
            stamp = time.strftime("%H:%M:%S")
            try:
                manifest = validate_manifest(plugin_dir)
                build_command, inferred_build = resolve_build_command(plugin_dir, args.build_command, args.skip_build)
                if build_command:
                    prefix = "auto-build" if inferred_build else "build"
                    print(f"[{stamp}] {prefix}: {build_command}")
                run_build_command(build_command, plugin_dir)
                target_dir = resolve_dev_target(plugin_dir, manifest, args)
                if target_dir != target_dir_before and target_dir_before != plugin_dir:
                    print(f"[{stamp}] plugin id changed; new target: {target_dir}")
                target_dir_before = target_dir
                if target_dir == plugin_dir:
                    fingerprint = tree_fingerprint(plugin_dir, args.include_node_modules)
                    print(f"[{stamp}] validated {manifest['id']} v{manifest['version']}")
                    continue
                stats = sync_plugin_tree(plugin_dir, target_dir, args.include_node_modules)
                fingerprint = tree_fingerprint(plugin_dir, args.include_node_modules)
                print(f"[{stamp}] synced {manifest['id']} -> {target_dir} ({format_sync_summary(stats)})")
            except SystemExit as exc:
                print(f"[{stamp}] {exc}", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        print("stopped")


def mock_host(args: argparse.Namespace) -> None:
    server = create_mock_host_server(args.host, args.port, args.token, verbose=True)
    base_url = f"http://{args.host}:{server.server_port}"
    print(f"PTP_HOST_URL={base_url}")
    print(f"PTP_HOST_TOKEN={args.token}")
    print("mock host ready; press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def run_plugin(args: argparse.Namespace) -> None:
    plugin_dir = Path(args.plugin_dir).resolve()
    manifest = validate_manifest(plugin_dir)
    entry = manifest.get("entry") if isinstance(manifest.get("entry"), dict) else {}
    if not entry.get("command"):
        raise SystemExit("run currently supports command-launched plugins only; use mock-host for base_url-only plugins")

    host_bind = args.host
    host_port = args.host_port if args.host_port > 0 else free_port()
    plugin_port = args.plugin_port if args.plugin_port > 0 else free_port()
    if host_port == plugin_port:
        raise SystemExit("host-port and plugin-port must be different")

    host_token = args.host_token or random_token()
    plugin_token = args.plugin_token or random_token()
    host_server = create_mock_host_server(host_bind, host_port, host_token, verbose=not args.quiet_host)
    host_thread = threading.Thread(target=host_server.serve_forever, daemon=True)
    host_thread.start()
    host_url = f"http://{host_bind}:{host_server.server_port}"
    plugin_url = f"http://127.0.0.1:{plugin_port}"

    env = os.environ.copy()
    env.update({
        "PTP_PLUGIN_ID": manifest["id"],
        "PTP_PLUGIN_PORT": str(plugin_port),
        "PTP_PLUGIN_TOKEN": plugin_token,
        "PTP_PLUGIN_BASE_URL": plugin_url,
        "PTP_PLUGIN_DIR": str(plugin_dir),
        "PTP_HOST_URL": host_url,
        "PTP_HOST_TOKEN": host_token,
        "PTP_HOST_PROTOCOL": "1",
        "PTP_HOST_CAPABILITIES": ",".join(SUPPORTED_HOST_CAPABILITIES),
    })
    for key, value in (entry.get("env") or {}).items():
        env[str(key)] = replace_vars(str(value), plugin_port, plugin_token, plugin_dir, manifest["id"])

    command = resolve_command(plugin_dir, str(entry.get("command") or ""))
    command_args = [replace_vars(str(item), plugin_port, plugin_token, plugin_dir, manifest["id"]) for item in (entry.get("args") or [])]
    work_dir = resolve_work_dir(plugin_dir, entry.get("work_dir"))

    print(f"host:   {host_url}")
    print(f"plugin: {plugin_url}")
    print(f"id:     {manifest['id']}")
    print(f"token:  {plugin_token}")
    print(f"exec:   {command} {' '.join(command_args)}".rstrip())

    process: subprocess.Popen[Any] | None = None
    try:
        try:
            process = subprocess.Popen([command, *command_args], cwd=work_dir, env=env)
        except FileNotFoundError as exc:
            raise SystemExit(f"command not found: {command}") from exc
        wait_for_health(plugin_url, str(entry.get("health") or "/health"), args.timeout, process)
        print("plugin healthy")

        config = defaults_from_schema(manifest.get("config_schema") if isinstance(manifest.get("config_schema"), list) else [])
        config.update(parse_json_object_arg("config", args.config))
        host_context = build_host_context(manifest, host_url, host_token)

        if args.event:
            event_response = plugin_request(plugin_url, plugin_token, "/event", {
                "type": args.event,
                "data": parse_json_object_arg("event-data", args.event_data),
                "config": config,
                "host": host_context,
            })
            print("event response:")
            print(json.dumps(event_response, indent=2, ensure_ascii=False))

        if args.action:
            action_response = plugin_request(plugin_url, plugin_token, "/action", {
                "action": args.action,
                "input": parse_json_object_arg("input", args.input),
                "config": config,
                "host": host_context,
            })
            print("action response:")
            print(json.dumps(action_response, indent=2, ensure_ascii=False))

        if args.once:
            return

        print("sandbox running; press Ctrl+C to stop")
        while True:
            if process.poll() is not None:
                raise SystemExit(f"plugin process exited with code {process.returncode}")
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("stopping")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        host_server.shutdown()
        host_server.server_close()
        host_thread.join(timeout=2)


PYTHON_TEMPLATE = r'''import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request


PLUGIN_TOKEN = os.environ.get("PTP_PLUGIN_TOKEN", "")


def host_context(payload):
    host = payload.get("host") or {}
    return {
        "base_url": os.environ.get("PTP_HOST_URL") or host.get("base_url", ""),
        "token": os.environ.get("PTP_HOST_TOKEN") or host.get("token", ""),
    }


def host_request(host, method, path, body=None):
    if not host["base_url"] or not host["token"]:
        return None
    data = None
    headers = {"Authorization": f"Bearer {host['token']}"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(host["base_url"].rstrip("/") + path, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=5) as res:
        raw = res.read().decode("utf-8")
        return json.loads(raw) if raw else {}


class Handler(BaseHTTPRequestHandler):
    def _auth(self):
        return not PLUGIN_TOKEN or self.headers.get("Authorization") == f"Bearer {PLUGIN_TOKEN}"

    def _json(self, status, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            self._json(401, {"error": "unauthorized"})
            return
        payload = self._body()
        host = host_context(payload)
        if self.path == "/event":
            host_request(host, "POST", "/log", {
                "level": "info",
                "event": payload.get("type", "event"),
                "message": "event received",
                "data": payload.get("data") or {},
            })
            self._json(200, {"ok": True})
            return
        if self.path == "/action":
            cfg = payload.get("config") or {}
            prefix = cfg.get("prefix") or "pong"
            counter = host_request(host, "GET", "/kv/ping-count") or {"found": False}
            next_count = int(counter.get("value") or 0) + 1
            host_request(host, "PUT", "/kv/ping-count", {"value": next_count})
            host_request(host, "POST", "/events", {
                "type": "plugin.demo.ping",
                "data": {"count": next_count},
            })
            self._json(200, {
                "ok": True,
                "output": {
                    "message": f"{prefix}: {payload.get('input') or {}}",
                    "count": next_count,
                },
            })
            return
        self._json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("PTP_PLUGIN_PORT", "19090"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
'''


TYPESCRIPT_TSCONFIG_TEMPLATE = """{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts"]
}
"""


TYPESCRIPT_TEMPLATE = r'''import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'

type JsonObject = Record<string, any>

const pluginToken = process.env.PTP_PLUGIN_TOKEN || ''

function hostContext(payload: JsonObject = {}) {
  const host = (payload.host || {}) as JsonObject
  return {
    baseUrl: process.env.PTP_HOST_URL || String(host.base_url || ''),
    token: process.env.PTP_HOST_TOKEN || String(host.token || ''),
  }
}

async function readBody(req: IncomingMessage): Promise<JsonObject> {
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  if (!chunks.length) return {}
  return JSON.parse(Buffer.concat(chunks).toString('utf-8'))
}

function writeJson(res: ServerResponse, status: number, data: JsonObject) {
  const raw = Buffer.from(JSON.stringify(data))
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.setHeader('Content-Length', String(raw.length))
  res.end(raw)
}

async function hostRequest(host: { baseUrl: string; token: string }, method: string, path: string, body?: JsonObject) {
  if (!host.baseUrl || !host.token) return null
  const res = await fetch(host.baseUrl.replace(/\/+$/, '') + path, {
    method,
    headers: {
      Authorization: `Bearer ${host.token}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  if (!res.ok) {
    throw new Error(`Host request ${method} ${path} failed: ${res.status} ${text}`)
  }
  return text ? JSON.parse(text) : {}
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      writeJson(res, 200, { ok: true })
      return
    }

    if (pluginToken && req.headers.authorization !== `Bearer ${pluginToken}`) {
      writeJson(res, 401, { error: 'unauthorized' })
      return
    }

    const payload = await readBody(req)
    const host = hostContext(payload)

    if (req.method === 'POST' && req.url === '/event') {
      await hostRequest(host, 'POST', '/log', {
        level: 'info',
        event: String(payload.type || 'plugin.event'),
        message: 'event received',
        data: payload.data || {},
      })
      writeJson(res, 200, { ok: true })
      return
    }

    if (req.method === 'POST' && req.url === '/action') {
      const config = (payload.config || {}) as JsonObject
      const prefix = String(config.prefix || 'pong')
      const current = (await hostRequest(host, 'GET', '/kv/ping-count')) || { found: false }
      const next = Number(current.value || 0) + 1
      await hostRequest(host, 'PUT', '/kv/ping-count', { value: next })
      await hostRequest(host, 'POST', '/events', {
        type: 'plugin.demo.ping',
        data: { count: next },
      })
      writeJson(res, 200, {
        ok: true,
        output: {
          message: `${prefix}: ${JSON.stringify(payload.input || {})}`,
          count: next,
        },
      })
      return
    }

    writeJson(res, 404, { error: 'not found' })
  } catch (error) {
    writeJson(res, 500, { error: error instanceof Error ? error.message : String(error) })
  }
})

const port = Number(process.env.PTP_PLUGIN_PORT || '19090')
server.listen(port, '127.0.0.1', () => {
  console.log(`plugin listening on http://127.0.0.1:${port}`)
})
'''


TYPESCRIPT_VIEW_TSCONFIG_TEMPLATE = """{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "outDir": "web",
    "rootDir": "web-src",
    "strict": true,
    "skipLibCheck": true,
    "lib": ["DOM", "ES2022"]
  },
  "include": ["web-src/**/*.ts", "web-src/**/*.d.ts"]
}
"""


TYPESCRIPT_VIEW_BUILD_SCRIPT_TEMPLATE = r"""import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs'
import { dirname, extname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = join(root, 'web')
const srcDir = join(root, 'web-src')
const tsc = join(root, 'node_modules', 'typescript', 'lib', 'tsc.js')

rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

const result = spawnSync(process.execPath, [tsc, '-p', 'tsconfig.view.json'], {
  cwd: root,
  stdio: 'inherit',
})
if (result.status !== 0) {
  process.exit(result.status ?? 1)
}

copyStatic(srcDir)

function copyStatic(current) {
  for (const entry of readdirSync(current)) {
    const src = join(current, entry)
    const rel = relative(srcDir, src)
    const dst = join(outDir, rel)
    const st = statSync(src)
    if (st.isDirectory()) {
      mkdirSync(dst, { recursive: true })
      copyStatic(src)
      continue
    }
    if (extname(src) === '.ts' || extname(src) === '.d.ts') {
      continue
    }
    mkdirSync(dirname(dst), { recursive: true })
    cpSync(src, dst)
  }
}
"""


TYPESCRIPT_VIEW_INDEX_TEMPLATE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Plugin View</title>
    <link rel="stylesheet" href="./styles.css" />
  </head>
  <body>
    <div class="shell">
      <header class="hero">
        <div>
          <div class="eyebrow">Plugin View</div>
          <h1>External HTTP Plugin</h1>
          <p>Built assets under <code>web/</code> are loaded inside the host iframe. Edit <code>web-src/</code>, then run <code>npm run build:view</code>.</p>
        </div>
        <button id="refresh" type="button">Refresh</button>
      </header>

      <section class="grid">
        <div class="panel">
          <div class="panel-title">Host State</div>
          <div id="status" class="status">Connecting…</div>
        </div>
        <div class="panel">
          <div class="panel-title">Counter</div>
          <div id="count" class="count">0</div>
          <button id="increment" type="button">Increment</button>
        </div>
      </section>

      <section class="panel">
        <div class="panel-title">Details</div>
        <pre id="meta" class="meta">Waiting for host bridge…</pre>
      </section>
    </div>
    <script type="module" src="./main.js"></script>
  </body>
</html>
"""


TYPESCRIPT_VIEW_STYLES_TEMPLATE = """:root {
  color-scheme: light dark;
  font-family: Inter, system-ui, sans-serif;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: #0f172a;
  color: #f8fafc;
}

code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}

.shell {
  max-width: 960px;
  margin: 0 auto;
  padding: 24px;
}

.hero,
.panel {
  background: rgba(15, 23, 42, 0.92);
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 8px;
}

.hero {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  padding: 20px;
}

.eyebrow {
  font-size: 12px;
  color: #94a3b8;
  text-transform: uppercase;
}

h1 {
  margin: 4px 0 10px;
  font-size: 28px;
}

p {
  margin: 0;
  color: #cbd5e1;
  line-height: 1.5;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-top: 16px;
}

.panel {
  padding: 18px;
}

.panel-title {
  margin-bottom: 12px;
  font-size: 14px;
  color: #94a3b8;
}

.status {
  color: #38bdf8;
}

.count {
  margin-bottom: 12px;
  font-size: 40px;
  font-weight: 600;
}

.meta {
  margin: 0;
  white-space: pre-wrap;
  color: #cbd5e1;
}

button {
  border: 0;
  border-radius: 8px;
  padding: 10px 14px;
  background: #2563eb;
  color: #fff;
  font: inherit;
  cursor: pointer;
}

button:hover {
  background: #1d4ed8;
}
"""


TYPESCRIPT_VIEW_TYPES_TEMPLATE = """export {}

declare global {
  interface Window {
    PTPatronus?: {
      capabilities: () => Promise<{ host_capabilities?: string[]; permissions?: string[] }>
      config?: { get: () => Promise<Record<string, unknown>> }
      log: (level: string, event: string, message: string, data?: Record<string, unknown>) => Promise<void>
      notice?: (title: string, body: string, level?: string) => Promise<void>
      publish: (type: string, data?: Record<string, unknown>) => Promise<void>
      kv: {
        get: (key: string) => Promise<{ found: boolean; value?: unknown }>
        set: (key: string, value: unknown) => Promise<void>
        delete: (key: string) => Promise<void>
      }
      sites?: {
        list: () => Promise<Array<{ id: number; name: string; base_url: string }>>
      }
    }
  }
}
"""


TYPESCRIPT_VIEW_MAIN_TEMPLATE = """const statusEl = element('status')
const countEl = element('count')
const metaEl = element('meta')
const refreshButton = button('refresh')
const incrementButton = button('increment')

refreshButton.addEventListener('click', () => {
  void load()
})

incrementButton.addEventListener('click', () => {
  void incrementCount()
})

void load()

async function load() {
  const host = window.PTPatronus
  if (!host) {
    statusEl.textContent = 'Host bridge unavailable'
    metaEl.textContent = 'Open this page inside PTPatronus to access the plugin view bridge.'
    incrementButton.disabled = true
    refreshButton.disabled = true
    return
  }
  incrementButton.disabled = false
  refreshButton.disabled = false
  const [caps, config, current] = await Promise.all([
    host.capabilities(),
    host.config?.get?.() ?? Promise.resolve({}),
    host.kv.get('view-count'),
  ])
  statusEl.textContent = 'Connected'
  countEl.textContent = String(Number(current.value || 0))
  metaEl.textContent = [
    'Permissions: ' + ((caps.permissions || []).join(', ') || '(none)'),
    'Capabilities: ' + ((caps.host_capabilities || []).join(', ') || '(none)'),
    'Config: ' + JSON.stringify(config),
  ].join('\\n')
}

async function incrementCount() {
  const host = window.PTPatronus
  if (!host) return
  const current = await host.kv.get('view-count')
  const next = Number(current.value || 0) + 1
  await host.kv.set('view-count', next)
  await host.log('info', 'plugin.view.increment', 'incremented plugin view counter', { next })
  if (host.notice) {
    await host.notice('Plugin counter updated', `Current value: ${next}`, 'info')
  }
  await load()
}

function element(id: string): HTMLElement {
  const found = document.getElementById(id)
  if (!found) throw new Error(`Missing element #${id}`)
  return found
}

function button(id: string): HTMLButtonElement {
  return element(id) as HTMLButtonElement
}
"""


TYPESCRIPT_VIEW_MAIN_JS_TEMPLATE = """const statusEl = element('status');
const countEl = element('count');
const metaEl = element('meta');
const refreshButton = button('refresh');
const incrementButton = button('increment');

refreshButton.addEventListener('click', () => {
  void load();
});

incrementButton.addEventListener('click', () => {
  void incrementCount();
});

void load();

async function load() {
  const host = window.PTPatronus;
  if (!host) {
    statusEl.textContent = 'Host bridge unavailable';
    metaEl.textContent = 'Open this page inside PTPatronus to access the plugin view bridge.';
    incrementButton.disabled = true;
    refreshButton.disabled = true;
    return;
  }
  incrementButton.disabled = false;
  refreshButton.disabled = false;
  const [caps, config, current] = await Promise.all([
    host.capabilities(),
    host.config?.get?.() ?? Promise.resolve({}),
    host.kv.get('view-count'),
  ]);
  statusEl.textContent = 'Connected';
  countEl.textContent = String(Number(current.value || 0));
  metaEl.textContent = [
    'Permissions: ' + ((caps.permissions || []).join(', ') || '(none)'),
    'Capabilities: ' + ((caps.host_capabilities || []).join(', ') || '(none)'),
    'Config: ' + JSON.stringify(config),
  ].join('\\n');
}

async function incrementCount() {
  const host = window.PTPatronus;
  if (!host) return;
  const current = await host.kv.get('view-count');
  const next = Number(current.value || 0) + 1;
  await host.kv.set('view-count', next);
  await host.log('info', 'plugin.view.increment', 'incremented plugin view counter', { next });
  if (host.notice) {
    await host.notice('Plugin counter updated', `Current value: ${next}`, 'info');
  }
  await load();
}

function element(id) {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing element #${id}`);
  return found;
}

function button(id) {
  return element(id);
}
"""


VIEW_TEMPLATE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Plugin View</title>
    <style>
      :root {
        color-scheme: light dark;
        font-family: Inter, system-ui, sans-serif;
      }
      body {
        margin: 0;
        padding: 24px;
        background: #0b1020;
        color: #f5f7fb;
      }
      .shell {
        max-width: 720px;
        margin: 0 auto;
      }
      .panel {
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid rgba(148, 163, 184, 0.24);
        border-radius: 8px;
        padding: 20px;
      }
      h1 {
        margin: 0 0 8px;
        font-size: 24px;
      }
      p {
        margin: 0 0 16px;
        color: #cbd5e1;
      }
      button {
        border: 0;
        border-radius: 8px;
        padding: 10px 14px;
        background: #3b82f6;
        color: #fff;
        font: inherit;
        cursor: pointer;
      }
      .meta {
        margin-top: 16px;
        color: #94a3b8;
        font-size: 14px;
        white-space: pre-wrap;
      }
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="panel">
        <h1>Plugin View</h1>
        <p>This page is loaded from your plugin package and can talk to the host through the injected bridge.</p>
        <button id="run" type="button">Increment View Counter</button>
        <div id="meta" class="meta">Waiting for host bridge...</div>
      </div>
    </div>
    <script>
      const meta = document.getElementById('meta');
      const run = document.getElementById('run');

      async function refresh() {
        if (!window.PTPatronus) {
          meta.textContent = 'The host bridge is available only inside the PTPatronus plugin view shell.';
          run.disabled = true;
          return;
        }
        const caps = await window.PTPatronus.capabilities();
        const config = window.PTPatronus.config ? await window.PTPatronus.config.get() : {};
        const current = await window.PTPatronus.kv.get('view-count');
        meta.textContent = [
          'Capabilities: ' + (caps.host_capabilities || []).join(', '),
          'Config: ' + JSON.stringify(config),
          'Current view-count: ' + String(current.value || 0),
        ].join('\\n');
      }

      run.addEventListener('click', async () => {
        if (!window.PTPatronus) return;
        const current = await window.PTPatronus.kv.get('view-count');
        const next = Number(current.value || 0) + 1;
        await window.PTPatronus.kv.set('view-count', next);
        await window.PTPatronus.log('info', 'plugin.view.click', 'incremented demo counter', { next });
        await refresh();
      });

      refresh().catch((error) => {
        meta.textContent = error instanceof Error ? error.message : String(error);
      });
    </script>
  </body>
</html>
"""


# ---------------------------------------------------------------------------
# Official market aggregation
# ---------------------------------------------------------------------------


def format_archive_ref(pattern: str, release_base: str, entry: dict[str, Any]) -> str:
    return (
        pattern
        .replace("{release_base}", release_base)
        .replace("{id}", str(entry.get("id") or ""))
        .replace("{version}", str(entry.get("version") or ""))
        .replace("{name}", slugify(str(entry.get("name") or entry.get("id") or "")))
    )


def validate_package_entry(path: Path, entry: dict[str, Any]) -> None:
    errors: list[str] = []
    for field in ("id", "version", "runtime", "archive"):
        if not str(entry.get(field) or "").strip():
            errors.append(f"missing required field: {field}")
    if errors:
        raise SystemExit(f"invalid package metadata {path}:\n- " + "\n- ".join(errors))


def collect_package_entries(args: argparse.Namespace) -> list[tuple[Path, dict[str, Any]]]:
    out_resolved = Path(args.out).resolve() if str(getattr(args, "out", "") or "").strip() else None
    entries: list[tuple[Path, dict[str, Any]]] = []
    seen: set[Path] = set()

    for raw in getattr(args, "package", None) or []:
        path = Path(raw).resolve()
        if not path.exists():
            raise SystemExit(f"package metadata not found: {raw}")
        entry = read_json_file(path, "package metadata")
        validate_package_entry(path, entry)
        if path in seen:
            continue
        entries.append((path, entry))
        seen.add(path)

    packages_dir = str(getattr(args, "packages_dir", "") or "").strip()
    if packages_dir:
        root = Path(packages_dir).resolve()
        if not root.exists():
            raise SystemExit(f"packages-dir not found: {packages_dir}")
        for path in sorted(root.rglob("*.json")):
            resolved = path.resolve()
            if resolved in seen or (out_resolved is not None and resolved == out_resolved):
                continue
            try:
                entry = read_json_file(resolved, "package metadata")
            except SystemExit:
                continue
            if not isinstance(entry, dict):
                continue
            if not (
                str(entry.get("id") or "").strip()
                and str(entry.get("version") or "").strip()
                and str(entry.get("archive") or "").strip()
            ):
                continue
            entries.append((resolved, entry))
            seen.add(resolved)

    if not entries:
        raise SystemExit("no plugin package metadata found; pass --package and/or --packages-dir")
    return entries


def dedup_package_entries(
    path_entries: list[tuple[Path, dict[str, Any]]],
    keep: str,
) -> list[tuple[Path, dict[str, Any]]]:
    grouped: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    order: list[str] = []
    for path, entry in path_entries:
        plugin_id = str(entry.get("id") or "").strip()
        if plugin_id not in grouped:
            grouped[plugin_id] = []
            order.append(plugin_id)
        grouped[plugin_id].append((path, entry))

    kept: list[tuple[Path, dict[str, Any]]] = []
    for plugin_id in order:
        group = grouped[plugin_id]
        if keep == "all" or len(group) == 1:
            kept.extend(group)
            continue
        best = group[0]
        for candidate in group[1:]:
            if compare_versions(
                str(candidate[1].get("version") or ""),
                str(best[1].get("version") or ""),
            ) > 0:
                best = candidate
        dropped = [str(pe[1].get("version") or "") for pe in group if pe is not best]
        print(
            f"plugin {plugin_id}: multiple versions found, keeping {best[1].get('version')} "
            f"(dropped {', '.join(dropped)})",
            file=sys.stderr,
        )
        kept.append(best)
    return kept


def resolve_local_archive(archives_dir: Path, archive_ref: str) -> Path | None:
    ref = str(archive_ref or "").strip().replace("\\", "/")
    if not ref:
        return None
    basename = os.path.basename(ref)
    candidates = [archives_dir / basename, archives_dir / ref]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def verify_entry_archive(
    archives_dir: Path,
    entry: dict[str, Any],
    public_key: bytes | None,
    meta_path: Path,
) -> None:
    plugin_id = str(entry.get("id") or "")
    local = resolve_local_archive(archives_dir, str(entry.get("archive") or ""))
    if local is None:
        print(
            f"warning: archive not found locally for {plugin_id}, skipping integrity check",
            file=sys.stderr,
        )
        return
    payload = local.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    expected = str(entry.get("sha256") or "").strip()
    if expected:
        if digest.lower() != expected.lower():
            raise SystemExit(
                f"sha256 mismatch for {plugin_id} ({local.name}): expected {expected}, got {digest}"
            )
    else:
        print(f"warning: {plugin_id} has no sha256; recording {digest} from {local.name}", file=sys.stderr)
        entry["sha256"] = digest
    signature_b64 = str(entry.get("signature") or "").strip()
    if public_key is not None and signature_b64:
        signature = decode_base64_key("signature", signature_b64)
        if not ed25519_verify(public_key, payload, signature):
            raise SystemExit(f"signature verification failed for {plugin_id} ({local.name})")


def market_aggregate_cmd(args: argparse.Namespace) -> None:
    release_base = str(getattr(args, "release_base", "") or "").strip()
    archive_pattern = str(getattr(args, "archive_pattern", "") or "").strip()
    rewrite = bool(release_base or archive_pattern)
    pattern = archive_pattern or "{release_base}/{id}-v{version}/{id}-{version}.zip"

    public_key_arg = str(getattr(args, "public_key", "") or "").strip()
    private_key_arg = str(getattr(args, "private_key", "") or "").strip()

    archives_dir = (
        Path(args.archives_dir).resolve()
        if str(getattr(args, "archives_dir", "") or "").strip()
        else None
    )

    # Central re-sign: the operator holds the market key and signs every archive
    # locally. This is the curated-market model — authors submit unsigned zips and
    # the key never leaves the operator. Requires the archive bytes on disk.
    resign_mode = bool(private_key_arg)
    if resign_mode and archives_dir is None:
        raise SystemExit(
            "central re-sign (--private-key) requires --archives-dir so every archive can be hashed and signed"
        )
    seed: bytes | None = None
    if resign_mode:
        seed = load_private_key_seed(private_key_arg)
        public_key = ed25519_public_key(seed)
        public_key_b64 = encode_base64(public_key)
    elif public_key_arg:
        public_key = load_public_key_bytes(public_key_arg)
        public_key_b64 = encode_base64(public_key)
    else:
        public_key = None
        public_key_b64 = ""

    raw_entries = collect_package_entries(args)
    rewritten: list[tuple[Path, dict[str, Any]]] = []
    for path, entry in raw_entries:
        normalized = copy.deepcopy(entry)
        if rewrite:
            normalized["archive"] = format_archive_ref(pattern, release_base, normalized)
        rewritten.append((path, normalized))

    kept = dedup_package_entries(rewritten, args.keep)

    for path, entry in kept:
        plugin_id = str(entry.get("id") or "")
        if resign_mode:
            local = resolve_local_archive(archives_dir, str(entry.get("archive") or ""))
            if local is None:
                raise SystemExit(
                    f"central re-sign requires every archive locally; not found for {plugin_id}"
                )
            payload = local.read_bytes()
            signature = ed25519_sign(seed, payload)
            if not ed25519_verify(public_key, payload, signature):
                raise SystemExit(f"generated signature failed self-verification for {plugin_id}")
            entry["signature"] = encode_base64(signature)
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            continue
        signature = str(entry.get("signature") or "").strip()
        if public_key_b64:
            if not signature:
                raise SystemExit(
                    f"signed market (--public-key) requires every plugin entry to be signed; "
                    f"unsigned entry: {plugin_id}"
                )
            if archives_dir is not None:
                verify_entry_archive(archives_dir, entry, public_key, path)
        elif signature:
            raise SystemExit(
                f"plugin {plugin_id} carries a signature but --public-key was not given; "
                "pass --public-key to build a signed market"
            )

    plugins = [copy.deepcopy(entry) for _, entry in kept]
    plugins.sort(key=lambda item: str(item.get("id") or "").lower())

    name = str(getattr(args, "name", "") or "").strip() or "PTPatronus Plugin Market"
    app_version, app_version_known = detect_app_version()
    resolved_app_version = (
        str(getattr(args, "app_version", "") or "").strip()
        or (app_version if app_version_known else "")
    )

    index: dict[str, Any] = {
        "version": 1,
        "name": name,
        "api_version": SUPPORTED_API_VERSION,
    }
    if resolved_app_version:
        index["app_version"] = resolved_app_version
    index["host_capabilities"] = list(SUPPORTED_HOST_CAPABILITIES)
    if public_key_b64:
        index["public_key"] = public_key_b64
    index["plugins"] = plugins

    out_path = Path(args.out).resolve()
    write_market_index(out_path, index)
    trust = "signed" if public_key_b64 else "unsigned"
    print(f"aggregated {len(plugins)} plugin(s) -> {out_path} ({trust})")


def market_init_cmd(args: argparse.Namespace) -> None:
    target = Path(args.directory).resolve()
    if target.exists() and any(target.iterdir()) and not args.force:
        raise SystemExit(f"target directory is not empty: {target} (use --force)")
    target.mkdir(parents=True, exist_ok=True)

    name = str(getattr(args, "name", "") or "").strip() or "PTPatronus Plugin Market"
    release_base = str(getattr(args, "release_base", "") or "").strip()

    packages_dir = target / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)
    (packages_dir / ".gitkeep").write_text("", encoding="utf-8")

    # The vendored tool is what makes the scaffold immediately runnable; always include it.
    tool_dir = write_vendored_tools(target, "tools/ptpatronus")
    tool_rel = workflow_tool_path(target, tool_dir / "pluginctl.py")

    keys_dir = target / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    public_key_rel = ""
    if args.generate_keys:
        seed = os.urandom(32)
        public_key = ed25519_public_key(seed)
        write_key_text(keys_dir / "plugin-market.private.key", encode_base64(seed), True)
        write_key_text(keys_dir / "plugin-market.public.key", encode_base64(public_key), True)
        public_key_rel = "keys/plugin-market.public.key"
        print(f"generated market keypair in {keys_dir}")
        print("keep plugin-market.private.key secret; it is gitignored")

    write_market_index(target / "plugin-market.json", {
        "version": 1,
        "name": name,
        "api_version": SUPPORTED_API_VERSION,
        "host_capabilities": list(SUPPORTED_HOST_CAPABILITIES),
        "plugins": [],
    })
    (target / "README.md").write_text(
        market_readme_template(name, release_base, public_key_rel),
        encoding="utf-8",
    )
    (target / ".gitignore").write_text(MARKET_GITIGNORE_TEMPLATE, encoding="utf-8")

    workflow_dir = target / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / "aggregate.yml").write_text(
        market_aggregate_workflow_template(tool_rel, public_key_rel, name, release_base),
        encoding="utf-8",
    )
    print(f"created market repo scaffold at {target}")


def market_cmd(args: argparse.Namespace) -> None:
    command = getattr(args, "market_command", "")
    if command == "aggregate":
        market_aggregate_cmd(args)
    elif command == "init":
        market_init_cmd(args)
    else:  # pragma: no cover - argparse enforces required subcommand
        raise SystemExit("market requires a subcommand: aggregate | init")


MARKET_GITIGNORE_TEMPLATE = """# Market signing private key — never commit
*.private.key
keys/*.private.key

# Python
__pycache__/
"""


def market_readme_template(name: str, release_base: str, public_key_rel: str) -> str:
    if public_key_rel:
        signing_section = (
            f"The market is verified with the public key in `{public_key_rel}`. Keep the matching "
            "private key out of this repo (it is gitignored); provision it to each plugin's CI as the "
            "`PTP_PLUGIN_MARKET_PRIVATE_KEY` secret so every `plugin-package.json` arrives already "
            "signed by this key."
        )
    else:
        signing_section = (
            "No key was generated here. Run `pluginctl keygen` (or `market init --generate-keys`) and "
            "set `PTP_PLUGIN_MARKET_PRIVATE_KEY` in each plugin's CI so package metadata arrives signed; "
            "then pass `--public-key` when aggregating."
        )

    if release_base:
        archive_section = (
            f"Archive URLs are normalized to "
            f"`{release_base}/<plugin-id>-v<version>/<plugin-id>-<version>.zip` by the aggregate workflow."
        )
    else:
        archive_section = (
            "Each `plugin-package.json` already carries a full archive URL emitted by its plugin's CI; "
            "the aggregator merges them verbatim. Pass `--release-base` to normalize them to one scheme."
        )

    rebuild_lines = [
        "python tools/ptpatronus/pluginctl.py market aggregate",
        "  --packages-dir packages",
        "  --out plugin-market.json",
    ]
    if public_key_rel:
        rebuild_lines.append(f"  --public-key {public_key_rel}")
    if release_base:
        rebuild_lines.append(f"  --release-base {release_base}")
    rebuild_cmd = "\n".join(
        line + (" \\" if index < len(rebuild_lines) - 1 else "")
        for index, line in enumerate(rebuild_lines)
    )

    return f"""# {name}

This repository is an official PTPatronus plugin market. It aggregates per-plugin
metadata into a single `plugin-market.json` that the PTPatronus plugin browser fetches.

## Layout

```text
plugin-market.json   # aggregated index (generated; commit this)
packages/            # submitted plugin-package.json files, one per plugin
keys/                # market Ed25519 public key (committed) + private key (gitignored)
tools/ptpatronus/    # vendored pluginctl.py used to regenerate the index
.github/workflows/aggregate.yml
```

## How a plugin joins this market

1. The plugin's own CI runs `pluginctl.py package ... --json-out dist/plugin-package.json`
   with `PTP_PLUGIN_MARKET_PRIVATE_KEY` set to this market's signing key.
2. Copy the resulting `dist/plugin-package.json` into `packages/<plugin-id>.json`
   (open a PR, or let a dispatch workflow do it).
3. The `aggregate.yml` workflow regenerates `plugin-market.json` automatically on push to `packages/`.

{signing_section}

{archive_section}

## Rebuild the index locally

```bash
{rebuild_cmd}
```
"""


def market_aggregate_workflow_template(
    tool_rel: str,
    public_key_rel: str,
    name: str,
    release_base: str,
) -> str:
    public_key_arg = f" \\\n            --public-key {public_key_rel}" if public_key_rel else ""
    release_base_arg = f" \\\n            --release-base {release_base}" if release_base else ""
    return f"""name: Aggregate Plugin Market

on:
  push:
    branches: [main]
    paths:
      - 'packages/**'
      - 'keys/**'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  aggregate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Aggregate market index
        run: |
          python {tool_rel} market aggregate \\
            --packages-dir packages \\
            --out plugin-market.json \\
            --name "{name}"{public_key_arg}{release_base_arg}

      - name: Commit regenerated index
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          if git diff --quiet -- plugin-market.json; then
            echo "plugin-market.json is up to date"
          else
            git add plugin-market.json
            git commit -m "chore: regenerate plugin-market.json"
            git push
          fi
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PTPatronus plugin developer helper")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create an external-http plugin template")
    create.add_argument("plugin_id")
    create.add_argument("--directory")
    create.add_argument("--name")
    create.add_argument("--author", default="PTPatronus Developer")
    create.add_argument("--template", choices=["python", "typescript"], default="python")
    create.add_argument("--with-view", action="store_true", help="also scaffold web/index.html and a plugin view contribution")
    create.add_argument("--vendor-tools", action="store_true", help="copy pluginctl.py and manifest schema into the new repo")
    create.add_argument("--tool-dir", default="tools/ptpatronus", help="target directory used by --vendor-tools and --with-ci")
    create.add_argument("--with-ci", choices=["github", "gitea", "both"], default="", help="also scaffold CI workflows that package the plugin repo")
    create.set_defaults(func=create_plugin)

    vendor = sub.add_parser("vendor-tools", help="copy pluginctl.py and manifest schema into a plugin repo")
    vendor.add_argument("plugin_dir")
    vendor.add_argument("--out-dir", default="tools/ptpatronus")
    vendor.set_defaults(func=vendor_tools_cmd)

    ci = sub.add_parser("ci", help="write CI workflow templates for a plugin repo")
    ci.add_argument("plugin_dir")
    ci.add_argument("--provider", choices=["github", "gitea", "both"], default="both")
    ci.add_argument("--tool-path", default="tools/ptpatronus/pluginctl.py", help="path to pluginctl.py relative to the plugin repo")
    ci.add_argument("--vendor-tools", action="store_true", help="copy the official tool bundle before writing workflows")
    ci.add_argument("--tool-dir", default="tools/ptpatronus", help="target directory used with --vendor-tools")
    ci.set_defaults(func=ci_cmd)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 market signing keypair")
    keygen.add_argument("--private-key-out", default="plugin-market.private.key")
    keygen.add_argument("--public-key-out", default="plugin-market.public.key")
    keygen.add_argument("--force", action="store_true")
    keygen.set_defaults(func=keygen_market)

    sign = sub.add_parser("sign", help="sign a file with an Ed25519 market private key")
    sign.add_argument("file")
    sign.add_argument("--private-key", required=True, help="base64 seed or a path to a key file created by keygen")
    sign.set_defaults(func=sign_file)

    validate = sub.add_parser("validate", help="validate plugin.json")
    validate.add_argument("plugin_dir")
    validate.set_defaults(func=validate_plugin)

    dev = sub.add_parser("dev", help="watch a plugin source directory and sync it into a live plugin target")
    dev.add_argument("plugin_dir")
    dev.add_argument("--plugin-root", default="data/plugins")
    dev.add_argument("--target-dir")
    dev.add_argument("--interval", type=float, default=1.0)
    dev.add_argument("--once", action="store_true")
    dev.add_argument("--include-node-modules", action="store_true")
    dev.add_argument("--build-command", default="", help="optional command to run in the plugin directory before each sync")
    dev.add_argument("--skip-build", action="store_true", help="disable automatic build inference from package.json")
    dev.set_defaults(func=dev_plugin)

    run = sub.add_parser("run", help="run a plugin in a local sandbox with a mock Host API")
    run.add_argument("plugin_dir")
    run.add_argument("--host", default="127.0.0.1", help="bind address for the mock host API")
    run.add_argument("--host-port", type=int, default=0, help="port for the mock host API; 0 chooses a free port")
    run.add_argument("--plugin-port", type=int, default=0, help="port exposed to the plugin; 0 chooses a free port")
    run.add_argument("--host-token", default="", help="host bearer token override")
    run.add_argument("--plugin-token", default="", help="plugin bearer token override")
    run.add_argument("--timeout", type=float, default=8.0, help="seconds to wait for /health")
    run.add_argument("--config", default="", help="JSON object merged onto config_schema defaults")
    run.add_argument("--action", default="", help="action name to invoke after the plugin becomes healthy")
    run.add_argument("--input", default="{}", help="JSON object passed as action input")
    run.add_argument("--event", default="", help="event type to publish after the plugin becomes healthy")
    run.add_argument("--event-data", default="{}", help="JSON object passed as event data")
    run.add_argument("--once", action="store_true", help="exit after health checks and optional action/event")
    run.add_argument("--quiet-host", action="store_true", help="suppress mock host log/event echo")
    run.set_defaults(func=run_plugin)

    package = sub.add_parser("package", help="package a plugin directory as a zip archive")
    package.add_argument("plugin_dir")
    package.add_argument("--out-dir", default="dist/plugins")
    package.add_argument("--include-node-modules", action="store_true")
    package.add_argument("--build-command", default="", help="optional command to run in the plugin directory before packaging")
    package.add_argument("--skip-build", action="store_true", help="disable automatic build inference from package.json")
    package.add_argument("--json-out", default="", help="optional file path for the generated package metadata JSON")
    package.add_argument("--private-key", default="", help="base64 Ed25519 seed or a path to a key file created by keygen")
    package.add_argument("--market", default="", help="optional market index JSON file to create or update")
    package.add_argument("--market-name", default="", help="market display name used when creating a new index")
    package.add_argument("--archive-ref", default="", help="archive reference stored in market JSON; defaults to a path relative to --market")
    package.add_argument("--publisher-id", default="")
    package.add_argument("--publisher-name", default="")
    package.add_argument("--publisher-website", default="")
    package.add_argument("--publisher-verified", action="store_true")
    package.add_argument("--published-at", default="", help="release timestamp or 'now'; defaults to current UTC when updating a market")
    package.add_argument("--changelog", action="append", default=[], help="repeat for each changelog line")
    package.set_defaults(func=package_plugin)

    mock = sub.add_parser("mock-host", help="run a local mock Host API for plugin development")
    mock.add_argument("--host", default="127.0.0.1")
    mock.add_argument("--port", type=int, default=19091)
    mock.add_argument("--token", default="dev-token")
    mock.set_defaults(func=mock_host)

    market = sub.add_parser("market", help="build and scaffold an official plugin market index")
    market_sub = market.add_subparsers(dest="market_command", required=True)

    aggregate = market_sub.add_parser(
        "aggregate",
        help="merge plugin-package.json files into one plugin-market.json",
    )
    aggregate.add_argument(
        "--package",
        action="append",
        default=[],
        help="path to a plugin-package.json file (repeatable)",
    )
    aggregate.add_argument(
        "--packages-dir",
        default="",
        help="directory to scan for plugin package metadata JSON files",
    )
    aggregate.add_argument("--out", default="plugin-market.json", help="output market index path")
    aggregate.add_argument("--name", default="", help="market display name")
    aggregate.add_argument(
        "--public-key",
        default="",
        help="market public key (base64 or path); produces a signed market",
    )
    aggregate.add_argument(
        "--private-key",
        default="",
        help="central re-sign: re-hash and sign every archive with this market key (requires --archives-dir)",
    )
    aggregate.add_argument(
        "--release-base",
        default="",
        help="base URL used to rewrite each entry's archive ref",
    )
    aggregate.add_argument(
        "--archive-pattern",
        default="",
        help="archive ref template using {release_base}/{id}/{version}/{name} placeholders",
    )
    aggregate.add_argument(
        "--archives-dir",
        default="",
        help="local directory of plugin zip archives for sha256/signature verification",
    )
    aggregate.add_argument(
        "--keep",
        choices=["latest", "all"],
        default="latest",
        help="dedup strategy when multiple versions of a plugin are present",
    )
    aggregate.add_argument("--app-version", default="", help="override the top-level app_version")
    aggregate.set_defaults(func=market_cmd)

    market_init = market_sub.add_parser(
        "init",
        help="scaffold an official plugin market repository",
    )
    market_init.add_argument("directory")
    market_init.add_argument("--name", default="", help="market display name")
    market_init.add_argument(
        "--release-base",
        default="",
        help="release base URL written into the scaffold README and workflow",
    )
    market_init.add_argument(
        "--generate-keys",
        action="store_true",
        help="generate an Ed25519 market keypair into keys/",
    )
    market_init.add_argument("--force", action="store_true")
    market_init.set_defaults(func=market_cmd)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
