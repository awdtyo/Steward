"""Per-service support: health checks, log parsing hints, allowed actions.

Services are defined in a YAML file (services.yaml, gitignored; see
services.example.yaml). Five first-class services ship as built-ins used
when the file is absent: Jellyfin, Nextcloud, Tailscale, Vaultwarden, and
Uptime Kuma.

Vaultwarden is monitor-only, enforced in code: only container up/down,
certificate expiry, and backup checks; no log hints; no allowed actions;
its logs, env, and paths never reach the LLM (only fixed alert titles and
structured statuses leave the verifier).
"""

from __future__ import annotations

import os
import re
import socket
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .agent_tools import Backend, ToolError
from .collectors import Reading
from .rules import Incident

CHECK_TYPES = ("container", "http", "tls_expiry", "backup")
MONITOR_ONLY_CHECKS = ("container", "tls_expiry", "backup")
TIER1_ACTION_KINDS = ("restart_container", "clear_cache")


class ServiceConfigError(ValueError):
    """Raised when service definitions are missing or invalid."""


@dataclass(frozen=True)
class LogHint:
    pattern: str  # regex source (compiled at load)
    label: str
    severity: str  # info | warning | critical


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    container: str
    monitor_only: bool = False
    checks: tuple = ()
    log_hints: tuple = ()
    allowed_actions: tuple | None = None  # None = no per-service restriction


@dataclass(frozen=True)
class ServiceHealth:
    service: str
    check: str
    status: str  # ok | fail | unknown
    detail: str = ""  # structured, never raw logs/paths/URLs
    severity: str | None = None  # fail override; defaults per check type


@dataclass(frozen=True)
class BackupStatus:
    ok: bool
    reason: str  # missing | stale | empty | unencrypted | unreadable | ok
    age_hours: float | None = None
    size_bytes: int | None = None
    encrypted: bool = False


def _compile_hints(raw: object, service: str) -> tuple:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ServiceConfigError(f"{service}: log_hints must be a list")
    hints = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ServiceConfigError(f"{service}: log hint must be a mapping")
        for key in ("pattern", "label", "severity"):
            if key not in entry:
                raise ServiceConfigError(
                    f"{service}: log hint missing {key!r}")
        if entry["severity"] not in ("info", "warning", "critical"):
            raise ServiceConfigError(
                f"{service}: bad hint severity {entry['severity']!r}")
        try:
            re.compile(str(entry["pattern"]))
        except re.error as exc:
            raise ServiceConfigError(
                f"{service}: bad hint regex: {exc}") from exc
        hints.append(LogHint(str(entry["pattern"]), str(entry["label"]),
                             str(entry["severity"])))
    return tuple(hints)


def _validate_checks(raw: object, service: str) -> tuple:
    if not isinstance(raw, list) or not raw:
        raise ServiceConfigError(f"{service}: checks must be a non-empty list")
    checks = []
    for entry in raw:
        if not isinstance(entry, dict) or entry.get("type") not in CHECK_TYPES:
            raise ServiceConfigError(
                f"{service}: bad check {entry!r} (types: {CHECK_TYPES})")
        checks.append(dict(entry))
    return tuple(checks)


def _parse_spec(entry: dict) -> ServiceSpec:
    if not isinstance(entry, dict) or not entry.get("name"):
        raise ServiceConfigError("Each service needs a name")
    name = str(entry["name"])
    if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", name):
        raise ServiceConfigError(f"Bad service name: {name!r}")
    monitor_only = bool(entry.get("monitor_only", False))
    checks = _validate_checks(entry.get("checks"), name)
    if monitor_only:
        for check in checks:
            if check["type"] not in MONITOR_ONLY_CHECKS:
                raise ServiceConfigError(
                    f"{name}: monitor-only services allow only "
                    f"{MONITOR_ONLY_CHECKS}")
        if entry.get("log_hints"):
            raise ServiceConfigError(
                f"{name}: monitor-only services define no log hints")
    allowed = entry.get("allowed_actions")
    if allowed is not None:
        allowed = tuple(str(a) for a in allowed)
        for kind in allowed:
            if kind not in TIER1_ACTION_KINDS:
                raise ServiceConfigError(
                    f"{name}: bad allowed action {kind!r}")
        if monitor_only and allowed:
            raise ServiceConfigError(
                f"{name}: monitor-only services allow no actions")
    return ServiceSpec(
        name=name,
        container=str(entry.get("container", name)),
        monitor_only=monitor_only,
        checks=checks,
        log_hints=_compile_hints(entry.get("log_hints"), name),
        allowed_actions=allowed)


def default_specs() -> list[ServiceSpec]:
    """Built-in definitions used when services.yaml is absent."""
    return [
        ServiceSpec("jellyfin", "jellyfin", checks=(
            {"type": "container"},
            {"type": "http", "url": "http://127.0.0.1:8096/health",
             "timeout": 5},)),
        ServiceSpec("nextcloud", "nextcloud", checks=(
            {"type": "container"},
            {"type": "http", "url": "http://127.0.0.1:8080/status.php",
             "timeout": 5},)),
        ServiceSpec("tailscale", "tailscale",
                    checks=({"type": "container"},)),
        ServiceSpec("vaultwarden", "vaultwarden", monitor_only=True, checks=(
            {"type": "container"},
            {"type": "tls_expiry", "host": "127.0.0.1", "port": 8443,
             "warn_days": 30, "crit_days": 14},
            {"type": "backup", "max_age_hours": 26},),
            allowed_actions=()),
        ServiceSpec("uptime-kuma", "uptime-kuma", checks=(
            {"type": "container"},
            {"type": "http", "url": "http://127.0.0.1:3001/",
             "timeout": 5},)),
    ]


def load_services(path: str | None) -> list[ServiceSpec]:
    """Load service definitions; fall back to built-ins when absent."""
    if not path or not os.path.exists(path):
        return default_specs()
    import yaml
    try:
        with open(path, encoding="utf-8") as fh:
            payload = yaml.safe_load(fh)
    except OSError as exc:
        raise ServiceConfigError(f"Cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ServiceConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(
            payload.get("services"), list):
        raise ServiceConfigError(f"{path}: expected a 'services' list")
    specs = [_parse_spec(entry) for entry in payload["services"]]
    names = [spec.name for spec in specs]
    if len(set(names)) != len(names):
        raise ServiceConfigError(f"{path}: duplicate service names")
    return specs


def match_hints(spec: ServiceSpec, text: str) -> list[dict]:
    """Match a service's log hints against text. Pure function."""
    matched = []
    for hint in spec.log_hints:
        if re.search(hint.pattern, text):
            matched.append({"label": hint.label,
                            "severity": hint.severity})
    return matched


def check_container(spec: ServiceSpec, backend: Backend) -> ServiceHealth:
    try:
        info = backend.container_inspect(spec.container)
    except ToolError:
        return ServiceHealth(spec.name, "container", "unknown",
                             "container unavailable")
    running = str(info.get("status", "")).lower() == "running"
    return ServiceHealth(spec.name, "container",
                         "ok" if running else "fail",
                         "running" if running else str(
                             info.get("status", "not running"))[:50])


def _default_http_get(url: str, timeout: float) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "steward/health"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def check_http(spec: ServiceSpec, url: str, timeout: float = 5.0,
               http_get=None) -> ServiceHealth:
    get = http_get or _default_http_get
    try:
        status = get(url, timeout)
    except Exception:
        return ServiceHealth(spec.name, "http", "fail", "connection failed")
    if isinstance(status, int) and status < 400:
        return ServiceHealth(spec.name, "http", "ok", f"HTTP {status}")
    return ServiceHealth(spec.name, "http", "fail", f"HTTP {status}")


def _default_tls_connect(host: str, port: int, timeout: float) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return dict(tls.getpeercert() or {})


def check_tls_expiry(spec: ServiceSpec, host: str, port: int,
                     warn_days: float = 30.0, crit_days: float = 14.0,
                     timeout: float = 10.0, tls_connect=None) -> ServiceHealth:
    connect = tls_connect or _default_tls_connect
    try:
        cert = connect(host, port, timeout)
        expires = ssl.cert_time_to_seconds(str(cert["notAfter"]))
        days_left = (expires - time.time()) / 86400.0
    except Exception:
        return ServiceHealth(spec.name, "tls_expiry", "unknown",
                             "handshake failed")
    detail = f"expires in {max(0, int(days_left))} days"
    if days_left < crit_days:
        return ServiceHealth(spec.name, "tls_expiry", "fail", detail,
                             "critical")
    if days_left < warn_days:
        return ServiceHealth(spec.name, "tls_expiry", "fail", detail,
                             "warning")
    return ServiceHealth(spec.name, "tls_expiry", "ok", detail)


ENCRYPTED_EXTS = (".age", ".gpg", ".pgp", ".enc")
AGE_MAGIC = b"age-encryption.org"


def verify_backup_vaultwarden(backup_dir: str,
                              max_age_hours: float = 26.0,
                              now: float | None = None) -> BackupStatus:
    """Check a recent, non-empty, encrypted Vaultwarden backup exists.

    Reads directory listings plus a few header bytes only -- never full
    backup contents, and no paths ever leave this function in outputs.
    """
    now = time.time() if now is None else now
    try:
        entries = os.listdir(backup_dir)
    except FileNotFoundError:
        return BackupStatus(False, "missing")
    except OSError:
        return BackupStatus(False, "unreadable")
    candidates = []
    for entry in entries:
        full = os.path.join(backup_dir, entry)
        try:
            if os.path.isfile(full):
                stat = os.stat(full)
                candidates.append((stat.st_mtime, stat.st_size, full))
        except OSError:
            continue
    if not candidates:
        return BackupStatus(False, "missing")
    mtime, size, newest = max(candidates)
    age_hours = (now - mtime) / 3600.0
    if size <= 0:
        return BackupStatus(False, "empty", age_hours, size, False)
    encrypted = newest.lower().endswith(ENCRYPTED_EXTS)
    if not encrypted:
        try:
            with open(newest, "rb") as fh:
                header = fh.read(64)
            encrypted = header.startswith(AGE_MAGIC)
        except OSError:
            return BackupStatus(False, "unreadable", age_hours, size, False)
    if not encrypted:
        return BackupStatus(False, "unencrypted", age_hours, size, False)
    if age_hours > max_age_hours:
        return BackupStatus(False, "stale", age_hours, size, True)
    return BackupStatus(True, "ok", age_hours, size, True)


def run_health_checks(specs: list[ServiceSpec], backend: Backend, *,
                      backup_dir: str = "", dry_run: bool = False,
                      http_get=None, tls_connect=None,
                      now: float | None = None) -> list[ServiceHealth]:
    """Run every spec's checks. Tool errors -> 'unknown' (never incidents).

    In dry-run mode only container checks run (no real network or disk
    touches); http/tls/backup report 'unknown' (skipped).
    """
    now = time.time() if now is None else now
    results: list[ServiceHealth] = []
    for spec in specs:
        for check in spec.checks:
            kind = check["type"]
            if kind == "container":
                results.append(check_container(spec, backend))
            elif dry_run:
                results.append(ServiceHealth(spec.name, kind, "unknown",
                                             "skipped in dry-run"))
            elif kind == "http":
                results.append(check_http(
                    spec, str(check.get("url", "")),
                    float(check.get("timeout", 5)), http_get))
            elif kind == "tls_expiry":
                results.append(check_tls_expiry(
                    spec, str(check.get("host", "127.0.0.1")),
                    int(check.get("port", 443)),
                    float(check.get("warn_days", 30)),
                    float(check.get("crit_days", 14)),
                    tls_connect=tls_connect))
            elif kind == "backup":
                if spec.name in ("vaultwarden",) and backup_dir:
                    status = verify_backup_vaultwarden(
                        backup_dir, float(check.get("max_age_hours", 26)),
                        now)
                    if status.ok:
                        results.append(ServiceHealth(
                            spec.name, kind, "ok",
                            f"backup {int(status.age_hours or 0)}h old"))
                    else:
                        results.append(ServiceHealth(
                            spec.name, kind, "fail", status.reason))
                else:
                    results.append(ServiceHealth(spec.name, kind, "unknown",
                                                 "backup dir unconfigured"))
    return results


def services_to_readings(health: list[ServiceHealth],
                         now: float | None = None) -> list[Reading]:
    """Health history as readings (unknown metrics stay rule-invisible)."""
    now = time.time() if now is None else now
    return [Reading("services", item.service, item.check, item.status,
                    "", now, item.status != "unknown", item.detail)
            for item in health]


def services_to_incidents(health: list[ServiceHealth],
                          now: float | None = None) -> list[Incident]:
    """Failing checks become incidents. Titles are fixed templates: no raw
    details (paths, URLs) ever reach emails, dashboard, or the LLM."""
    from .rules import Incident as IncidentRecord

    now = time.time() if now is None else now
    out: list[IncidentRecord] = []
    for item in health:
        if item.status != "fail":
            continue
        key = f"svc:{item.service}:{item.check}"
        if item.check == "container":
            critical = item.service == "vaultwarden"
            out.append(IncidentRecord(
                key, item.service, "svc_container",
                f"Service {item.service} container down",
                "critical" if critical else "warning", now))
        elif item.check == "http":
            out.append(IncidentRecord(
                key, item.service, "svc_http",
                f"Service {item.service} unreachable", "warning", now))
        elif item.check == "tls_expiry":
            out.append(IncidentRecord(
                key, item.service, "svc_tls",
                f"Service {item.service} certificate expiring "
                f"({item.detail})", item.severity or "warning", now))
        elif item.check == "backup":
            missing = item.detail == "missing"
            out.append(IncidentRecord(
                key, item.service, "svc_backup",
                f"Vaultwarden backup {item.detail}",
                "critical" if missing else "warning", now))
    return out


__all__ = [
    "BackupStatus",
    "CHECK_TYPES",
    "LogHint",
    "ServiceConfigError",
    "ServiceHealth",
    "ServiceSpec",
    "check_container",
    "check_http",
    "check_tls_expiry",
    "default_specs",
    "load_services",
    "match_hints",
    "run_health_checks",
    "services_to_incidents",
    "services_to_readings",
    "verify_backup_vaultwarden",
]
