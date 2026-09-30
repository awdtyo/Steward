"""Collectors: read-only Tier 0 sampling of host and service state.

Sources: Docker (via the docker SDK, read-only API), system RAM/CPU/
temperature/throttling (via /proc, /sys, stdlib -- no shell), disk usage
(stdlib), SMART health and Tailscale status (via allowlisted tools only).

No LLM calls. Missing tools/daemons degrade to "no readings", never crash.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import asdict, dataclass, field

from .tools import ToolError, run_tool

Value = float | str | bool | None


@dataclass
class Reading:
    source: str  # system | docker | smart | tailscale
    service: str  # host | container name | device | tailscale
    metric: str  # mem_used_pct | load_per_cpu | temp_c | throttled | ...
    value: Value
    unit: str = ""
    ts: float = field(default_factory=time.time)
    ok: bool = True
    detail: str = ""  # stored only; never mailed or sent to the LLM

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Reading:
        return cls(
            source=str(data.get("source", "")),
            service=str(data.get("service", "")),
            metric=str(data.get("metric", "")),
            value=data.get("value"),
            unit=str(data.get("unit", "")),
            ts=float(data.get("ts", time.time())),
            ok=bool(data.get("ok", True)),
            detail=str(data.get("detail", "")),
        )


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def collect_system(now: float | None = None) -> list[Reading]:
    """RAM, CPU load, temperature, throttling, disk usage. Stdlib + /proc."""
    now = time.time() if now is None else now
    out: list[Reading] = []

    meminfo = _read("/proc/meminfo")
    if meminfo:
        fields: dict[str, float] = {}
        for line in meminfo.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(":"):
                try:
                    fields[parts[0][:-1]] = float(parts[1])
                except ValueError:
                    continue
        total = fields.get("MemTotal")
        avail = fields.get("MemAvailable", fields.get("MemFree"))
        if total and avail is not None and total > 0:
            out.append(Reading("system", "host", "mem_used_pct",
                               round(100.0 * (total - avail) / total, 1),
                               "%", now))

    try:
        load1 = os.getloadavg()[0]
        cpus = os.cpu_count() or 1
        out.append(Reading("system", "host", "load_per_cpu",
                           round(load1 / cpus, 2), "x", now))
    except OSError:
        pass

    temp = _read("/sys/class/thermal/thermal_zone0/temp")
    if temp:
        try:
            out.append(Reading("system", "host", "temp_c",
                               round(float(temp.strip()) / 1000.0, 1), "C", now))
        except ValueError:
            pass

    try:
        raw = run_tool("vcgencmd_throttled", timeout=5).strip()
        # Expected: throttled=0x0 ; nonzero means throttled/under-voltage.
        if "=" in raw:
            out.append(Reading("system", "host", "throttled",
                               raw.split("=", 1)[1].strip() != "0x0", "", now))
    except ToolError:
        pass

    try:
        usage = shutil.disk_usage("/")
        pct = 100.0 * usage.used / usage.total if usage.total else 0.0
        out.append(Reading("system", "host", "disk_used_pct",
                           round(pct, 1), "%", now))
    except OSError:
        pass
    return out


def collect_docker(now: float | None = None) -> list[Reading]:
    """Container states + recent events via the docker SDK (read-only)."""
    now = time.time() if now is None else now
    try:
        import docker  # lazy: daemon/SDK absence must not break imports
    except ImportError:
        return []
    out: list[Reading] = []
    try:
        client = docker.from_env(timeout=10)
        for container in client.containers.list(all=True):
            name = (container.name or "").lstrip("/") or container.short_id
            out.append(Reading(
                "docker", name, "container_state",
                str(container.status or "unknown"), "", now, True,
                detail=str(getattr(container, "image", ""))[:200],
            ))
            try:
                health = (container.attrs.get("State") or {}).get("Health", {})
                status = health.get("Status")
                if status and status != "healthy":
                    out.append(Reading("docker", name, "container_unhealthy",
                                       str(status), "", now))
            except (AttributeError, TypeError):
                pass
        try:
            events = client.events(since=int(now - 600), until=int(now),
                                   decode=True)
            for event in events:
                action = str(event.get("Action", ""))
                if action in {"die", "oom", "kill", "destroy"}:
                    actor = event.get("Actor") or {}
                    attrs = actor.get("Attributes") or {}
                    svc = attrs.get("name", "unknown").lstrip("/")
                    out.append(Reading("docker", svc, "docker_event",
                                       action, "", now))
        except Exception:
            pass  # events are best-effort; container states already collected
    except Exception:
        return []  # daemon down: no readings, no crash
    return out


SMART_DEVICES = ("/dev/sda", "/dev/nvme0n1")


def collect_smart(devices: tuple[str, ...] = SMART_DEVICES,
                  now: float | None = None) -> list[Reading]:
    """SMART health per device via the allowlisted smartctl tool only."""
    now = time.time() if now is None else now
    out: list[Reading] = []
    for device in devices:
        try:
            payload = json.loads(run_tool("smartctl_health", device, timeout=15))
        except (ToolError, json.JSONDecodeError, ValueError):
            continue
        passed = ((payload.get("smart_status") or {}).get("passed"))
        if passed is None:
            continue
        out.append(Reading("smart", f"disk:{device.rsplit('/', 1)[-1]}",
                           "health", "pass" if passed else "fail", "", now))
    return out


def collect_tailscale(now: float | None = None) -> list[Reading]:
    """Tailscale connectivity via the allowlisted tailscale tool only."""
    now = time.time() if now is None else now
    try:
        payload = json.loads(run_tool("tailscale_status", timeout=10))
    except (ToolError, json.JSONDecodeError, ValueError):
        return []
    backend = str(payload.get("BackendState", ""))
    self_node = payload.get("Self") or {}
    online = backend == "Running" and bool(self_node.get("Online", True))
    return [Reading("tailscale", "tailscale", "online", online, "", now)]


def collect_all(now: float | None = None) -> list[Reading]:
    """Run every collector; individual failures yield fewer readings."""
    now = time.time() if now is None else now
    readings: list[Reading] = []
    for collector in (collect_system, collect_docker, collect_smart,
                      collect_tailscale):
        try:
            readings.extend(collector(now=now))
        except Exception:
            continue
    return readings


__all__ = [
    "Reading",
    "SMART_DEVICES",
    "collect_all",
    "collect_docker",
    "collect_smart",
    "collect_system",
    "collect_tailscale",
]
