"""Threshold/rule engine: readings in, incidents out. No LLM calls.

Titles are short templates -- never raw logs. Dedupe is per incident key
(service + rule) with per-service cooldowns (seconds between repeat alerts).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Literal

from .collectors import Reading

Severity = Literal["info", "warning", "critical"]

# warn_at / crit_at thresholds. Tuned for a 4 GB Pi 5 homelab.
THRESHOLDS: dict[str, dict[str, float]] = {
    "mem_used_pct": {"warn": 75.0, "crit": 90.0},
    "load_per_cpu": {"warn": 1.0, "crit": 2.0},
    "temp_c": {"warn": 65.0, "crit": 80.0},
    "disk_used_pct": {"warn": 80.0, "crit": 90.0},
}

# Seconds between repeat alerts for the same incident, per service.
DEFAULT_COOLDOWNS: dict[str, float] = {"default": 3600.0}

# Docker states below warning level are informational (transient phases).
_DOCKER_INFO_STATES = {"created", "restarting", "paused", "removing"}


@dataclass
class Incident:
    key: str  # stable dedupe key: f"{service}:{rule}"
    service: str
    rule: str
    title: str  # short template; never raw logs
    severity: Severity
    observed_ts: float = field(default_factory=time.time)


def _level(metric: str, value: float) -> Severity | None:
    bands = THRESHOLDS.get(metric)
    if bands is None:
        return None
    if value >= bands["crit"]:
        return "critical"
    if value >= bands["warn"]:
        return "warning"
    return None


def _threshold_incident(reading: Reading) -> Incident | None:
    if not isinstance(reading.value, (int, float)):
        return None
    severity = _level(reading.metric, float(reading.value))
    if severity is None:
        return None
    titles = {
        "mem_used_pct": f"Host memory usage {reading.value:.0f}%",
        "load_per_cpu": f"Host CPU load {reading.value:.2f}x per core",
        "temp_c": f"Host temperature {reading.value:.0f}C",
        "disk_used_pct": f"Host disk usage {reading.value:.0f}%",
    }
    title = titles.get(reading.metric, f"{reading.metric} at {reading.value}")
    key = f"{reading.service}:{reading.metric}"
    return Incident(key, reading.service, reading.metric, title, severity,
                    reading.ts)


def _apply(reading: Reading) -> Incident | None:
    if not reading.ok or reading.value is None:
        return None
    source, metric = reading.source, reading.metric

    if source == "system" and metric in THRESHOLDS:
        return _threshold_incident(reading)

    if source == "system" and metric == "throttled" and reading.value is True:
        return Incident(f"{reading.service}:throttled", reading.service,
                        "throttled",
                        "Host CPU throttled (heat or under-voltage)",
                        "warning", reading.ts)

    if source == "smart" and metric == "health" and reading.value == "fail":
        return Incident(f"{reading.service}:smart", reading.service, "smart",
                        f"Disk {reading.service} SMART health failing",
                        "critical", reading.ts)

    if source == "docker" and metric == "container_state":
        state = str(reading.value)
        if state == "running":
            return None
        severity: Severity = ("info" if state in _DOCKER_INFO_STATES
                              else "warning")
        return Incident(f"{reading.service}:container", reading.service,
                        "container", f"{reading.service} container {state}",
                        severity, reading.ts)

    if source == "docker" and metric == "container_unhealthy":
        return Incident(f"{reading.service}:health", reading.service,
                        "container_health",
                        f"{reading.service} container unhealthy",
                        "warning", reading.ts)

    if source == "docker" and metric == "docker_event":
        action = str(reading.value)
        severity = "critical" if action == "oom" else "warning"
        return Incident(f"{reading.service}:event:{action}", reading.service,
                        f"event_{action}",
                        f"{reading.service} container {action}", severity,
                        reading.ts)

    if source == "tailscale" and metric == "online" and not reading.value:
        return Incident("tailscale:online", "tailscale", "online",
                        "Tailscale offline (remote access down)",
                        "critical", reading.ts)
    return None


def evaluate(readings: list[Reading],
             now: float | None = None) -> list[Incident]:
    """Turn current readings into active incidents (stateless)."""
    now = time.time() if now is None else now
    active: list[Incident] = []
    for reading in readings:
        incident = _apply(reading)
        if incident is not None:
            incident.observed_ts = now
            active.append(incident)
    return active


class Deduper:
    """Per-incident alert gating with per-service cooldowns.

    should_alert() returns True for a newly seen key, or when the cooldown
    for the incident's service has expired since the last alert. forget()
    drops a key so a re-firing incident after recovery alerts immediately.
    """

    def __init__(self,
                 cooldowns: dict[str, float] | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self.cooldowns = {**DEFAULT_COOLDOWNS, **(cooldowns or {})}
        self._clock = clock or time.time
        self._last_alert: dict[str, float] = {}

    def cooldown_for(self, service: str) -> float:
        return self.cooldowns.get(service, self.cooldowns["default"])

    def should_alert(self, incident: Incident,
                     now: float | None = None) -> bool:
        now = self._clock() if now is None else now
        last = self._last_alert.get(incident.key)
        if last is None or now - last >= self.cooldown_for(incident.service):
            self._last_alert[incident.key] = now
            return True
        return False

    def forget(self, key: str) -> None:
        self._last_alert.pop(key, None)

    def __len__(self) -> int:
        return len(self._last_alert)


__all__ = [
    "DEFAULT_COOLDOWNS",
    "THRESHOLDS",
    "Deduper",
    "Incident",
    "Severity",
    "evaluate",
]
