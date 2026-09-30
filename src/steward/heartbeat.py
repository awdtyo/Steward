"""Heartbeat pings to HEALTHCHECK_URL on a schedule. Stdlib only."""

from __future__ import annotations

import time
import urllib.request

USER_AGENT = "steward/0.1.0 heartbeat"


def ping(url: str, timeout: int = 10) -> bool:
    """GET *url* once. Empty URL is a no-op (False); never raises."""
    if not url:
        return False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


class Heartbeat:
    """Schedule helper: ping at most once per *interval_s*."""

    def __init__(self, url: str = "", interval_s: float = 300.0) -> None:
        self.url = url
        self.interval_s = interval_s
        self.last_sent = 0.0

    def due(self, now: float | None = None) -> bool:
        if not self.url:
            return False
        now = time.time() if now is None else now
        return now - self.last_sent >= self.interval_s

    def ping_if_due(self, now: float | None = None) -> bool | None:
        """Ping when due. True/False = ping result, None = not due."""
        now = time.time() if now is None else now
        if not self.due(now):
            return None
        ok = ping(self.url)
        if ok:
            self.last_sent = now
        return ok


__all__ = ["Heartbeat", "ping"]
