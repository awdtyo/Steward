"""Monitor tick: collect -> evaluate -> store -> alert -> heartbeat.

Dry-run replays the mock fixture instead of touching anything real.
Critical incidents mail immediately (per dedupe cooldowns); warning/info
incidents stay open for the daily digest (see send_digest_for_open).
Resolved incidents get one recovery mail.
"""

from __future__ import annotations

import sqlite3
import time

from . import alerts
from .agent import diagnose_and_store
from .alerts import row_to_incident
from .collectors import Reading, collect_all
from .config import Settings
from .dryrun import replay
from .heartbeat import Heartbeat
from .llm import VaultwardenRefusal
from .rules import Deduper, evaluate
from . import store as store_module

_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


def tick(settings: Settings,
         conn: sqlite3.Connection,
         deduper: Deduper,
         heartbeat: Heartbeat,
         now: float | None = None,
         readings: list[Reading] | None = None,
         run_diagnosis: bool = True,
         backend=None,
         llm_chat=None) -> dict:
    """Run one monitoring pass. Returns a small summary dict."""
    now = time.time() if now is None else now
    if readings is None:
        if settings.dry_run:
            try:
                readings = next(iter(replay()))
            except StopIteration:
                readings = []
        else:
            readings = collect_all(now=now)

    store_module.save_readings(conn, readings)
    active = evaluate(readings, now=now)
    active_keys = {i.key for i in active}
    fired = []
    for incident in active:
        # Escalation (e.g. warning -> critical) bypasses the cooldown so the
        # critical mail still goes out immediately.
        row = store_module.get_incident(conn, incident.key)
        if row is None or row["status"] != "open":
            fired.append(incident)  # newly opened (or reopened): diagnose it
        if (row is not None and row["status"] == "open"
                and _SEVERITY_RANK[incident.severity]
                > _SEVERITY_RANK.get(row["severity"], 0)):
            deduper.forget(incident.key)
        store_module.upsert_incident(conn, incident, now=now)

    previously_open = {row["key"] for row in store_module.get_open(conn)}
    resolved: list[str] = []
    for key in previously_open - active_keys:
        if store_module.resolve_incident(conn, key, now=now):
            deduper.forget(key)
            row = store_module.get_incident(conn, key)
            if row is not None:
                alerts.send_email(settings,
                                  alerts.recovery_email(
                                      settings, row_to_incident(row)))
            resolved.append(key)

    mailed = {"critical": 0, "warning": 0, "info": 0}
    for incident in active:
        if not deduper.should_alert(incident, now=now):
            continue
        store_module.mark_alerted(conn, incident.key, now=now)
        if incident.severity == "critical":
            alerts.send_email(settings,
                              alerts.critical_email(settings, incident))
            mailed["critical"] += 1
        else:
            mailed[incident.severity] += 1  # queued for the daily digest

    hb = heartbeat.ping_if_due(now=now)

    diagnosed: list[str] = []
    diagnosis_skipped: list[str] = []
    if run_diagnosis:
        for incident in fired:
            try:
                diagnose_and_store(settings, conn, incident,
                                   backend=backend, llm_chat=llm_chat)
                diagnosed.append(incident.key)
            except (VaultwardenRefusal, Exception):
                # Never let diagnosis break the monitoring pass.
                diagnosis_skipped.append(incident.key)

    return {"active": len(active), "resolved": resolved,
            "mailed": mailed, "heartbeat": hb, "diagnosed": diagnosed,
            "diagnosis_skipped": diagnosis_skipped}


def send_digest_for_open(settings: Settings,
                         conn: sqlite3.Connection):
    """Build and send the daily digest of open warning/info incidents."""
    incidents = [row_to_incident(row) for row in store_module.get_open(conn)]
    email = alerts.digest_email(settings, incidents)
    if email is None:
        return None
    alerts.send_email(settings, email)
    return email


__all__ = ["send_digest_for_open", "tick"]
