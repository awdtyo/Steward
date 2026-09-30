"""Tests for the monitor tick: escalation, recovery mail, digest flow."""

import pytest

from steward import store
from steward.alerts import OUTBOX
from steward.collectors import Reading
from steward.config import load_config
from steward.heartbeat import Heartbeat
from steward.monitor import send_digest_for_open, tick
from steward.rules import Deduper


@pytest.fixture
def setup():
    OUTBOX.clear()
    settings = load_config({"DRY_RUN": "true",
                            "ALERT_TO": "admin@example.com"})
    conn = store.init_db(":memory:")
    yield settings, conn, Deduper(), Heartbeat()
    OUTBOX.clear()
    conn.close()


def _reading(metric, value, service="host", source="system"):
    return Reading(source, service, metric, value, ts=1700000000.0)


def test_escalation_mails_critical_despite_cooldown(setup):
    settings, conn, deduper, hb = setup
    tick(settings, conn, deduper, hb, now=1000.0,
         readings=[_reading("mem_used_pct", 80.0)])  # warning, queued
    assert [m["Subject"] for m in OUTBOX] == []
    tick(settings, conn, deduper, hb, now=1100.0,
         readings=[_reading("mem_used_pct", 95.0)])  # escalated
    subjects = [m["Subject"] for m in OUTBOX]
    assert subjects == ["[steward CRITICAL] Host memory usage 95%"]


def test_resolution_sends_recovery_mail(setup):
    settings, conn, deduper, hb = setup
    tick(settings, conn, deduper, hb, now=1000.0,
         readings=[_reading("disk_used_pct", 95.0)])
    assert len(OUTBOX) == 1  # critical mailed immediately
    summary = tick(settings, conn, deduper, hb, now=2000.0,
                   readings=[_reading("disk_used_pct", 40.0)])
    assert summary["resolved"] == ["host:disk_used_pct"]
    assert [m["Subject"] for m in OUTBOX][-1] == (
        "[steward RECOVERED] Host disk usage 95%")
    assert store.get_open(conn) == []


def test_digest_flow_for_warnings(setup):
    settings, conn, deduper, hb = setup
    tick(settings, conn, deduper, hb, now=1000.0,
         readings=[_reading("disk_used_pct", 85.0)])
    assert OUTBOX == []  # warnings wait for the digest, no immediate mail
    email = send_digest_for_open(settings, conn)
    assert email is not None
    assert "Host disk usage 85%" in email.body
    assert len(OUTBOX) == 1
