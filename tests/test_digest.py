"""Tests for email bodies: digest membership, redaction, links, no logs."""

import pytest

from steward.alerts import (OUTBOX, critical_email, digest_email,
                            recovery_email, send_email)
from steward.config import load_config
from steward.rules import Incident


@pytest.fixture
def settings():
    return load_config({
        "DRY_RUN": "true",
        "ALERT_TO": "admin@example.com",
        "DASHBOARD_BASE_URL": "http://dashboard.example.com:8000",
    })


@pytest.fixture(autouse=True)
def clean_outbox():
    OUTBOX.clear()
    yield
    OUTBOX.clear()


def _incident(key="host:disk_used_pct", service="host", severity="warning",
              title="Host disk usage 86%"):
    return Incident(key, service, "disk_used_pct", title, severity,
                    observed_ts=1700000000.0)


def test_digest_includes_warnings_and_info_excludes_critical(settings):
    email = digest_email(settings, [
        _incident("a", "host", "warning", "disk warning"),
        _incident("b", "host", "info", "container restarting"),
        _incident("c", "host", "critical", "memory critical"),
    ])
    assert email is not None
    assert "disk warning" in email.body
    assert "container restarting" in email.body
    assert "memory critical" not in email.body
    assert email.to == "admin@example.com"


def test_digest_empty_or_only_critical_is_none(settings):
    assert digest_email(settings, []) is None
    assert digest_email(settings, [_incident("c", "host", "critical")]) is None


def test_digest_redacts_sensitive_values(settings):
    nasty = _incident("k", "svc", "warning",
                      "disk on 192.168.1.5 token=abc123 admin@mail.home "
                      "key=DEADBEEF0123456789abcdef01234567")
    email = digest_email(settings, [nasty])
    assert email is not None
    assert "192.168.1.5" not in email.body
    assert "abc123" not in email.body
    assert "admin@mail.home" not in email.body
    assert "DEADBEEF0123456789abcdef01234567" not in email.body
    assert "[redacted" in email.body


def test_digest_links_to_dashboard_incident_page(settings):
    email = digest_email(settings, [_incident()])
    assert email is not None
    assert ("http://dashboard.example.com:8000/incidents/host:disk_used_pct"
            in email.body)


def test_bodies_contain_no_raw_logs(settings):
    raw = "Traceback (most recent call last): ... api_key=SUPERSECRET 10.9.9.9"
    incident = _incident()
    for email in (digest_email(settings, [incident]),
                  critical_email(settings, incident),
                  recovery_email(settings, incident)):
        assert email is not None
        assert raw not in email.body
        assert "Traceback" not in email.body


def test_critical_and_recovery_subjects(settings):
    crit = critical_email(settings, _incident(title="memory 95%"))
    assert crit.subject == "[steward CRITICAL] memory 95%"
    assert "/incidents/" in crit.body
    rec = recovery_email(settings, _incident(title="memory 95%"))
    assert rec.subject == "[steward RECOVERED] memory 95%"
    assert "cleared" in rec.body


def test_dry_run_send_captures_to_outbox(settings):
    email = digest_email(settings, [_incident()])
    assert email is not None
    assert send_email(settings, email) is True
    assert len(OUTBOX) == 1
    assert OUTBOX[0]["To"] == "admin@example.com"
