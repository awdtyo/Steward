"""Tests for per-incident dedupe with per-service cooldowns."""

from steward.rules import Deduper, Incident


def _incident(key="host:mem_used_pct", service="host",
              severity="warning"):
    return Incident(key, service, "mem_used_pct", "Host memory usage 80%",
                    severity, observed_ts=1000.0)


def _clocked(cooldowns=None):
    now = [1000.0]
    return Deduper(cooldowns=cooldowns, clock=lambda: now[0]), now


def test_first_sighting_alerts_then_suppressed():
    deduper, now = _clocked()
    incident = _incident()
    assert deduper.should_alert(incident) is True
    assert deduper.should_alert(incident) is False  # repeat: suppressed


def test_cooldown_expiry_realerts():
    deduper, now = _clocked()
    incident = _incident()
    assert deduper.should_alert(incident) is True
    now[0] += 3599.0
    assert deduper.should_alert(incident) is False
    now[0] += 1.0  # default cooldown 3600s
    assert deduper.should_alert(incident) is True


def test_per_service_cooldowns():
    deduper, now = _clocked(cooldowns={"jellyfin": 60.0})
    fast = _incident("jellyfin:container", "jellyfin")
    slow = _incident("host:mem_used_pct", "host")
    assert deduper.should_alert(fast) is True
    assert deduper.should_alert(slow) is True
    now[0] += 61.0
    assert deduper.should_alert(fast) is True  # short cooldown expired
    assert deduper.should_alert(slow) is False  # default still cooling down


def test_keys_are_independent():
    deduper, _ = _clocked()
    assert deduper.should_alert(_incident("a:x", "a")) is True
    assert deduper.should_alert(_incident("b:y", "b")) is True
    assert deduper.should_alert(_incident("a:x", "a")) is False
    assert deduper.should_alert(_incident("b:y", "b")) is False


def test_forget_rearms_after_recovery():
    deduper, now = _clocked()
    incident = _incident()
    assert deduper.should_alert(incident) is True
    deduper.forget(incident.key)  # incident resolved; re-fire alerts at once
    assert deduper.should_alert(incident) is True


def test_cooldown_for_falls_back_to_default():
    deduper, _ = _clocked(cooldowns={"jellyfin": 60.0})
    assert deduper.cooldown_for("jellyfin") == 60.0
    assert deduper.cooldown_for("unknown-service") == 3600.0
