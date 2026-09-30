"""Tests for the threshold/rule engine (readings -> incidents)."""

from steward.collectors import Reading
from steward.rules import evaluate


def _reading(source, service, metric, value, ok=True):
    return Reading(source, service, metric, value, ts=1700000000.0, ok=ok)


def _severities(readings):
    return {(i.key, i.severity) for i in evaluate(readings, now=1700000000.0)}


def test_quiet_readings_produce_no_incidents():
    readings = [
        _reading("system", "host", "mem_used_pct", 42.0),
        _reading("system", "host", "load_per_cpu", 0.4),
        _reading("system", "host", "temp_c", 48.0),
        _reading("system", "host", "disk_used_pct", 55.0),
        _reading("system", "host", "throttled", False),
        _reading("docker", "jellyfin", "container_state", "running"),
        _reading("smart", "disk:sda", "health", "pass"),
        _reading("tailscale", "tailscale", "online", True),
    ]
    assert evaluate(readings, now=1700000000.0) == []


def test_threshold_severity_bands():
    assert _severities([_reading("system", "host", "mem_used_pct", 80.0)]) == {
        ("host:mem_used_pct", "warning")}
    assert _severities([_reading("system", "host", "mem_used_pct", 95.0)]) == {
        ("host:mem_used_pct", "critical")}
    assert _severities([_reading("system", "host", "temp_c", 70.0)]) == {
        ("host:temp_c", "warning")}
    assert _severities([_reading("system", "host", "temp_c", 85.0)]) == {
        ("host:temp_c", "critical")}
    assert _severities([_reading("system", "host", "disk_used_pct", 85.0)]) == {
        ("host:disk_used_pct", "warning")}
    assert _severities([_reading("system", "host", "disk_used_pct", 95.0)]) == {
        ("host:disk_used_pct", "critical")}
    assert _severities([_reading("system", "host", "load_per_cpu", 1.5)]) == {
        ("host:load_per_cpu", "warning")}
    assert _severities([_reading("system", "host", "load_per_cpu", 2.5)]) == {
        ("host:load_per_cpu", "critical")}
    # Just under warn band: silent.
    assert _severities([_reading("system", "host", "mem_used_pct", 74.9)]) == set()


def test_throttled_and_smart():
    assert _severities([_reading("system", "host", "throttled", True)]) == {
        ("host:throttled", "warning")}
    assert _severities([_reading("system", "host", "throttled", False)]) == set()
    assert _severities([_reading("smart", "disk:sda", "health", "fail")]) == {
        ("disk:sda:smart", "critical")}


def test_docker_states():
    assert _severities(
        [_reading("docker", "jellyfin", "container_state", "exited")]) == {
        ("jellyfin:container", "warning")}
    assert _severities(
        [_reading("docker", "nextcloud", "container_state", "restarting")]) == {
        ("nextcloud:container", "info")}
    assert _severities(
        [_reading("docker", "x", "container_state", "running")]) == set()
    assert _severities(
        [_reading("docker", "x", "container_unhealthy", "unhealthy")]) == {
        ("x:health", "warning")}
    assert _severities(
        [_reading("docker", "x", "docker_event", "die")]) == {
        ("x:event:die", "warning")}
    assert _severities(
        [_reading("docker", "x", "docker_event", "oom")]) == {
        ("x:event:oom", "critical")}


def test_tailscale_offline_is_critical():
    assert _severities(
        [_reading("tailscale", "tailscale", "online", False)]) == {
        ("tailscale:online", "critical")}


def test_bad_readings_ignored():
    assert evaluate([_reading("system", "host", "mem_used_pct", 99.0,
                              ok=False)], now=1.0) == []
    assert evaluate([_reading("system", "host", "mem_used_pct", None)],
                    now=1.0) == []
    assert evaluate([_reading("system", "host", "nope", 99.0)], now=1.0) == []
    assert evaluate([_reading("system", "host", "mem_used_pct", "high")],
                    now=1.0) == []


def test_titles_never_contain_raw_detail():
    reading = _reading("docker", "jellyfin", "container_state", "exited")
    reading.detail = "Traceback Traceback api_key=SECRET-123 10.0.0.9"
    incidents = evaluate([reading], now=1.0)
    assert len(incidents) == 1
    assert "Traceback" not in incidents[0].title
    assert "SECRET-123" not in incidents[0].title
    assert incidents[0].key == "jellyfin:container"
