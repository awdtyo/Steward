"""Tests for per-service support: YAML config, checks, backup, hints."""

import os
import time

import pytest

from steward import actions, store
from steward.agent import diagnose
from steward.agent_tools import MockBackend, ToolDenied
from steward.collectors import Reading
from steward.config import load_config
from steward.heartbeat import Heartbeat
from steward.llm import LLMResponse
from steward.monitor import tick
from steward.rules import Deduper, Incident, evaluate
from steward.services import (ServiceConfigError, check_container,
                              check_http, check_tls_expiry, default_specs,
                              load_services, match_hints, run_health_checks,
                              services_to_incidents, services_to_readings,
                              verify_backup_vaultwarden)

YAML_DOC = """
services:
  - name: jellyfin
    container: jellyfin
    checks:
      - type: container
    log_hints:
      - pattern: "SQLite.*locked"
        label: sqlite-lock
        severity: warning
    allowed_actions: [restart_container]
  - name: vaultwarden
    container: vaultwarden
    monitor_only: true
    checks:
      - type: container
      - type: tls_expiry
        host: 127.0.0.1
        port: 8443
      - type: backup
        max_age_hours: 26
    allowed_actions: []
"""


@pytest.fixture
def settings():
    return load_config({"DRY_RUN": "true"})


def write_yaml(tmp_path, text=YAML_DOC):
    path = tmp_path / "services.yaml"
    path.write_text(text)
    return str(path)


def test_load_yaml_and_defaults(tmp_path):
    specs = load_services(write_yaml(tmp_path))
    assert [s.name for s in specs] == ["jellyfin", "vaultwarden"]
    jellyfin = specs[0]
    assert jellyfin.checks[0]["type"] == "container"
    assert jellyfin.log_hints[0].label == "sqlite-lock"
    assert jellyfin.allowed_actions == ("restart_container",)
    vaultwarden = specs[1]
    assert vaultwarden.monitor_only is True
    assert vaultwarden.allowed_actions == ()


def test_missing_file_falls_back_to_builtins(tmp_path):
    specs = load_services(str(tmp_path / "nope.yaml"))
    assert [s.name for s in specs] == ["jellyfin", "nextcloud", "tailscale",
                                       "vaultwarden", "uptime-kuma"]
    vaultwarden = [s for s in specs if s.name == "vaultwarden"][0]
    assert vaultwarden.monitor_only is True
    assert vaultwarden.allowed_actions == ()
    assert vaultwarden.log_hints == ()


@pytest.mark.parametrize("doc", [
    "services:\n  - name: x\n    checks:\n      - type: nope",
    "services:\n  - name: vaultwarden\n    monitor_only: true\n"
    "    checks:\n      - type: http\n        url: http://x/\n"
    "    allowed_actions: []",
    "services:\n  - name: vaultwarden\n    monitor_only: true\n"
    "    checks:\n      - type: container\n"
    "    log_hints:\n      - {pattern: x, label: y, severity: info}\n"
    "    allowed_actions: []",
    "services:\n  - name: vaultwarden\n    monitor_only: true\n"
    "    checks:\n      - type: container\n"
    "    allowed_actions: [restart_container]",
    "services:\n  - name: a\n    checks:\n      - type: container\n"
    "  - name: a\n    checks:\n      - type: container\n",
    "services:\n  - name: jellyfin\n    checks:\n      - type: container\n"
    "    log_hints:\n      - {pattern: '([', label: y, severity: info}",
    "services:\n  - name: jellyfin\n    checks:\n      - type: container\n"
    "    allowed_actions: [wipe_disk]",
    "not: [valid, yaml: : :",
])
def test_invalid_configs_rejected(tmp_path, doc):
    with pytest.raises(ServiceConfigError):
        load_services(write_yaml(tmp_path, doc))


def test_match_hints(tmp_path):
    spec = load_services(write_yaml(tmp_path))[0]
    matched = match_hints(spec, "ERROR SQLite database is locked")
    assert matched == [{"label": "sqlite-lock", "severity": "warning"}]
    assert match_hints(spec, "all quiet") == []


def test_container_check():
    backend = MockBackend(inspect={"up": {"status": "running"},
                                   "down": {"status": "exited"}})
    up = check_container(
        type("S", (), {"name": "up", "container": "up"})(), backend)
    assert (up.status, up.detail) == ("ok", "running")
    down = check_container(
        type("S", (), {"name": "down", "container": "down"})(), backend)
    assert down.status == "fail"


def test_http_check():
    spec = default_specs()[0]
    assert check_http(spec, "http://x/", http_get=lambda u, t: 200).status == "ok"
    assert check_http(spec, "http://x/",
                      http_get=lambda u, t: 503).status == "fail"

    def boom(url, timeout):
        raise ConnectionError("refused")

    result = check_http(spec, "http://x/", http_get=boom)
    assert (result.status, result.detail) == ("fail", "connection failed")


def _cert_in(days):
    later = time.time() + days * 86400.0
    return {"notAfter": time.strftime("%b %d %H:%M:%S %Y GMT",
                                      time.gmtime(later))}


def test_tls_expiry_levels():
    spec = default_specs()[3]
    ok = check_tls_expiry(spec, "h", 1,
                          tls_connect=lambda h, p, t: _cert_in(60))
    assert (ok.status, ok.severity) == ("ok", None)
    warn = check_tls_expiry(spec, "h", 1,
                            tls_connect=lambda h, p, t: _cert_in(20))
    assert (warn.status, warn.severity) == ("fail", "warning")
    crit = check_tls_expiry(spec, "h", 1,
                            tls_connect=lambda h, p, t: _cert_in(5))
    assert (crit.status, crit.severity) == ("fail", "critical")

    def boom(host, port, timeout):
        raise OSError("no route")

    unknown = check_tls_expiry(spec, "h", 1, tls_connect=boom)
    assert unknown.status == "unknown"


def test_backup_verifier(tmp_path):
    now = 1700000000.0
    assert verify_backup_vaultwarden(
        str(tmp_path / "missing"), now=now).reason == "missing"
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("x")
    assert verify_backup_vaultwarden(
        str(not_a_dir), now=now).reason == "unreadable"
    backup = tmp_path / "backups"
    backup.mkdir()
    old = backup / "bw.age"
    old.write_bytes(b"age-encryption.org v1 header...")
    os.utime(old, (now - 48 * 3600, now - 48 * 3600))
    stale = verify_backup_vaultwarden(str(backup), now=now)
    assert stale.reason == "stale" and stale.encrypted is True
    assert stale.age_hours == pytest.approx(48.0)
    empty = backup / "empty.age"
    empty.write_bytes(b"")
    os.utime(empty, (now - 120, now - 120))
    old.unlink()
    assert verify_backup_vaultwarden(
        str(backup), now=now).reason == "empty"
    plain = backup / "notes.txt"
    plain.write_text("hello")
    os.utime(plain, (now, now))
    empty.unlink()
    result = verify_backup_vaultwarden(str(backup), now=now)
    assert (result.reason, result.encrypted) == ("unencrypted", False)
    good = backup / "bw-2024.age"
    good.write_bytes(b"age-encryption.org v1 " + b"x" * 100)
    plain.unlink()
    result = verify_backup_vaultwarden(str(backup), now=now)
    assert result.ok and result.reason == "ok"
    # No paths ever leak through the status object.
    assert str(backup) not in repr(result)


def test_health_run_and_incident_mapping():
    backend = MockBackend(inspect={"jellyfin": {"status": "exited"},
                                   "vaultwarden": {"status": "exited"}})
    specs = default_specs()
    health = run_health_checks(
        [s for s in specs if s.name in ("jellyfin", "vaultwarden")],
        backend, dry_run=True)
    # dry-run skips network/fs checks; container checks still run.
    by_key = {(h.service, h.check): h for h in health}
    assert by_key[("jellyfin", "container")].status == "fail"
    assert by_key[("vaultwarden", "container")].status == "fail"
    assert by_key[("vaultwarden", "tls_expiry")].status == "unknown"

    incidents = services_to_incidents(health, now=1.0)
    assert {(i.key, i.severity) for i in incidents} == {
        ("svc:jellyfin:container", "warning"),
        ("svc:vaultwarden:container", "critical")}
    for incident in incidents:
        assert "127.0.0.1" not in incident.title
    crit_tls = services_to_incidents(
        [type("H", (), {"service": "vaultwarden", "check": "tls_expiry",
                        "status": "fail", "detail": "expires in 3 days",
                        "severity": "critical"})()], now=1.0)
    assert crit_tls[0].severity == "critical"
    # ok/unknown produce nothing.
    assert services_to_incidents(
        [type("H", (), {"service": "x", "check": "http",
                        "status": "ok", "detail": "", "severity": None})()],
        now=1.0) == []


def test_service_readings_stay_rule_invisible():
    readings = services_to_readings(
        [type("H", (), {"service": "jellyfin", "check": "container",
                        "status": "fail", "detail": "exited"})()], now=1.0)
    assert readings[0].value == "fail"
    assert evaluate(readings, now=1.0) == []


class MockLLM:
    def __init__(self, content):
        self.content = content
        self.calls = []

    def __call__(self, settings, messages, *, model=None, purpose="",
                 **kwargs):
        import json as _json
        self.calls.append([m["content"] for m in messages])
        return LLMResponse(
            model=model or "mock", content=_json.dumps({"diagnosis": {
                "summary": self.content, "likely_cause": "c",
                "confidence": 0.8, "suggested_fix": "f"}}),
            prompt_tokens=1, completion_tokens=1, total_tokens=2)


def test_tick_runs_service_checks_and_diagnoses(settings):
    conn = store.init_db(":memory:")
    backend = MockBackend(inspect={"jellyfin": {"status": "exited"}})
    specs = [s for s in default_specs() if s.name == "jellyfin"]
    summary = tick(settings, conn, Deduper(), Heartbeat(), now=1000.0,
                   readings=[], backend=backend, llm_chat=MockLLM("db"),
                   service_specs=specs)
    assert summary["service_incidents"] == ["svc:jellyfin:container"]
    assert summary["diagnosed"] == ["svc:jellyfin:container"]
    saved, _ = store.get_trace(conn, "svc:jellyfin:container")
    assert saved["summary"] == "db"
    conn.close()


def test_tick_vaultwarden_incident_skips_diagnosis(settings):
    conn = store.init_db(":memory:")
    backend = MockBackend(inspect={"vaultwarden": {"status": "exited"}})
    specs = [s for s in default_specs() if s.name == "vaultwarden"]
    summary = tick(settings, conn, Deduper(), Heartbeat(), now=1000.0,
                   readings=[], backend=backend, llm_chat=MockLLM("db"),
                   service_specs=specs)
    assert summary["service_incidents"] == ["svc:vaultwarden:container"]
    assert summary["diagnosis_skipped"] == ["svc:vaultwarden:container"]
    conn.close()


def test_diagnosis_brief_includes_hint_labels(settings, tmp_path):
    specs = load_services(write_yaml(tmp_path))
    llm = MockLLM("x")
    diagnose(settings,
             Incident("jellyfin:container", "jellyfin", "container",
                      "jellyfin container exited", "warning", 1.0),
             backend=MockBackend(), llm_chat=llm, service_specs=specs)
    brief = llm.calls[0][1]
    assert "sqlite-lock" in brief


def test_per_service_allowed_actions(settings, tmp_path):
    conn = store.init_db(":memory:")
    specs = load_services(write_yaml(tmp_path))
    args = {"service": "jellyfin"}
    assert actions.propose_action(
        conn, settings, tier=1, kind="restart_container", args=args,
        service_specs=specs) > 0
    with pytest.raises(ToolDenied, match="allowed action"):
        actions.propose_action(
            conn, settings, tier=1, kind="clear_cache", args=args,
            service_specs=specs)
    conn.close()
