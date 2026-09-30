"""Tests for the FastAPI dashboard: pages, SSE stream, and escaping."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from steward import store
from steward.app import create_app, render_status_fragment, status_snapshot
from steward.collectors import Reading
from steward.config import load_config
from steward.rules import Incident


@pytest.fixture
def client():
    settings = load_config({"DRY_RUN": "true", "ALERT_TO": "admin@example.com"})
    conn = store.init_db(":memory:")
    store.upsert_incident(
        conn,
        Incident("host:disk_used_pct", "host", "disk_used_pct",
                 "Host disk usage 86%", "warning", 1700000000.0),
        now=1700000000.0,
    )
    store.upsert_incident(
        conn,
        Incident("xss:test", "svc", "test",
                 "<script>alert(1)</script> seen at 10.9.8.7", "critical",
                 1700000000.0),
        now=1700000000.0,
    )
    app = create_app(settings, conn, beat_interval=0.01)
    with TestClient(app) as test_client:
        yield test_client
    conn.close()


def test_status_page_has_live_region_and_htmx(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Homelab status" in resp.text
    assert 'sse-connect="/events"' in resp.text
    assert 'sse-swap="status"' in resp.text
    assert "https://unpkg.com/htmx.org@2.0.4" in resp.text
    assert "htmx-ext-sse" in resp.text
    # Dry-run fixture readings render on first load.
    assert "42.0 %" in resp.text


def test_incident_list_escapes_and_redacts(client):
    resp = client.get("/incidents")
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
    assert "10.9.8.7" not in resp.text
    assert "[redacted ip]" in resp.text
    assert "/incidents/xss%3Atest" in resp.text
    assert "Host disk usage 86%" in resp.text


def test_incident_detail_and_404(client):
    resp = client.get("/incidents/host:disk_used_pct")
    assert resp.status_code == 200
    assert "Host disk usage 86%" in resp.text
    assert "warning" in resp.text
    missing = client.get("/incidents/nope:missing")
    assert missing.status_code == 404


def test_sse_stream_pushes_status_events():
    # Raw ASGI level: Starlette's TestClient blocks on infinite streams,
    # so drive the app directly and cancel after the first beats.
    settings = load_config({"DRY_RUN": "true"})
    conn = store.init_db(":memory:")
    app = create_app(settings, conn, beat_interval=0.01)
    messages: list[dict] = []

    async def receive():
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {"type": "http", "http_version": "1.1", "method": "GET",
             "scheme": "http", "path": "/events", "query_string": b"",
             "headers": [], "client": ("testclient", 50000),
             "server": ("testserver", 80)}

    async def run():
        await asyncio.wait_for(app(scope, receive, send), timeout=0.5)

    with pytest.raises(TimeoutError):
        asyncio.run(run())
    conn.close()

    start = messages[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 200
    assert (b"text/event-stream" in
            dict(start["headers"])[b"content-type"])
    body = b"".join(m.get("body", b"") for m in messages
                    if m["type"] == "http.response.body")
    assert b"event: status" in body
    assert b"data:" in body


def test_status_fragment_escapes_untrusted_names():
    readings = [Reading("docker", "<img src=x onerror=alert(1)>",
                        "container_state", "exited")]
    fragment = render_status_fragment(status_snapshot(readings))
    assert "<img" not in fragment
    assert "&lt;img" in fragment


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}
