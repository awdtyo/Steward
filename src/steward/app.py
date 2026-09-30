"""FastAPI dashboard. Read-only Tier 0 pages bound to 127.0.0.1.

Pages: live status (host metrics + service health, pushed over SSE),
incident list, incident detail (the target of alert email links).

Rendering rule: every dynamic value passes through esc() (redact, then
HTML-escape). Templates hold no logic; $placeholders receive either escaped
text or HTML fragments built here from escaped parts. No raw logs are stored
or rendered anywhere.
"""

from __future__ import annotations

import asyncio
import html
import itertools
import sqlite3
from datetime import datetime
from pathlib import Path
from string import Template
from urllib.parse import quote

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from . import collectors, store
from .collectors import Reading
from .config import Settings, load_config
from .dryrun import load_fixture
from .redact import redact

HOST = "127.0.0.1"
TEMPLATES = Path(__file__).parent / "templates"


def esc(value: object) -> str:
    """Redact sensitive values, then HTML-escape. All dynamic output."""
    return html.escape(redact(str(value)), quote=True)


def _template(name: str) -> Template:
    return Template((TEMPLATES / name).read_text(encoding="utf-8"))


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "—"


def _fmt_value(value: object, unit: str = "") -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        text = f"{value:.1f}"
    else:
        text = str(value)
    return f"{text} {unit}".strip()


def status_snapshot(readings: list[Reading]) -> dict:
    """Reduce readings to display rows. Pure function (tested)."""
    last: dict[tuple[str, str, str], Reading] = {}
    for reading in readings:
        if reading.ok:
            last[(reading.source, reading.service, reading.metric)] = reading

    def get(source: str, service: str, metric: str) -> Reading | None:
        return last.get((source, service, metric))

    metrics: list[tuple[str, str]] = []
    for label, metric, unit in (("Memory", "mem_used_pct", "%"),
                                ("CPU load per core", "load_per_cpu", "x"),
                                ("Temperature", "temp_c", "C"),
                                ("Disk", "disk_used_pct", "%")):
        reading = get("system", "host", metric)
        metrics.append((label, _fmt_value(reading.value if reading else None,
                                          unit)))
    throttled = get("system", "host", "throttled")
    metrics.append(("Throttled", _fmt_value(
        throttled.value if throttled else None)))
    tailscale = get("tailscale", "tailscale", "online")
    metrics.append(("Tailscale", "online" if tailscale and tailscale.value
                   else ("offline" if tailscale else "—")))
    services = sorted(
        {(r.service, str(r.value))
         for r in last.values()
         if r.source == "docker" and r.metric == "container_state"},
        key=lambda pair: pair[0],
    )
    smart = sorted(
        {(r.service, str(r.value))
         for r in last.values()
         if r.source == "smart" and r.metric == "health"},
        key=lambda pair: pair[0],
    )
    return {"metrics": metrics, "services": services, "smart": smart}


def render_status_fragment(snapshot: dict) -> str:
    """Render the SSE-swapped status partial from escaped parts only."""
    metric_rows = "\n".join(
        f"<tr><td>{esc(label)}</td><td>{esc(display)}</td></tr>"
        for label, display in snapshot["metrics"])
    service_rows = "\n".join(
        f"<tr><td>{esc(name)}</td><td>{esc(state)}</td></tr>"
        for name, state in snapshot["services"]) or (
        '<tr><td colspan="2">No container data</td></tr>')
    smart_rows = "\n".join(
        f"<tr><td>{esc(f'SMART {name}')}</td><td>{esc(state)}</td></tr>"
        for name, state in snapshot["smart"])
    if smart_rows:
        metric_rows += "\n" + smart_rows
    return _template("_status.html").safe_substitute(
        metric_rows=metric_rows, service_rows=service_rows)


def _page(title: str, content: str) -> str:
    return _template("base.html").safe_substitute(title=esc(title),
                                                  content=content)


def _incident_item(row: sqlite3.Row) -> str:
    url = f"/incidents/{quote(row['key'], safe='')}"
    return (
        f"<li><span class=\"{esc(row['severity'])}\">"
        f"[{esc(row['severity'])}]</span> "
        f"<a href=\"{esc(url)}\">{esc(row['title'])}</a> "
        f"<span class=\"muted\">{esc(row['service'])} · "
        f"{esc(_fmt_ts(row['first_seen']))}</span></li>"
    )


def create_app(settings: Settings, conn: sqlite3.Connection,
               beat_interval: float = 5.0) -> FastAPI:
    """Build the dashboard app. No network activity at construction."""
    if settings.dry_run:
        try:
            ticks = itertools.cycle(load_fixture())
        except (OSError, ValueError):
            ticks = itertools.cycle([[]])
        def _provider() -> list[Reading]:
            return next(ticks)
    else:
        def _provider() -> list[Reading]:
            try:
                return collectors.collect_all()
            except Exception:
                return []

    app = FastAPI(title="steward")

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    @app.get("/", response_class=HTMLResponse)
    def status_page() -> str:
        fragment = render_status_fragment(status_snapshot(_provider()))
        content = _template("status.html").safe_substitute(
            status_fragment=fragment)
        return _page("Status", content)

    @app.get("/incidents", response_class=HTMLResponse)
    def incident_list() -> str:
        open_rows = store.get_open(conn)
        resolved_rows = conn.execute(
            "SELECT * FROM incidents WHERE status='resolved'"
            " ORDER BY last_seen DESC LIMIT 20").fetchall()
        content = _template("incidents.html").safe_substitute(
            open_items="\n".join(_incident_item(r) for r in open_rows)
            or "<li>None</li>",
            resolved_items="\n".join(_incident_item(r) for r in resolved_rows)
            or "<li>None</li>",
        )
        return _page("Incidents", content)

    @app.get("/incidents/{key:path}", response_class=HTMLResponse)
    def incident_detail(key: str):
        row = store.get_incident(conn, key)
        if row is None:
            return HTMLResponse(_page("Not found", "<h1>Unknown incident</h1>"),
                                status_code=404)
        content = _template("incident.html").safe_substitute(
            severity=esc(row["severity"]), status=esc(row["status"]),
            title=esc(row["title"]), service=esc(row["service"]),
            rule=esc(row["rule"]),
            first_seen=esc(_fmt_ts(row["first_seen"])),
            last_seen=esc(_fmt_ts(row["last_seen"])),
            count=esc(row["count"]),
            trace_url=esc(f"/trace/{quote(row['key'], safe='')}"),
        )
        return _page(f"Incident {row['key']}", content)

    @app.get("/trace/{key:path}", response_class=HTMLResponse)
    def agent_trace(key: str):
        diagnosis, step_rows = store.get_trace(conn, key)
        if diagnosis is None:
            diagnosis_block = "<p>No diagnosis recorded yet.</p>"
        else:
            escalated = " (escalated)" if diagnosis["escalated"] else ""
            diagnosis_block = (
                "<table>"
                f"<tr><th>Summary</th><td>{esc(diagnosis['summary'])}</td></tr>"
                "<tr><th>Likely cause</th>"
                f"<td>{esc(diagnosis['likely_cause'])}</td></tr>"
                "<tr><th>Confidence</th>"
                f"<td>{esc(diagnosis['confidence'])}</td></tr>"
                "<tr><th>Suggested fix</th>"
                f"<td>{esc(diagnosis['suggested_fix'])}</td></tr>"
                f"<tr><th>Model</th><td>{esc(diagnosis['model'])}{escalated}"
                "</td></tr>"
                "</table>")
        rows = []
        for step in step_rows:
            args = step["args_json"]
            if len(args) > 200:
                args = args[:200] + "..."
            detail = step["error"] or step["output"]
            if len(detail) > 500:
                detail = detail[:500] + "..."
            rows.append(
                "<tr>"
                f"<td>{esc(step['step_no'])}</td>"
                f"<td>{esc(step['kind'])}</td>"
                f"<td>{esc(step['model'])}</td>"
                f"<td>{esc(step['tool'])} {esc(args)}</td>"
                f"<td>{esc(step['prompt_tokens'])}/"
                f"{esc(step['completion_tokens'])}/"
                f"{esc(step['total_tokens'])}</td>"
                f"<td>{esc(step['redaction_count'])}</td>"
                f"<td>{esc(round(step['latency_s'], 2))}s</td>"
                f"<td>{esc(detail)}</td>"
                "</tr>")
        content = _template("trace.html").safe_substitute(
            incident_key=esc(key), diagnosis_block=diagnosis_block,
            step_rows="\n".join(rows) or "<tr><td colspan=\"8\">None</td></tr>",
            incident_url=esc(quote(key, safe="")),
        )
        return _page(f"Trace {key}", content)

    @app.get("/events")
    async def events() -> StreamingResponse:
        async def _stream():
            # Disconnects surface as task cancellation (uvicorn cancels the
            # response task; TestClient cancels on stream close).
            yield ": connected\n\n"
            try:
                while True:
                    fragment = render_status_fragment(
                        status_snapshot(_provider()))
                    lines = "".join(
                        f"data: {line}\n" for line in fragment.splitlines()
                        if line.strip())
                    yield f"event: status\n{lines}\n"
                    await asyncio.sleep(beat_interval)
            except asyncio.CancelledError:
                pass

        return StreamingResponse(_stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    return app


def main() -> None:
    """Serve the dashboard on loopback only; expose via tailscale serve."""
    settings = load_config()
    conn = store.init_db(settings.db_path)
    uvicorn.run(create_app(settings, conn), host=HOST, port=settings.port)


if __name__ == "__main__":
    main()


__all__ = ["HOST", "create_app", "esc", "main", "render_status_fragment",
           "status_snapshot"]
