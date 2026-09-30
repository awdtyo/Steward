"""SQLite storage for readings and incidents. Stdlib sqlite3 only."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .collectors import Reading
from .rules import Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS readings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  source TEXT NOT NULL,
  service TEXT NOT NULL,
  metric TEXT NOT NULL,
  value TEXT,
  unit TEXT NOT NULL DEFAULT '',
  ok INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS incidents (
  key TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  rule TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  last_alerted REAL,
  count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_readings_ts ON readings (ts);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE TABLE IF NOT EXISTS llm_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  purpose TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd REAL NOT NULL DEFAULT 0.0,
  latency_s REAL NOT NULL DEFAULT 0.0,
  redaction_count INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 1,
  ok INTEGER NOT NULL DEFAULT 1,
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_llm_calls_ts ON llm_calls (ts);
CREATE TABLE IF NOT EXISTS agent_steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  incident_key TEXT NOT NULL,
  step_no INTEGER NOT NULL,
  kind TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  tool TEXT NOT NULL DEFAULT '',
  args_json TEXT NOT NULL DEFAULT '{}',
  output TEXT NOT NULL DEFAULT '',
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  redaction_count INTEGER NOT NULL DEFAULT 0,
  latency_s REAL NOT NULL DEFAULT 0.0,
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_steps_key ON agent_steps (incident_key);
CREATE TABLE IF NOT EXISTS diagnoses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  incident_key TEXT NOT NULL,
  summary TEXT NOT NULL,
  likely_cause TEXT NOT NULL,
  confidence REAL NOT NULL,
  suggested_fix TEXT NOT NULL,
  model TEXT NOT NULL,
  steps INTEGER NOT NULL,
  escalated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_diagnoses_key ON diagnoses (incident_key);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  incident_key TEXT NOT NULL DEFAULT '',
  tier INTEGER NOT NULL,
  kind TEXT NOT NULL,
  args_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'proposed',
  requested_by TEXT NOT NULL DEFAULT '',
  approved_by TEXT NOT NULL DEFAULT '',
  decided_ts REAL,
  snapshot_id INTEGER,
  rollback_plan TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions (status);
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  action_id INTEGER NOT NULL,
  compose_text TEXT NOT NULL DEFAULT '',
  config_json TEXT NOT NULL DEFAULT '{}',
  note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);
-- Append-only: updates and deletes are rejected at the database level.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;
-- Hand-logged incident memory (CLI): symptom/cause/fix recall.
CREATE TABLE IF NOT EXISTS memory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  service TEXT NOT NULL DEFAULT '',
  symptom TEXT NOT NULL,
  cause TEXT NOT NULL DEFAULT '',
  fix TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_memory_service ON memory (service);
"""


def init_db(path: str | Path) -> sqlite3.Connection:
    """Open (creating parents) and migrate the steward database."""
    path = Path(path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def save_readings(conn: sqlite3.Connection,
                  readings: list[Reading]) -> int:
    """Persist readings (values only, never raw logs). Returns row count."""
    conn.executemany(
        "INSERT INTO readings (ts, source, service, metric, value, unit, ok)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r.ts, r.source, r.service, r.metric,
          None if r.value is None else str(r.value), r.unit, int(r.ok))
         for r in readings],
    )
    conn.commit()
    return len(readings)


def upsert_incident(conn: sqlite3.Connection, incident: Incident,
                    now: float | None = None) -> None:
    """Insert a new open incident or refresh an existing one (any status)."""
    now = time.time() if now is None else now
    conn.execute(
        """INSERT INTO incidents
             (key, service, rule, title, severity, status,
              first_seen, last_seen, count)
           VALUES (?, ?, ?, ?, ?, 'open', ?, ?, 1)
           ON CONFLICT(key) DO UPDATE SET
             service=excluded.service, rule=excluded.rule,
             title=excluded.title, severity=excluded.severity,
             status='open', last_seen=excluded.last_seen,
             count=incidents.count+1""",
        (incident.key, incident.service, incident.rule, incident.title,
         incident.severity, incident.observed_ts, now),
    )
    conn.commit()


def mark_alerted(conn: sqlite3.Connection, key: str,
                 now: float | None = None) -> None:
    now = time.time() if now is None else now
    conn.execute("UPDATE incidents SET last_alerted=? WHERE key=?", (now, key))
    conn.commit()


def resolve_incident(conn: sqlite3.Connection, key: str,
                     now: float | None = None) -> bool:
    """Mark an open incident resolved. Returns True if one was open."""
    now = time.time() if now is None else now
    cur = conn.execute(
        "UPDATE incidents SET status='resolved', last_seen=?"
        " WHERE key=? AND status='open'",
        (now, key),
    )
    conn.commit()
    return cur.rowcount > 0


def get_open(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM incidents WHERE status='open' ORDER BY first_seen"))


def get_incident(conn: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM incidents WHERE key=?", (key,)).fetchone()


def log_llm_call(conn: sqlite3.Connection, *, purpose: str, model: str,
                 prompt_tokens: int = 0, completion_tokens: int = 0,
                 total_tokens: int = 0, cost_usd: float = 0.0,
                 latency_s: float = 0.0, redaction_count: int = 0,
                 attempts: int = 1, ok: bool = True,
                 error: str = "") -> int:
    """Persist one LLM call for cost/latency auditing. Returns the row id."""
    cur = conn.execute(
        """INSERT INTO llm_calls
             (ts, purpose, model, prompt_tokens, completion_tokens,
              total_tokens, cost_usd, latency_s, redaction_count,
              attempts, ok, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.time(), purpose, model, prompt_tokens, completion_tokens,
         total_tokens, cost_usd, latency_s, redaction_count, attempts,
         int(ok), error),
    )
    conn.commit()
    return cur.lastrowid


def llm_usage_totals(conn: sqlite3.Connection) -> dict:
    """Aggregate token/cost/call counts across all logged LLM calls."""
    row = conn.execute(
        """SELECT COUNT(*) AS calls,
                  COALESCE(SUM(prompt_tokens), 0) AS prompt_tokens,
                  COALESCE(SUM(completion_tokens), 0) AS completion_tokens,
                  COALESCE(SUM(total_tokens), 0) AS total_tokens,
                  COALESCE(SUM(cost_usd), 0.0) AS cost_usd,
                  COALESCE(SUM(latency_s), 0.0) AS latency_s
           FROM llm_calls""").fetchone()
    return dict(row)


def save_agent_step(conn: sqlite3.Connection, incident_key: str, step_no: int,
                    kind: str, *, model: str = "", tool: str = "",
                    args_json: str = "{}", output: str = "",
                    prompt_tokens: int = 0, completion_tokens: int = 0,
                    total_tokens: int = 0, redaction_count: int = 0,
                    latency_s: float = 0.0, error: str = "") -> int:
    """Persist one agent step (tool outputs stored redacted)."""
    cur = conn.execute(
        """INSERT INTO agent_steps
             (ts, incident_key, step_no, kind, model, tool, args_json,
              output, prompt_tokens, completion_tokens, total_tokens,
              redaction_count, latency_s, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.time(), incident_key, step_no, kind, model, tool, args_json,
         output, prompt_tokens, completion_tokens, total_tokens,
         redaction_count, latency_s, error),
    )
    conn.commit()
    return cur.lastrowid


def save_diagnosis(conn: sqlite3.Connection, incident_key: str, summary: str,
                   likely_cause: str, confidence: float, suggested_fix: str,
                   model: str, steps: int, escalated: bool = False) -> int:
    """Persist the final diagnosis for an incident."""
    cur = conn.execute(
        """INSERT INTO diagnoses
             (ts, incident_key, summary, likely_cause, confidence,
              suggested_fix, model, steps, escalated)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.time(), incident_key, summary, likely_cause, confidence,
         suggested_fix, model, steps, int(escalated)),
    )
    conn.commit()
    return cur.lastrowid


def get_trace(conn: sqlite3.Connection,
              incident_key: str) -> tuple[sqlite3.Row | None,
                                         list[sqlite3.Row]]:
    """Latest diagnosis plus all steps for an incident key."""
    diagnosis = conn.execute(
        "SELECT * FROM diagnoses WHERE incident_key=? ORDER BY id DESC LIMIT 1",
        (incident_key,)).fetchone()
    steps = list(conn.execute(
        "SELECT * FROM agent_steps WHERE incident_key=? ORDER BY step_no",
        (incident_key,)))
    return diagnosis, steps


def insert_action(conn: sqlite3.Connection, *, incident_key: str, tier: int,
                  kind: str, args_json: str, status: str, requested_by: str,
                  approved_by: str = "", snapshot_id: int | None = None,
                  rollback_plan: str = "") -> int:
    cur = conn.execute(
        """INSERT INTO actions
             (ts, incident_key, tier, kind, args_json, status, requested_by,
              approved_by, snapshot_id, rollback_plan)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.time(), incident_key, tier, kind, args_json, status,
         requested_by, approved_by, snapshot_id, rollback_plan),
    )
    conn.commit()
    return cur.lastrowid


def get_action(conn: sqlite3.Connection, action_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()


def list_actions(conn: sqlite3.Connection, *,
                 status: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
    if status is None:
        return list(conn.execute(
            "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)))
    return list(conn.execute(
        "SELECT * FROM actions WHERE status=? ORDER BY id DESC LIMIT ?",
        (status, limit)))


def set_action(conn: sqlite3.Connection, action_id: int, **fields) -> None:
    """Update whitelisted action columns (status lifecycle only)."""
    allowed = {"status", "approved_by", "decided_ts", "snapshot_id",
               "result", "error"}
    updates = {key: value for key, value in fields.items() if key in allowed}
    if not updates:
        raise ValueError("No updatable action fields provided")
    assignments = ", ".join(f"{key}=?" for key in updates)
    conn.execute(f"UPDATE actions SET {assignments} WHERE id=?",
                 (*updates.values(), action_id))
    conn.commit()


def save_snapshot(conn: sqlite3.Connection, action_id: int, compose_text: str,
                  config_json: str, note: str = "") -> int:
    cur = conn.execute(
        """INSERT INTO snapshots
             (ts, action_id, compose_text, config_json, note)
           VALUES (?, ?, ?, ?, ?)""",
        (time.time(), action_id, compose_text, config_json, note),
    )
    conn.commit()
    return cur.lastrowid


def get_snapshot(conn: sqlite3.Connection,
                 snapshot_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()


def audit_append(conn: sqlite3.Connection, actor: str, action: str,
                 details: dict | str = "") -> int:
    """Append one audit entry. There is no update or delete path."""
    if not isinstance(details, str):
        import json as _json
        details = _json.dumps(details, default=str)
    cur = conn.execute(
        "INSERT INTO audit_log (ts, actor, action, details_json)"
        " VALUES (?, ?, ?, ?)",
        (time.time(), actor, action, details),
    )
    conn.commit()
    return cur.lastrowid


def audit_list(conn: sqlite3.Connection, limit: int = 200) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)))


def audit_for_action(conn: sqlite3.Connection,
                     action_id: int) -> list[sqlite3.Row]:
    """Audit entries referencing one action (newest first)."""
    import json as _json

    out = []
    for row in audit_list(conn, limit=1000):
        try:
            details = _json.loads(row["details_json"])
        except (ValueError, TypeError):
            continue
        if isinstance(details, dict) and details.get("action_id") == action_id:
            out.append(row)
    return out


def memory_add(conn: sqlite3.Connection, *, service: str = "",
               symptom: str, cause: str = "", fix: str = "",
               tags: str = "") -> int:
    """Hand-log one incident into memory. Symptom is required."""
    if not symptom.strip():
        raise ValueError("Symptom is required")
    cur = conn.execute(
        """INSERT INTO memory (ts, service, symptom, cause, fix, tags)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (time.time(), service.strip(), symptom.strip(), cause.strip(),
         fix.strip(), tags.strip()),
    )
    conn.commit()
    return cur.lastrowid


def memory_list(conn: sqlite3.Connection, limit: int = 20) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM memory ORDER BY id DESC LIMIT ?", (limit,)))


def memory_search(conn: sqlite3.Connection, query: str,
                  limit: int = 20) -> list[sqlite3.Row]:
    """Substring recall over service/symptom/cause/fix/tags."""
    escaped = (query.replace("\\", "\\\\").replace("%", "\\%")
               .replace("_", "\\_"))
    like = f"%{escaped}%"
    return list(conn.execute(
        """SELECT * FROM memory
           WHERE service LIKE ? ESCAPE '\\' OR symptom LIKE ? ESCAPE '\\'
             OR cause LIKE ? ESCAPE '\\' OR fix LIKE ? ESCAPE '\\'
             OR tags LIKE ? ESCAPE '\\'
           ORDER BY id DESC LIMIT ?""",
        (like, like, like, like, like, limit)))


__all__ = [
    "audit_append",
    "audit_for_action",
    "audit_list",
    "get_action",
    "get_incident",
    "get_open",
    "get_snapshot",
    "get_trace",
    "init_db",
    "insert_action",
    "list_actions",
    "llm_usage_totals",
    "log_llm_call",
    "mark_alerted",
    "memory_add",
    "memory_list",
    "memory_search",
    "resolve_incident",
    "save_agent_step",
    "save_diagnosis",
    "save_readings",
    "save_snapshot",
    "set_action",
    "upsert_incident",
]
