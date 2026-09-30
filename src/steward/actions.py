"""Action layer policy: propose / approve / deny / execute / rollback.

Tiers (AGENTS.md):
- Tier 1 (restart_container, clear_cache): reversible and automatic. A
  proposal is auto-approved by policy, but only for services on the
  per-service allowlist, and every transition is audit-logged.
- Tier 2 (restore_snapshot, config_change): destructive or config-changing.
  Requires a human approval (never the requester -- self-approval is
  rejected in code), a pre-action snapshot (compose file + redacted config
  copy, plus a documented volume-backup step), and a stored rollback plan.
- config_change is proposal-only: approval and snapshot are recorded, but
  no automatic executor exists, so a human performs the change manually.
- Vaultwarden is rejected in code on every path, even if allowlisted.

Statuses: proposed -> approved|denied -> executed|failed (-> rolled_back).
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from . import store as store_module
from .agent_tools import (AGENT_TOOLS, AgentTool, Backend, ToolDenied,
                          ToolError, _check_service, _guard_protected_args,
                          validate_args)
from .config import Settings
from .redact import redact

TIER1_POLICY_APPROVER = "policy:tier1"

# Kinds the machine may execute after approval. config_change is
# deliberately absent: proposal-only, human performs the change.
AUTO_EXECUTORS = frozenset({"restart_container", "clear_cache",
                            "restore_snapshot"})

VOLUME_BACKUP_DOC = (
    "Before touching volumes, back up each named volume first, e.g.: "
    "docker run --rm -v <volume>:/data -v <backup-dir>:/backup "
    "busybox tar czf /backup/<volume>-<date>.tgz -C /data . "
    "Verify the archive ('tar tzf ...') before proceeding."
)


def _validate_action(kind: str, args: object,
                     settings: Settings) -> tuple[AgentTool, dict]:
    """Registry + schema + protected + allowlist checks. No side effects."""
    tool = AGENT_TOOLS.get(kind)
    if tool is None:
        raise ToolDenied(f"Unknown action (not allowlisted): {kind}")
    if tool.tier not in (1, 2):
        raise ToolDenied(f"Tool {kind} is not a Tier 1/2 action")
    validated = validate_args(tool, args)
    _guard_protected_args(validated)
    service = validated.get("service")
    if service is not None:
        # Protected reject first: Vaultwarden can never be allowlisted.
        _check_service(service)
        if tool.tier == 1 and service not in settings.tier1_allow_services:
            raise ToolDenied(
                f"Service {service} is not on the Tier-1 allowlist")
    return tool, validated


def run_mutating_tool(name: str, args: dict, backend: Backend,
                      settings: Settings) -> Any:
    """Validate (registry, schema, allowlist) then run a Tier 1/2 tool."""
    _, validated = _validate_action(name, args, settings)
    tool = AGENT_TOOLS[name]
    try:
        return tool.func(validated, backend)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Tool {name} failed: {exc}") from exc


def _snapshot_settings(settings: Settings) -> str:
    """Redacted config copy for snapshots (never includes secrets)."""
    safe = {"llm_base_url": settings.llm_base_url,
            "model_nano": settings.model_nano,
            "model_super": settings.model_super,
            "model_ultra": settings.model_ultra,
            "dashboard_base_url": settings.dashboard_base_url,
            "port": settings.port}
    return redact(json.dumps(safe, sort_keys=True))


def propose_action(conn: sqlite3.Connection, settings: Settings, *,
                   incident_key: str = "", tier: int, kind: str,
                   args: dict, requested_by: str = "agent",
                   rollback_plan: str = "",
                   service_specs=None) -> int:
    """Validate and record an action. Tier 1 auto-approves by policy."""
    tool, validated = _validate_action(kind, args, settings)
    if tier != tool.tier:
        raise ToolDenied(f"{kind} is Tier {tool.tier}, not Tier {tier}")
    service = validated.get("service")
    if service_specs and service:
        for spec in service_specs:
            if spec.name == service and spec.allowed_actions is not None \
                    and kind not in spec.allowed_actions:
                raise ToolDenied(
                    f"{kind} is not an allowed action for {service}")
    plan = (rollback_plan or "").strip()
    if tool.tier == 2:
        if len(plan) < 20:
            raise ToolDenied("Tier 2 requires a rollback plan (min 20 chars)")
        if "volume" in json.dumps(validated).lower() \
                and "backup" not in plan.lower():
            raise ToolDenied("Tier 2 touching volumes needs a documented "
                             "backup step in the rollback plan")
    status = "approved" if tier == 1 else "proposed"
    approved_by = TIER1_POLICY_APPROVER if tier == 1 else ""
    action_id = store_module.insert_action(
        conn, incident_key=incident_key, tier=tier, kind=kind,
        args_json=json.dumps(validated), status=status,
        requested_by=requested_by, approved_by=approved_by,
        rollback_plan=plan)
    if tier == 1:
        store_module.set_action(conn, action_id, decided_ts=time.time())
        store_module.audit_append(conn, TIER1_POLICY_APPROVER,
                                  "action.approved",
                                  {"action_id": action_id, "kind": kind,
                                   "automatic": True})
    store_module.audit_append(conn, requested_by, "action.proposed",
                              {"action_id": action_id, "tier": tier,
                               "kind": kind, "incident_key": incident_key})
    return action_id


def _check_approver(settings: Settings, approver: str, *,
                    requested_by: str, allow_self: bool = False) -> str:
    who = (approver or "").strip()
    if not who:
        raise ToolDenied("Approver identity is required")
    if not settings.allowed_approver:
        raise ToolDenied("No approver configured: approvals fail closed")
    if who.lower() != settings.allowed_approver.lower():
        raise ToolDenied(f"Approver {who} is not authorized")
    if not allow_self and who.lower() == (requested_by or "").lower():
        raise ToolDenied("Self-approval is denied")
    return who


def _take_snapshot(conn: sqlite3.Connection, settings: Settings,
                   backend: Backend, action_id: int) -> int:
    compose = backend.compose_text()  # ToolError aborts the approval
    snapshot_id = store_module.save_snapshot(
        conn, action_id, compose, _snapshot_settings(settings),
        note=f"Pre-action snapshot. Volumes: {VOLUME_BACKUP_DOC}")
    store_module.audit_append(conn, "system", "snapshot.taken",
                              {"action_id": action_id,
                               "snapshot_id": snapshot_id})
    return snapshot_id


def approve_action(conn: sqlite3.Connection, settings: Settings,
                   backend: Backend, action_id: int, *,
                   approver: str) -> sqlite3.Row:
    """Human-approve a proposed action (Tier 2 snapshots first)."""
    row = store_module.get_action(conn, action_id)
    if row is None:
        raise ToolDenied(f"Unknown action: {action_id}")
    if row["status"] != "proposed":
        raise ToolDenied(
            f"Cannot approve action in status {row['status']}")
    who = _check_approver(settings, approver,
                          requested_by=row["requested_by"])
    snapshot_id = None
    if row["tier"] == 2:
        snapshot_id = _take_snapshot(conn, settings, backend, action_id)
    store_module.set_action(conn, action_id, status="approved",
                            approved_by=who, decided_ts=time.time(),
                            snapshot_id=snapshot_id)
    store_module.audit_append(conn, who, "action.approved",
                              {"action_id": action_id, "kind": row["kind"],
                               "snapshot_id": snapshot_id})
    return store_module.get_action(conn, action_id)


def deny_action(conn: sqlite3.Connection, settings: Settings, action_id: int,
                *, approver: str, reason: str = "") -> sqlite3.Row:
    """Human-deny a proposed action (self-deny allowed: safe direction)."""
    row = store_module.get_action(conn, action_id)
    if row is None:
        raise ToolDenied(f"Unknown action: {action_id}")
    if row["status"] != "proposed":
        raise ToolDenied(f"Cannot deny action in status {row['status']}")
    who = _check_approver(settings, approver,
                          requested_by=row["requested_by"], allow_self=True)
    store_module.set_action(conn, action_id, status="denied",
                            approved_by=who, decided_ts=time.time())
    store_module.audit_append(conn, who, "action.denied",
                              {"action_id": action_id, "kind": row["kind"],
                               "reason": reason})
    return store_module.get_action(conn, action_id)


def execute_action(conn: sqlite3.Connection, settings: Settings,
                   backend: Backend, action_id: int, *,
                   actor: str = "system") -> dict:
    """Execute an approved action. Tier 2 needs its snapshot on record."""
    row = store_module.get_action(conn, action_id)
    if row is None:
        raise ToolDenied(f"Unknown action: {action_id}")
    if row["status"] != "approved":
        raise ToolDenied(
            f"Cannot execute action in status {row['status']}: "
            "approval required first")
    kind = row["kind"]
    if kind not in AUTO_EXECUTORS:
        raise ToolDenied(
            f"{kind} has no automatic executor: perform the change "
            "manually following the stored rollback plan")
    if row["tier"] == 2 and not row["snapshot_id"]:
        raise ToolDenied("Tier 2 execution needs a pre-action snapshot")
    args = json.loads(row["args_json"])
    if kind == "restore_snapshot":
        snapshot = store_module.get_snapshot(conn, args["snapshot_id"])
        if snapshot is None:
            raise ToolDenied("Snapshot for restore is missing")
        args = {**args, "compose_text": snapshot["compose_text"]}
    try:
        result = run_mutating_tool(kind, args, backend, settings)
    except (ToolDenied, ToolError) as exc:
        store_module.set_action(conn, action_id, status="failed",
                                error=f"{type(exc).__name__}: {exc}")
        store_module.audit_append(conn, actor, "action.failed",
                                  {"action_id": action_id, "kind": kind,
                                   "error": str(exc)})
        raise
    store_module.set_action(conn, action_id, status="executed",
                            result=json.dumps(result, default=str))
    store_module.audit_append(conn, actor, "action.executed",
                              {"action_id": action_id, "kind": kind,
                               "result": result})
    return result


def approve_and_execute(conn: sqlite3.Connection, settings: Settings,
                        backend: Backend, action_id: int, *,
                        approver: str) -> sqlite3.Row:
    """Dashboard flow: approve, then execute when an executor exists."""
    row = approve_action(conn, settings, backend, action_id,
                         approver=approver)
    if row["kind"] in AUTO_EXECUTORS:
        execute_action(conn, settings, backend, action_id, actor=approver)
        return store_module.get_action(conn, action_id)
    return row


def rollback_action(conn: sqlite3.Connection, settings: Settings,
                    backend: Backend, action_id: int, *,
                    actor: str) -> int:
    """Roll back an executed Tier-2 action by restoring its snapshot.

    The rollback itself is pre-authorized by the original human approval
    (recorded on the new action row); a fresh snapshot is taken first so
    the rollback is itself rollbackable.
    """
    if not (actor or "").strip():
        raise ToolDenied("Rollback actor identity is required")
    orig = store_module.get_action(conn, action_id)
    if orig is None:
        raise ToolDenied(f"Unknown action: {action_id}")
    if orig["tier"] != 2:
        raise ToolDenied("Tier-1 actions need no rollback (reversible)")
    if orig["status"] != "executed":
        raise ToolDenied(
            f"Cannot roll back action in status {orig['status']}")
    if not orig["snapshot_id"] or not orig["rollback_plan"]:
        raise ToolDenied("Rollback needs the original snapshot and plan")
    snapshot = store_module.get_snapshot(conn, orig["snapshot_id"])
    if snapshot is None:
        raise ToolDenied("Original snapshot is missing")
    requested_by = f"{actor} (rollback of #{orig['id']})"
    new_id = store_module.insert_action(
        conn, incident_key=orig["incident_key"], tier=2,
        kind="restore_snapshot",
        args_json=json.dumps({"snapshot_id": orig["snapshot_id"]}),
        status="approved", requested_by=requested_by,
        approved_by=orig["approved_by"],
        rollback_plan=f"Rollback of action #{orig['id']}: restore the "
                      f"pre-action snapshot. {VOLUME_BACKUP_DOC}")
    store_module.set_action(conn, new_id, decided_ts=time.time())
    pre_snapshot_id = _take_snapshot(conn, settings, backend, new_id)
    store_module.set_action(conn, new_id, snapshot_id=pre_snapshot_id)
    store_module.audit_append(conn, actor, "action.rollback_started",
                              {"action_id": new_id,
                               "rolls_back": orig["id"],
                               "pre_authorized_by": orig["approved_by"]})
    execute_action(conn, settings, backend, new_id, actor=actor)
    store_module.set_action(conn, orig["id"], status="rolled_back")
    store_module.audit_append(conn, actor, "action.rolled_back",
                              {"action_id": orig["id"],
                               "via_action": new_id})
    return new_id


__all__ = [
    "AUTO_EXECUTORS",
    "TIER1_POLICY_APPROVER",
    "VOLUME_BACKUP_DOC",
    "approve_action",
    "approve_and_execute",
    "deny_action",
    "execute_action",
    "propose_action",
    "rollback_action",
    "run_mutating_tool",
]
