"""Tests for the action layer: allowlists, approvals, audit, dashboard."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from steward import actions, store
from steward.agent_tools import (MockBackend, ToolDenied, ToolError,
                                 run_agent_tool)
from steward.app import create_app
from steward.config import load_config

ADMIN = "admin@example.com"
PLAN = ("Restore the previous compose file from the stored snapshot. "
        "Volume backup: tar each named volume before executing.")


@pytest.fixture
def settings():
    return load_config({"DRY_RUN": "true", "ALLOWED_APPROVER": ADMIN})


@pytest.fixture
def backend():
    return MockBackend()


@pytest.fixture
def conn():
    connection = store.init_db(":memory:")
    yield connection
    connection.close()


def propose_t1(conn, settings, service="jellyfin", kind="restart_container"):
    return actions.propose_action(
        conn, settings, incident_key="jellyfin:container", tier=1,
        kind=kind, args={"service": service}, requested_by="agent")


def propose_t2(conn, settings, kind="restore_snapshot", args=None):
    return actions.propose_action(
        conn, settings, incident_key="host:disk_used_pct", tier=2,
        kind=kind, args=args or {"snapshot_id": 1},
        requested_by="agent", rollback_plan=PLAN)


def test_agent_loop_cannot_reach_mutating_tools(backend):
    # The diagnosis dispatcher only runs Tier 0, enforced in code.
    for name in ("restart_container", "clear_cache", "restore_snapshot",
                 "config_change", "rm_rf"):
        with pytest.raises(ToolDenied):
            run_agent_tool(name, {"service": "jellyfin"}, backend)
    assert backend.calls == [] and backend.restarts == []


def test_tier1_auto_approves_and_executes(conn, settings, backend):
    action_id = propose_t1(conn, settings)
    row = store.get_action(conn, action_id)
    assert (row["status"], row["approved_by"]) == ("approved", "policy:tier1")
    result = actions.execute_action(conn, settings, backend, action_id,
                                    actor="system")
    assert result == {"restarted": True, "service": "jellyfin"}
    assert backend.restarts == ["jellyfin"]
    assert store.get_action(conn, action_id)["status"] == "executed"
    entries = store.audit_for_action(conn, action_id)
    assert {entry["action"] for entry in entries} >= {
        "action.proposed", "action.approved", "action.executed"}


def test_clear_cache_uses_fixed_paths(conn, settings, backend):
    action_id = propose_t1(conn, settings, kind="clear_cache")
    actions.execute_action(conn, settings, backend, action_id)
    assert backend.cleared == [(("jellyfin", ("/tmp", "/var/tmp")))]


def test_allowlist_and_vaultwarden_rejection(conn, settings, backend):
    with pytest.raises(ToolDenied, match="allowlist"):
        propose_t1(conn, settings, service="pihole")
    # Even explicitly allowlisted, Vaultwarden is rejected in code.
    permissive = load_config({"DRY_RUN": "true",
                              "TIER1_ALLOW_SERVICES": "vaultwarden,jellyfin",
                              "ALLOWED_APPROVER": ADMIN})
    with pytest.raises(ToolDenied):
        propose_t1(conn, permissive, service="vaultwarden")
    with pytest.raises(ToolDenied):
        actions.propose_action(
            conn, permissive, tier=2, kind="config_change",
            args={"service": "vaultwarden", "summary": "x" * 30,
                  "target": "/data"}, requested_by="agent",
            rollback_plan=PLAN)
    # Unknown kinds are outside the allowlist entirely.
    with pytest.raises(ToolDenied, match="allowlisted"):
        actions.propose_action(
            conn, settings, tier=1, kind="wipe_disk", args={},
            requested_by="agent")


def test_failed_execution_is_recorded(conn, settings):
    backend = MockBackend(fail_services=("jellyfin",))
    action_id = propose_t1(conn, settings)
    with pytest.raises(ToolError, match="Mock restart failure"):
        actions.execute_action(conn, settings, backend, action_id)
    row = store.get_action(conn, action_id)
    assert row["status"] == "failed" and "Mock restart failure" in row["error"]


def test_tier2_needs_plan_approval_and_snapshot(conn, settings, backend):
    with pytest.raises(ToolDenied, match="rollback plan"):
        actions.propose_action(
            conn, settings, tier=2, kind="restore_snapshot",
            args={"snapshot_id": 1}, requested_by="agent")
    with pytest.raises(ToolDenied, match="rollback plan"):
        actions.propose_action(
            conn, settings, tier=2, kind="config_change",
            args={"summary": "bump memory", "target": "jellyfin"},
            requested_by="agent", rollback_plan="too short")
    action_id = actions.propose_action(
        conn, settings, tier=2, kind="config_change",
        args={"summary": "bump memory limit", "target": "jellyfin"},
        requested_by="agent", rollback_plan=PLAN)
    assert store.get_action(conn, action_id)["status"] == "proposed"
    # No approval, no execution.
    with pytest.raises(ToolDenied, match="approval required"):
        actions.execute_action(conn, settings, backend, action_id)
    row = actions.approve_action(conn, settings, backend, action_id,
                                 approver=ADMIN)
    assert row["status"] == "approved" and row["approved_by"] == ADMIN
    assert row["snapshot_id"] is not None
    snapshot = store.get_snapshot(conn, row["snapshot_id"])
    assert "services:" in snapshot["compose_text"]
    assert "backup" in snapshot["note"].lower()
    # Proposal-only kind: approved, but no automatic executor.
    with pytest.raises(ToolDenied, match="no automatic executor"):
        actions.execute_action(conn, settings, backend, action_id)


def test_volume_plan_requires_backup_step(conn, settings):
    with pytest.raises(ToolDenied, match="backup"):
        actions.propose_action(
            conn, settings, tier=2, kind="config_change",
            args={"summary": "move data volume", "target": "jellyfin volumes"},
            requested_by="agent",
            rollback_plan="Restore the previous compose file afterwards.")


def test_self_approval_and_identity_denied(conn, settings, backend):
    action_id = propose_t2(conn, settings)
    # The agent can never approve its own request, even when it is the
    # configured approver identity.
    agent_identity = load_config({"DRY_RUN": "true",
                                  "ALLOWED_APPROVER": "agent"})
    with pytest.raises(ToolDenied, match="Self-approval"):
        actions.approve_action(conn, agent_identity, backend, action_id,
                               approver="agent")
    # ...nor can anyone but the configured approver...
    with pytest.raises(ToolDenied, match="not authorized"):
        actions.approve_action(conn, settings, backend, action_id,
                               approver="intruder@example.com")
    # ...and with no approver configured, approvals fail closed.
    unconfigured = load_config({"DRY_RUN": "true"})
    with pytest.raises(ToolDenied, match="fail closed"):
        actions.approve_action(conn, unconfigured, backend, action_id,
                               approver=ADMIN)
    # Self-deny is allowed (safe direction).
    row = actions.deny_action(conn, settings, action_id, approver=ADMIN,
                              reason="not now")
    assert row["status"] == "denied"


def test_rollback_restores_snapshot(conn, settings, backend):
    backend.compose_text_value = "services:\n  jellyfin:\n    image: v1\n"
    action_id = propose_t2(conn, settings)
    actions.approve_and_execute(conn, settings, backend, action_id,
                                approver=ADMIN)
    assert backend.compose_text_value == "services:\n  jellyfin:\n    image: v1\n"
    backend.compose_text_value = "services:\n  jellyfin:\n    image: v2\n"
    new_id = actions.rollback_action(conn, settings, backend, action_id,
                                     actor=ADMIN)
    assert backend.compose_text_value == "services:\n  jellyfin:\n    image: v1\n"
    assert store.get_action(conn, action_id)["status"] == "rolled_back"
    assert store.get_action(conn, new_id)["status"] == "executed"
    # Tier-1 actions have nothing to roll back.
    t1 = propose_t1(conn, settings)
    actions.execute_action(conn, settings, backend, t1)
    with pytest.raises(ToolDenied, match="no rollback"):
        actions.rollback_action(conn, settings, backend, t1, actor=ADMIN)


def test_audit_log_is_append_only(conn):
    store.audit_append(conn, "agent", "action.proposed", {"action_id": 1})
    assert len(store.audit_list(conn)) == 1
    with pytest.raises(sqlite3.Error, match="append-only"):
        conn.execute("UPDATE audit_log SET actor='x' WHERE id=1")
    with pytest.raises(sqlite3.Error, match="append-only"):
        conn.execute("DELETE FROM audit_log WHERE id=1")
    assert store.audit_list(conn)[0]["actor"] == "agent"


# --- Dashboard approvals page ---

@pytest.fixture
def client(settings):
    connection = store.init_db(":memory:")
    app = create_app(settings, connection)
    with TestClient(app) as test_client:
        yield test_client, connection
    connection.close()


def _csrf(test_client):
    page = test_client.get("/approvals")
    assert page.status_code == 200
    return test_client.cookies.get("steward_csrf")


def _propose_restore(connection, settings):
    return actions.propose_action(
        connection, settings, tier=2, kind="restore_snapshot",
        args={"snapshot_id": 1}, requested_by="agent",
        rollback_plan=PLAN)


def test_approvals_page_lists_pending(client, settings):
    test_client, connection = client
    _propose_restore(connection, settings)
    page = test_client.get("/approvals")
    assert page.status_code == 200
    assert "restore_snapshot" in page.text
    assert "steward_csrf" in test_client.cookies


def test_approve_rejects_csrf_confirm_identity(client, settings):
    test_client, connection = client
    action_id = _propose_restore(connection, settings)
    url = f"/approvals/{action_id}/approve"
    # No CSRF token at all.
    assert test_client.post(url, data={"confirm": "yes"}).status_code == 403
    token = _csrf(test_client)
    headers = {"Tailscale-User-Login": ADMIN}
    # Wrong token.
    resp = test_client.post(url, data={"csrf_token": "bogus",
                                       "confirm": "yes"}, headers=headers)
    assert resp.status_code == 403
    # Missing confirm step.
    resp = test_client.post(url, data={"csrf_token": token}, headers=headers)
    assert resp.status_code == 400
    # Unknown identity (no header).
    resp = test_client.post(url, data={"csrf_token": token,
                                       "confirm": "yes"})
    assert resp.status_code == 403
    # Wrong identity.
    resp = test_client.post(
        url, data={"csrf_token": token, "confirm": "yes"},
        headers={"Tailscale-User-Login": "intruder@example.com"})
    assert resp.status_code == 403
    assert store.get_action(connection, action_id)["status"] == "proposed"


def test_approve_and_rollback_flow(client, settings):
    test_client, connection = client
    action_id = _propose_restore(connection, settings)
    token = _csrf(test_client)
    headers = {"Tailscale-User-Login": ADMIN}
    resp = test_client.post(
        f"/approvals/{action_id}/approve",
        data={"csrf_token": token, "confirm": "yes"}, headers=headers,
        follow_redirects=False)
    assert resp.status_code == 303
    row = store.get_action(connection, action_id)
    assert row["status"] == "executed" and row["approved_by"] == ADMIN
    assert row["snapshot_id"] is not None
    detail = test_client.get(f"/approvals/{action_id}")
    assert "executed" in detail.text and "Audit trail" in detail.text
    resp = test_client.post(
        f"/approvals/{action_id}/rollback",
        data={"csrf_token": token, "confirm": "yes"}, headers=headers,
        follow_redirects=False)
    assert resp.status_code == 303
    assert store.get_action(connection, action_id)["status"] == "rolled_back"


def test_deny_flow(client, settings):
    test_client, connection = client
    action_id = _propose_restore(connection, settings)
    token = _csrf(test_client)
    resp = test_client.post(
        f"/approvals/{action_id}/deny",
        data={"csrf_token": token, "confirm": "yes",
              "reason": "too risky"},
        headers={"Tailscale-User-Login": ADMIN}, follow_redirects=False)
    assert resp.status_code == 303
    assert store.get_action(connection, action_id)["status"] == "denied"
