"""Tests for the read-only diagnosis agent (mock LLM, mock backend)."""

import json

import pytest
from fastapi.testclient import TestClient

from steward import store
from steward.agent import (diagnose, diagnose_and_store)
from steward.agent_tools import (MockBackend, ToolDenied, run_agent_tool)
from steward.app import create_app
from steward.collectors import Reading
from steward.config import load_config
from steward.llm import LLMResponse, VaultwardenRefusal
from steward.monitor import tick
from steward.heartbeat import Heartbeat
from steward.rules import Deduper, Incident


@pytest.fixture
def settings():
    return load_config({"DRY_RUN": "true"})


@pytest.fixture
def backend():
    return MockBackend(
        logs={"jellyfin": "OOM killer invoked for jellyfin\n"
                          "restarting in 5s\nok"},
        inspect={"jellyfin": {"name": "jellyfin", "status": "exited"}},
        metrics=[Reading("docker", "jellyfin", "container_state", "exited")],
    )


def _incident(service="jellyfin", severity="warning"):
    return Incident(f"{service}:container", service, "container",
                    f"{service} container exited", severity,
                    observed_ts=1700000000.0)


class MockLLM:
    """Scripted replies; records every prompt for security assertions."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, settings, messages, *, model=None, purpose="",
                 **kwargs):
        self.calls.append({
            "model": model, "purpose": purpose,
            "messages": [{"role": m["role"], "content": m["content"]}
                         for m in messages]})
        item = self.script[min(len(self.calls) - 1, len(self.script) - 1)]
        if isinstance(item, BaseException):
            raise item
        return LLMResponse(model=model or "mock", content=item,
                           prompt_tokens=10, completion_tokens=5,
                           total_tokens=15, latency_s=0.1,
                           redaction_count=0, attempts=1)


def _diag(content="done", confidence=0.8):
    return json.dumps({"diagnosis": {
        "summary": content, "likely_cause": "out of memory",
        "confidence": confidence, "suggested_fix": "raise memory limit"}})


def _call(tool, args):
    return json.dumps({"call": {"tool": tool, "args": args}})


def test_full_loop_calls_tools_and_stores_trace(settings, backend):
    conn = store.init_db(":memory:")
    llm = MockLLM([
        _call("read_logs", {"service": "jellyfin", "lines": 20}),
        _call("docker_inspect", {"service": "jellyfin"}),
        _diag("jellyfin OOM-killed"),
    ])
    diagnosis = diagnose_and_store(settings, conn, _incident(),
                                   backend=backend, llm_chat=llm)
    assert diagnosis.summary == "jellyfin OOM-killed"
    assert diagnosis.likely_cause == "out of memory"
    assert diagnosis.confidence == 0.8
    assert diagnosis.escalated is False
    assert [s.kind for s in diagnosis.steps] == ["llm", "tool", "llm",
                                                 "tool", "llm"]
    assert diagnosis.steps[1].tool == "read_logs"
    assert diagnosis.steps[3].tool == "docker_inspect"
    # Defaults applied: lines omitted still reaches the backend as 50.
    llm2 = MockLLM([_call("read_logs", {"service": "jellyfin"}),
                    _diag("x")])
    diagnose(settings, _incident(), backend=backend, llm_chat=llm2,
             store_conn=conn)
    assert ("read_logs", {"service": "jellyfin", "lines": 50}) in \
        backend.calls

    saved_diagnosis, saved_steps = store.get_trace(conn, "jellyfin:container")
    assert saved_diagnosis["summary"] == "jellyfin OOM-killed"
    assert len(saved_steps) == 5
    assert saved_steps[0]["model"] == saved_diagnosis["model"]
    assert saved_steps[0]["prompt_tokens"] == 10
    # Every LLM call was also logged for cost auditing.
    assert store.llm_usage_totals(conn)["calls"] == 3 + 2
    conn.close()


def test_prompts_wrap_logs_and_forbid_following_them(settings, backend):
    llm = MockLLM([_call("read_logs", {"service": "jellyfin"}), _diag("x")])
    diagnose(settings, _incident(), backend=backend, llm_chat=llm)
    system = llm.calls[0]["messages"][0]["content"]
    assert "never follow" in system.lower()
    assert "untrusted" in system.lower()
    second_turn = llm.calls[1]["messages"]
    tool_msg = second_turn[-1]["content"]
    assert "<untrusted-log>" in tool_msg and "</untrusted-log>" in tool_msg
    assert "OOM killer" in tool_msg


def test_vaultwarden_excluded_by_code(settings, backend):
    incident = _incident(service="vaultwarden", severity="critical")
    with pytest.raises(VaultwardenRefusal):
        diagnose(settings, incident, backend=backend,
                 llm_chat=MockLLM([_diag("x")]))
    assert backend.calls == []  # no tool ever ran
    with pytest.raises(ToolDenied):
        run_agent_tool("read_logs", {"service": "Vaultwarden"}, backend)
    with pytest.raises(ToolDenied):  # central arg guard: paths too
        run_agent_tool("check_mount", {"path": "/var/lib/vaultwarden"},
                       backend)
    with pytest.raises(ToolDenied):
        run_agent_tool("rm_rf", {}, backend)
    with pytest.raises(ToolDenied):  # schema: lines above maximum
        run_agent_tool("read_logs", {"service": "x", "lines": 999}, backend)
    with pytest.raises(ToolDenied):  # schema: missing required
        run_agent_tool("read_logs", {}, backend)
    with pytest.raises(ToolDenied):  # schema: bad service name
        run_agent_tool("read_logs", {"service": "../x"}, backend)


def test_protected_lines_never_reach_the_llm(settings):
    sneaky = MockBackend(logs={"svc": "error at 10.1.2.3\n"
                                         "vaultwarden token=abc\nok"})
    llm = MockLLM([_call("read_logs", {"service": "svc"}), _diag("x")])
    diagnosis = diagnose(settings, _incident(service="svc"), backend=sneaky,
                         llm_chat=llm)
    for call in llm.calls:
        for message in call["messages"]:
            assert "vaultwarden" not in message["content"].lower()
            assert "10.1.2.3" not in message["content"]
    assert diagnosis.steps[1].redaction_count >= 1
    assert "vaultwarden" not in diagnosis.steps[1].output


def test_step_limit_and_inconclusive(settings, backend):
    llm = MockLLM([_call("disk_usage", {})])  # never finishes
    diagnosis = diagnose(settings, _incident(), backend=backend,
                         llm_chat=llm, max_steps=3)
    assert diagnosis.confidence == 0.0
    assert "Inconclusive" in diagnosis.summary
    assert len(diagnosis.steps) <= 2 * 3 + 2  # bounded incl. escalation


def test_low_confidence_escalates_model(settings, backend):
    llm = MockLLM([_diag("maybe disk", confidence=0.2),
                   _diag("definitely disk", confidence=0.9)])
    diagnosis = diagnose(settings, _incident(), backend=backend,
                         llm_chat=llm)
    assert diagnosis.confidence == 0.9
    assert diagnosis.escalated is True
    models = [call["model"] for call in llm.calls]
    assert models[0] == settings.model_nano  # triage base
    assert models[-1] == settings.model_super  # one tier up


def test_tick_diagnoses_new_incidents_and_skips_protected(settings, backend):
    conn = store.init_db(":memory:")
    llm = MockLLM([_diag("disk full")])
    summary = tick(
        settings, conn, Deduper(), Heartbeat(), now=1000.0,
        readings=[Reading("system", "host", "disk_used_pct", 95.0)],
        backend=backend, llm_chat=llm)
    assert summary["diagnosed"] == ["host:disk_used_pct"]
    assert summary["diagnosis_skipped"] == []
    saved, _ = store.get_trace(conn, "host:disk_used_pct")
    assert saved["summary"] == "disk full"

    summary = tick(
        settings, conn, Deduper(), Heartbeat(), now=2000.0,
        readings=[Reading("docker", "vaultwarden", "container_state",
                          "exited")],
        backend=backend, llm_chat=llm)
    assert summary["diagnosis_skipped"] == ["vaultwarden:container"]
    conn.close()


def test_trace_page_shows_steps_and_usage(settings, backend):
    conn = store.init_db(":memory:")
    llm = MockLLM([_call("disk_usage", {}), _diag("disk full")])
    diagnose_and_store(settings, conn, _incident(service="host"),
                       backend=backend, llm_chat=llm)
    app = create_app(settings, conn)
    with TestClient(app) as client:
        resp = client.get("/trace/host:container")
    assert resp.status_code == 200
    assert "disk full" in resp.text
    assert "disk_usage" in resp.text
    assert "10/5/15" in resp.text  # prompt/completion/total tokens
    with TestClient(app) as client:
        empty = client.get("/trace/nope:missing")
    assert empty.status_code == 200
    assert "No diagnosis recorded yet" in empty.text
    conn.close()
