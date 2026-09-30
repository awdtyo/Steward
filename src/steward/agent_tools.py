"""Agent tools: allowlisted, JSON schemas, tiered.

AGENTS.md: the agent may only call named tools defined in code. Tier 0 is
read-only; Tier 1 is reversible/automatic (restart, cache clear, both bound
to a per-service allowlist); Tier 2 edits config or volumes and always needs
a human approval plus a snapshot (see actions.py). Vaultwarden is excluded
by code (not by prompt): any service/path argument referencing it raises
ToolDenied before anything runs, in both the central dispatcher and each
individual tool.

run_agent_tool() only runs Tier 0 (the diagnosis loop uses it, so the
diagnosing agent can never trigger a mutation). Mutating tiers run only via
actions.run_action_tool().
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .collectors import Reading, collect_all


class ToolError(Exception):
    """Base class for agent tool failures."""


class ToolDenied(ToolError):
    """Refused: unknown tool, protected service, or invalid arguments."""


PROTECTED = frozenset({"vaultwarden"})
_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MAX_LOG_CHARS = 4000


def _check_service(service: object) -> str:
    if not isinstance(service, str) or not _SERVICE_RE.match(service):
        raise ToolDenied(f"Invalid service name: {service!r}")
    if service.strip().lower() in PROTECTED:
        raise ToolDenied(f"Protected service is off-limits: {service}")
    return service


def _check_path(path: object) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ToolDenied(f"Path must be absolute: {path!r}")
    normalized = os.path.normpath(path)
    if ".." in normalized.split(os.sep):
        raise ToolDenied(f"Path escapes root: {path!r}")
    return normalized


def _guard_protected_args(args: dict) -> None:
    """Central deny: no argument value may reference Vaultwarden."""

    def _scan(value: Any) -> None:
        if isinstance(value, str):
            lowered = value.lower()
            if any(name in lowered for name in PROTECTED):
                raise ToolDenied("Arguments referencing Vaultwarden denied")
        elif isinstance(value, dict):
            for item in value.values():
                _scan(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                _scan(item)

    for value in args.values():
        _scan(value)


class Backend:
    """Primitives behind the tools; swapped for fakes in tests/dry-run."""

    def container_logs(self, service: str, lines: int) -> str:
        raise NotImplementedError

    def container_inspect(self, service: str) -> dict:
        raise NotImplementedError

    def disk_usage(self) -> dict:
        raise NotImplementedError

    def check_mount(self, path: str) -> dict:
        raise NotImplementedError

    def latest_metrics(self, service: str | None = None) -> list[dict]:
        raise NotImplementedError

    # -- Tier 1/2 primitives (mutating; only reachable via actions.py) --

    def container_restart(self, service: str) -> dict:
        raise NotImplementedError

    def container_clear_cache(self, service: str,
                              paths: tuple[str, ...]) -> dict:
        raise NotImplementedError

    def compose_text(self) -> str:
        raise NotImplementedError

    def compose_restore(self, text: str) -> dict:
        raise NotImplementedError


class LiveBackend(Backend):
    """Real Tier-0 sampling plus Tier-1/2 primitives (docker SDK, files)."""

    def __init__(self, compose_path: str = "docker-compose.yml") -> None:
        self.compose_path = compose_path

    def container_logs(self, service: str, lines: int) -> str:
        try:
            import docker
        except ImportError as exc:
            raise ToolError("docker SDK unavailable") from exc
        try:
            client = docker.from_env(timeout=10)
            container = client.containers.get(service)
            raw = container.logs(tail=lines, timestamps=False)
        except Exception as exc:
            raise ToolError(f"Cannot read logs for {service}: {exc}") from exc
        text = raw.decode("utf-8", errors="replace") if isinstance(
            raw, bytes) else str(raw)
        return _truncate(text)

    def container_inspect(self, service: str) -> dict:
        try:
            import docker
        except ImportError as exc:
            raise ToolError("docker SDK unavailable") from exc
        try:
            client = docker.from_env(timeout=10)
            attrs = client.containers.get(service).attrs or {}
        except Exception as exc:
            raise ToolError(f"Cannot inspect {service}: {exc}") from exc
        state = attrs.get("State") or {}
        # Allowlist of fields; Config.Env (secrets) is never included.
        return {
            "id": str(attrs.get("Id", ""))[:12],
            "name": str(attrs.get("Name", "")).lstrip("/"),
            "image": str((attrs.get("Config") or {}).get("Image", "")),
            "created": str(attrs.get("Created", "")),
            "status": str(state.get("Status", "")),
            "exit_code": state.get("ExitCode"),
            "error": str(state.get("Error", "")),
            "health": str((state.get("Health") or {}).get("Status", "")),
            "mounts": [
                {"source": str(m.get("Source", "")),
                 "destination": str(m.get("Destination", "")),
                 "mode": str(m.get("Mode", ""))}
                for m in attrs.get("Mounts", [])],
        }

    def disk_usage(self) -> dict:
        try:
            usage = shutil.disk_usage("/")
        except OSError as exc:
            raise ToolError(f"disk_usage failed: {exc}") from exc
        return {"path": "/",
                "total_bytes": usage.total, "used_bytes": usage.used,
                "free_bytes": usage.free,
                "used_pct": round(100.0 * usage.used / usage.total, 1)
                if usage.total else 0.0}

    def check_mount(self, path: str) -> dict:
        return {"path": path, "exists": os.path.exists(path),
                "mounted": os.path.ismount(path)}

    def latest_metrics(self, service: str | None = None) -> list[dict]:
        try:
            readings = collect_all()
        except Exception as exc:
            raise ToolError(f"metrics collection failed: {exc}") from exc
        out = []
        for reading in readings:
            if service is not None and reading.service != service:
                continue
            item = reading.to_dict()
            item.pop("detail", None)  # never ship stored detail to the LLM
            out.append(item)
        return out

    def _container(self, service: str):
        try:
            import docker
        except ImportError as exc:
            raise ToolError("docker SDK unavailable") from exc
        try:
            return docker.from_env(timeout=10).containers.get(service)
        except Exception as exc:
            raise ToolError(f"Container {service} unavailable: {exc}") from exc

    def container_restart(self, service: str) -> dict:
        try:
            self._container(service).restart(timeout=30)
        except ToolError:
            raise
        except Exception as exc:
            raise ToolError(f"Restart of {service} failed: {exc}") from exc
        return {"restarted": True, "service": service}

    def container_clear_cache(self, service: str,
                              paths: tuple[str, ...]) -> dict:
        # Fixed argv, no shell: only the allowlisted tmp dirs are removed.
        try:
            result = self._container(service).exec_run(
                ["rm", "-rf", *paths], demux=False)
            exit_code = getattr(result, "exit_code", result[0]
                                if isinstance(result, tuple) else 1)
        except ToolError:
            raise
        except Exception as exc:
            raise ToolError(f"Cache clear on {service} failed: {exc}") from exc
        if exit_code != 0:
            raise ToolError(f"Cache clear on {service} exited {exit_code}")
        return {"cleared": True, "service": service,
                "paths": list(paths)}

    def compose_text(self) -> str:
        try:
            return Path(self.compose_path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ToolError(f"Cannot read {self.compose_path}: {exc}") from exc

    def compose_restore(self, text: str) -> dict:
        if not text or "services" not in text:
            raise ToolError("Refusing to write an invalid compose file")
        try:
            Path(self.compose_path).write_text(text, encoding="utf-8")
        except OSError as exc:
            raise ToolError(f"Cannot write {self.compose_path}: {exc}") from exc
        return {"restored": True, "bytes": len(text)}


class MockBackend(Backend):
    """Canned Tier-0 data for tests and dry-run mode."""

    def __init__(self, *, logs: dict | None = None,
                 inspect: dict | None = None, disk: dict | None = None,
                 mounts: dict | None = None,
                 metrics: list[Reading] | None = None,
                 fail_services: tuple[str, ...] = (),
                 compose_text: str = "services:\n  placeholder:\n"
                                     "    image: example/placeholder\n") -> None:
        self.logs = dict(logs or {})
        self.inspect = dict(inspect or {})
        self.disk = dict(disk or {"path": "/", "used_pct": 42.0})
        self.mounts = dict(mounts or {})
        self.metrics = list(metrics or [])
        self.fail_services = set(fail_services)
        self.compose_text_value = compose_text
        self.calls: list[tuple[str, dict]] = []
        self.restarts: list[str] = []
        self.cleared: list[tuple[str, tuple[str, ...]]] = []
        self.restored_texts: list[str] = []

    def container_logs(self, service: str, lines: int) -> str:
        self.calls.append(("read_logs", {"service": service, "lines": lines}))
        if service not in self.logs:
            raise ToolError(f"Unknown mock service: {service}")
        return _truncate("\n".join(self.logs[service].splitlines()[-lines:]))

    def container_inspect(self, service: str) -> dict:
        self.calls.append(("docker_inspect", {"service": service}))
        if service not in self.inspect:
            raise ToolError(f"Unknown mock service: {service}")
        return self.inspect[service]

    def disk_usage(self) -> dict:
        self.calls.append(("disk_usage", {}))
        return self.disk

    def check_mount(self, path: str) -> dict:
        self.calls.append(("check_mount", {"path": path}))
        return {"path": path, "exists": path in self.mounts,
                "mounted": bool(self.mounts.get(path, False))}

    def latest_metrics(self, service: str | None = None) -> list[dict]:
        self.calls.append(("get_metrics", {"service": service}))
        out = []
        for reading in self.metrics:
            if service is not None and reading.service != service:
                continue
            item = reading.to_dict()
            item.pop("detail", None)
            out.append(item)
        return out

    def container_restart(self, service: str) -> dict:
        self.calls.append(("restart_container", {"service": service}))
        self.restarts.append(service)
        if service in self.fail_services:
            raise ToolError(f"Mock restart failure for {service}")
        return {"restarted": True, "service": service}

    def container_clear_cache(self, service: str,
                              paths: tuple[str, ...]) -> dict:
        self.calls.append(("clear_cache",
                           {"service": service, "paths": list(paths)}))
        self.cleared.append((service, tuple(paths)))
        if service in self.fail_services:
            raise ToolError(f"Mock cache-clear failure for {service}")
        return {"cleared": True, "service": service,
                "paths": list(paths)}

    def compose_text(self) -> str:
        self.calls.append(("compose_read", {}))
        return self.compose_text_value

    def compose_restore(self, text: str) -> dict:
        self.calls.append(("compose_restore", {"bytes": len(text)}))
        self.restored_texts.append(text)
        self.compose_text_value = text
        return {"restored": True, "bytes": len(text)}


def _truncate(text: str, limit: int = _MAX_LOG_CHARS) -> str:
    if len(text) > limit:
        return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
    return text


def _read_logs(args: dict, backend: Backend) -> str:
    service = _check_service(args.get("service"))
    return backend.container_logs(service, args.get("lines", 50))


def _docker_inspect(args: dict, backend: Backend) -> dict:
    return backend.container_inspect(_check_service(args.get("service")))


def _disk_usage(args: dict, backend: Backend) -> dict:
    return backend.disk_usage()


def _check_mount(args: dict, backend: Backend) -> dict:
    return backend.check_mount(_check_path(args.get("path")))


def _get_metrics(args: dict, backend: Backend) -> list[dict]:
    service = args.get("service")
    if service is not None:
        _check_service(service)
    return backend.latest_metrics(service)


# Fixed cache targets for clear_cache: container tmp dirs only. Tmp is by
# definition disposable, which keeps this Tier 1 (reversible, automatic).
CACHE_CLEAR_PATHS = ("/tmp", "/var/tmp")


def _restart_container(args: dict, backend: Backend) -> dict:
    return backend.container_restart(_check_service(args.get("service")))


def _clear_cache(args: dict, backend: Backend) -> dict:
    service = _check_service(args.get("service"))
    return backend.container_clear_cache(service, CACHE_CLEAR_PATHS)


def _restore_snapshot(args: dict, backend: Backend) -> dict:
    # Snapshot text is injected by the rollback flow (actions.py), never by
    # the agent: the schema only requires the id for audit clarity.
    text = args.get("compose_text", "")
    if not isinstance(text, str) or "services" not in text:
        raise ToolDenied("restore_snapshot needs snapshot compose text")
    return backend.compose_restore(text)


def _config_change(args: dict, backend: Backend) -> dict:
    # Proposal-only: there is deliberately no automatic executor for
    # free-form config/volume changes. A human approves (snapshot stored)
    # and performs the change manually following the rollback plan.
    raise ToolDenied("config_change has no automatic executor: approve to "
                     "record the decision and snapshot, then perform the "
                     "change manually")


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    tier: int  # always 0 here; enforced by run_agent_tool
    schema: dict
    func: Any


AGENT_TOOLS: dict[str, AgentTool] = {
    "read_logs": AgentTool(
        "read_logs", "Read recent read-only logs for a service container.",
        0,
        {"type": "object",
         "properties": {
             "service": {"type": "string"},
             "lines": {"type": "integer", "default": 50,
                       "minimum": 1, "maximum": 200}},
         "required": ["service"], "additionalProperties": False},
        _read_logs),
    "docker_inspect": AgentTool(
        "docker_inspect", "Read-only container state, image, and mounts"
        " (never includes environment/secrets).", 0,
        {"type": "object",
         "properties": {"service": {"type": "string"}},
         "required": ["service"], "additionalProperties": False},
        _docker_inspect),
    "disk_usage": AgentTool(
        "disk_usage", "Read-only root filesystem usage.", 0,
        {"type": "object", "properties": {},
         "additionalProperties": False},
        _disk_usage),
    "check_mount": AgentTool(
        "check_mount", "Check whether an absolute path exists and is a"
        " mount point (read-only).", 0,
        {"type": "object",
         "properties": {"path": {"type": "string"}},
         "required": ["path"], "additionalProperties": False},
        _check_mount),
    "get_metrics": AgentTool(
        "get_metrics", "Fresh read-only host/service metric snapshot,"
        " optionally filtered to one service.", 0,
        {"type": "object",
         "properties": {"service": {"type": "string"}},
         "required": [], "additionalProperties": False},
        _get_metrics),
    "restart_container": AgentTool(
        "restart_container", "Tier 1: restart one allowlisted service"
        " container (reversible, automatic, logged).", 1,
        {"type": "object",
         "properties": {"service": {"type": "string"}},
         "required": ["service"], "additionalProperties": False},
        _restart_container),
    "clear_cache": AgentTool(
        "clear_cache", "Tier 1: remove container tmp dirs (/tmp, /var/tmp)"
        " on one allowlisted service (reversible, automatic, logged).", 1,
        {"type": "object",
         "properties": {"service": {"type": "string"}},
         "required": ["service"], "additionalProperties": False},
        _clear_cache),
    "restore_snapshot": AgentTool(
        "restore_snapshot", "Tier 2: restore the compose file from a"
        " snapshot (rollback path; needs approval + snapshot).", 2,
        {"type": "object",
         "properties": {"snapshot_id": {"type": "integer", "minimum": 1},
                        "compose_text": {"type": "string"}},
         "required": ["snapshot_id"], "additionalProperties": False},
        _restore_snapshot),
    "config_change": AgentTool(
        "config_change", "Tier 2: proposal-only record for a config/volume"
        " change (approval + snapshot stored; human performs the change).", 2,
        {"type": "object",
         "properties": {"service": {"type": "string"},
                        "summary": {"type": "string"},
                        "target": {"type": "string"}},
         "required": ["summary", "target"], "additionalProperties": False},
        _config_change),
}


def validate_args(tool: AgentTool, args: object) -> dict:
    """Validate *args* against the tool schema; apply defaults."""
    if not isinstance(args, dict):
        raise ToolDenied(f"Args for {tool.name} must be an object")
    schema = tool.schema
    if schema.get("additionalProperties") is False:
        for key in args:
            if key not in schema.get("properties", {}):
                raise ToolDenied(f"Unknown arg {key!r} for {tool.name}")
    validated: dict = {}
    for name in schema.get("required", []):
        if name not in args:
            raise ToolDenied(f"Missing required arg {name!r} for {tool.name}")
    for name, spec in schema.get("properties", {}).items():
        if name not in args:
            if "default" in spec:
                validated[name] = spec["default"]
            continue
        validated[name] = _check_value(tool.name, name, spec, args[name])
    return validated


def _check_value(tool_name: str, name: str, spec: dict,
                 value: object) -> object:
    expected = spec.get("type")
    if expected == "string" and not isinstance(value, str):
        raise ToolDenied(f"Arg {name!r} for {tool_name} must be a string")
    if expected == "integer" and not (isinstance(value, int)
                                      and not isinstance(value, bool)):
        raise ToolDenied(f"Arg {name!r} for {tool_name} must be an integer")
    if expected == "number" and not isinstance(value, (int, float)):
        raise ToolDenied(f"Arg {name!r} for {tool_name} must be a number")
    if "minimum" in spec and value < spec["minimum"]:
        raise ToolDenied(f"Arg {name!r} for {tool_name} below minimum")
    if "maximum" in spec and value > spec["maximum"]:
        raise ToolDenied(f"Arg {name!r} for {tool_name} above maximum")
    if "enum" in spec and value not in spec["enum"]:
        raise ToolDenied(f"Arg {name!r} for {tool_name} not allowed")
    return value


def run_agent_tool(name: str, args: dict, backend: Backend) -> Any:
    """Run one allowlisted Tier-0 tool. Returns raw output (redact later)."""
    tool = AGENT_TOOLS.get(name)
    if tool is None:
        raise ToolDenied(f"Unknown tool (not allowlisted): {name}")
    if tool.tier != 0:
        raise ToolDenied(f"Tool {name} is not Tier 0 read-only")
    validated = validate_args(tool, args)
    _guard_protected_args(validated)
    try:
        return tool.func(validated, backend)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"Tool {name} failed: {exc}") from exc


def tool_specs_for_prompt(tier: int | None = None) -> str:
    """Render the tool registry as prompt text, optionally tier-filtered.

    The diagnosis loop passes tier=0 so the model only ever sees read-only
    tools; run_agent_tool() enforces the same boundary in code.
    """
    import json as _json

    lines = []
    for tool in AGENT_TOOLS.values():
        if tier is not None and tool.tier != tier:
            continue
        scope = "read-only" if tool.tier == 0 else "restricted"
        lines.append(
            f"- {tool.name} (Tier {tool.tier}, {scope}): "
            f"{tool.description} Args: {_json.dumps(tool.schema)}")
    return "\n".join(lines)


__all__ = [
    "AGENT_TOOLS",
    "AgentTool",
    "Backend",
    "LiveBackend",
    "MockBackend",
    "ToolDenied",
    "ToolError",
    "run_agent_tool",
    "tool_specs_for_prompt",
    "validate_args",
]
