"""Agent tools: Tier 0 (read-only) only, allowlisted, JSON schemas.

AGENTS.md: the agent may only call named tools defined in code. Every tool
here is read-only; mutating tiers do not exist yet. Vaultwarden is excluded
by code (not by prompt): any service/path argument referencing it raises
ToolDenied before anything runs, in both the central dispatcher and each
individual tool.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
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


class LiveBackend(Backend):
    """Real Tier-0 sampling: docker SDK (read-only), stdlib, collectors."""

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


class MockBackend(Backend):
    """Canned Tier-0 data for tests and dry-run mode."""

    def __init__(self, *, logs: dict | None = None,
                 inspect: dict | None = None, disk: dict | None = None,
                 mounts: dict | None = None,
                 metrics: list[Reading] | None = None) -> None:
        self.logs = dict(logs or {})
        self.inspect = dict(inspect or {})
        self.disk = dict(disk or {"path": "/", "used_pct": 42.0})
        self.mounts = dict(mounts or {})
        self.metrics = list(metrics or [])
        self.calls: list[tuple[str, dict]] = []

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


def tool_specs_for_prompt() -> str:
    """Render the tool registry as prompt text (names, tiers, schemas)."""
    import json as _json

    lines = []
    for tool in AGENT_TOOLS.values():
        lines.append(
            f"- {tool.name} (Tier {tool.tier}, read-only): "
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
