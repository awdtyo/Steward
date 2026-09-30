"""Named, allowlisted tools.

AGENTS.md: the agent must never run arbitrary shell commands. Collectors may
only invoke tools registered in TOOLS below: fixed argv, no shell, extra
arguments validated against a strict pattern. Anything else raises ToolError.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


class ToolError(Exception):
    """Raised when a tool is unknown, unavailable, or fails."""


@dataclass(frozen=True)
class Tool:
    name: str
    argv: tuple[str, ...]
    extra_pattern: str | None  # regex each extra arg must match, else no extras
    description: str


# Read-only diagnostics only. No Tier 1/2 (mutating) tools live here.
TOOLS: dict[str, Tool] = {
    "tailscale_status": Tool(
        name="tailscale_status",
        argv=("tailscale", "status", "--json"),
        extra_pattern=None,
        description="Tailscale connectivity status (read-only).",
    ),
    "smartctl_health": Tool(
        name="smartctl_health",
        argv=("smartctl", "--json", "-H"),
        extra_pattern=r"^/dev/(sd[a-z]+|nvme\d+n\d+|mmcblk\d+|vd[a-z]+|hd[a-z]+)$",
        description="Disk SMART health for one device node (read-only).",
    ),
    "vcgencmd_throttled": Tool(
        name="vcgencmd_throttled",
        argv=("vcgencmd", "get_throttled"),
        extra_pattern=None,
        description="Raspberry Pi throttling flags (read-only).",
    ),
}


def run_tool(name: str, *args: str, timeout: int = 10) -> str:
    """Run a registered tool and return its stdout. Never uses a shell."""
    tool = TOOLS.get(name)
    if tool is None:
        raise ToolError(f"Unknown tool (not allowlisted): {name}")
    if args and tool.extra_pattern is None:
        raise ToolError(f"Tool {name} takes no arguments")
    pattern = re.compile(tool.extra_pattern) if tool.extra_pattern else None
    for arg in args:
        if pattern is None or not pattern.match(arg):
            raise ToolError(f"Rejected argument for {name}: {arg!r}")
    exe = shutil.which(tool.argv[0])
    if exe is None:
        raise ToolError(f"Tool unavailable (not installed): {tool.argv[0]}")
    try:
        proc = subprocess.run(
            [exe, *tool.argv[1:], *args],
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Tool timed out: {name}") from exc
    except OSError as exc:
        raise ToolError(f"Tool failed to start: {name}: {exc}") from exc
    if proc.returncode != 0:
        raise ToolError(f"Tool failed: {name}: {proc.stderr.strip()[:200]}")
    return proc.stdout


__all__ = ["TOOLS", "Tool", "ToolError", "run_tool"]
