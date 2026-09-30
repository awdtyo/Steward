"""Dry-run mode: replay mock events from a JSON fixture.

The fixture holds ticks of readings (no real collectors, no network, no
mail). Format: {"ticks": [{"readings": [<Reading dict>, ...]}, ...]}.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from .collectors import Reading

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "mock_events.json"


def load_fixture(path: str | Path = FIXTURE_PATH) -> list[list[Reading]]:
    """Load fixture ticks as lists of readings."""
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    ticks = payload.get("ticks", [])
    if not isinstance(ticks, list):
        raise ValueError("Fixture must contain a 'ticks' list")
    out: list[list[Reading]] = []
    for tick in ticks:
        readings = tick.get("readings", []) if isinstance(tick, dict) else []
        out.append([Reading.from_dict(r) for r in readings])
    return out


def replay(path: str | Path = FIXTURE_PATH) -> Iterator[list[Reading]]:
    """Yield one list of readings per fixture tick."""
    yield from load_fixture(path)


__all__ = ["FIXTURE_PATH", "load_fixture", "replay"]
