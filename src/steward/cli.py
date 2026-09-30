"""steward CLI: hand-log real incidents into memory. Stdlib argparse only.

Usage:
  steward incident add --symptom "..." --cause "..." --fix "..."
      [--service NAME] [--tags a,b]
  steward incident list [--limit N]
  steward incident search <text>
"""

from __future__ import annotations

import argparse
import sys

from . import store as store_module
from .config import Settings, load_config


def _settings(settings: Settings | None) -> Settings:
    return settings if settings is not None else load_config()


def _cmd_add(conn, args) -> int:
    entry_id = store_module.memory_add(
        conn, service=args.service, symptom=args.symptom,
        cause=args.cause, fix=args.fix, tags=args.tags)
    print(f"Recorded incident #{entry_id} in memory.")
    return 0


def _print_entries(rows) -> None:
    if not rows:
        print("No incidents in memory.")
        return
    for row in rows:
        print(f"#{row['id']} [{row['service'] or 'general'}] {row['symptom']}")
        if row["cause"]:
            print(f"  cause: {row['cause']}")
        if row["fix"]:
            print(f"  fix: {row['fix']}")
        if row["tags"]:
            print(f"  tags: {row['tags']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="steward",
                                     description="Steward homelab operator")
    sub = parser.add_subparsers(dest="resource", required=True)
    incident = sub.add_parser("incident", help="hand-logged incident memory")
    ops = incident.add_subparsers(dest="op", required=True)

    add = ops.add_parser("add", help="log an incident by hand")
    add.add_argument("--symptom", required=True)
    add.add_argument("--cause", default="")
    add.add_argument("--fix", default="")
    add.add_argument("--service", default="")
    add.add_argument("--tags", default="")

    listing = ops.add_parser("list", help="list remembered incidents")
    listing.add_argument("--limit", type=int, default=20)

    search = ops.add_parser("search", help="search remembered incidents")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=20)
    return parser


def main(argv: list[str] | None = None,
         settings: Settings | None = None) -> int:
    """Entry point (also installed as the `steward` console script)."""
    args = build_parser().parse_args(argv)
    conn = store_module.init_db(_settings(settings).db_path)
    try:
        if args.op == "add":
            return _cmd_add(conn, args)
        if args.op == "list":
            _print_entries(store_module.memory_list(conn, args.limit))
            return 0
        if args.op == "search":
            _print_entries(store_module.memory_search(conn, args.query,
                                                      args.limit))
            return 0
    finally:
        conn.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["build_parser", "main"]
