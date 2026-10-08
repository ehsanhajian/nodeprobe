#!/usr/bin/env python3
"""Write GitHub release notes that list new and renamed Chainlist networks."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "scanner" / "src" / "nodeprobe" / "data" / "chains_mini.json"
REFRESH = ROOT / "scripts" / "refresh_chainlist.py"

SPEC = importlib.util.spec_from_file_location("refresh_chainlist", REFRESH)
assert SPEC and SPEC.loader
refresh_chainlist = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refresh_chainlist)


def load_registry(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Registry must be an object: {path}")
    return payload


def registry_from_git(ref: str) -> dict[str, dict[str, Any]]:
    blob = subprocess.check_output(
        ["git", "show", f"{ref}:scanner/src/nodeprobe/data/chains_mini.json"],
        cwd=ROOT,
    )
    payload = json.loads(blob.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Registry at {ref} must be an object")
    return payload


def previous_release_tag() -> str | None:
    raw = subprocess.check_output(
        ["git", "tag", "--list", "v*", "--sort=-v:refname"],
        cwd=ROOT,
    )
    tags = [line.strip() for line in raw.decode().splitlines() if line.strip()]
    return tags[0] if tags else None


def format_release_notes(
    previous: dict[str, dict[str, Any]],
    registry: dict[str, dict[str, Any]],
) -> str:
    added, _removed, _renamed = refresh_chainlist.registry_delta(previous, registry)
    lines = ["## Chainlist", ""]
    if added:
        noun = "network" if len(added) == 1 else "networks"
        lines.append(f"Added **{len(added)}** {noun}:")
        lines.append("")
        for chain_id in added:
            name = registry[chain_id].get("name") or f"Chain {chain_id}"
            lines.append(f"- {name} (`{chain_id}`)")
        lines.append("")
    else:
        lines.append("No new Chainlist networks in this release.")
        lines.append("")
    lines.extend(
        [
            "```bash",
            "pipx upgrade nodeprobe",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--since",
        default=None,
        help="Git ref of the previous registry (default: latest v* tag)",
    )
    args = parser.parse_args()
    since = args.since or previous_release_tag()
    previous = registry_from_git(since) if since else {}
    notes = format_release_notes(previous, load_registry(REGISTRY))
    print(notes, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
