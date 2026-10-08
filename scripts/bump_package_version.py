#!/usr/bin/env python3
"""Bump Nodeprobe's package patch version in lockstep files."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "scanner" / "pyproject.toml"
INIT = ROOT / "scanner" / "src" / "nodeprobe" / "__init__.py"

TOML_VERSION = re.compile(
    r'^(version = ")(\d+)\.(\d+)\.(\d+)(")',
    re.MULTILINE,
)
INIT_VERSION = re.compile(
    r'^(__version__ = ")(\d+)\.(\d+)\.(\d+)(")',
    re.MULTILINE,
)


def bump_patch_in_text(text: str, pattern: re.Pattern[str]) -> tuple[str, str, str]:
    match = pattern.search(text)
    if not match:
        raise ValueError("Could not find a semantic version to bump")
    old = f"{match.group(2)}.{match.group(3)}.{match.group(4)}"
    new = f"{match.group(2)}.{match.group(3)}.{int(match.group(4)) + 1}"
    updated = pattern.sub(rf"\g<1>{new}\g<5>", text, count=1)
    return updated, old, new


def bump_package_patch() -> str:
    pyproject_text = PYPROJECT.read_text(encoding="utf-8")
    init_text = INIT.read_text(encoding="utf-8")
    pyproject_updated, old, new = bump_patch_in_text(pyproject_text, TOML_VERSION)
    init_updated, init_old, init_new = bump_patch_in_text(init_text, INIT_VERSION)
    if old != init_old or new != init_new:
        raise ValueError(
            f"Version mismatch before bump: pyproject {old} vs __init__ {init_old}"
        )
    PYPROJECT.write_text(pyproject_updated, encoding="utf-8")
    INIT.write_text(init_updated, encoding="utf-8")
    return new


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    new = bump_package_patch()
    print(f"Bumped package version to {new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
