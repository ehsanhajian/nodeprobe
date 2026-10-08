from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bump_package_version.py"
SPEC = importlib.util.spec_from_file_location("bump_package_version", SCRIPT)
assert SPEC and SPEC.loader
bump_package_version = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bump_package_version)


def test_bump_patch_in_text_increments_patch_only():
    text = 'name = "nodeprobe"\nversion = "0.1.5"\n'
    updated, old, new = bump_package_version.bump_patch_in_text(
        text,
        bump_package_version.TOML_VERSION,
    )
    assert old == "0.1.5"
    assert new == "0.1.6"
    assert 'version = "0.1.6"' in updated
