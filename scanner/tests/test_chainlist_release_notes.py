from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "chainlist_release_notes.py"
SPEC = importlib.util.spec_from_file_location("chainlist_release_notes", SCRIPT)
assert SPEC and SPEC.loader
notes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notes)


def test_release_notes_list_added_and_renamed_networks():
    previous = {
        "1": {"name": "Ethereum Mainnet", "short_name": "eth", "is_testnet": False},
        "10": {"name": "Old OP", "short_name": "oeth", "is_testnet": False},
        "206": {"name": "VinuChain Testnet", "short_name": "VCTEST", "is_testnet": True},
    }
    registry = {
        "1": {"name": "Ethereum Mainnet", "short_name": "eth", "is_testnet": False},
        "10": {"name": "OP Mainnet", "short_name": "oeth", "is_testnet": False},
        "99": {"name": "New Chain", "short_name": "new", "is_testnet": True},
        "206": {"name": "VinuChain Testnet", "short_name": "vc-testnet", "is_testnet": True},
    }

    text = notes.format_release_notes(previous, registry)

    assert "Added **1** network:" in text
    assert "- New Chain (`99`)" in text
    assert "- Old OP → OP Mainnet (`10`)" in text
    assert "VinuChain Testnet" not in text.split("Renamed:")[1]
    assert "pipx upgrade nodeprobe" in text
