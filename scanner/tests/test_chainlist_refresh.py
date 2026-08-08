from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "refresh_chainlist.py"
SPEC = importlib.util.spec_from_file_location("refresh_chainlist", SCRIPT)
assert SPEC and SPEC.loader
refresh_chainlist = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refresh_chainlist)


def test_build_registry_is_sorted_and_preserves_known_classification():
    payload = [
        {"chainId": 10, "name": "OP Mainnet", "shortName": "oeth"},
        {"chainId": 1, "name": "Ethereum Mainnet", "shortName": "eth"},
        {"chainId": 99, "name": "New Devnet", "shortName": "new-dev"},
    ]
    existing = {
        "10": {
            "name": "Old OP Name",
            "short_name": "oeth",
            "is_testnet": True,
        }
    }

    registry = refresh_chainlist.build_registry(payload, existing=existing)

    assert list(registry) == ["1", "10", "99"]
    assert registry["10"]["name"] == "OP Mainnet"
    assert registry["10"]["is_testnet"] is True
    assert registry["99"]["is_testnet"] is True


def test_build_registry_rejects_duplicate_chain_ids():
    payload = [
        {"chainId": 1, "name": "One", "shortName": "one"},
        {"chainId": 1, "name": "Duplicate", "shortName": "dup"},
    ]

    with pytest.raises(ValueError, match="Duplicate chainId"):
        refresh_chainlist.build_registry(payload)


def test_serialized_registry_is_compact_and_stable():
    registry = {
        "1": {
            "name": "Ethereum Mainnet",
            "short_name": "eth",
            "is_testnet": False,
        }
    }

    first = refresh_chainlist.serialize_registry(registry)
    second = refresh_chainlist.serialize_registry(registry)

    assert first == second
    assert first.endswith("\n")
    assert json.loads(first) == registry
    assert "\n" not in first.rstrip("\n")


def test_validate_registry_rejects_truncated_source():
    with pytest.raises(ValueError, match="suspiciously small"):
        refresh_chainlist.validate_registry(
            {
                "1": {
                    "name": "Ethereum Mainnet",
                    "short_name": "eth",
                    "is_testnet": False,
                }
            }
        )
