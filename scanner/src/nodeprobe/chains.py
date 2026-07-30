"""EVM chain registry — any chain ID is accepted; names from Chainlist when known."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True)
class ChainInfo:
    chain_id: int
    name: str
    short_name: str
    is_testnet: bool = False
    listed: bool = True


# Backward-compatible alias used by older imports/tests.
SUPPORTED_CHAINS: dict[int, ChainInfo] = {}


class UnsupportedChainError(ValueError):
    """Deprecated: scans no longer abort on unknown chains.

    Kept so older callers that catch this exception continue to work.
    """

    def __init__(self, chain_id: int | None, message: str | None = None):
        self.chain_id = chain_id
        super().__init__(
            message or f"Unsupported or unknown chain ID: {chain_id}."
        )


@lru_cache(maxsize=1)
def _load_registry() -> dict[int, ChainInfo]:
    text = resources.files("nodeprobe").joinpath("data/chains_mini.json").read_text(
        encoding="utf-8"
    )
    raw = json.loads(text)
    registry: dict[int, ChainInfo] = {}
    for key, value in raw.items():
        chain_id = int(key)
        registry[chain_id] = ChainInfo(
            chain_id=chain_id,
            name=str(value["name"]),
            short_name=str(value.get("short_name") or f"chain-{chain_id}"),
            is_testnet=bool(value.get("is_testnet")),
            listed=True,
        )
    # Populate alias for introspection / tests that inspect the map.
    SUPPORTED_CHAINS.clear()
    SUPPORTED_CHAINS.update(registry)
    return registry


def known_chains() -> dict[int, ChainInfo]:
    return dict(_load_registry())


def resolve_chain(chain_id: int) -> ChainInfo:
    """Resolve any EVM chain ID. Unknown IDs get a generic name and continue scanning."""
    if not isinstance(chain_id, int):
        raise TypeError(f"chain_id must be int, got {type(chain_id)!r}")
    if chain_id < 0:
        raise ValueError(f"chain_id must be non-negative, got {chain_id}")
    info = _load_registry().get(chain_id)
    if info is not None:
        return info
    return ChainInfo(
        chain_id=chain_id,
        name=f"Chain {chain_id}",
        short_name=f"chain-{chain_id}",
        is_testnet=False,
        listed=False,
    )


def parse_hex_or_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.startswith("0x") or text.startswith("0X"):
        return int(text, 16)
    return int(text)
