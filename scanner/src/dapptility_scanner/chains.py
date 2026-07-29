"""Supported EVM chain registry."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChainInfo:
    chain_id: int
    name: str
    short_name: str
    is_testnet: bool = False


# Initial MVP set — expand via ChainList import in V1.
SUPPORTED_CHAINS: dict[int, ChainInfo] = {
    1: ChainInfo(1, "Ethereum Mainnet", "eth"),
    10: ChainInfo(10, "Optimism", "op"),
    56: ChainInfo(56, "BNB Smart Chain", "bsc"),
    137: ChainInfo(137, "Polygon", "polygon"),
    250: ChainInfo(250, "Fantom", "ftm"),
    42161: ChainInfo(42161, "Arbitrum One", "arb"),
    43114: ChainInfo(43114, "Avalanche C-Chain", "avax"),
    8453: ChainInfo(8453, "Base", "base"),
    59144: ChainInfo(59144, "Linea", "linea"),
    534352: ChainInfo(534352, "Scroll", "scroll"),
    324: ChainInfo(324, "zkSync Era", "zksync"),
    100: ChainInfo(100, "Gnosis", "gnosis"),
    42220: ChainInfo(42220, "Celo", "celo"),
    # Common testnets
    11155111: ChainInfo(11155111, "Sepolia", "sepolia", is_testnet=True),
    84532: ChainInfo(84532, "Base Sepolia", "base-sepolia", is_testnet=True),
    421614: ChainInfo(421614, "Arbitrum Sepolia", "arb-sepolia", is_testnet=True),
    11155420: ChainInfo(11155420, "Optimism Sepolia", "op-sepolia", is_testnet=True),
    97: ChainInfo(97, "BNB Smart Chain Testnet", "bsc-testnet", is_testnet=True),
    80002: ChainInfo(80002, "Polygon Amoy", "polygon-amoy", is_testnet=True),
}


class UnsupportedChainError(ValueError):
    def __init__(self, chain_id: int | None, message: str | None = None):
        self.chain_id = chain_id
        super().__init__(
            message
            or (
                f"Unsupported or unknown chain ID: {chain_id}. "
                "Dapptility currently supports a fixed EVM chain list for MVP."
            )
        )


def resolve_chain(chain_id: int) -> ChainInfo:
    info = SUPPORTED_CHAINS.get(chain_id)
    if info is None:
        raise UnsupportedChainError(chain_id)
    return info


def parse_hex_or_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.startswith("0x") or text.startswith("0X"):
        return int(text, 16)
    return int(text)
