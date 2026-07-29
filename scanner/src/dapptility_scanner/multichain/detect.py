"""Auto-detect RPC protocol family from a public endpoint."""

from __future__ import annotations

from typing import Literal

from dapptility_scanner.multichain.common import is_rpc_failure
from dapptility_scanner.rpc import RpcClient

RpcFamily = Literal["evm", "solana", "substrate", "cosmos"]


def detect_family(client: RpcClient) -> RpcFamily | None:
    """Probe cheap identity methods. Order prefers unambiguous signals."""
    # Solana
    ok, result = client.method_available("getHealth")
    if ok and result == "ok":
        return "solana"
    ok, result = client.method_available("getVersion")
    if ok and isinstance(result, dict) and "solana-core" in result:
        return "solana"

    # Substrate / Polkadot
    ok, result = client.method_available("system_chain")
    if ok and isinstance(result, str) and result and not is_rpc_failure(result):
        return "substrate"

    # Cosmos Tendermint JSON-RPC
    ok, result = client.method_available("status")
    if ok and isinstance(result, dict) and (
        "node_info" in result or "sync_info" in result
    ):
        return "cosmos"

    # EVM last (many endpoints answer eth_* with errors that still look "available")
    ok, result = client.method_available("eth_chainId")
    if ok and isinstance(result, str) and result.startswith("0x"):
        return "evm"
    ok, result = client.method_available("net_version")
    if ok and not is_rpc_failure(result):
        return "evm"

    return None
