"""Auto-detect RPC protocol family from a public endpoint."""

from __future__ import annotations

from typing import Literal

from nodeprobe.multichain.aptos_engine import looks_like_aptos_ledger, normalize_aptos_base
from nodeprobe.multichain.common import is_rpc_failure
from nodeprobe.rpc import RpcClient

RpcFamily = Literal["evm", "solana", "substrate", "cosmos", "aptos"]


def detect_family(client: RpcClient) -> RpcFamily | None:
    """Probe cheap identity methods. Order prefers unambiguous signals."""
    # Aptos REST /v1 ledger (before JSON-RPC families)
    aptos = _detect_aptos(client)
    if aptos:
        return "aptos"

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


def _detect_aptos(client: RpcClient) -> bool:
    import time

    base = normalize_aptos_base(client.target.original_url)
    try:
        client._enforce_budget()  # noqa: SLF001
        t0 = time.monotonic()
        response = client._client.get(base)  # noqa: SLF001
        client._record(response, t0)  # noqa: SLF001
    except Exception:  # noqa: BLE001
        return False
    if response.status_code != 200:
        return False
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        return False
    return looks_like_aptos_ledger(payload)
